#!/usr/bin/env python3

"""
Offline DELEG-aware DNSSEC zone signer for adns_server.

Stage 1 (this file): NSEC chain, single CSK. Strips any existing DNSSEC
records and re-signs from scratch with explicit absolute RRSIG times, writing
<zonefile>.signed atomically. NSEC3, multi-key rollover, and DELEG cut handling
are later stages. See Signer.md.
"""

import argparse
import calendar
import collections
import os
import random  # pylint: disable=unused-import
import sys
import time

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.dnssec
import dns.exception

from dnssec_util import (  # pylint: disable=unused-import
    zone_from_file, load_private_key, key_basename,
    make_nsec_rrset, AUTH_IN_PARENT_RRTYPES)
# make_nsec_rrset and AUTH_IN_PARENT_RRTYPES are unused in this stage but are
# consumed by sign_zone() once it is implemented in Task 4.


class SignerError(Exception):
    """Fatal signer error: reported to stderr, nonzero exit, no output."""


_UNIT_SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400,
                 'w': 604800, 'y': 31536000}


def parse_duration(spec):
    """Parse a duration into seconds. Bare integer = seconds; a trailing
    s/m/h/d/w/y unit multiplies accordingly. Used directly for -j (jitter)."""
    spec = spec.strip()
    if not spec:
        raise SignerError("empty duration")
    unit = spec[-1]
    if unit in _UNIT_SECONDS:
        value = spec[:-1]
        mult = _UNIT_SECONDS[unit]
    else:
        value = spec
        mult = 1
    try:
        return int(value) * mult
    except ValueError as exc:
        raise SignerError(f"bad duration {spec!r}") from exc


def parse_time(spec, now):
    """Resolve an -e/-i time spec to an absolute epoch (int seconds, UTC).

    - 14-digit YYYYMMDDHHMMSS  -> that absolute UTC instant.
    - leading '+' or unsigned  -> now + parse_duration(rest).
    - leading '-'              -> now - parse_duration(rest).
    """
    spec = spec.strip()
    if len(spec) == 14 and spec.isdigit():
        struct = time.strptime(spec, "%Y%m%d%H%M%S")
        return calendar.timegm(struct)
    if spec.startswith('-'):
        return now - parse_duration(spec[1:])
    if spec.startswith('+'):
        return now + parse_duration(spec[1:])
    return now + parse_duration(spec)


KeyInfo = collections.namedtuple(
    "KeyInfo", ["dnskey_rdata", "keytag", "algorithm", "is_sep", "private_key"])

SEP_BIT = 0x0001


def discover_keys(zone, keydir):
    """Return a KeyInfo per apex DNSKEY. For each, compute the keytag and look
    for <keydir>/<zone>+<alg>+<keytag>.pem; load it if present (active), else
    the key is publish-only (private_key=None). Errors if the zone has no
    DNSKEY, or if no DNSKEY has a matching PEM (nothing to sign with)."""
    dnskey_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.DNSKEY)
    if not dnskey_rdataset:
        raise SignerError("zone has no apex DNSKEY RRset")
    zonename = zone.origin.to_text().rstrip('.')
    keys = []
    for rdata in dnskey_rdataset:
        keytag = dns.dnssec.key_id(rdata)
        pem = os.path.join(keydir,
                           key_basename(zonename, rdata.algorithm, keytag)
                           + ".pem")
        private_key = load_private_key(pem) if os.path.exists(pem) else None
        keys.append(KeyInfo(rdata, keytag, rdata.algorithm,
                            bool(rdata.flags & SEP_BIT), private_key))
    if not any(k.private_key is not None for k in keys):
        raise SignerError(
            f"no private key found in {keydir!r} for any DNSKEY of "
            f"{zonename} (looked for {zonename}+<alg>+<keytag>.pem)")
    return keys


def strip_dnssec(zone):
    """Remove all RRSIG/NSEC/NSEC3 rdatasets in place; keep DNSKEY/NSEC3PARAM."""
    doomed = (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
    for _name, node in zone.nodes.items():
        node.rdatasets = [rds for rds in node.rdatasets
                          if rds.rdtype not in doomed]


def write_zone(zone, output_path):
    """Serialize the (signed) zone. Absolute names (relativize=False). Writes
    to a temp file in the destination dir then atomically renames, so a failure
    leaves no partial .signed. output_path '-' writes to stdout."""
    text = zone.to_text(relativize=False)
    if output_path == '-':
        sys.stdout.write(text)
        return
    directory = os.path.dirname(os.path.abspath(output_path))
    tmp = os.path.join(directory, f".{os.path.basename(output_path)}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, output_path)


def sign_zone(zone, keys, inception, base_expiration, jitter):
    """Add RRSIGs and an NSEC chain to the stripped zone. Implemented in the
    next task."""
    raise NotImplementedError


def make_arg_parser():
    """Build the signzone.py argument parser (Signer.md §2)."""
    parser = argparse.ArgumentParser(
        description="Offline DNSSEC zone signer (NSEC, single CSK).")
    parser.add_argument("zonename", help="zone origin (e.g. example.com)")
    parser.add_argument("zonefile", help="unsigned zone file")
    parser.add_argument("-K", "--keydir", default=".",
                        help="directory of keytag-named PEM keys (default: .)")
    parser.add_argument("-o", "--output", default=None,
                        help="output file ('-' = stdout); "
                             "default <zonefile>.signed")
    parser.add_argument("-e", "--expiration", default="+30d",
                        help="RRSIG expiration (default: +30d)")
    parser.add_argument("-i", "--inception", default="-1h",
                        help="RRSIG inception (default: -1h)")
    parser.add_argument("-j", "--jitter", default="6h",
                        help="+/- jitter applied per-RRSIG (default: 6h)")
    parser.add_argument("--bump", action="store_true",
                        help="increment the SOA serial")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="per-RRset signing trace to stderr")
    return parser


def bump_serial(zone):
    """Increment the apex SOA serial (RFC 1982 wrap not handled; +1)."""
    soa_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    soa_rdataset[0].serial = (soa_rdataset[0].serial + 1) & 0xFFFFFFFF


def main(argv=None):
    """CLI entry point. Returns an exit code."""
    args = make_arg_parser().parse_args(argv)
    now = int(time.time())
    try:  # pylint: disable=too-many-try-statements
        inception = parse_time(args.inception, now)
        expiration = parse_time(args.expiration, now)
        jitter = parse_duration(args.jitter)
        zone = zone_from_file(dns.name.from_text(args.zonename), args.zonefile)
        keys = discover_keys(zone, args.keydir)
        strip_dnssec(zone)
        if args.bump:
            bump_serial(zone)
        sign_zone(zone, keys, inception, expiration, jitter)
        output = args.output or (args.zonefile + ".signed")
        write_zone(zone, output)
    except SignerError as exc:
        print(f"signzone: {exc}", file=sys.stderr)
        return 1
    except dns.exception.DNSException as exc:
        print(f"signzone: zone load/parse error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
