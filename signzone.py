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
import random
import sys
import time

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.dnssec
import dns.exception

from dnssec_util import (
    zone_from_file, load_private_key, key_basename,
    make_nsec_rrset, AUTH_IN_PARENT_RRTYPES)


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
        private_key = None
        if os.path.exists(pem):
            try:
                private_key = load_private_key(pem)
            except (ValueError, OSError) as exc:
                raise SignerError(f"cannot load private key {pem!r}: {exc}") from exc
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


def rrsig_rdata(rrset, private_key, signer,      # pylint: disable=too-many-positional-arguments
                dnskey, inception, expiration):
    """Uncached RRSIG generation with explicit absolute times -- the offline
    analog of the server's cached sign_rrset(). Returns RRSIG rdata."""
    return dns.dnssec.sign(rrset, private_key, signer, dnskey,
                           inception=inception, expiration=expiration)


def classify_signers(keys):
    """Return (dnskey_signers, rest_signers) from the active (PEM-bearing)
    keys. Invariant (Signer.md §§3-4): the DNSKEY RRset is signed by every SEP
    key that has a PEM; everything else by every non-SEP key that has a PEM. A
    single SEP key with no separate ZSK is a CSK and signs both."""
    active = [k for k in keys if k.private_key is not None]
    sep = [k for k in active if k.is_sep]
    zsk = [k for k in active if not k.is_sep]
    dnskey_signers = sep or zsk            # SEP signs DNSKEY; fall back to ZSK
    rest_signers = zsk or sep              # ZSK signs the rest; CSK fallback
    return dnskey_signers, rest_signers


def _jittered_expiration(base_expiration, jitter):
    """base_expiration +/- a uniform random offset in [-jitter, +jitter]."""
    if jitter <= 0:
        return base_expiration
    return base_expiration + random.randint(-jitter, jitter)


def _cut_names(zone):
    """Owners (other than the apex) that are delegation cuts: they have NS
    and/or a Delegation Type (DELEG). Returned as a set of dns.name.Name."""
    cuts = set()
    for name, node in zone.nodes.items():
        if name == zone.origin:
            continue
        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS):
            cuts.add(name)
            continue
        for rdtype in AUTH_IN_PARENT_RRTYPES:
            if rdtype == dns.rdatatype.DS:
                continue
            if node.get_rdataset(dns.rdataclass.IN, rdtype):
                cuts.add(name)
                break
    return cuts


def is_occluded(name, cut_names):
    """True if name is strictly below some delegation cut (glue / occluded)."""
    return any(name != cut and name.is_subdomain(cut) for cut in cut_names)


def authoritative_owners(zone, cut_names):
    """Owners that get an NSEC, in canonical sorted order: every non-ENT,
    non-occluded owner that owned an RRset in the unsigned zone. ENT nodes are
    empty (no rdatasets) and excluded; occluded glue below a cut is excluded."""
    owners = []
    for name, node in zone.nodes.items():
        if not node.rdatasets:                 # ENT
            continue
        if is_occluded(name, cut_names):        # glue below a cut
            continue
        owners.append(name)
    return sorted(owners)


def _rrsets_to_sign(name, node, is_cut):
    """Yield the authoritative RRsets at a node. At a cut only the
    authoritative-in-parent types (DS/DELEG) are signed; NS and glue are not.
    Elsewhere every non-DNSSEC RRset is authoritative."""
    for rdataset in list(node.rdatasets):
        rdtype = rdataset.rdtype
        if rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                      dns.rdatatype.NSEC3):
            continue
        if is_cut and rdtype not in AUTH_IN_PARENT_RRTYPES:
            continue
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        rrset.update(rdataset)
        yield rrset


def _add_rrsig(node, rrset, rrsig):
    """Attach an RRSIG rdata (covering rrset.rdtype) to node."""
    rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                  covers=rrset.rdtype, create=True)
    rdataset.add(rrsig, ttl=rrset.ttl)


def _sign_with_keys(node, rrset, signer, signers,          # pylint: disable=too-many-positional-arguments
                    inception, base_expiration, jitter):
    """Sign rrset with every key in signers and attach the RRSIGs to node."""
    for key in signers:
        rrsig = rrsig_rdata(rrset, key.private_key, signer, key.dnskey_rdata,
                            inception,
                            _jittered_expiration(base_expiration, jitter))
        _add_rrsig(node, rrset, rrsig)


def _sign_authoritative_rrsets(zone, cut_names, dnskey_signers, rest_signers,  # pylint: disable=too-many-positional-arguments
                               inception, base_expiration, jitter):
    """Sign every authoritative RRset in the zone (skip occluded glue)."""
    for name, node in zone.nodes.items():
        if is_occluded(name, cut_names):
            continue
        is_cut = name in cut_names
        for rrset in _rrsets_to_sign(name, node, is_cut):
            signers = (dnskey_signers if rrset.rdtype == dns.rdatatype.DNSKEY
                      else rest_signers)
            _sign_with_keys(node, rrset, zone.origin, signers,
                            inception, base_expiration, jitter)


def _build_nsec_chain(zone, cut_names, rest_signers,     # pylint: disable=too-many-positional-arguments
                      inception, base_expiration, jitter):
    """Build and sign the NSEC chain over authoritative owners."""
    owners = authoritative_owners(zone, cut_names)
    for i, owner in enumerate(owners):
        node = zone.get_node(owner)
        nextname = owners[(i + 1) % len(owners)]
        present = {rds.rdtype for rds in node.rdatasets
                   if rds.rdtype != dns.rdatatype.NSEC}
        present.add(dns.rdatatype.NSEC)
        present.add(dns.rdatatype.RRSIG)
        nsec_rrset = make_nsec_rrset(owner, nextname, sorted(present),
                                     zone.soa_min_ttl)
        node.rdatasets.append(nsec_rrset.to_rdataset())
        _sign_with_keys(node, nsec_rrset, zone.origin, rest_signers,
                        inception, base_expiration, jitter)


def sign_zone(zone, keys, inception, base_expiration, jitter):
    """Sign every authoritative RRset and build the NSEC chain in place."""
    dnskey_signers, rest_signers = classify_signers(keys)
    cut_names = _cut_names(zone)
    _sign_authoritative_rrsets(zone, cut_names, dnskey_signers, rest_signers,
                               inception, base_expiration, jitter)
    _build_nsec_chain(zone, cut_names, rest_signers,
                      inception, base_expiration, jitter)


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
    """Increment the apex SOA serial (RFC 1982 wrap not handled; +1).
    dnspython Rdata is immutable, so replace the rdata rather than mutating."""
    soa_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    old = soa_rdataset[0]
    new = old.replace(serial=(old.serial + 1) & 0xFFFFFFFF)
    ttl = soa_rdataset.ttl
    soa_rdataset.clear()
    soa_rdataset.add(new, ttl=ttl)


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
    except OSError as exc:
        print(f"signzone: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
