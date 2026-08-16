#!/usr/bin/env python3

"""
Offline DELEG-aware DNSSEC zone signer for adns_server.

Strips any existing DNSSEC records and re-signs from scratch with explicit
absolute RRSIG times, writing <zonefile>.signed atomically. Keys are
discovered from the keydir by matching each apex DNSKEY to a PEM: the SEP
key(s) sign the DNSKEY RRset and the ZSK(s) sign everything else, so a
KSK/ZSK split or a single combined-signing key (CSK) both work with no
flag. The mode of authenticated denial is data-driven: an apex NSEC3PARAM
record makes the signer build an NSEC3 chain (using that record's
parameters), otherwise it builds an NSEC chain. DELEG cuts are signed
authoritatively in the delegating zone: the DELEG (and any DS) RRset at a cut
is signed and its type appears in the delegation-point NSEC/NSEC3 bitmap, while
NS, glue, and names below the cut are occluded. Key rollover (pre-published
stand-by keys) is a later stage. See Signer.md.
"""

import argparse
import binascii
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
from dns.rdtypes.dnskeybase import SEP

from adns.crypto import (load_private_key, key_basename, mldsa_rrsig_rdata,
                         DnssecUnsupported)
from adns.zone import zone_from_file, make_nsec_rrset, make_nsec3_rrset, nsec3hash
from adns.constants import AUTH_IN_PARENT_RRTYPES


class SignerError(Exception):
    """Fatal signer error: reported to stderr, nonzero exit, no output."""


_UNIT_SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400,
                 'w': 604800, 'y': 31536000}

ALG_MLDSA44 = 18


def parse_duration(spec):
    """
    Parse a duration into seconds. Bare integer = seconds; a trailing
    s/m/h/d/w/y unit multiplies accordingly. Used directly for -j (jitter).
    """
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
    """
    Resolve an -e/-i time spec to an absolute epoch (int seconds, UTC).

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


def discover_keys(zone, keydir):
    """
    Return a KeyInfo per apex DNSKEY. For each, compute the keytag and look
    for <keydir>/<zone>+<alg>+<keytag>.pem; load it if present (active), else
    the key is publish-only (private_key=None). Errors if the zone has no
    DNSKEY, or if no DNSKEY has a matching PEM (nothing to sign with).
    """
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
                            bool(rdata.flags & SEP), private_key))
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
    """
    Serialize the (signed) zone. Absolute names (relativize=False). Writes
    to a temp file in the destination dir then atomically renames, so a failure
    leaves no partial .signed. output_path '-' writes to stdout.

    Serialize node-by-node in canonical order, skipping empty non-terminal
    nodes. zone_from_file() synthesizes an empty (no-rdataset) node for each
    ENT so the server can tell NODATA from NXDOMAIN; zone.to_text() would emit
    each as a blank line. An ENT never carries authoritative data (its NSEC3,
    in NSEC3 mode, lives at the hashed owner, a different node), so dropping
    empty nodes here is correct for both NSEC and NSEC3 output.
    """
    parts = []
    for name, node in zone.nodes.items():
        node_text = node.to_text(name, relativize=False)
        if node_text:
            parts.append(node_text)
    text = "\n".join(parts) + "\n"
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
    """
    Uncached RRSIG generation with explicit absolute times -- the offline
    analog of the server's cached sign_rrset(). Returns RRSIG rdata.

    Algorithm 18 (ML-DSA-44) is signed by mldsa_rrsig_rdata() (in adns.crypto)
    because dns.dnssec.sign() rejects it; every other algorithm goes through
    dns.dnssec.sign() unchanged.
    """
    if dnskey.algorithm == ALG_MLDSA44:
        return mldsa_rrsig_rdata(rrset, private_key, signer, dnskey,
                                 inception, expiration)
    return dns.dnssec.sign(rrset, private_key, signer, dnskey,
                           inception=inception, expiration=expiration)


def classify_signers(keys):
    """
    Return (dnskey_signers, rest_signers) from the active (PEM-bearing)
    keys. Invariant (Signer.md §§3-4): the DNSKEY RRset is signed by every SEP
    key that has a PEM; everything else by every non-SEP key that has a PEM. A
    single SEP key with no separate ZSK is a CSK and signs both.
    """
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
    """
    Owners (other than the apex) that are delegation cuts: they have NS
    and/or a Delegation Type (DELEG). Returned as a set of dns.name.Name.
    """
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


def _occluding_parents(zone, cut_names):
    """
    Names below which every descendant is occluded -- unsigned, no NSEC:
    delegation cuts (NS/DELEG) plus DNAME owners. Per RFC 6672 a DNAME occludes
    the entire subtree strictly below its owner, exactly as glue is occluded
    below a delegation cut. The DNAME owner node itself is ordinary
    authoritative data (its DNAME RRset is signed and it gets an NSEC), so it
    is NOT added here; only names strictly below it are occluded.
    """
    occluding = set(cut_names)
    for name, node in zone.nodes.items():
        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNAME):
            occluding.add(name)
    return occluding


def is_occluded(name, occluding_parents):
    """
    True if name is strictly below a delegation cut or a DNAME owner
    (occluded glue / occluded subtree).
    """
    return any(name != p and name.is_subdomain(p) for p in occluding_parents)


def authoritative_owners(zone, occluding_parents):
    """
    Owners that get an NSEC, in canonical sorted order: every non-ENT,
    non-occluded owner that owned an RRset in the unsigned zone. ENT nodes are
    empty (no rdatasets) and excluded; occluded names below a cut or DNAME are
    excluded.
    """
    owners = []
    for name, node in zone.nodes.items():
        if not node.rdatasets:                 # ENT
            continue
        if is_occluded(name, occluding_parents):
            continue
        owners.append(name)
    return sorted(owners)


def _rrsets_to_sign(name, node, is_cut):
    """
    Yield the authoritative RRsets at a node. At a cut only the
    authoritative-in-parent types (DS/DELEG) are signed; NS and glue are not.
    Elsewhere every non-DNSSEC RRset is authoritative.
    """
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


def _bitmap_rdtypes(node, is_cut):
    """
    RR types present at a node that belong in its NSEC/NSEC3 type bitmap. At a
    delegation cut only the delegation's parent-side types are visible -- NS,
    the authoritative-in-parent types (DS/DELEG), and any RRSIG covering them;
    other RRsets sitting at the cut (e.g. a leftover private-type record) are
    occluded and excluded, mirroring _rrsets_to_sign(). Elsewhere every present
    type is listed. The NSEC/NSEC3 and its RRSIG are added by the caller.
    """
    types = {rds.rdtype for rds in node.rdatasets}
    if is_cut:
        allowed = ({dns.rdatatype.NS, dns.rdatatype.RRSIG}
                   | set(AUTH_IN_PARENT_RRTYPES))
        types &= allowed
    return types


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


def _sign_authoritative_rrsets(zone, cut_names, occluding_parents,  # pylint: disable=too-many-positional-arguments
                               dnskey_signers, rest_signers,
                               inception, base_expiration, jitter):
    """Sign every authoritative RRset in the zone (skip occluded names)."""
    for name, node in zone.nodes.items():
        if is_occluded(name, occluding_parents):
            continue
        is_cut = name in cut_names
        for rrset in _rrsets_to_sign(name, node, is_cut):
            signers = (dnskey_signers if rrset.rdtype == dns.rdatatype.DNSKEY
                      else rest_signers)
            _sign_with_keys(node, rrset, zone.origin, signers,
                            inception, base_expiration, jitter)


def _build_nsec_chain(zone, cut_names, occluding_parents, rest_signers,  # pylint: disable=too-many-positional-arguments
                      inception, base_expiration, jitter):
    """Build and sign the NSEC chain over authoritative owners."""
    owners = authoritative_owners(zone, occluding_parents)
    for i, owner in enumerate(owners):
        node = zone.get_node(owner)
        nextname = owners[(i + 1) % len(owners)]
        present = _bitmap_rdtypes(node, owner in cut_names)
        present.add(dns.rdatatype.NSEC)
        present.add(dns.rdatatype.RRSIG)
        nsec_rrset = make_nsec_rrset(owner, nextname, sorted(present),
                                     zone.soa_min_ttl)
        node.rdatasets.append(nsec_rrset.to_rdataset())
        _sign_with_keys(node, nsec_rrset, zone.origin, rest_signers,
                        inception, base_expiration, jitter)


def _nsec3param(zone):
    """
    Return the apex NSEC3PARAM rdata if present (NSEC3 mode), else None. The
    record itself is the mode switch (Signer.md 4); no CLI toggle. Enforces the
    same single-record rule as Zone.init_dnssec().
    """
    rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.NSEC3PARAM)
    if not rdataset:
        return None
    if len(rdataset) > 1:
        raise SignerError("only one NSEC3PARAM record is supported")
    return rdataset[0]


def nsec3_owners(zone, occluding_parents):
    """
    Owners that get an NSEC3, in original-name canonical order: every
    non-occluded owner, INCLUDING empty non-terminals. This is the reverse of
    the NSEC chain (RFC 5155 7.1: "Each empty non-terminal MUST have a
    corresponding NSEC3 RR", vs RFC 4035 which excludes ENTs from NSEC).
    Occluded names below a delegation cut or DNAME are still excluded.
    """
    owners = []
    for name in zone.nodes:
        if is_occluded(name, occluding_parents):
            continue
        owners.append(name)
    return sorted(owners)


def _nsec3_entries(zone, params, cut_names, occluding_parents):
    """
    (binary_hash, hashed_owner_name, bitmap) for every NSEC3 owner, sorted by
    hash. Owners include ENTs (RFC 5155 7.1); the bitmap is the original name's
    visible types (occluded records at a cut dropped, per _bitmap_rdtypes) and
    never the NSEC3 bit itself. ENTs own nothing -> empty bitmap.
    """
    entries = []
    for name in nsec3_owners(zone, occluding_parents):
        node = zone.get_node(name)
        h_str = nsec3hash(name, params.algorithm, params.salt,
                          params.iterations)
        h_bin = nsec3hash(name, params.algorithm, params.salt,
                          params.iterations, binary_out=True)
        hashed_owner = dns.name.Name((h_str.encode(),) + zone.origin.labels)
        bitmap = sorted(_bitmap_rdtypes(node, name in cut_names))
        entries.append((h_bin, hashed_owner, bitmap))
    entries.sort(key=lambda entry: entry[0])
    return entries


def _build_nsec3_chain(zone, params, cut_names, occluding_parents, rest_signers,  # pylint: disable=too-many-positional-arguments
                       inception, base_expiration, jitter):
    """
    Build and sign the NSEC3 chain in hash-sorted order. Because NSEC3 sorts by
    hash, this is a separate pass from the name-sorted signing walk: hash every
    owner (incl. ENTs), sort by hash, then link each hashed owner's next field
    to the following hash (wrapping to the smallest -- a closed loop).
    """
    entries = _nsec3_entries(zone, params, cut_names, occluding_parents)
    count = len(entries)
    for i, (_h_bin, hashed_owner, bitmap) in enumerate(entries):
        next_hash = entries[(i + 1) % count][0]
        nsec3_rrset = make_nsec3_rrset(params, hashed_owner, next_hash,
                                       bitmap, zone.soa_min_ttl)
        node = zone.find_node(hashed_owner, create=True)
        node.rdatasets.append(nsec3_rrset.to_rdataset())
        _sign_with_keys(node, nsec3_rrset, zone.origin, rest_signers,
                        inception, base_expiration, jitter)


def sign_zone(zone, keys, inception, base_expiration, jitter):
    """
    Sign every authoritative RRset and build the denial-of-existence chain in
    place. The chain is NSEC3 if the apex has an NSEC3PARAM record, else NSEC.
    """
    try:
        zone.reject_wildcard_deleg()
    except ValueError as exc:
        raise SignerError(str(exc)) from exc
    dnskey_signers, rest_signers = classify_signers(keys)
    cut_names = _cut_names(zone)
    occluding_parents = _occluding_parents(zone, cut_names)
    _sign_authoritative_rrsets(zone, cut_names, occluding_parents,
                               dnskey_signers, rest_signers,
                               inception, base_expiration, jitter)
    params = _nsec3param(zone)
    if params is not None:
        _build_nsec3_chain(zone, params, cut_names, occluding_parents,
                           rest_signers, inception, base_expiration, jitter)
    else:
        _build_nsec_chain(zone, cut_names, occluding_parents, rest_signers,
                          inception, base_expiration, jitter)


def make_arg_parser():
    """Build the signzone argument parser (Signer.md §2)."""
    parser = argparse.ArgumentParser(
        description="Offline DNSSEC zone signer (NSEC/NSEC3, KSK/ZSK or CSK).")
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
    return parser


def bump_serial(zone):
    """
    Increment the apex SOA serial (RFC 1982 wrap not handled; +1).
    dnspython Rdata is immutable, so replace the rdata rather than mutating.
    """
    soa_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    old = soa_rdataset[0]
    new = old.replace(serial=(old.serial + 1) & 0xFFFFFFFF)
    ttl = soa_rdataset.ttl
    soa_rdataset.clear()
    soa_rdataset.add(new, ttl=ttl)


def _key_role(key, has_separate_zsk):
    """
    KSK/ZSK/CSK label for a discovered key: a non-SEP key is a ZSK, a SEP key
    is a KSK, unless it is the sole signer (no separate ZSK present) and so acts
    as a combined-signing key (CSK). Mirrors classify_signers().
    """
    if not key.is_sep:
        return "ZSK"
    return "KSK" if has_separate_zsk else "CSK"


def _alg_keyids(keys):
    """
    Render the active signing keys grouped by algorithm, keytags listed under
    each: 'ECDSAP256SHA256 (keyid 47571), RSASHA256 (keyid 12345)'. Groups in
    first-seen algorithm order so a single-algorithm zone reads naturally and a
    multi-algorithm zone stays unambiguous about which keytag signs with which.
    """
    by_alg = collections.OrderedDict()
    for key in keys:
        if key.private_key is None:
            continue
        alg = dns.dnssec.algorithm_to_text(key.algorithm)
        by_alg.setdefault(alg, []).append(str(key.keytag))
    return ", ".join(f"{alg} (keyid {', '.join(tags)})"
                     for alg, tags in by_alg.items())


def _denial_summary(zone):
    """One-line description of the zone's authenticated-denial mode."""
    params = _nsec3param(zone)
    if params is None:
        return "NSEC"
    salt = binascii.hexlify(params.salt).decode().upper() or "-"
    return f"NSEC3 ({params.iterations} iterations, salt {salt})"


def print_summary(zone, keys, keydir, output_path, out=sys.stderr):
    """
    Emit a succinct signing summary (dnssec-signzone style) to stderr: the
    active keys loaded, the signing algorithm(s), the denial-of-existence mode,
    and per-algorithm active/present key counts. "active" = published DNSKEY
    with a matching PEM (used to sign); "present" = published but publish-only,
    no PEM. The output path (if not stdout) is printed to stdout so the tool
    stays scriptable.
    """
    zonename = zone.origin.to_text().rstrip('.')
    has_separate_zsk = any(not k.is_sep and k.private_key is not None
                           for k in keys)
    for key in keys:
        if key.private_key is None:
            continue
        alg = dns.dnssec.algorithm_to_text(key.algorithm)
        print(f"Loading {zonename}/{alg}/{key.keytag} "
              f"({_key_role(key, has_separate_zsk)}) from {keydir}", file=out)
    print(f"Signing zone {zonename} with "
          f"algorithm(s): {_alg_keyids(keys)}", file=out)
    print(f"Denial of existence: {_denial_summary(zone)}", file=out)
    print("Zone signed:", file=out)
    _print_key_counts(keys, has_separate_zsk, out)
    if output_path != '-':
        print(output_path)


def _print_key_counts(keys, has_separate_zsk, out):
    """
    Print per-algorithm active/present key counts, one line per role
    (KSK/ZSK/CSK), continuation lines aligned under the first. Called by
    print_summary().
    """
    counts = collections.OrderedDict()
    for key in keys:
        alg = dns.dnssec.algorithm_to_text(key.algorithm)
        role = _key_role(key, has_separate_zsk)
        pair = counts.setdefault(alg, collections.OrderedDict()).setdefault(
            role, [0, 0])
        pair[0 if key.private_key is not None else 1] += 1
    for alg, roles in counts.items():
        prefix = f"Algorithm: {alg}: "
        indent = " " * len(prefix)
        for i, role in enumerate(r for r in ("KSK", "ZSK", "CSK")
                                 if r in roles):
            active, present = roles[role]
            print(f"{prefix if i == 0 else indent}"
                  f"{role}s: {active} active, {present} present", file=out)


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
        print_summary(zone, keys, args.keydir, output)
    except (SignerError, DnssecUnsupported) as exc:
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
