"""
Assertion vocabulary for the adns_server test suite.

These helpers let tests make declarative, semantic assertions about DNS
responses -- rcode/flags/sections, EDE codes, DNSSEC signature validity, and
NSEC/NSEC3 proof coverage -- instead of diffing volatile dig transcripts.
"""

import base64
import hashlib

import dns.dnssec
import dns.edns
import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset


# --------------------------------------------------------------------------
# Basic response inspection
# --------------------------------------------------------------------------

def rcode(resp):
    """Return the response RCODE as text (e.g. 'NOERROR', 'NXDOMAIN')."""
    return dns.rcode.to_text(resp.rcode())


def has_flag(resp, flagname):
    """Is the named header flag (e.g. 'AA', 'TC', 'QR') set?"""
    return bool(resp.flags & dns.flags.from_text(flagname))


def section_types(section):
    """Return the set of RR type mnemonics present in a message section."""
    return {dns.rdatatype.to_text(rr.rdtype) for rr in section}


def rrsets_of_type(section, rdtype):
    """Return all RRsets of a given type (text or int) in a section."""
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    return [rr for rr in section if rr.rdtype == rdtype]


def get_rrset(section, name, rdtype):
    """Return the RRset with the given owner name and type, or None."""
    if isinstance(name, str):
        name = dns.name.from_text(name)
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    for rr in section:
        if rr.name == name and rr.rdtype == rdtype:
            return rr
    return None


def ede_codes(resp):
    """Return the set of Extended DNS Error INFO-CODEs present in the OPT."""
    codes = set()
    for opt in resp.options:
        if opt.otype == dns.edns.EDE:
            codes.add(opt.code)
    return codes


def has_edns_flag(resp, flag):
    """Is the given EDNS header flag (integer mask) set in the response?"""
    return bool(resp.ednsflags & flag)


# --------------------------------------------------------------------------
# DNSSEC signature validation
# --------------------------------------------------------------------------

def validate_rrset(rrset, section, dnskey_rrset, zone):
    """
    Validate the RRSIG(s) covering a single RRset against the zone DNSKEY.
    Raises dns.dnssec.ValidationFailure on failure. Returns the RRSIG used.
    """
    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    rrsig = None
    for rr in section:
        if (rr.rdtype == dns.rdatatype.RRSIG and rr.name == rrset.name
                and rr[0].type_covered == rrset.rdtype):
            rrsig = rr
            break
    if rrsig is None:
        raise AssertionError(
            f"no RRSIG covering {rrset.name} "
            f"{dns.rdatatype.to_text(rrset.rdtype)}")
    dns.dnssec.validate(rrset, rrsig, {zone: dnskey_rrset})
    return rrsig


def validate_all(resp, dnskey_rrset, zone):
    """
    Cryptographically validate every signed RRset in the answer and authority
    sections against the zone DNSKEY. Raises on any failure. Returns the count
    of RRsets validated.
    """
    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    count = 0
    for section in (resp.answer, resp.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            # Only validate rrsets that actually carry a covering RRSIG.
            has_sig = any(
                rr.rdtype == dns.rdatatype.RRSIG and rr.name == rrset.name
                and rr[0].type_covered == rrset.rdtype
                for rr in section)
            if not has_sig:
                continue
            validate_rrset(rrset, section, dnskey_rrset, zone)
            count += 1
    return count


# --------------------------------------------------------------------------
# NSEC coverage / matching
# --------------------------------------------------------------------------

def nsec_matches(nsec_rrset, name):
    """Does this NSEC RRset's owner name match the given name?"""
    if isinstance(name, str):
        name = dns.name.from_text(name)
    return nsec_rrset.name == name


def nsec_covers(nsec_rrset, name):
    """
    Does this NSEC RRset cover (prove nonexistence of) the given name?
    True when owner < name < next in canonical DNS name order, with wrap-around
    handling for the apex NSEC whose next name sorts before the owner.
    """
    if isinstance(name, str):
        name = dns.name.from_text(name)
    owner = nsec_rrset.name
    nxt = nsec_rrset[0].next
    if owner < nxt:
        return owner < name < nxt
    # Wrap-around (last NSEC in the zone): covers names > owner or < next.
    return name > owner or name < nxt


def nsec_bitmap(nsec_rrset):
    """Return the set of RR type mnemonics in an NSEC/NSEC3 type bitmap."""
    windows = nsec_rrset[0].windows
    types = set()
    for window, bitmap in windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    rrtype = window * 256 + i * 8 + bit
                    types.add(dns.rdatatype.to_text(rrtype))
    return types


# --------------------------------------------------------------------------
# NSEC3 coverage / matching
# --------------------------------------------------------------------------

def _b32hex_encode(digest):
    """Base32hex-encode (RFC 4648) a binary NSEC3 hash, unpadded, upper-case."""
    return base64.b32encode(digest).translate(
        bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                        b'0123456789ABCDEFGHIJKLMNOPQRSTUV')).decode().rstrip(
                            "=")


def nsec3_hash(name, salt, iterations, algorithm=1):
    """Compute the NSEC3 base32hex hash label for a name."""
    if isinstance(name, str):
        name = dns.name.from_text(name)
    if isinstance(salt, str):
        salt = bytes.fromhex(salt) if salt not in ("-", "") else b""
    wire = name.canonicalize().to_wire()
    digest = wire
    for _ in range(iterations + 1):
        digest = hashlib.sha1(digest + salt).digest()
    return _b32hex_encode(digest)


def nsec3_owner_hash(nsec3_rrset):
    """Return the (upper-case) hash label of an NSEC3 record's owner name."""
    return nsec3_rrset.name.labels[0].decode().upper()


def nsec3_next_hash(nsec3_rrset):
    """Return the (upper-case) base32hex next-hash of an NSEC3 record."""
    return _b32hex_encode(nsec3_rrset[0].next)


def nsec3_matches(nsec3_rrset, name, zone):
    """Does this NSEC3 record match (its owner hash equals H(name))?"""
    rd = nsec3_rrset[0]
    salt = rd.salt.hex() if rd.salt else "-"
    fqdn = _fqdn(name, zone)
    return nsec3_owner_hash(nsec3_rrset) == nsec3_hash(
        fqdn, salt, rd.iterations, rd.algorithm)


def nsec3_covers(nsec3_rrset, name, zone):
    """Does this NSEC3 record cover H(name) in its (owner, next) interval?"""
    rd = nsec3_rrset[0]
    salt = rd.salt.hex() if rd.salt else "-"
    fqdn = _fqdn(name, zone)
    target = nsec3_hash(fqdn, salt, rd.iterations, rd.algorithm)
    owner = nsec3_owner_hash(nsec3_rrset)
    nxt = nsec3_next_hash(nsec3_rrset)
    if owner < nxt:
        return owner < target < nxt
    return target > owner or target < nxt


def _fqdn(name, zone):
    """
    Return name as an absolute dns.name.Name. Test callers pass fully
    qualified names (e.g. "degonly.nsec3.test"); a relative name is anchored
    at the zone origin, and an already-absolute name is returned as-is.
    """
    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    if isinstance(name, str):
        name = dns.name.from_text(name)   # absolute; ends at root
    if not name.is_absolute():
        name = name.concatenate(zone)
    return name
