"""
Online (dynamic) signing of an algorithm-18 (ML-DSA-44) zone: a
dynamic_signing: true zone whose CSK is an alg-18 key, so the server generates
each RRSIG live (phase 3).

dns.dnssec.validate rejects alg 18, so RRSIGs are verified directly with
cryptography's MLDSA44PublicKey over independently-reconstructed RFC 4034
3.1.8.1 data. Because ML-DSA signing is hedged (randomized), the process-wide
signature cache is what makes repeated answers byte-stable -- see
test_sig_cache_returns_stable_signature.
"""

import pytest

mldsa = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa")

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG

from conftest import _make_query_fn

ZONE = "mldsa-online.test."


def _verify_rrsig(rrset, rrsig_rrset, pub_bytes):
    """
    Independently verify each alg-18 RRSIG in rrsig_rrset over rrset.

    Rebuilds RFC 4034 3.1.8.1 data from a fresh empty-signature RRSIG template
    and calls MLDSA44PublicKey.verify(). Raises on failure.
    """
    pub = mldsa.MLDSA44PublicKey.from_public_bytes(pub_bytes)
    for rrsig in rrsig_rrset:
        assert rrsig.algorithm == 18
        template = dns.rdtypes.ANY.RRSIG.RRSIG(
            rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.RRSIG,
            type_covered=rrset.rdtype, algorithm=18,
            labels=len(rrset.name) - 1, original_ttl=rrsig.original_ttl,
            expiration=rrsig.expiration, inception=rrsig.inception,
            key_tag=rrsig.key_tag, signer=rrsig.signer, signature=b"")
        data = dns.dnssec._make_rrsig_signature_data(rrset, template, None)
        pub.verify(rrsig.signature, data, context=None)


def _answer_pair(resp, qtype):
    """Return (rrset, rrsig_rrset) for qtype at the zone apex in resp.answer."""
    name = dns.name.from_text(ZONE)
    rdtype = dns.rdatatype.from_text(qtype)
    rrset = resp.get_rrset(resp.answer, name, dns.rdataclass.IN, rdtype)
    rrsig = resp.get_rrset(resp.answer, name, dns.rdataclass.IN,
                           dns.rdatatype.RRSIG, covers=rdtype)
    return rrset, rrsig


def test_soa_rrsig_live_signed(mldsa_online_server):
    """The apex SOA comes back with a live-generated alg-18 RRSIG that verifies."""
    query = _make_query_fn(mldsa_online_server["endpoint"])
    resp = query(ZONE, "SOA", do=True, udpsize=4096)
    rrset, rrsig = _answer_pair(resp, "SOA")
    assert rrset is not None
    assert rrsig is not None
    _verify_rrsig(rrset, rrsig, mldsa_online_server["pub"])


def test_dnskey_rrsig_live_signed(mldsa_online_server):
    """The apex DNSKEY RRset is self-signed live by the CSK, and verifies."""
    query = _make_query_fn(mldsa_online_server["endpoint"])
    resp = query(ZONE, "DNSKEY", do=True, udpsize=4096)
    rrset, rrsig = _answer_pair(resp, "DNSKEY")
    assert rrset is not None
    assert rrsig is not None
    _verify_rrsig(rrset, rrsig, mldsa_online_server["pub"])


def test_sig_cache_returns_stable_signature(mldsa_online_server):
    """
    Two identical DO queries return byte-identical RRSIG signatures. ML-DSA
    signing is hedged (randomized), so absent the process-wide signature cache
    the two answers would carry different valid signatures; a stable signature
    proves the cached online-signing path.
    """
    query = _make_query_fn(mldsa_online_server["endpoint"])
    _, rrsig1 = _answer_pair(query(ZONE, "SOA", do=True, udpsize=4096), "SOA")
    _, rrsig2 = _answer_pair(query(ZONE, "SOA", do=True, udpsize=4096), "SOA")
    assert rrsig1 is not None and rrsig2 is not None
    assert rrsig1[0].signature == rrsig2[0].signature


def test_negative_response_nsec_signed(mldsa_online_server):
    """
    An NXDOMAIN carries a live-signed NSEC + SOA whose alg-18 RRSIGs verify.
    Exercises the negative-answer online-signing path.

    Queried over TCP: the white-lie NXDOMAIN response signs three RRsets
    (SOA + two synthesized NSECs), and at ~2420 octets per ML-DSA-44 RRSIG
    that total genuinely exceeds the fixture's 4096-octet EDNS ceiling, so a
    UDP query here truncates (TC=1, empty sections) -- real, correct
    truncate-rather-than-fragment behavior, not something to work around.
    """
    query = _make_query_fn(mldsa_online_server["endpoint"])
    resp = query("nope." + ZONE, "A", do=True, udpsize=4096, tcp=True)
    assert resp.rcode() == dns.rcode.NXDOMAIN
    # Every RRSIG in the authority section must verify over its covered RRset.
    verified = 0
    for rrsig_rrset in resp.authority:
        if rrsig_rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        covered = resp.get_rrset(resp.authority, rrsig_rrset.name,
                                 dns.rdataclass.IN, rrsig_rrset.covers)
        assert covered is not None
        _verify_rrsig(covered, rrsig_rrset, mldsa_online_server["pub"])
        verified += 1
    assert verified >= 2   # at least the SOA and an NSEC proof
