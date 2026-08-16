"""
Serving an offline pre-signed algorithm-18 (ML-DSA-44) zone under two EDNS
ceilings: a large buffer that returns the full DNSKEY+RRSIG over UDP, and a
capped buffer that truncates (TC=1) and is recovered over TCP.

Online alg-18 signing does not exist yet (phase 3), so the zone is pre-signed
offline and served statically. dns.dnssec.validate rejects alg 18, so RRSIGs
are verified directly with cryptography's MLDSA44PublicKey.

Loopback caveat: lo0 has a 65536 MTU, so the OS never fragments on the wire.
The large-buffer test validates that the SERVER emits the oversized UDP
datagram rather than truncating -- not on-wire fragmentation.
"""

import pytest

mldsa = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mldsa")

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG

import dnsutil as du
from conftest import _make_query_fn


def _verify_dnskey_rrsig(resp, pub_bytes):
    """
    Independently verify the DNSKEY RRset's alg-18 RRSIG in resp.answer.

    Rebuilds the RFC 4034 3.1.8.1 signing data from a fresh RRSIG template
    (its only difference from the wire RRSIG is the empty signature) and calls
    MLDSA44PublicKey.verify(). Raises on failure; returns the verified RRSIG.
    """
    name = dns.name.from_text("mldsa.test.")
    dnskey_rrset = resp.get_rrset(resp.answer, name, dns.rdataclass.IN,
                                  dns.rdatatype.DNSKEY)
    rrsig_rrset = resp.get_rrset(resp.answer, name, dns.rdataclass.IN,
                                 dns.rdatatype.RRSIG,
                                 covers=dns.rdatatype.DNSKEY)
    assert dnskey_rrset is not None
    assert rrsig_rrset is not None
    pub = mldsa.MLDSA44PublicKey.from_public_bytes(pub_bytes)
    for rrsig in rrsig_rrset:
        assert rrsig.algorithm == 18
        template = dns.rdtypes.ANY.RRSIG.RRSIG(
            rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.RRSIG,
            type_covered=dns.rdatatype.DNSKEY, algorithm=18,
            labels=len(name) - 1, original_ttl=rrsig.original_ttl,
            expiration=rrsig.expiration, inception=rrsig.inception,
            key_tag=rrsig.key_tag, signer=rrsig.signer, signature=b"")
        data = dns.dnssec._make_rrsig_signature_data(
            dnskey_rrset, template, None)
        pub.verify(rrsig.signature, data, context=None)
    return rrsig_rrset


def test_mldsa_large_buffer_udp(mldsa_servers):
    """
    edns: 4096 server, client advertising 4096: the full DNSKEY+RRSIG comes
    back over UDP with TC=0, and the RRSIG verifies.
    """
    query = _make_query_fn(mldsa_servers["large"])
    resp = query("mldsa.test", "DNSKEY", do=True, udpsize=4096)
    assert not du.has_flag(resp, "TC")
    _verify_dnskey_rrsig(resp, mldsa_servers["pub"])


def test_mldsa_capped_truncates_then_tcp(mldsa_servers):
    """
    edns: 1432 server, client advertising 4096: the server truncates (TC=1)
    even though the client is willing to receive a large datagram -- the
    truncate-rather-than-fragment posture. The TCP retry returns the full
    DNSKEY+RRSIG, which verifies.
    """
    query = _make_query_fn(mldsa_servers["capped"])
    resp = query("mldsa.test", "DNSKEY", do=True, udpsize=4096)
    assert du.has_flag(resp, "TC")
    # Truncated: the oversized DNSKEY+RRSIG is dropped, not partially sent.
    assert resp.answer == []

    resp_tcp = query("mldsa.test", "DNSKEY", do=True, udpsize=4096, tcp=True)
    assert not du.has_flag(resp_tcp, "TC")
    _verify_dnskey_rrsig(resp_tcp, mldsa_servers["pub"])
