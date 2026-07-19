"""
Regression tests for DNS 0x20 case randomization interacting with online
signing.

A mixed-case query name must not leak into the signed data of synthesized
records (notably the NSEC RDATA next-domain-name, which is NOT downcased
during DNSSEC canonicalization per RFC 6840 5.1). Every denial below is
issued with both canonical lower case and 0x20 mixed case; both must produce
DNSSEC-valid responses.

Also guards the signature-cache keying: synthesized records that share an
owner name and type but differ in RDATA (e.g. the covering NSEC for an
occlusion vs. the ENT-style NSEC for NODATA at the same cut) must not collide
in the online signature cache.
"""

import pytest

import dnsutil as du

DELEG = "TYPE61440"


DENIAL_CASES = [
    # (label, qname, qtype, de, zone, expected_rcode)
    ("nsec_compact_nxdomain", "nope.deleg.test", "A", False, "deleg.test",
     "NOERROR"),                          # compact denial: NOERROR w/o CO
    ("deleg_occlusion_below", "www.sub5.deleg.test", "A", False, "deleg.test",
     "NXDOMAIN"),
    ("deleg_occlusion_at", "sub5.deleg.test", "A", False, "deleg.test",
     "NOERROR"),
    ("deleg_referral_de1", "foo.sub5.deleg.test", "A", True, "deleg.test",
     None),
    ("ns_referral_de1", "foo.sub7.deleg.test", "A", True, "deleg.test",
     None),
    ("nsec3_nxdomain", "nope.nsec3.test", "A", False, "nsec3.test",
     "NXDOMAIN"),
    ("nsec3_occlusion", "foo.degonly.nsec3.test", "A", False, "nsec3.test",
     "NXDOMAIN"),
]


@pytest.mark.parametrize("qname,qtype,de,zone", [c[1:5] for c in DENIAL_CASES],
                         ids=[c[0] for c in DENIAL_CASES])
@pytest.mark.parametrize("randomize", [False, True], ids=["lower", "0x20"])
def test_denial_validates_under_case(query, dnskey, qname, qtype, de,
                                     zone, randomize):
    """Each denial/referral validates in both lower and mixed case."""
    r = query(qname, qtype, do=True, de=de, case_randomize=randomize)
    du.validate_all(r, dnskey(zone), zone)


def test_rcode_stable_across_case(query):
    """The RCODE must not depend on query case."""
    for _label, qname, qtype, de, _zone, expected in DENIAL_CASES:
        if expected is None:
            continue
        lo = query(qname, qtype, do=True, de=de, case_randomize=False)
        hi = query(qname, qtype, do=True, de=de, case_randomize=True)
        assert du.rcode(lo) == expected
        assert du.rcode(hi) == expected


def test_cache_no_collision_occlusion_vs_nodata(query, dnskey):
    """
    The covering NSEC for an occlusion (owner=sub5, next=sub5\\000) and the
    NODATA NSEC at the same cut (owner=sub5, next=\\000.sub5) share owner+type
    but differ in RDATA. Querying both in sequence must yield individually
    valid signatures (no signature-cache collision on owner+type alone).
    """
    below = query("www.sub5.deleg.test", "A", do=True, de=False)
    at_cut = query("sub5.deleg.test", "A", do=True, de=False)
    du.validate_all(below, dnskey("deleg.test"), "deleg.test")
    du.validate_all(at_cut, dnskey("deleg.test"), "deleg.test")
    # ... and again in the reverse order, to defeat any ordering dependence.
    at_cut2 = query("sub5.deleg.test", "A", do=True, de=False)
    below2 = query("www.sub5.deleg.test", "A", do=True, de=False)
    du.validate_all(at_cut2, dnskey("deleg.test"), "deleg.test")
    du.validate_all(below2, dnskey("deleg.test"), "deleg.test")
