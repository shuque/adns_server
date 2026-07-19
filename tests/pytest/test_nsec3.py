"""
NSEC3 denial-of-existence proofs (nsec3.test zone, online signing).
"""

import dnsutil as du

ZONE = "nsec3.test"


def test_nsec3_nodata(query, dnskey):
    """Existing name, missing type -> NSEC3 NODATA proof that validates."""
    r = query("www.nsec3.test", "TXT", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    assert du.rrsets_of_type(r.authority, "NSEC3")
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nsec3_nxdomain_proof(query, dnskey):
    """NXDOMAIN: closest-encloser + next-closer + wildcard NSEC3 chain."""
    r = query("no.such.name.nsec3.test", "A", do=True)
    assert du.rcode(r) == "NXDOMAIN"
    nsec3s = du.rrsets_of_type(r.authority, "NSEC3")
    assert len(nsec3s) >= 2
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nsec3_closest_encloser_matches(query, dnskey):
    """
    For a name below the apex, the closest-encloser NSEC3 must match an
    existing ancestor and the next-closer name must be covered.
    """
    r = query("no.such.name.nsec3.test", "A", do=True)
    nsec3s = du.rrsets_of_type(r.authority, "NSEC3")
    # apex is the closest encloser here; its NSEC3 should match nsec3.test
    assert any(du.nsec3_matches(n, "nsec3.test", ZONE) for n in nsec3s)
    # the next closer (name.nsec3.test) should be covered by some NSEC3
    assert any(du.nsec3_covers(n, "name.nsec3.test", ZONE) for n in nsec3s)
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nsec3_wildcard_nodata(query, dnskey):
    """A name matching the wildcard, wrong type -> NSEC3 wildcard NODATA."""
    r = query("x.wild.nsec3.test", "TXT", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nsec3_secure_delegation_referral(query, dnskey):
    """sub1 (NS+DS) referral carries a validatable DS."""
    r = query("host.sub1.nsec3.test", "A", do=True, de=True)
    assert "NS" in du.section_types(r.authority)
    assert "DS" in du.section_types(r.authority)
    du.validate_all(r, dnskey(ZONE), ZONE)
