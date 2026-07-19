"""
DELEG referral and occlusion behavior (draft-ietf-deleg-10 / delext-08).

Exercises the DE=1 (DELEG-aware) and DE=0 (DELEG-unaware) code paths against
the deleg.test (NSEC + compact) and nsec3.test (NSEC3) zones, and the
unsigned.test zone. Signatures are cryptographically validated; NSEC/NSEC3
proofs are checked for correct coverage and type-bitmap contents.
"""

import dnsutil as du

DELEG = "TYPE61440"
NXNAME = "TYPE128"


# --------------------------------------------------------------------------
# DE=1 (DELEG-aware) referrals -- deleg-10 5.2.1
# --------------------------------------------------------------------------

def test_de1_deleg_with_ds(query, dnskey):
    """sub1: NS+DS+DELEG -> DELEG RRset + DS, NO NS; all signatures valid."""
    r = query("foo.sub1.deleg.test", "A", do=True, de=True)
    types = du.section_types(r.authority)
    assert DELEG in types
    assert "DS" in types
    assert "NS" not in types
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de1_deleg_no_ds_proves_ds_absence(query, dnskey):
    """sub3: NS+DELEG, no DS -> DELEG RRset + NSEC proving DS absence."""
    r = query("foo.sub3.deleg.test", "A", do=True, de=True)
    types = du.section_types(r.authority)
    assert DELEG in types
    assert "NS" not in types
    assert "DS" not in types
    assert "NSEC" in types
    nsec = du.rrsets_of_type(r.authority, "NSEC")[0]
    assert du.nsec_matches(nsec, "sub3.deleg.test")
    bitmap = du.nsec_bitmap(nsec)
    assert "DS" not in bitmap        # proves DS absence
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de1_deleg_only(query, dnskey):
    """sub5: DELEG only -> DELEG RRset + NSEC (covering next-name form)."""
    r = query("foo.sub5.deleg.test", "A", do=True, de=True)
    types = du.section_types(r.authority)
    assert DELEG in types
    assert "NS" not in types
    nsec = du.rrsets_of_type(r.authority, "NSEC")[0]
    assert du.nsec_matches(nsec, "sub5.deleg.test")
    assert DELEG in du.nsec_bitmap(nsec)
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de1_ns_only_proves_deleg_absence(query, dnskey):
    """sub7: NS only -> NS RRset + NSEC proving DELEG absence."""
    r = query("foo.sub7.deleg.test", "A", do=True, de=True)
    types = du.section_types(r.authority)
    assert "NS" in types
    assert DELEG not in types
    nsec = du.rrsets_of_type(r.authority, "NSEC")[0]
    assert du.nsec_matches(nsec, "sub7.deleg.test")
    bitmap = du.nsec_bitmap(nsec)
    assert DELEG not in bitmap       # proves DELEG absence
    assert "NS" in bitmap
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de1_secure_ns_only_has_ds(query, dnskey):
    """sub2: NS+DS, no DELEG -> NS + DS + NSEC proving DELEG absence."""
    r = query("foo.sub2.deleg.test", "A", do=True, de=True)
    types = du.section_types(r.authority)
    assert "NS" in types
    assert "DS" in types
    assert DELEG not in types
    nsec = du.rrsets_of_type(r.authority, "NSEC")[0]
    assert DELEG not in du.nsec_bitmap(nsec)
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


# --------------------------------------------------------------------------
# DE=0 (DELEG-unaware) behavior -- deleg-10 5.2.2 (delext-08 principle)
# --------------------------------------------------------------------------

def test_de0_ns_present_is_legacy_referral(query):
    """sub1 (NS+DS+DELEG) with DE=0: NS occludes DELEG -> legacy referral."""
    r = query("foo.sub1.deleg.test", "A", do=True, de=False)
    types = du.section_types(r.authority)
    assert "NS" in types
    assert DELEG not in types
    assert not du.has_flag(r, "AA")   # referral, not authoritative


def test_de0_below_deleg_only_cut_is_nxdomain(query, dnskey):
    """
    DELEG-only cut (sub5), DE=0, name below it: authoritative NXDOMAIN with a
    covering NSEC that retains the DELEG bit, plus a New Delegation Only EDE.
    """
    r = query("www.sub5.deleg.test", "A", do=True, de=False)
    assert du.rcode(r) == "NXDOMAIN"
    assert du.has_flag(r, "AA")
    assert 31 in du.ede_codes(r)
    nsec = du.rrsets_of_type(r.authority, "NSEC")[0]
    assert du.nsec_matches(nsec, "sub5.deleg.test")
    assert du.nsec_covers(nsec, "www.sub5.deleg.test")
    assert DELEG in du.nsec_bitmap(nsec)
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de0_at_deleg_only_cut_is_nodata(query, dnskey):
    """DELEG-only cut (sub5) name itself, DE=0: authoritative NODATA + EDE."""
    r = query("sub5.deleg.test", "A", do=True, de=False)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    assert du.has_flag(r, "AA")
    assert 31 in du.ede_codes(r)
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_de0_qtype_deleg_returned_as_data(query, dnskey):
    """DELEG-only cut, DE=0, QTYPE=DELEG: DELEG returned as ordinary data."""
    r = query("sub5.deleg.test", DELEG, do=True, de=False)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    assert du.rrsets_of_type(r.answer, DELEG)
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


# --------------------------------------------------------------------------
# NSEC3 zone occlusion
# --------------------------------------------------------------------------

def test_nsec3_de1_deleg_only(query, dnskey):
    """nsec3.test degonly: DE=1 -> DELEG + NSEC3 closest-encloser (DELEG bit)."""
    r = query("foo.degonly.nsec3.test", "A", do=True, de=True)
    assert DELEG in du.section_types(r.authority)
    nsec3s = du.rrsets_of_type(r.authority, "NSEC3")
    assert any(DELEG in du.nsec_bitmap(n) for n in nsec3s)
    du.validate_all(r, dnskey("nsec3.test"), "nsec3.test")


def test_nsec3_de0_occlusion_nxdomain(query, dnskey):
    """
    nsec3.test degonly, DE=0, below cut: authoritative NXDOMAIN with the
    closest-encloser NSEC3 carrying DELEG, next-closer + wildcard covers, EDE.
    """
    r = query("foo.degonly.nsec3.test", "A", do=True, de=False)
    assert du.rcode(r) == "NXDOMAIN"
    assert du.has_flag(r, "AA")
    assert 31 in du.ede_codes(r)
    nsec3s = du.rrsets_of_type(r.authority, "NSEC3")
    # closest encloser (the cut) matches and carries the DELEG bit
    assert any(du.nsec3_matches(n, "degonly.nsec3.test", "nsec3.test")
               and DELEG in du.nsec_bitmap(n) for n in nsec3s)
    du.validate_all(r, dnskey("nsec3.test"), "nsec3.test")


# --------------------------------------------------------------------------
# Unsigned zone
# --------------------------------------------------------------------------

def test_unsigned_ns_referral(query):
    """unsigned.test sub1: NS referral with in-domain glue."""
    r = query("foo.sub1.unsigned.test", "A", do=False, de=True)
    assert "NS" in du.section_types(r.authority)
    assert not du.has_flag(r, "AA")
    # glue present in additional
    assert du.rrsets_of_type(r.additional, "A")


def test_unsigned_deleg_only_de1(query):
    """unsigned.test sub5 (DELEG only), DE=1: DELEG RRset in authority."""
    r = query("foo.sub5.unsigned.test", "A", do=False, de=True)
    assert DELEG in du.section_types(r.authority)
