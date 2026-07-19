"""
Basic positive and negative answer behavior (non-DELEG).
"""

import dnsutil as du


def test_positive_answer(query, dnskey):
    """A record for an existing name, with a valid signature."""
    r = query("www.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.10"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_apex_soa(query, dnskey):
    r = query("deleg.test", "SOA", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.rrsets_of_type(r.answer, "SOA")
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_apex_ns(query, dnskey):
    r = query("deleg.test", "NS", do=True)
    assert du.rrsets_of_type(r.answer, "NS")
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_nodata_existing_name(query, dnskey):
    """Existing name, missing type -> NODATA (NOERROR, empty answer)."""
    r = query("www.deleg.test", "TXT", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    assert du.rrsets_of_type(r.authority, "SOA")
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_wildcard_match(query, dnskey):
    """A name matching only the wildcard is answered from it."""
    r = query("anything.wild.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.20"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_explicit_name_beside_wildcard(query, dnskey):
    """An explicit name parallel to a wildcard wins over the wildcard."""
    r = query("exact.wild.deleg.test", "A", do=True)
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.21"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_empty_non_terminal_nodata(query, dnskey):
    """An empty non-terminal (ent) is NODATA, not NXDOMAIN."""
    r = query("deep.ent.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_nxdomain_below_ent(query, dnskey):
    """A truly nonexistent name yields NXDOMAIN (compact denial: NOERROR)."""
    r = query("does.not.exist.deleg.test", "A", do=True)
    # deleg.test uses compact denial; without CO the rcode is NOERROR.
    assert du.rcode(r) == "NOERROR"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_compact_answer_ok_gives_nxdomain(query, dnskey):
    """With the CO flag, compact denial returns a real NXDOMAIN."""
    r = query("does.not.exist.deleg.test", "A", do=True, co=True)
    assert du.rcode(r) == "NXDOMAIN"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")
