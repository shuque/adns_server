"""
CNAME and DNAME answer processing (process_cname / process_dname).

These exercise the two answer paths the rest of the suite didn't touch: a
direct CNAME, a wildcard CNAME, and a DNAME that synthesizes a CNAME for a
name below its owner. The zone (deleg.test) is online-signed, so the CNAME and
DNAME RRsets themselves carry RRSIGs and are cryptographically validated; the
DNAME-synthesized CNAME is unsigned (generated on the fly) and validate_all()
skips it.
"""

import dnsutil as du


def test_cname_answer(query, dnskey):
    """A CNAME owner returns the CNAME plus the resolved in-zone target."""
    r = query("alias.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    cname = du.rrsets_of_type(r.answer, "CNAME")
    assert cname and cname[0][0].target.to_text() == "www.deleg.test."
    # The chain is followed and the target A record is in the same answer.
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.10"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_cname_direct_query(query, dnskey):
    """Querying the CNAME type directly returns just the CNAME (no chase)."""
    r = query("alias.deleg.test", "CNAME", do=True)
    assert du.rcode(r) == "NOERROR"
    cname = du.rrsets_of_type(r.answer, "CNAME")
    assert cname and cname[0][0].target.to_text() == "www.deleg.test."
    assert not du.rrsets_of_type(r.answer, "A")
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_wildcard_cname(query, dnskey):
    """A name matching only a wildcard CNAME is answered from it and chased."""
    r = query("anything.wc.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    cname = du.rrsets_of_type(r.answer, "CNAME")
    assert cname and cname[0][0].target.to_text() == "www.deleg.test."
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.10"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_dname_synthesizes_cname(query, dnskey):
    """
    A query below a DNAME owner returns the DNAME, a synthesized CNAME
    redirecting to the target subtree, and the target's answer.
    """
    r = query("host.old.deleg.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    dname = du.rrsets_of_type(r.answer, "DNAME")
    assert dname and dname[0][0].target.to_text() == "new.deleg.test."
    # Synthesized CNAME: host.old -> host.new.
    cname = du.rrsets_of_type(r.answer, "CNAME")
    assert cname
    assert cname[0].name.to_text() == "host.old.deleg.test."
    assert cname[0][0].target.to_text() == "host.new.deleg.test."
    # Resolved target A record.
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.40"
    # The signed RRsets (DNAME, target A) validate; the synthesized CNAME is
    # unsigned and is skipped by validate_all.
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def test_dname_direct_query(query, dnskey):
    """Querying the DNAME owner for DNAME returns the DNAME itself."""
    r = query("old.deleg.test", "DNAME", do=True)
    assert du.rcode(r) == "NOERROR"
    dname = du.rrsets_of_type(r.answer, "DNAME")
    assert dname and dname[0][0].target.to_text() == "new.deleg.test."
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")
