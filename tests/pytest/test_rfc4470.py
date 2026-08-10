"""
RFC 4470 minimally-covering NSEC ("online NSEC white lies").

The whitelies.test zone is online-signed NSEC with compact_denial explicitly
false and no NSEC3PARAM record, so denial of existence uses RFC 4470
synthesized, minimally-covering NSEC records rather than the Compact Denial
(RFC 9824) black lie that the other online-NSEC test zone (deleg.test) uses.

Two modalities:

  * Live-server tests (query/dnskey fixtures): drive the running server with
    real queries and cryptographically validate the synthesized NSECs and their
    RRSIGs, checking owner < qname < next coverage, the wildcard-nonexistence
    NSEC, matching NODATA/ENT NSECs, and the absence of any NXNAME black lie.

  * Direct-import unit tests: exercise Zone.covering_predecessor /
    covering_successor and the module-level predecessor/successor helpers,
    including the collision case where the syntactic predecessor would span a
    real zone name and must snap to the real floor's successor.
"""

import os
import sys

import dns.name
import dns.rdatatype
import dns.zone

import dnsutil as du

# Import the server module from the repository root (direct-import modality).
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
import adns_server as adns   # noqa: E402

ZONE = "whitelies.test"


# --------------------------------------------------------------------------
# Live server: NXDOMAIN via minimally-covering NSEC white lies
# --------------------------------------------------------------------------

def _nsecs(section):
    return du.rrsets_of_type(section, "NSEC")


def test_nxdomain_covering_nsec(query, dnskey):
    """
    A nonexistent name yields NXDOMAIN with two synthesized NSECs (one covering
    the qname, one covering the wildcard), all of which validate.
    """
    r = query("nonexist.whitelies.test", "A", do=True)
    assert du.rcode(r) == "NXDOMAIN"
    nsecs = _nsecs(r.authority)
    assert len(nsecs) == 2
    # One NSEC strictly covers the queried name (owner < qname < next).
    assert any(du.nsec_covers(n, "nonexist.whitelies.test") for n in nsecs)
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nxdomain_wildcard_nsec(query, dnskey):
    """The second NSEC proves the source-of-synthesis wildcard does not exist."""
    r = query("nonexist.whitelies.test", "A", do=True)
    nsecs = _nsecs(r.authority)
    assert any(du.nsec_covers(n, "*.whitelies.test") for n in nsecs)
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nxdomain_deep_name_covered(query, dnskey):
    """
    A qname several labels below the closest encloser is still covered: the
    predecessor is taken of the next-closer name and the successor of the full
    qname, so the interval spans the whole qname.
    """
    r = query("a.b.c.whitelies.test", "A", do=True)
    assert du.rcode(r) == "NXDOMAIN"
    nsecs = _nsecs(r.authority)
    assert any(du.nsec_covers(n, "a.b.c.whitelies.test") for n in nsecs)
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_nxdomain_is_not_compact_black_lie(query):
    """
    White lies use a real NXDOMAIN rcode and never set the NXNAME bit (that is
    the Compact Denial black lie, which this zone does not use).
    """
    r = query("nonexist.whitelies.test", "A", do=True)
    assert du.rcode(r) == "NXDOMAIN"
    for n in _nsecs(r.authority):
        bitmap = du.nsec_bitmap(n)
        assert "NXNAME" not in bitmap
        assert "TYPE128" not in bitmap


def test_nxdomain_covering_nsec_owner_below_qname(query):
    """The covering NSEC's owner sorts strictly below the qname it denies."""
    qname = dns.name.from_text("nonexist.whitelies.test.")
    r = query(qname, "A", do=True)
    covering = [n for n in _nsecs(r.authority) if du.nsec_covers(n, qname)]
    assert covering
    for n in covering:
        assert n.name < qname < n[0].next


# --------------------------------------------------------------------------
# Live server: NODATA is an ordinary matching NSEC (no white lie, no NXNAME)
# --------------------------------------------------------------------------

def test_nodata_matching_nsec(query, dnskey):
    """
    Existing name, missing type -> a *matching* NSEC (owner = the name), whose
    bitmap lists the name's real types plus RRSIG and NSEC. No predecessor
    synthesis, no NXNAME.
    """
    r = query("www.whitelies.test", "TXT", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    nsec = du.get_rrset(r.authority, "www.whitelies.test", "NSEC")
    assert nsec is not None
    bitmap = du.nsec_bitmap(nsec)
    assert {"A", "AAAA", "RRSIG", "NSEC"} <= bitmap
    assert "TXT" not in bitmap
    assert "NXNAME" not in bitmap
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_ent_nodata_matching_nsec(query, dnskey):
    """
    An empty non-terminal (deep.ent, with host.deep.ent below it) answers
    NODATA with a matching NSEC whose bitmap carries only RRSIG and NSEC.
    """
    r = query("deep.ent.whitelies.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    nsec = du.get_rrset(r.authority, "deep.ent.whitelies.test", "NSEC")
    assert nsec is not None
    bitmap = du.nsec_bitmap(nsec)
    assert bitmap == {"RRSIG", "NSEC"}
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_wildcard_nodata(query, dnskey):
    """A name matching *.wild, wrong type -> matching wildcard NODATA NSEC."""
    r = query("x.wild.whitelies.test", "TXT", do=True)
    assert du.rcode(r) == "NOERROR"
    assert not r.answer
    du.validate_all(r, dnskey(ZONE), ZONE)


def test_positive_answer_still_signs(query, dnskey):
    """Sanity: a positive answer in this mode still validates."""
    r = query("www.whitelies.test", "A", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.rrsets_of_type(r.answer, "A")
    du.validate_all(r, dnskey(ZONE), ZONE)


# --------------------------------------------------------------------------
# Direct-import unit tests: predecessor/successor helpers and the
# collision-aware Zone.covering_predecessor / covering_successor.
# --------------------------------------------------------------------------

def _zone(records):
    """Build an in-memory Zone from apex boilerplate plus the given records."""
    text = ("$ORIGIN whitelies.test.\n"
            "$TTL 3600\n"
            "@ IN SOA ns hostmaster 1 43200 3600 3628800 3600\n"
            "@ IN NS ns\n"
            + "\n".join(records) + "\n")
    zone = dns.zone.from_text(text, origin="whitelies.test.",
                              zone_factory=adns.Zone, relativize=False)
    zone.add_ent_nodes()
    return zone


def _n(text):
    return dns.name.from_text(text)


def test_predecessor_label_good():
    """Good-enough form decrements the last octet and appends '~' (0x7e)."""
    assert adns.predecessor_label_good(b"foo") == b"fon\x7e"
    # A last octet of 0x00 has no smaller value; the label empties out.
    assert adns.predecessor_label_good(b"fo\x00") == b"fo"


def test_predecessor_label_ideal():
    """Ideal form decrements then pads 0xff out to the 63-octet maximum."""
    label = adns.predecessor_label_ideal(b"foo")
    assert label[:3] == b"fon"
    assert len(label) == adns.MAX_LABEL_OCTETS
    assert set(label[3:]) == {0xff}


def test_predecessor_name_drops_empty_label():
    """A leftmost label that decrements to nothing is dropped entirely."""
    name = dns.name.Name((b"\x00", b"foo", b"whitelies", b"test", b""))
    pred = adns.predecessor_name(name)
    assert pred == dns.name.Name((b"foo", b"whitelies", b"test", b""))


def test_successor_name():
    """Successor prepends an empty (0x00) leftmost label."""
    assert adns.successor_name(_n("foo.whitelies.test.")) == \
        dns.name.Name((b"\x00", b"foo", b"whitelies", b"test", b""))


def test_covering_predecessor_no_collision():
    """
    With no real name in the syntactic-predecessor's window, the plain
    predecessor is returned and it strictly covers (floor < P < qname).
    """
    zone = _zone(["foo IN A 192.0.2.1"])
    qname = _n("fop.whitelies.test.")
    pred = zone.covering_predecessor(qname)
    assert pred == _n("foo\\126.whitelies.test.")   # 'foo~'
    floor = _n("foo.whitelies.test.")
    assert floor < pred < qname


def test_covering_predecessor_snaps_on_collision():
    """
    When a real name sorts inside (predecessor, qname) -- here a name with a
    0x7f octet, which sorts above the '~' sentinel -- the synthetic predecessor
    would span it, so covering_predecessor snaps to successor_name(floor).
    """
    # foo\127 (0x7f) sorts above foo~ (0x7e) but below fop, so it is the floor
    # for a query of "fop" and lands inside the syntactic predecessor window.
    zone = _zone(["foo IN A 192.0.2.1",
                  "foo\\127 IN A 192.0.2.2"])
    qname = _n("fop.whitelies.test.")
    floor = _n("foo\\127.whitelies.test.")
    pred = zone.covering_predecessor(qname)
    assert pred == adns.successor_name(floor)        # \000.foo\127
    # The snapped predecessor sits strictly between the real floor and qname,
    # so it neither hits nor spans the real name.
    assert floor < pred < qname


def test_covering_predecessor_nothing_below():
    """A qname sorting below every real name returns the bare candidate."""
    zone = _zone(["zzz IN A 192.0.2.1"])
    qname = _n("aaa.whitelies.test.")
    pred = zone.covering_predecessor(qname)
    assert pred == adns.predecessor_name(qname)


def test_covering_successor_normal():
    """Absent a literal \\000-prefixed owner, the successor is \\000.name."""
    zone = _zone(["foo IN A 192.0.2.1"])
    name = _n("foo.whitelies.test.")
    assert zone.covering_successor(name) == adns.successor_name(name)


def test_covering_successor_collision_guard():
    """
    Pathological guard: if the literal successor \\000.name already exists, fall
    back to a name derived from the next real owner above it, still > name.
    """
    zone = _zone(["x IN A 192.0.2.1",
                  "\\000.x IN A 192.0.2.2",
                  "z IN A 192.0.2.3"])
    name = _n("x.whitelies.test.")
    successor = zone.covering_successor(name)
    assert successor != adns.successor_name(name)
    assert successor > name
