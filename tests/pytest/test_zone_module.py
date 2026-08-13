"""Guards the adns.zone extraction: the module must import standalone and
expose the moved symbols."""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import adns.zone  # noqa: E402


def test_zone_module_exposes_moved_symbols():
    for name in ("RRtype", "AUTH_IN_PARENT_RRTYPES", "hashalg", "nsec3hash",
                 "predecessor_label_good", "predecessor_label_ideal",
                 "predecessor_name", "successor_name", "rrset_from_rdataset",
                 "make_nsec_rrset", "make_nsec3_rrset",
                 "make_nsec3_rrset_minimal", "Zone", "ZoneDict",
                 "HashableRRset", "zone_from_file", "MAX_LABEL_OCTETS",
                 "PREDECESSOR_SENTINEL", "B32_TO_EXT_HEX",
                 "NSEC3HASH_SIZE_IN_OCTETS"):
        assert hasattr(adns.zone, name), f"adns.zone missing {name}"


def test_rrtype_values_intact():
    assert adns.zone.RRtype.DELEG == 61440
    assert adns.zone.RRtype.DELEGPARAM == 65433
    assert adns.zone.RRtype.NXNAME == 128


def test_successor_appends_zero_octet():
    import dns.name
    name = dns.name.from_text("sub5.example.")
    succ = adns.zone.successor_name(name)
    assert succ.labels[0] == b"sub5\x00"


def test_zone_nodes_use_map_factory(tmp_path):
    """
    zone_from_file must yield a zone whose node map is the Zone.map_factory
    (SortedDict), not a plain dict. dnspython's zone reader honoring
    map_factory is what the whole DNSSEC ordering model relies on; a
    dnspython 2.0-era regression once remapped it back to dict (fixed before
    our 2.7.0 floor). This guards against that regression returning, in place
    of the defensive re-wrap zone_from_file used to carry.
    """
    import dns.name
    from sortedcontainers import SortedDict

    zonefile = tmp_path / "mf.test.zone"
    zonefile.write_text(
        "$ORIGIN mf.test.\n"
        "$TTL 3600\n"
        "@ IN SOA ns hostmaster 1 43200 3600 3628800 3600\n"
        "@ IN NS ns\n"
        "ns IN A 192.0.2.1\n"
        "b.a IN A 192.0.2.2\n"
        "z IN A 192.0.2.26\n"
    )
    zone = adns.zone.zone_from_file(dns.name.from_text("mf.test."),
                                    str(zonefile))
    assert adns.zone.Zone.map_factory is SortedDict
    assert isinstance(zone.nodes, zone.map_factory)
    # Keys are kept in canonical dns.name.Name order (apex first), which is
    # what the covering-NSEC/NSEC3 searches depend on -- not text order.
    keys = list(zone.nodes)
    assert keys == sorted(keys)
    # The synthesized ENT must be present as an explicit node.
    assert dns.name.from_text("a.mf.test.") in zone.nodes
