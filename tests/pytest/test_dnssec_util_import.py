"""Guards the dnssec_util extraction: the module must import standalone and
expose the moved symbols, and adns_server must re-export them so existing
references (adns_server.Zone, adns_server.successor_name, ...) still resolve."""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import dnssec_util  # noqa: E402


def test_dnssec_util_exposes_moved_symbols():
    for name in ("RRtype", "AUTH_IN_PARENT_RRTYPES", "hashalg", "nsec3hash",
                 "predecessor_label_good", "predecessor_label_ideal",
                 "predecessor_name", "successor_name", "rrset_from_rdataset",
                 "make_nsec_rrset", "make_nsec3_rrset", "load_private_key",
                 "Zone", "zone_from_file", "MAX_LABEL_OCTETS",
                 "PREDECESSOR_SENTINEL", "B32_TO_EXT_HEX",
                 "NSEC3HASH_SIZE_IN_OCTETS"):
        assert hasattr(dnssec_util, name), f"dnssec_util missing {name}"


def test_rrtype_values_intact():
    assert dnssec_util.RRtype.DELEG == 61440
    assert dnssec_util.RRtype.DELEGPARAM == 65433
    assert dnssec_util.RRtype.NXNAME == 128


def test_successor_appends_zero_octet():
    import dns.name
    name = dns.name.from_text("sub5.example.")
    succ = dnssec_util.successor_name(name)
    assert succ.labels[0] == b"sub5\x00"


def test_adns_server_reexports_moved_symbols():
    import adns_server
    for name in ("RRtype", "AUTH_IN_PARENT_RRTYPES", "successor_name",
                 "predecessor_name", "predecessor_label_good",
                 "predecessor_label_ideal", "Zone", "ZoneDict",
                 "nsec3hash", "zone_from_file", "make_nsec_rrset",
                 "load_private_key"):
        assert hasattr(adns_server, name), f"adns_server missing {name}"
    # Re-exported objects must be the SAME objects as in dnssec_util
    assert adns_server.Zone is dnssec_util.Zone
    assert adns_server.successor_name is dnssec_util.successor_name
