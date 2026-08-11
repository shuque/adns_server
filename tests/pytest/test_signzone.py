"""Unit + round-trip tests for signzone.py (Stage 1: NSEC single-CSK)."""
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import dnssec_util  # noqa: E402


def test_key_basename_format():
    assert dnssec_util.key_basename("signer-nsec.test", 13, 34063) == \
        "signer-nsec.test+013+34063"
    # alg and keytag are zero-padded to 3 and 5 digits respectively.
    assert dnssec_util.key_basename("x.test", 8, 42) == "x.test+008+00042"


GENKEY = os.path.join(REPO_ROOT, "genkey.py")


def test_genkey_keydir_writes_triple(tmp_path):
    keydir = tmp_path / "keys"
    result = subprocess.run(
        [sys.executable, GENKEY, "signer-nsec.test", "-a", "13", "-f", "257",
         "--keydir", str(keydir)],
        capture_output=True, text=True, check=True)
    pems = list(keydir.glob("signer-nsec.test+013+*.pem"))
    assert len(pems) == 1, result.stdout
    base = pems[0].name[:-4]  # strip .pem
    assert (keydir / (base + ".dnskey")).exists()
    ds_path = keydir / (base + ".ds")
    assert ds_path.exists()
    assert ds_path.read_text().startswith("signer-nsec.test. IN DS ")
    # Private key file is owner-only (0600).
    assert (pems[0].stat().st_mode & 0o777) == 0o600
    # Private key loads and DNSKEY parses; keytag in filename matches the key.
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    key = dnssec_util.load_private_key(str(pems[0]))
    assert key is not None
    dnskey_text = (keydir / (base + ".dnskey")).read_text()
    # basename tag is the last +NNNNN before .pem
    tag_in_name = int(base.rsplit("+", 1)[1])
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                dnskey_text.split("DNSKEY", 1)[1].strip())
    import dns.dnssec
    assert dns.dnssec.key_id(rdata) == tag_in_name


import dns.name          # noqa: E402
import dns.rdatatype     # noqa: E402

ZONE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_zones")
NSEC_ZONE_NAME = "signer-nsec.test"
NSEC_ZONE_FILE = os.path.join(ZONE_DIR, "signer-nsec.test", "zonefile")


def _load_fixture():
    # zone_from_file resolves $INCLUDE relative to cwd; run from ZONE_DIR.
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        return dnssec_util.zone_from_file(
            dns.name.from_text(NSEC_ZONE_NAME), "signer-nsec.test/zonefile")
    finally:
        os.chdir(cwd)


def test_fixture_shape():
    zone = _load_fixture()
    origin = dns.name.from_text(NSEC_ZONE_NAME)
    assert zone.get_rdataset(origin, dns.rdatatype.SOA)
    assert zone.get_rdataset(origin, dns.rdatatype.DNSKEY)
    # ENT nodes present but empty (added by add_ent_nodes()).
    ent = dns.name.from_text("deep.ent." + NSEC_ZONE_NAME + ".")
    assert ent in zone.nodes and not zone.get_node(ent).rdatasets
    # Delegation cut with in-zone glue.
    sub = dns.name.from_text("sub." + NSEC_ZONE_NAME + ".")
    assert zone.get_rdataset(sub, dns.rdatatype.NS)
    assert zone.get_rdataset(sub, dns.rdatatype.DS)
    glue = dns.name.from_text("ns1.sub." + NSEC_ZONE_NAME + ".")
    assert zone.get_rdataset(glue, dns.rdatatype.A)


def _signzone():
    import importlib
    return importlib.import_module("signzone")


def test_parse_duration_units():
    sz = _signzone()
    assert sz.parse_duration("30") == 30
    assert sz.parse_duration("90s") == 90
    assert sz.parse_duration("5m") == 300
    assert sz.parse_duration("2h") == 7200
    assert sz.parse_duration("30d") == 2592000
    assert sz.parse_duration("1w") == 604800
    assert sz.parse_duration("1y") == 31536000


def test_parse_time_relative_and_absolute():
    sz = _signzone()
    now = 1_000_000
    assert sz.parse_time("+30d", now) == now + 2592000
    assert sz.parse_time("30d", now) == now + 2592000     # unsigned => future
    assert sz.parse_time("-1h", now) == now - 3600
    # 14-digit absolute UTC: 2030-01-01 00:00:00Z
    assert sz.parse_time("20300101000000", now) == 1893456000


def test_discover_keys_finds_csk():
    sz = _signzone()
    zone = _load_fixture()
    keydir = os.path.join(ZONE_DIR, "signer-nsec.test")
    keys = sz.discover_keys(zone, keydir)
    assert len(keys) == 1
    (k,) = keys
    assert k.is_sep is True                 # flags 257 -> SEP set
    assert k.private_key is not None        # PEM present -> active
    assert k.algorithm == 13


def test_discover_keys_no_pem_is_error(tmp_path):
    sz = _signzone()
    zone = _load_fixture()
    with pytest.raises(sz.SignerError):
        sz.discover_keys(zone, str(tmp_path))   # empty keydir


def test_strip_removes_dnssec_records():
    sz = _signzone()
    zone = _load_fixture()
    # Fixture is unsigned; strip must be a no-op that keeps DNSKEY.
    sz.strip_dnssec(zone)
    origin = dns.name.from_text(NSEC_ZONE_NAME)
    assert zone.get_rdataset(origin, dns.rdatatype.DNSKEY)
    for _name, node in zone.nodes.items():
        for rds in node.rdatasets:
            assert rds.rdtype not in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                                      dns.rdatatype.NSEC3)
