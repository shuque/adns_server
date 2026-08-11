"""Unit + round-trip tests for signzone.py (NSEC / NSEC3 single-CSK)."""
import base64
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import dnssec_util  # noqa: E402

pytestmark = pytest.mark.signer


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


import dns.dnssec       # noqa: E402


def _sign_fixture(inception=None, expiration=None, jitter=0):
    """Load, strip, and sign the fixture in memory; return the signed Zone."""
    sz = _signzone()
    zone = _load_fixture()
    keydir = os.path.join(ZONE_DIR, "signer-nsec.test")
    keys = sz.discover_keys(zone, keydir)
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    inc = inception if inception is not None else now - 3600
    exp = expiration if expiration is not None else now + 2592000
    sz.sign_zone(zone, keys, inc, exp, jitter)
    return zone, keys


def _dnskey_rrset_of(zone):
    origin = zone.origin
    rdataset = zone.get_rdataset(origin, dns.rdatatype.DNSKEY)
    rrset = dns.rrset.RRset(origin, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rrset.update(rdataset)
    return rrset


def test_signed_rrsets_validate():
    import dns.rrset
    zone, _keys = _sign_fixture()
    origin = zone.origin
    dnskey_rrset = _dnskey_rrset_of(zone)
    checked = 0
    for name, node in zone.nodes.items():
        rrsig_sets = [r for r in node.rdatasets
                      if r.rdtype == dns.rdatatype.RRSIG]
        for rrsig_ds in rrsig_sets:
            covered = rrsig_ds.covers
            covered_ds = node.get_rdataset(dns.rdataclass.IN, covered)
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, covered)
            rrset.update(covered_ds)
            rrsig = dns.rrset.RRset(name, dns.rdataclass.IN,
                                    dns.rdatatype.RRSIG, covered)
            rrsig.update(rrsig_ds)
            # Fixed 'now' matching _sign_fixture()'s inception/expiration
            # epoch: dns.dnssec.validate() defaults to the real wall clock,
            # which would spuriously report "expired" once real time drifts
            # past the fixture's fixed signing window.
            dns.dnssec.validate(rrset, rrsig, {origin: dnskey_rrset},
                                now=1_700_000_000)
            checked += 1
    assert checked >= 6      # apex SOA/NS/DNSKEY + A's + DS + NSECs


def test_cut_authority_rule():
    zone, _keys = _sign_fixture()
    sub = dns.name.from_text("sub." + NSEC_ZONE_NAME + ".")
    node = zone.get_node(sub)
    covers = {r.covers for r in node.rdatasets
              if r.rdtype == dns.rdatatype.RRSIG}
    # DS and NSEC signed at the cut; NS is NOT. A data RRset (TXT) sitting at
    # the cut is occluded parent-side data: it must NOT be signed.
    assert dns.rdatatype.DS in covers
    assert dns.rdatatype.NSEC in covers
    assert dns.rdatatype.NS not in covers
    assert dns.rdatatype.TXT not in covers
    # The cut's NSEC bitmap lists only the parent-visible types (NS/DS/RRSIG/
    # NSEC); the occluded TXT must not leak into it (would break validation --
    # BIND dnssec-verify rejects the extra bit).
    nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)[0]
    bitmap = _nsec_types(nsec)
    assert dns.rdatatype.TXT not in bitmap
    assert {dns.rdatatype.NS, dns.rdatatype.DS,
            dns.rdatatype.RRSIG, dns.rdatatype.NSEC} <= bitmap
    # Occluded glue below the cut is neither signed nor NSEC'd.
    glue = dns.name.from_text("ns1.sub." + NSEC_ZONE_NAME + ".")
    gnode = zone.get_node(glue)
    gcovers = {r.rdtype for r in gnode.rdatasets}
    assert dns.rdatatype.RRSIG not in gcovers
    assert dns.rdatatype.NSEC not in gcovers


def test_dname_owner_signed_but_subtree_occluded():
    # RFC 6672: the DNAME owner is authoritative -- its DNAME RRset is signed
    # and it gets an NSEC (bitmap includes DNAME). Names strictly BELOW the
    # DNAME owner are occluded: neither signed nor given an NSEC.
    zone, _keys = _sign_fixture()
    dname = dns.name.from_text("dname." + NSEC_ZONE_NAME + ".")
    dnode = zone.get_node(dname)
    dcovers = {r.covers for r in dnode.rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert dns.rdatatype.DNAME in dcovers        # DNAME RRset is signed
    assert dns.rdatatype.NSEC in dcovers         # NSEC at the DNAME owner
    nsec = dnode.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)[0]
    assert dns.rdatatype.DNAME in _nsec_types(nsec)
    # The name below the DNAME is occluded: no RRSIG, no NSEC.
    below = dns.name.from_text("below.dname." + NSEC_ZONE_NAME + ".")
    bnode = zone.get_node(below)
    btypes = {r.rdtype for r in bnode.rdatasets}
    assert dns.rdatatype.RRSIG not in btypes
    assert dns.rdatatype.NSEC not in btypes


def _nsec_types(nsec):
    """Set of RR types present in an NSEC rdata's type bitmap."""
    present = set()
    for window, bitmap in nsec.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    present.add(window * 256 + i * 8 + bit)
    return present


def test_nsec_chain_closed_and_excludes_ents():
    zone, _keys = _sign_fixture()
    origin = zone.origin
    # Collect NSEC owners and their next names.
    owners, nexts = [], {}
    for name, node in zone.nodes.items():
        nsec_ds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        if nsec_ds is not None:
            owners.append(name)
            nexts[name] = nsec_ds[0].next
    owners_sorted = sorted(owners)
    # ENTs excluded.
    ent = dns.name.from_text("deep.ent." + NSEC_ZONE_NAME + ".")
    assert ent not in nexts
    # Occluded glue excluded.
    glue = dns.name.from_text("ns1.sub." + NSEC_ZONE_NAME + ".")
    assert glue not in nexts
    # Closed loop: each owner's next is the following owner; last -> apex.
    for i, owner in enumerate(owners_sorted):
        expected = owners_sorted[(i + 1) % len(owners_sorted)]
        assert nexts[owner] == expected, (owner, nexts[owner], expected)
    assert origin in owners


def test_nsec_bitmap_includes_present_types():
    zone, _keys = _sign_fixture()
    origin = zone.origin
    node = zone.get_node(origin)
    nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)[0]
    present = set()
    for window, bitmap in nsec.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    present.add(window * 256 + i * 8 + bit)
    for rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS, dns.rdatatype.DNSKEY,
                   dns.rdatatype.NSEC, dns.rdatatype.RRSIG):
        assert rdtype in present


def test_bump_serial_increments_soa():
    # dnspython Rdata (incl. SOA) is immutable on 2.7.0+; bump_serial must
    # replace the rdata rather than mutating soa_rdataset[0].serial in place
    # (that raises TypeError: object doesn't support attribute assignment).
    sz = _signzone()
    zone = _load_fixture()
    origin = zone.origin
    before = zone.get_rdataset(origin, dns.rdatatype.SOA)[0].serial
    assert before == 1          # fixture's starting serial
    sz.bump_serial(zone)
    after = zone.get_rdataset(origin, dns.rdatatype.SOA)[0].serial
    assert after == before + 1


def test_discover_keys_bad_pem_raises_signer_error(tmp_path):
    sz = _signzone()
    zone = _load_fixture()
    # Keytag 55608 matches the fixture's DNSKEY (see
    # signer-nsec.test+013+55608.pem); discover_keys must find this file by
    # name and fail to parse it as a private key.
    bad_pem = tmp_path / "signer-nsec.test+013+55608.pem"
    bad_pem.write_text("not a valid PEM key\n")
    with pytest.raises(sz.SignerError):
        sz.discover_keys(zone, str(tmp_path))


# --------------------------------------------------------------------------
# NSEC3 mode (Signer.md 4): an apex NSEC3PARAM record switches the signer to
# an NSEC3 chain. The signer-nsec3.test fixture mirrors the NSEC one (same
# DNAME, ENT chain, secure cut + glue, wildcard) plus an NSEC3PARAM record.
# --------------------------------------------------------------------------

NSEC3_ZONE_NAME = "signer-nsec3.test"


def _load_nsec3_fixture():
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        return dnssec_util.zone_from_file(
            dns.name.from_text(NSEC3_ZONE_NAME), "signer-nsec3.test/zonefile")
    finally:
        os.chdir(cwd)


def _sign_nsec3_fixture(jitter=0):
    """Load, strip, and sign the NSEC3 fixture in memory; return the Zone."""
    sz = _signzone()
    zone = _load_nsec3_fixture()
    keydir = os.path.join(ZONE_DIR, "signer-nsec3.test")
    keys = sz.discover_keys(zone, keydir)
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    sz.sign_zone(zone, keys, now - 3600, now + 2592000, jitter)
    return zone, keys


def _nsec3_records(zone):
    """Return {owner_name: nsec3_rdata} for every NSEC3 in the zone."""
    out = {}
    for name, node in zone.nodes.items():
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
        if rds is not None:
            out[name] = rds[0]
    return out


def _hashed(zone, name):
    """Hashed owner name for `name` under the fixture's NSEC3PARAM."""
    params = zone.get_rdataset(zone.origin, dns.rdatatype.NSEC3PARAM)[0]
    h = dnssec_util.nsec3hash(name, params.algorithm, params.salt,
                              params.iterations)
    return dns.name.Name((h.encode(),) + zone.origin.labels)


def test_nsec3param_switches_mode():
    # The zone gets an NSEC3 chain (not NSEC) purely because it has NSEC3PARAM.
    zone, _keys = _sign_nsec3_fixture()
    n3 = _nsec3_records(zone)
    assert n3, "expected an NSEC3 chain"
    # No plain NSEC anywhere.
    for _name, node in zone.nodes.items():
        assert node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC) is None


def test_nsec3_signed_rrsets_validate():
    import dns.rrset
    zone, _keys = _sign_nsec3_fixture()
    origin = zone.origin
    dnskey_rrset = _dnskey_rrset_of(zone)
    checked = 0
    for name, node in zone.nodes.items():
        for rrsig_ds in [r for r in node.rdatasets
                         if r.rdtype == dns.rdatatype.RRSIG]:
            covered = rrsig_ds.covers
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, covered)
            rrset.update(node.get_rdataset(dns.rdataclass.IN, covered))
            rrsig = dns.rrset.RRset(name, dns.rdataclass.IN,
                                    dns.rdatatype.RRSIG, covered)
            rrsig.update(rrsig_ds)
            dns.dnssec.validate(rrset, rrsig, {origin: dnskey_rrset},
                                now=1_700_000_000)
            checked += 1
    assert checked >= 6      # apex SOA/NS/DNSKEY/NSEC3PARAM + A's + DS + NSEC3s


def test_nsec3_chain_includes_ents():
    # The reverse of NSEC: every empty non-terminal gets its own NSEC3, with an
    # empty type bitmap (RFC 5155 7.1). 'ent', 'deep.ent', and 'wild' are ENTs.
    zone, _keys = _sign_nsec3_fixture()
    n3 = _nsec3_records(zone)
    for ent_label in ("ent", "deep.ent", "wild"):
        ent = dns.name.from_text(ent_label + "." + NSEC3_ZONE_NAME + ".")
        owner = _hashed(zone, ent)
        assert owner in n3, f"no NSEC3 for ENT {ent_label}"
        assert not _nsec_types(n3[owner]), "ENT NSEC3 bitmap must be empty"


def test_nsec3_excludes_occluded_names():
    # Occluded glue below the cut, and the subtree below a DNAME, get no NSEC3.
    zone, _keys = _sign_nsec3_fixture()
    n3 = _nsec3_records(zone)
    for occluded in ("ns1.sub", "below.dname"):
        name = dns.name.from_text(occluded + "." + NSEC3_ZONE_NAME + ".")
        assert _hashed(zone, name) not in n3, \
            f"{occluded} must not have an NSEC3"


def test_nsec3_cut_bitmap_excludes_occluded_data():
    # A data RRset (TXT) sitting at a delegation cut is occluded parent-side
    # data: it must not be signed, and must not appear in the cut's NSEC3 type
    # bitmap (only NS/DS/RRSIG do). Regression for the m3.huque.com 'newsub'
    # case where a private-type record at a secure cut leaked into the bitmap
    # and BIND dnssec-verify rejected the chain.
    zone, _keys = _sign_nsec3_fixture()
    sub = dns.name.from_text("sub." + NSEC3_ZONE_NAME + ".")
    covers = {r.covers for r in zone.get_node(sub).rdatasets
              if r.rdtype == dns.rdatatype.RRSIG}
    assert dns.rdatatype.TXT not in covers
    owner = _hashed(zone, sub)
    n3 = _nsec3_records(zone)
    bitmap = _nsec_types(n3[owner])
    assert dns.rdatatype.TXT not in bitmap
    assert {dns.rdatatype.NS, dns.rdatatype.DS, dns.rdatatype.RRSIG} <= bitmap


def test_nsec3_dname_owner_is_hashed_and_signed():
    # The DNAME owner is authoritative: its DNAME RRset is signed and it gets an
    # NSEC3 whose bitmap lists DNAME (mirrors the NSEC-mode DNAME test).
    zone, _keys = _sign_nsec3_fixture()
    dname = dns.name.from_text("dname." + NSEC3_ZONE_NAME + ".")
    dnode = zone.get_node(dname)
    dcovers = {r.covers for r in dnode.rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert dns.rdatatype.DNAME in dcovers
    owner = _hashed(zone, dname)
    n3 = _nsec3_records(zone)
    assert owner in n3
    assert dns.rdatatype.DNAME in _nsec_types(n3[owner])


# base32hex (extended-hex, RFC 4648) label -> standard base32, for decoding an
# NSEC3 owner label back to the 20-octet hash it encodes.
_HEX_TO_B32 = bytes.maketrans(b'0123456789ABCDEFGHIJKLMNOPQRSTUV',
                              b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')


def _label_to_hash(label):
    """Decode a base32hex NSEC3 owner label into its raw 20-octet hash."""
    return base64.b32decode(label.translate(_HEX_TO_B32))


def test_nsec3_chain_is_closed_and_hash_sorted():
    # NSEC3 sorts by hash: owners in base32hex order, each next field = the
    # following owner's hash, last wrapping to the first (closed loop).
    zone, _keys = _sign_nsec3_fixture()
    n3 = _nsec3_records(zone)
    owners = sorted(n3, key=lambda n: n.labels[0])   # base32hex sorts as hash
    for i, owner in enumerate(owners):
        follow_label = owners[(i + 1) % len(owners)].labels[0]
        assert n3[owner].next == _label_to_hash(follow_label), (owner, i)
    # The apex is part of the chain.
    assert _hashed(zone, zone.origin) in n3


# --------------------------------------------------------------------------
# Two-key KSK(257)/ZSK(256) mode (BIND dnssec-signzone -S -x): the DNSKEY
# RRset is signed only by the SEP key, everything else only by the ZSK. This
# is the shape of the real m1/m3.huque.com zones. NSEC3 + salt + iterations.
# --------------------------------------------------------------------------

TWOKEY_ZONE_NAME = "signer-2key.test"


def _sign_2key_fixture(jitter=0):
    """Load, strip, and sign the two-key fixture in memory; return (zone, keys)."""
    sz = _signzone()
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        zone = dnssec_util.zone_from_file(
            dns.name.from_text(TWOKEY_ZONE_NAME), "signer-2key.test/zonefile")
    finally:
        os.chdir(cwd)
    keydir = os.path.join(ZONE_DIR, "signer-2key.test")
    keys = sz.discover_keys(zone, keydir)
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    sz.sign_zone(zone, keys, now - 3600, now + 2592000, jitter)
    return zone, keys


def _keytags_of_covering_rrsigs(node, covered):
    """Set of key_tags of the RRSIGs at `node` that cover rdtype `covered`."""
    tags = set()
    for rds in node.rdatasets:
        if rds.rdtype == dns.rdatatype.RRSIG and rds.covers == covered:
            for rrsig in rds:
                tags.add(rrsig.key_tag)
    return tags


def test_2key_discovers_both_keys():
    zone, keys = _sign_2key_fixture()
    assert len(keys) == 2
    sep = [k for k in keys if k.is_sep]
    zsk = [k for k in keys if not k.is_sep]
    assert len(sep) == 1 and len(zsk) == 1        # one KSK, one ZSK
    assert all(k.private_key is not None for k in keys)   # both active
    assert zone.get_rdataset(zone.origin, dns.rdatatype.NSEC3PARAM)


def test_2key_dnskey_signed_by_ksk_rest_by_zsk():
    # The core of the split: DNSKEY is signed only by the SEP key; other
    # RRsets (SOA, A, ...) only by the ZSK. (dnssec-signzone -x / classify_signers.)
    zone, keys = _sign_2key_fixture()
    ksk_tag = next(k.keytag for k in keys if k.is_sep)
    zsk_tag = next(k.keytag for k in keys if not k.is_sep)
    origin = zone.origin
    apex = zone.get_node(origin)
    assert _keytags_of_covering_rrsigs(apex, dns.rdatatype.DNSKEY) == {ksk_tag}
    assert _keytags_of_covering_rrsigs(apex, dns.rdatatype.SOA) == {zsk_tag}
    www = zone.get_node(dns.name.from_text("www." + TWOKEY_ZONE_NAME + "."))
    assert _keytags_of_covering_rrsigs(www, dns.rdatatype.A) == {zsk_tag}


def test_2key_signed_rrsets_validate():
    import dns.rrset
    zone, _keys = _sign_2key_fixture()
    origin = zone.origin
    dnskey_rrset = _dnskey_rrset_of(zone)
    checked = 0
    for name, node in zone.nodes.items():
        for rrsig_ds in [r for r in node.rdatasets
                         if r.rdtype == dns.rdatatype.RRSIG]:
            covered = rrsig_ds.covers
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, covered)
            rrset.update(node.get_rdataset(dns.rdataclass.IN, covered))
            rrsig = dns.rrset.RRset(name, dns.rdataclass.IN,
                                    dns.rdatatype.RRSIG, covered)
            rrsig.update(rrsig_ds)
            # Both keys are in the apex DNSKEY RRset, so validate() finds the
            # right one for each RRSIG regardless of KSK/ZSK role.
            dns.dnssec.validate(rrset, rrsig, {origin: dnskey_rrset},
                                now=1_700_000_000)
            checked += 1
    assert checked >= 6
