"""Unit + round-trip tests for adns.signer (NSEC / NSEC3 single-CSK)."""
import base64
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import adns.zone     # noqa: E402
import adns.crypto    # noqa: E402

pytestmark = pytest.mark.signer

# `-m adns.keygen` is a package import that a subprocess cannot resolve on its
# own -- this process's sys.path.insert(0, REPO_ROOT) above does not propagate
# to a child. Put the repo root on the child's PYTHONPATH explicitly (Task 8
# pattern, reused here for the signer/keygen subprocess launches).
SUBPROCESS_ENV = {**os.environ,
                  "PYTHONPATH": REPO_ROOT + os.pathsep +
                  os.environ.get("PYTHONPATH", "")}


def test_key_basename_format():
    assert adns.crypto.key_basename("signer-nsec.test", 13, 34063) == \
        "signer-nsec.test+013+34063"
    # alg and keytag are zero-padded to 3 and 5 digits respectively.
    assert adns.crypto.key_basename("x.test", 8, 42) == "x.test+008+00042"


GENKEY = [sys.executable, "-m", "adns.keygen"]


def test_adnskeygen_keydir_writes_triple(tmp_path):
    keydir = tmp_path / "keys"
    result = subprocess.run(
        GENKEY + ["signer-nsec.test", "-a", "13", "-f", "257",
                  "--keydir", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
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
    key = adns.crypto.load_private_key(str(pems[0]))
    assert key is not None
    dnskey_text = (keydir / (base + ".dnskey")).read_text()
    # basename tag is the last +NNNNN before .pem
    tag_in_name = int(base.rsplit("+", 1)[1])
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                dnskey_text.split("DNSKEY", 1)[1].strip())
    import dns.dnssec
    assert dns.dnssec.key_id(rdata) == tag_in_name


def test_adnskeygen_prepublish_writes_prepublish_pem(tmp_path):
    keydir = tmp_path / "keys"
    result = subprocess.run(
        GENKEY + ["prepub.test", "-a", "13", "-f", "256",
                  "--keydir", str(keydir), "--prepublish"],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    # The private key is written with the .prepublish.pem suffix, so
    # discover_keys' exact <zone>+<alg>+<keytag>.pem match ignores it: the
    # DNSKEY is published but not used to sign until the operator renames it.
    prepub = list(keydir.glob("prepub.test+013+*.prepublish.pem"))
    assert len(prepub) == 1, result.stdout
    plain = [p for p in keydir.glob("prepub.test+013+*.pem")
             if not p.name.endswith(".prepublish.pem")]
    assert not plain            # no active .pem was written
    base = prepub[0].name[:-len(".prepublish.pem")]
    # The .dnskey companion is written; no .ds since this is a ZSK (-f 256).
    assert (keydir / (base + ".dnskey")).exists()
    assert not (keydir / (base + ".ds")).exists()
    # Private key file is owner-only (0600).
    assert (prepub[0].stat().st_mode & 0o777) == 0o600


def test_adnskeygen_prepublish_requires_keydir():
    # --prepublish without -K/--keydir has nowhere to write the .prepublish.pem.
    result = subprocess.run(
        GENKEY + ["prepub.test", "--prepublish"],
        capture_output=True, text=True, env=SUBPROCESS_ENV)
    assert result.returncode != 0
    assert "requires -K" in result.stderr


def test_adnskeygen_ds_only_for_sep_key(tmp_path):
    # DS is emitted (stdout + .ds file) only for SEP keys (KSK/CSK). A KSK
    # (-f 257) gets a .ds; a ZSK (-f 256) does not.
    ksk_dir = tmp_path / "ksk"
    ksk = subprocess.run(
        GENKEY + ["sep.test", "-a", "13", "-f", "257",
                  "--keydir", str(ksk_dir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    ds = list(ksk_dir.glob("sep.test+013+*.ds"))
    assert len(ds) == 1
    assert "### DS record" in ksk.stdout

    zsk_dir = tmp_path / "zsk"
    zsk = subprocess.run(
        GENKEY + ["sep.test", "-a", "13", "-f", "256",
                  "--keydir", str(zsk_dir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    assert not list(zsk_dir.glob("sep.test+013+*.ds"))
    assert list(zsk_dir.glob("sep.test+013+*.dnskey"))   # .dnskey still written
    assert "### DS record" not in zsk.stdout


import dns.name          # noqa: E402
import dns.rdatatype     # noqa: E402

ZONE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_zones")
NSEC_ZONE_NAME = "signer-nsec.test"


def _load_fixture():
    # zone_from_file resolves $INCLUDE relative to cwd; run from ZONE_DIR.
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        return adns.zone.zone_from_file(
            dns.name.from_text(NSEC_ZONE_NAME), "signer-nsec.test/zonefile")
    finally:
        os.chdir(cwd)


def _inject_deleg_matrix(zone, zone_name):
    """
    Add a DELEG cut matrix to an in-memory zone: a DELEG-only cut
    ('delegonly' + occluded 'x.delegonly') and an NS+DELEG cut ('nsdeleg' +
    glue). Kept out of the on-disk fixtures because BIND's dnssec-verify (the
    oracle in test_signzone_oracle.py) treats TYPE61440 as ordinary data and
    would reject the authoritative-in-parent signing.
    """
    import dns.rdata
    deleg_wire = (r"\# 26 "
                  "00000a636f6e66696731323334076578616d706c6503636f6d00")
    deleg = adns.zone.RRtype.DELEG

    def add(owner, rdtype, text):
        name = dns.name.from_text(owner + "." + zone_name + ".")
        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, text)
        zone.find_rdataset(name, rdtype, create=True).add(rdata, 3600)

    add("delegonly", deleg, deleg_wire)
    add("x.delegonly", dns.rdatatype.A, "192.0.2.50")
    add("nsdeleg", dns.rdatatype.NS, "ns1.nsdeleg." + zone_name + ".")
    add("nsdeleg", deleg, deleg_wire)
    add("ns1.nsdeleg", dns.rdatatype.A, "192.0.2.51")


def _sign_with_deleg(zone_name, keysubdir, jitter=0):
    """Load the named fixture, inject the DELEG matrix, strip, and sign it."""
    sz = _signzone()
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        zone = adns.zone.zone_from_file(
            dns.name.from_text(zone_name), keysubdir + "/zonefile")
    finally:
        os.chdir(cwd)
    keydir = os.path.join(ZONE_DIR, keysubdir)
    keys = sz.discover_keys(zone, keydir)
    _inject_deleg_matrix(zone, zone_name)
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    sz.sign_zone(zone, keys, now - 3600, now + 2592000, jitter)
    return zone, keys


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
    return importlib.import_module("adns.signer")


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


def test_deleg_signed_at_cut():
    # DELEG (TYPE61440) is authoritative-in-parent (delext-10): at a cut it is
    # signed and its type appears in the delegation-point NSEC bitmap, exactly
    # like DS. NS is not signed. A DELEG-only cut (no NS) still occludes its
    # subtree.
    deleg = adns.zone.RRtype.DELEG
    zone, _keys = _sign_with_deleg(NSEC_ZONE_NAME, "signer-nsec.test")
    # DELEG-only cut: DELEG + NSEC signed, DELEG bit in the bitmap.
    donly = dns.name.from_text("delegonly." + NSEC_ZONE_NAME + ".")
    dnode = zone.get_node(donly)
    dcovers = {r.covers for r in dnode.rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert deleg in dcovers
    assert dns.rdatatype.NSEC in dcovers
    dnsec = dnode.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)[0]
    assert deleg in _nsec_types(dnsec)
    assert dns.rdatatype.NS not in _nsec_types(dnsec)
    # Subtree below the DELEG-only cut is occluded: neither signed nor NSEC'd.
    below = dns.name.from_text("x.delegonly." + NSEC_ZONE_NAME + ".")
    btypes = {r.rdtype for r in zone.get_node(below).rdatasets}
    assert dns.rdatatype.RRSIG not in btypes
    assert dns.rdatatype.NSEC not in btypes
    # NS+DELEG cut: DELEG signed, NS not; bitmap has NS and DELEG.
    nsd = dns.name.from_text("nsdeleg." + NSEC_ZONE_NAME + ".")
    nnode = zone.get_node(nsd)
    ncovers = {r.covers for r in nnode.rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert deleg in ncovers
    assert dns.rdatatype.NS not in ncovers
    nnsec = nnode.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)[0]
    assert {dns.rdatatype.NS, deleg} <= _nsec_types(nnsec)


def test_wildcard_deleg_fails_fast():
    # delext-10 4.4: "A wildcard owner name MUST NOT have Delegation Types."
    # The signer enforces this before doing any work: sign_zone must raise
    # SignerError and leave the zone unsigned (no RRSIG/NSEC records added).
    import dns.rdata
    import dns.rdataset
    sz = _signzone()
    zone = _load_fixture()
    keydir = os.path.join(ZONE_DIR, "signer-nsec.test")
    keys = sz.discover_keys(zone, keydir)
    sz.strip_dnssec(zone)
    # Plant a DELEG RRset at a wildcard owner.
    star = dns.name.from_text("*.bad." + NSEC_ZONE_NAME + ".")
    rdata = dns.rdata.from_text(dns.rdataclass.IN, adns.zone.RRtype.DELEG,
                                r"\# 26 "
                                "00000a636f6e66696731323334076578616d706c65"
                                "03636f6d00")
    zone.find_rdataset(star, adns.zone.RRtype.DELEG,
                       create=True).add(rdata, 3600)
    now = 1_700_000_000
    with pytest.raises(sz.SignerError, match="4.4"):
        sz.sign_zone(zone, keys, now - 3600, now + 2592000, 0)
    # Fail-fast: nothing was signed.
    for _name, node in zone.nodes.items():
        for rds in node.rdatasets:
            assert rds.rdtype not in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                                      dns.rdatatype.NSEC3)


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
        return adns.zone.zone_from_file(
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
    h = adns.zone.nsec3hash(name, params.algorithm, params.salt,
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


def test_nsec3_deleg_signed_at_cut():
    # DELEG at a cut is signed and its type appears in the delegation-point
    # NSEC3 bitmap (mirrors the NSEC-mode test). The DELEG-only cut occludes its
    # subtree.
    deleg = adns.zone.RRtype.DELEG
    zone, _keys = _sign_with_deleg(NSEC3_ZONE_NAME, "signer-nsec3.test")
    n3 = _nsec3_records(zone)
    donly = dns.name.from_text("delegonly." + NSEC3_ZONE_NAME + ".")
    dcovers = {r.covers for r in zone.get_node(donly).rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert deleg in dcovers
    dbitmap = _nsec_types(n3[_hashed(zone, donly)])
    assert deleg in dbitmap
    assert dns.rdatatype.NS not in dbitmap
    # Subtree below the DELEG-only cut is occluded: no NSEC3, not signed.
    below = dns.name.from_text("x.delegonly." + NSEC3_ZONE_NAME + ".")
    assert _hashed(zone, below) not in n3
    assert dns.rdatatype.RRSIG not in {r.rdtype
                                       for r in zone.get_node(below).rdatasets}
    # NS+DELEG cut: DELEG signed, NS not; bitmap has NS and DELEG.
    nsd = dns.name.from_text("nsdeleg." + NSEC3_ZONE_NAME + ".")
    ncovers = {r.covers for r in zone.get_node(nsd).rdatasets
               if r.rdtype == dns.rdatatype.RRSIG}
    assert deleg in ncovers
    assert dns.rdatatype.NS not in ncovers
    assert {dns.rdatatype.NS, deleg} <= _nsec_types(n3[_hashed(zone, nsd)])


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
        zone = adns.zone.zone_from_file(
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


def _sign_2key_one_pem(keydir, jitter=0):
    """
    Load the 2-key fixture but discover keys from `keydir`, which the caller has
    seeded with only ONE of the two PEMs. The PEM-less DNSKEY is discovered as
    publish-only (private_key=None). Returns (zone, keys).
    """
    sz = _signzone()
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        zone = adns.zone.zone_from_file(
            dns.name.from_text(TWOKEY_ZONE_NAME), "signer-2key.test/zonefile")
    finally:
        os.chdir(cwd)
    keys = sz.discover_keys(zone, str(keydir))
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    sz.sign_zone(zone, keys, now - 3600, now + 2592000, jitter)
    return zone, keys


def test_2key_prepublished_key_is_published_not_signing(tmp_path):
    # Pre-publish rollover: a DNSKEY with no matching PEM must still be published
    # in the apex DNSKEY RRset but must NOT sign anything (its keytag appears in
    # no RRSIG). Seed a keydir with only one of the fixture's two PEMs.
    import shutil
    src = os.path.join(ZONE_DIR, "signer-2key.test")
    all_pems = [f for f in os.listdir(src) if f.endswith(".pem")]
    assert len(all_pems) == 2
    keydir = tmp_path / "keys"
    keydir.mkdir()
    shutil.copy(os.path.join(src, all_pems[0]), str(keydir))  # only one active

    zone, keys = _sign_2key_one_pem(keydir)
    assert len(keys) == 2
    publish_only = [k for k in keys if k.private_key is None]
    active = [k for k in keys if k.private_key is not None]
    assert len(publish_only) == 1 and len(active) == 1
    pub_tag = publish_only[0].keytag

    # Both keys are still published in the apex DNSKEY RRset.
    dnskey_rds = zone.get_rdataset(zone.origin, dns.rdatatype.DNSKEY)
    published_tags = {dns.dnssec.key_id(r) for r in dnskey_rds}
    assert published_tags == {k.keytag for k in keys}
    assert pub_tag in published_tags

    # The publish-only key signs nothing, anywhere in the zone.
    for _name, node in zone.nodes.items():
        for rds in node.rdatasets:
            if rds.rdtype == dns.rdatatype.RRSIG:
                assert pub_tag not in {r.key_tag for r in rds}


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


import adns.keygen    # noqa: E402


def test_generate_key_alg8_default_bits():
    """generate_key(8) yields a 1280-bit RSA key whose DNSKEY has algorithm 8."""
    priv, pub = adns.keygen.generate_key(8)
    assert priv.key_size == 1280
    dnskey = dns.dnssec.make_dnskey(pub, 8, 257, 3)
    assert dnskey.algorithm == 8


def test_generate_key_alg8_custom_bits():
    priv, _pub = adns.keygen.generate_key(8, bits=1536)
    assert priv.key_size == 1536


def test_generate_key_alg8_below_floor_raises():
    with pytest.raises(ValueError):
        adns.keygen.generate_key(8, bits=1024)


def test_generate_key_bits_ignored_for_ec():
    """bits is irrelevant for 13/15; passing a sub-floor value still succeeds."""
    priv, _pub = adns.keygen.generate_key(13, bits=1024)
    assert priv is not None


MLDSA_SEED = bytes(range(32))
MLDSA_KEYTAG = 59829
MLDSA_DS = "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa"


def test_dnskey_rdata_for_mldsa_matches_section6():
    """
    draft-westerbaan-dnssec-mldsa-04 Section 6 conformance vector: a known
    seed's DNSKEY has the published keytag and DS, proving our DNSKEY-rdata
    construction (base64 raw public key) and dnspython's keytag/DS math on
    it match the spec byte-for-byte.
    """
    from cryptography.hazmat.primitives.asymmetric import mldsa

    priv = mldsa.MLDSA44PrivateKey.from_seed_bytes(MLDSA_SEED)
    rdata = adns.keygen.dnskey_rdata_for(priv.public_key(), 18, 257)
    assert rdata.algorithm == 18
    assert dns.dnssec.key_id(rdata) == MLDSA_KEYTAG
    ds = dns.dnssec.make_ds(dns.name.from_text("example.com."), rdata, algorithm=2)
    assert ds.to_text() == f"{MLDSA_KEYTAG} 18 2 {MLDSA_DS}"


def test_generate_key_mldsa():
    """generate_key(18) yields an ML-DSA-44 key whose DNSKEY builds and keytags."""
    from cryptography.hazmat.primitives.asymmetric import mldsa

    priv, pub = adns.keygen.generate_key(18)
    assert isinstance(priv, mldsa.MLDSA44PrivateKey)
    assert len(pub.public_bytes_raw()) == 1312
    rdata = adns.keygen.dnskey_rdata_for(pub, 18, 257)
    assert isinstance(dns.dnssec.key_id(rdata), int)


def test_adnskeygen_mldsa_writes_triple(tmp_path):
    """adnskeygen -a 18 writes a +018+ key triple whose PEM loads as ML-DSA-44."""
    keydir = tmp_path / "keys"
    result = subprocess.run(
        GENKEY + ["mldsa.test", "-a", "18", "-f", "257",
                  "--keydir", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    pems = list(keydir.glob("mldsa.test+018+*.pem"))
    assert len(pems) == 1, result.stdout
    base = pems[0].name[:-4]
    assert (keydir / (base + ".dnskey")).exists()
    ds_path = keydir / (base + ".ds")
    assert ds_path.exists()
    assert ds_path.read_text().startswith("mldsa.test. IN DS ")
    assert (pems[0].stat().st_mode & 0o777) == 0o600
    # The PKCS8-PEM ML-DSA private key loads via the unchanged crypto loader,
    # and its public key round-trips to the keytag encoded in the filename.
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    key = adns.crypto.load_private_key(str(pems[0]))
    assert isinstance(key, _mldsa.MLDSA44PrivateKey)
    tag_in_name = int(base.rsplit("+", 1)[1])
    rdata = adns.keygen.dnskey_rdata_for(key.public_key(), 18, 257)
    assert dns.dnssec.key_id(rdata) == tag_in_name


def test_generate_key_alg8_pem_roundtrips(tmp_path):
    """An alg-8 PEM written by keygen loads back through crypto.load_private_key."""
    priv, _pub = adns.keygen.generate_key(8)
    pem_path = tmp_path / "rsa.pem"
    pem_path.write_text(adns.keygen.pem_data_for_private_key(priv))
    loaded = adns.crypto.load_private_key(str(pem_path))
    assert loaded.key_size == 1280


def test_adnskeygen_cli_alg8_writes_triple(tmp_path):
    """adnskeygen -a 8 -b 1280 writes a +008+ key triple that loads."""
    keydir = tmp_path / "keys"
    result = subprocess.run(
        GENKEY + ["rsa.test", "-a", "8", "-b", "1280", "-f", "257",
                  "--keydir", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    pems = list(keydir.glob("rsa.test+008+*.pem"))
    assert len(pems) == 1, result.stdout
    key = adns.crypto.load_private_key(str(pems[0]))
    assert key.key_size == 1280


def test_adnskeygen_cli_rejects_alg_rsasha1():
    """argparse choices reject an algorithm outside {8,13,15} (e.g. 5)."""
    result = subprocess.run(
        GENKEY + ["x.test", "-a", "5"],
        capture_output=True, text=True, check=False, env=SUBPROCESS_ENV)
    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_adnskeygen_cli_below_floor_clean_error():
    """
    adnskeygen -a 8 -b <below-floor> gives a clean error, not a Python traceback.
    """
    result = subprocess.run(
        GENKEY + ["rsa.test", "-a", "8", "-b", "512"],
        capture_output=True, text=True, check=False, env=SUBPROCESS_ENV)
    assert result.returncode != 0
    assert "adnskeygen:" in result.stderr
    assert "Traceback" not in result.stderr


import adns.signer    # noqa: E402


def test_alg8_signatures_validate_offline_and_online():
    """
    An alg-8 key signs an RRset via both the offline (signer.rrsig_rdata) and
    online (crypto.sign_rrset) paths, and dns.dnssec.validate accepts both.
    Proves the unchanged signing/serving code already supports RSASHA256.
    """
    import time
    import dns.name
    import dns.rrset
    import dns.dnssec
    from adns.zone import HashableRRset

    priv, pub = adns.keygen.generate_key(8)
    origin = dns.name.from_text("rsa.test.")
    dnskey = dns.dnssec.make_dnskey(pub, 8, 257, 3)
    dnskey_rrset = dns.rrset.from_text_list(
        origin, 7200, "IN", "DNSKEY", [dnskey.to_text()])
    rrset = dns.rrset.from_text("www.rsa.test.", 3600, "IN", "A", "192.0.2.1")
    keyring = {origin: dnskey_rrset}

    # Offline path.
    now = int(time.time())
    off_sig = adns.signer.rrsig_rdata(rrset, priv, origin, dnskey,
                                      now - 3600, now + 172800)
    off_rrsig = dns.rrset.from_rdata(rrset.name, 3600, off_sig)
    dns.dnssec.validate(rrset, off_rrsig, keyring)

    # Online path via crypto.sign_rrset, using a minimal zone stand-in.
    class _Zone:
        pass
    z = _Zone()
    z.privatekey = priv
    z.origin = origin
    z.signing_dnskey = dnskey
    on_rrsig = adns.crypto.sign_rrset(z, HashableRRset(rrset))
    dns.dnssec.validate(rrset, on_rrsig, keyring)


def test_rrsig_rdata_mldsa_verifies():
    """rrsig_rdata() signs an RRset with an alg-18 key and the RRSIG verifies.

    The oracle rebuilds the RFC 4034 3.1.8.1 signing data itself and calls
    MLDSA44PublicKey.verify() -- an independent cross-check, not a call back
    into the production _rrsig_rdata_mldsa. dns.dnssec.validate() cannot be
    used here because it rejects algorithm 18.
    """
    import base64
    import dns.name
    import dns.rrset
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.dnssec
    import dns.rdtypes.ANY.RRSIG
    from cryptography.hazmat.primitives.asymmetric import mldsa

    sz = _signzone()
    priv = mldsa.MLDSA44PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode()
    dnskey = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                 f"257 3 18 {pub_b64}")
    signer = dns.name.from_text("mldsa.test.")
    rrset = dns.rrset.from_text("mldsa.test.", 3600, "IN", "MX",
                                "10 mail.mldsa.test.")
    inception, expiration = 1_700_000_000 - 3600, 1_700_000_000 + 2592000

    rrsig = sz.rrsig_rdata(rrset, priv, signer, dnskey, inception, expiration)

    assert rrsig.algorithm == 18
    assert rrsig.key_tag == dns.dnssec.key_id(dnskey)
    assert rrsig.type_covered == dns.rdatatype.MX
    assert len(rrsig.signature) == 2420

    # Independent oracle: rebuild the signing data from a fresh template whose
    # only difference from the produced RRSIG is the empty signature.
    template = dns.rdtypes.ANY.RRSIG.RRSIG(
        rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.RRSIG,
        type_covered=rrset.rdtype, algorithm=18,
        labels=len(rrset.name) - 1, original_ttl=rrset.ttl,
        expiration=expiration, inception=inception,
        key_tag=dns.dnssec.key_id(dnskey), signer=signer, signature=b"")
    data = dns.dnssec._make_rrsig_signature_data(rrset, template, None)
    pub.verify(rrsig.signature, data, context=None)   # raises on failure


def test_mldsa_offline_signing_end_to_end(tmp_path):
    """
    Generate an alg-18 CSK, sign the signer-mldsa.test fixture through the real
    discover_keys -> sign_zone path, and verify every RRSIG with an independent
    MLDSA44PublicKey.verify() of the reconstructed RFC 4034 3.1.8.1 data.
    """
    import base64
    import dns.name
    import dns.rrset
    import dns.rdataclass
    import dns.rdatatype
    import dns.dnssec
    import dns.rdtypes.ANY.RRSIG
    from cryptography.hazmat.primitives.asymmetric import mldsa

    sz = _signzone()
    zone_name = "signer-mldsa.test"

    # 1. Generate the alg-18 CSK triple into a tmp keydir via the keygen CLI.
    keydir = tmp_path / "keys"
    subprocess.run(
        GENKEY + [zone_name, "-a", "18", "-f", "257", "--keydir", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    dnskey_file = list(keydir.glob(f"{zone_name}+018+*.dnskey"))[0]

    # 2. Load the fixture and inject the generated apex DNSKEY (the fixture has
    #    no $INCLUDE because the key is random per run).
    cwd = os.getcwd()
    os.chdir(ZONE_DIR)
    try:
        zone = adns.zone.zone_from_file(
            dns.name.from_text(zone_name), f"{zone_name}/zonefile")
    finally:
        os.chdir(cwd)
    origin = zone.origin
    # The .dnskey file is "<owner> <ttl> IN DNSKEY <flags> 3 18 <b64>"; take the
    # rdata after the DNSKEY token.
    dnskey_line = dnskey_file.read_text().split("DNSKEY", 1)[1].strip()
    dnskey_rdata = dns.rdata.from_text(dns.rdataclass.IN,
                                       dns.rdatatype.DNSKEY, dnskey_line)
    zone.find_rdataset(origin, dns.rdatatype.DNSKEY, create=True).add(
        dnskey_rdata, 7200)

    # 3. Discover the key, strip, and sign (NSEC mode; no NSEC3PARAM in fixture).
    keys = sz.discover_keys(zone, str(keydir))
    sz.strip_dnssec(zone)
    now = 1_700_000_000
    inception, expiration = now - 3600, now + 2592000
    sz.sign_zone(zone, keys, inception, expiration, 0)

    # 4. Independent verify oracle over every RRSIG in the signed zone.
    # (dnskey_rdata.key holds the raw public-key bytes; going via str() and
    # splitting on whitespace would only grab the first base64 wrap-chunk.)
    pub = mldsa.MLDSA44PublicKey.from_public_bytes(dnskey_rdata.key)
    verified = 0
    for name, node in zone.nodes.items():
        for rrsig_ds in [r for r in node.rdatasets
                         if r.rdtype == dns.rdatatype.RRSIG]:
            covered = rrsig_ds.covers
            covered_ds = node.get_rdataset(dns.rdataclass.IN, covered)
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, covered)
            rrset.update(covered_ds)
            for rrsig in rrsig_ds:
                assert rrsig.algorithm == 18
                assert rrsig.key_tag == keys[0].keytag
                labels = len(name) - 1
                if name.is_wild():
                    labels -= 1
                template = dns.rdtypes.ANY.RRSIG.RRSIG(
                    rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.RRSIG,
                    type_covered=covered, algorithm=18, labels=labels,
                    original_ttl=rrset.ttl, expiration=rrsig.expiration,
                    inception=rrsig.inception, key_tag=rrsig.key_tag,
                    signer=rrsig.signer, signature=b"")
                data = dns.dnssec._make_rrsig_signature_data(
                    rrset, template, None)
                pub.verify(rrsig.signature, data, context=None)
                verified += 1
    # apex SOA + NS + DNSKEY + ns A + www A + www AAAA + NSEC chain (>= 4 NSECs)
    assert verified >= 9
