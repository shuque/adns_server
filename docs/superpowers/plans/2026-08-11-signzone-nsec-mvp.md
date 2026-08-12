# signzone.py — Stage 1: NSEC Single-CSK Signer MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MVP of the offline DNSSEC zone signer `signzone.py` — a single-CSK, NSEC-only signer that strips-and-re-signs a zone deterministically — plus the `genkey.py --keydir` companion and a minimal NSEC test fixture.

**Architecture:** `signzone.py` is a new repo-root script that imports the shared zone model and pure helpers from `dnssec_util.py` (extracted in Stage 0). It loads a zone with `zone_from_file()`, discovers per-DNSKEY private keys from a keydir by keytag-named filename, strips existing DNSSEC records, signs every authoritative RRset with an uncached explicit-time RRSIG helper (the offline analog of the server's cached `sign_rrset()`), builds an NSEC chain over authoritative owners (excluding ENTs and occluded glue), and writes `<zonefile>.signed` via temp-file + atomic rename. Multi-key/rollover, NSEC3, and DELEG cut handling are later stages; this stage implements the general key-classification invariant but only exercises the single-CSK path.

**Tech Stack:** Python 3.9 (shipped-code ceiling — see Global Constraints), dnspython 2.7.0 (`dns.dnssec.sign` with explicit `inception`/`expiration` and `deterministic=True` — both present in 2.7.0, not new in 2.8.0), `cryptography` (PEM PKCS8 keys), pytest, BIND 9.20.x (`dnssec-verify`, `dnssec-signzone`) as independent oracles. dnspython 2.8.0 may be used for local test/validation runs but MUST NOT be relied on by shipped code.

## Global Constraints

- **No commits or pushes by the executor** beyond what SDD's per-task commit cadence performs on the `signer` branch; never merge to `master` (signer work is incomplete). The branch already exists and is checked out.
- **Work stays on the `signer` branch.** Do not branch from or commit to `master`.
- Use `python3` (not `python`) — Darwin box.
- `rm` is aliased to `rm -i`; use `/bin/rm -f` for non-interactive deletes.
- The existing `tests/pytest/` suite must stay green (Stage 0 baseline: 139 passed). Signer changes are additive.
- `pylint` must stay clean per the repo `pylintrc` (Stage 0 baseline: `adns_server.py` 9.91/10 from pre-existing R0917; new files should score ≥9.5).
- **Keytag-named key filename format is a hard contract shared by `genkey.py` and `signzone.py`:** `<zonename>+<alg:03d>+<keytag:05d>.pem` where `<zonename>` is the origin text with the trailing dot stripped (e.g. `signer-nsec.test+013+34063.pem`). This is produced by a single shared helper `dnssec_util.key_basename()`; both programs MUST use it — never hand-format the filename.
- **Python 3.9 / dnspython 2.7.0 ceiling for shipped code.** `signzone.py`, `genkey.py`, and `dnssec_util.py` MUST run on Python 3.9 with dnspython 2.7.0 (the version on RHEL9 / Amazon Linux 2023 targets such as guvnor). No 3.10+ syntax (no `match`, no PEP 604 `X | Y` runtime annotations, no `datetime.UTC`). `pylintrc` already pins `py-version = 3.8.0`, which flags newer syntax. The signer's `dns.dnssec.sign` usage (explicit `inception`/`expiration`, default `deterministic=True`) is available identically in 2.7.0 — verified. dnspython 2.8.0 may be used only for local test/validation runs.
- **Verification interpreter:** run the test commands below with the 2.7.0 environment (`/Users/shuque/virt/adnstest/bin/python3` — Python 3.12 + dnspython 2.7.0) so behavior is validated against the shipped dnspython ceiling, not the base `python3` (which carries 2.8.0). The commands below write `python3`; substitute that interpreter. (A true 3.9 runtime check is deferred to deployment; the 2.7.0 API surface is the binding constraint here.)
- **Determinism:** signing with fixed absolute `-i`/`-e` and `-j 0` MUST produce byte-identical output across runs. Rely on dnspython's default `deterministic=True` (RFC 6979 ECDSA, present in 2.7.0) and Ed25519's inherent determinism — do not pass `deterministic=False`.
- **Strip-and-re-sign:** on load, discard all RRSIG, NSEC, NSEC3 records; **retain** DNSKEY and NSEC3PARAM.
- **Cut-authority rule (RFC 4035):** at a delegation cut (owner ≠ apex with NS and/or DELEG), only the `AUTH_IN_PARENT_RRTYPES` set (`[DS, DELEG]`) is authoritative-in-parent and signed; NS and glue A/AAAA are NOT signed. Owners strictly below a cut (occluded glue) are NOT signed and get NO NSEC. The cut owner itself gets an NSEC.
- **ENTs are EXCLUDED from the NSEC chain** (RFC 4035 §2.3): an empty non-terminal owns no RRset and gets no NSEC. `add_ent_nodes()` adds empty ENT nodes to the `SortedDict`; the NSEC pass must positively select only owners that owned an RRset in the unsigned zone.
- **No partial output on error:** temp file + atomic rename on success; any key/parse/semantic error → clear stderr message, nonzero exit, no `.signed` written.

---

## File Structure

- **Create `signzone.py`** (repo root, beside `adns_server.py` and `dnssec_util.py`) — the signer. Import-safe: all logic in module-level functions, guarded by `if __name__ == '__main__':`, so tests can import its helpers and its `sign_zone()` core without running the CLI.
- **Modify `dnssec_util.py`** — add the pure `key_basename()` helper (shared filename contract).
- **Modify `genkey.py`** — add `--keydir` option writing the keytag-named `.pem`/`.dnskey`/`.ds` triple (opt-in; absent, current stdout-only behavior unchanged). Defer `--prepublish` to Stage 3.
- **Create `tests/pytest/test_zones/signer-nsec.test/`** — new minimal NSEC fixture: `zonefile`, `dnskey.txt` ($INCLUDE'd), and the keytag-named `signer-nsec.test+013+<tag>.pem` private key (checked in, like the existing `deleg.test/privkey.pem`).
- **Modify `tests/pytest/test_dnssec_util_import.py`** — add `key_basename` to the guarded symbol list.
- **Create `tests/pytest/test_signzone.py`** — unit tests (time parsing, key discovery, strip) + round-trip cryptographic validation against the fixture.
- **Create `tests/pytest/test_signzone_oracle.py`** — BIND `dnssec-verify` / `dnssec-signzone` cross-checks + determinism (skipped gracefully if BIND tools absent).

Signer references: RFC 4035 §2 (NSEC), Signer.md §§2–3 (CLI/IO + engine).

---

### Task 1: `dnssec_util.key_basename()` + `genkey.py --keydir`

**Files:**
- Modify: `dnssec_util.py` (add `key_basename` after the `load_private_key` definition, ~line 45)
- Modify: `genkey.py` (add `--keydir`, refactor `__main__` body into functions)
- Modify: `tests/pytest/test_dnssec_util_import.py:15-22` (add `key_basename` to symbol list)
- Test: `tests/pytest/test_signzone.py` (new — `key_basename` + genkey-keydir tests)

**Interfaces:**
- Produces: `dnssec_util.key_basename(zonename, algorithm, keytag) -> str` where `zonename` is the origin text WITHOUT trailing dot; returns e.g. `"signer-nsec.test+013+34063"` (no extension). Consumed by `genkey.py` and `signzone.py` (Task 3).
- Produces: `genkey.py` with `--keydir DIR`; when given, writes `<basename>.pem` (PEM PKCS8 private), `<basename>.dnskey` (full DNSKEY RR text), `<basename>.ds` (DS RR text, alg 2 / SHA-256) into DIR, and still prints to stdout.

- [ ] **Step 1: Write the failing test for `key_basename`**

Append to a new `tests/pytest/test_signzone.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py::test_key_basename_format -v`
Expected: FAIL — `AttributeError: module 'dnssec_util' has no attribute 'key_basename'`

- [ ] **Step 3: Add `key_basename` to `dnssec_util.py`**

Insert after the `load_private_key` function (after line 44):

```python
def key_basename(zonename, algorithm, keytag):
    """Return the keytag-named base filename (no extension) shared by genkey
    and signzone: '<zonename>+<alg:03d>+<keytag:05d>'. zonename must be the
    origin text with any trailing dot stripped. Matches BIND's +%03d+%05d
    convention so the files are greppable and self-describing."""
    return f"{zonename}+{algorithm:03d}+{keytag:05d}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py::test_key_basename_format -v`
Expected: PASS

- [ ] **Step 5: Add `key_basename` to the extraction guard test**

In `tests/pytest/test_dnssec_util_import.py`, add `"key_basename"` to the tuple in `test_dnssec_util_exposes_moved_symbols` (line ~15-21):

```python
    for name in ("RRtype", "AUTH_IN_PARENT_RRTYPES", "hashalg", "nsec3hash",
                 "predecessor_label_good", "predecessor_label_ideal",
                 "predecessor_name", "successor_name", "rrset_from_rdataset",
                 "make_nsec_rrset", "make_nsec3_rrset", "load_private_key",
                 "Zone", "zone_from_file", "MAX_LABEL_OCTETS",
                 "PREDECESSOR_SENTINEL", "B32_TO_EXT_HEX",
                 "NSEC3HASH_SIZE_IN_OCTETS", "key_basename"):
```

- [ ] **Step 6: Refactor `genkey.py` `__main__` into functions and add `--keydir`**

Add `--keydir` to `process_arguments()`:

```python
    parser.add_argument("-K", "--keydir", metavar='DIR', default=None,
                        help="write keytag-named .pem/.dnskey/.ds triple here")
```

Add imports at the top of `genkey.py` (it currently references `dns.rrset`/`dns.rdataset`/`dns.rdataclass`/`dns.rdatatype` in `__main__` without importing them — add the missing ones and the shared helper):

```python
import os
import dns.rrset
import dns.rdataset
import dns.rdataclass
import dns.rdatatype

from dnssec_util import key_basename
```

Refactor the `__main__` block. Extract the RR construction into helpers so it is testable, and write the triple when `--keydir` is given:

```python
def build_dnskey_rrset(zone, dnskey_rdata):
    """Build the apex DNSKEY RRset (single key) for printing / .dnskey output."""
    rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                     ttl=TTL)
    rdataset.add(dnskey_rdata)
    rrset.update(rdataset)
    return rrset


def write_key_triple(keydir, zone, algorithm, keytag, private_key,
                     dnskey_rrset, ds_rr):
    """Write <basename>.pem/.dnskey/.ds into keydir. zone is a dns.name.Name."""
    os.makedirs(keydir, exist_ok=True)
    basename = key_basename(zone.to_text().rstrip('.'), algorithm, keytag)
    pem_path = os.path.join(keydir, basename + ".pem")
    with open(pem_path, "w", encoding="utf-8") as f:
        f.write(pem_data_for_private_key(private_key))
    with open(os.path.join(keydir, basename + ".dnskey"), "w",
              encoding="utf-8") as f:
        f.write(dnskey_rrset.to_text() + "\n")
    with open(os.path.join(keydir, basename + ".ds"), "w",
              encoding="utf-8") as f:
        f.write(ds_rr.to_text(zone) + "\n")
    return basename
```

Then update `if __name__ == '__main__':` to compute `keytag = dns.dnssec.key_id(dnskey_rdata)`, build `DNSKEY_RRSET = build_dnskey_rrset(ZONE, dnskey_rdata)`, keep all existing stdout prints, and — if `CONFIG.keydir` — call `write_key_triple(...)` and print `### Wrote key files: <basename>.{pem,dnskey,ds}`. The `ds` object from `dns.dnssec.make_ds(ZONE, dnskey_rdata, algorithm=2)` is bare rdata; render it with `ds.to_text(ZONE)` for the `.ds` file (owner-qualified). Preserve every existing stdout line.

- [ ] **Step 7: Write the failing test for genkey --keydir**

Add to `tests/pytest/test_signzone.py`:

```python
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
    assert (keydir / (base + ".ds")).exists()
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
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py tests/pytest/test_dnssec_util_import.py -v`
Expected: PASS (key_basename + genkey triple + guard test)

- [ ] **Step 9: Lint and commit**

```bash
cd /Users/shuque/git/adns_server
python3 -m pylint --rcfile=pylintrc dnssec_util.py genkey.py
git add dnssec_util.py genkey.py tests/pytest/test_signzone.py tests/pytest/test_dnssec_util_import.py
git commit -m "signzone Stage 1: key_basename helper + genkey --keydir triple"
```

---

### Task 2: Minimal NSEC test fixture

**Files:**
- Create: `tests/pytest/test_zones/signer-nsec.test/zonefile`
- Create: `tests/pytest/test_zones/signer-nsec.test/dnskey.txt`
- Create: `tests/pytest/test_zones/signer-nsec.test/signer-nsec.test+013+<tag>.pem` (generated via Task 1's genkey)
- Test: `tests/pytest/test_signzone.py` (add a fixture-shape smoke test)

**Interfaces:**
- Produces: an unsigned NSEC-mode zone `signer-nsec.test` and its checked-in CSK PEM, keytag-named per the contract, discoverable by `signzone.py`. Consumed by Tasks 4–5.

The zone exercises: apex SOA/NS/DNSKEY; ordinary A/AAAA; a wildcard (`*.wild`) with a parallel explicit name; an empty non-terminal (`host.deep.ent` → `ent` and `deep.ent` are ENTs); and one traditional secure delegation cut with **in-zone glue** (`sub` NS+DS, `ns1.sub` glue A below the cut). No DELEG (Stage 4). Single CSK (flags 257, SEP set).

- [ ] **Step 1: Generate the CSK into the fixture dir**

```bash
cd /Users/shuque/git/adns_server/tests/pytest/test_zones/signer-nsec.test
python3 /Users/shuque/git/adns_server/genkey.py signer-nsec.test -a 13 -f 257 \
    --keydir . > /tmp/signer-nsec-genkey.out
ls signer-nsec.test+013+*.pem     # note the keytag
```

Keep the `.pem`. Move the generated `.dnskey` content into `dnskey.txt` (next step). The `.ds` file is not needed by tests — `/bin/rm -f signer-nsec.test+013+*.ds`.

- [ ] **Step 2: Create `dnskey.txt` from the generated DNSKEY**

Write `tests/pytest/test_zones/signer-nsec.test/dnskey.txt` containing the DNSKEY RR from the genkey `.dnskey` output (owner `signer-nsec.test.`), mirroring the existing `deleg.test/dnskey.txt` layout:

```
; flags=257 keytag=<tag>
signer-nsec.test. IN DNSKEY 257 3 13 <base64 from genkey>
```

Then `/bin/rm -f signer-nsec.test+013+*.dnskey` (its content now lives in `dnskey.txt`).

- [ ] **Step 3: Create the zonefile**

Write `tests/pytest/test_zones/signer-nsec.test/zonefile`:

```
$TTL 86400
$ORIGIN signer-nsec.test.
@		IN	SOA	ns.signer-nsec.test. hostmaster.signer-nsec.test. (
				1          ; Serial
				43200      ; Refresh
				3600       ; Retry
				3628800    ; Expire
				3600 )     ; Minimum
		IN	NS	ns.signer-nsec.test.
$INCLUDE signer-nsec.test/dnskey.txt
;;
;; Apex nameserver and a couple of ordinary names.
;;
ns		IN	A	192.0.2.1
www		IN	A	192.0.2.10
www		IN	AAAA	2001:db8::10
;;
;; Wildcard and a parallel explicit name.
;;
*.wild		IN	A	192.0.2.20
exact.wild	IN	A	192.0.2.21
;;
;; Empty non-terminal: 'ent' and 'deep.ent' own no RRset; host.deep.ent does.
;;
host.deep.ent	IN	A	192.0.2.30
;;
;; Traditional secure delegation with IN-ZONE glue below the cut.
;; 'sub' is a cut (NS+DS); ns1.sub is occluded glue: not signed, no NSEC.
;;
sub		IN	NS	ns1.sub.signer-nsec.test.
sub		IN	DS	40524 13 2 0000000000000000000000000000000000000000000000000000000000000001
ns1.sub		IN	A	192.0.2.2
```

Note: the `$INCLUDE` path is relative to the server/test working directory (`test_zones/`), matching how `deleg.test/zonefile` includes `deleg.test/dnskey.txt`.

- [ ] **Step 4: Write the fixture-shape smoke test**

Add to `tests/pytest/test_signzone.py`:

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py::test_fixture_shape -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/shuque/git/adns_server
git add tests/pytest/test_zones/signer-nsec.test tests/pytest/test_signzone.py
git commit -m "signzone Stage 1: minimal NSEC test fixture (apex/ENT/wildcard/cut+glue)"
```

---

### Task 3: `signzone.py` — CLI, time parsing, key discovery, strip, atomic output

**Files:**
- Create: `signzone.py`
- Test: `tests/pytest/test_signzone.py` (add time-parse, discovery, strip, output tests)

**Interfaces:**
- Consumes: `dnssec_util.zone_from_file`, `load_private_key`, `key_basename`, `AUTH_IN_PARENT_RRTYPES`, `RRtype`, `make_nsec_rrset`, `Zone`.
- Produces (all importable, module-level; the CLI is a thin `main()` under `if __name__ == '__main__'`):
  - `parse_duration(spec) -> int` — seconds; bare int or `s/m/h/d/w/y` suffix.
  - `parse_time(spec, now) -> int` — absolute epoch; unsigned/`+`-prefixed duration → `now + secs`, `-`-prefixed → `now - secs`, 14-digit `YYYYMMDDHHMMSS` → absolute UTC epoch.
  - `KeyInfo` namedtuple `(dnskey_rdata, keytag, algorithm, is_sep, private_key)`.
  - `discover_keys(zone, keydir) -> list[KeyInfo]` — one per apex DNSKEY; `private_key=None` = publish-only. Raises `SignerError` if the zone has no DNSKEY, or if NO DNSKEY has a matching PEM.
  - `strip_dnssec(zone) -> None` — mutates: removes RRSIG/NSEC/NSEC3 rdatasets from every node; retains DNSKEY/NSEC3PARAM.
  - `write_zone(zone, output_path) -> None` — temp file in the same directory + atomic `os.replace`; `output_path == '-'` writes to stdout.
  - `SignerError(Exception)`.
- Produces for Task 4: `sign_zone(zone, keys, inception, base_expiration, jitter) -> None` is declared here as a stub raising `NotImplementedError` and filled in Task 4; `main()` wires argparse → load → discover → strip → `sign_zone` → write.

- [ ] **Step 1: Write failing tests for time parsing**

Add to `tests/pytest/test_signzone.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py -k "parse_" -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'signzone'`

- [ ] **Step 3: Create `signzone.py` scaffold — imports, errors, time parsing**

```python
#!/usr/bin/env python3

"""
Offline DELEG-aware DNSSEC zone signer for adns_server.

Stage 1 (this file): NSEC chain, single CSK. Strips any existing DNSSEC
records and re-signs from scratch with explicit absolute RRSIG times, writing
<zonefile>.signed atomically. NSEC3, multi-key rollover, and DELEG cut handling
are later stages. See Signer.md.
"""

import argparse
import calendar
import collections
import os
import random
import sys
import time

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.dnssec

from dnssec_util import (zone_from_file, load_private_key, key_basename,
                         make_nsec_rrset, AUTH_IN_PARENT_RRTYPES)


class SignerError(Exception):
    """Fatal signer error: reported to stderr, nonzero exit, no output."""


_UNIT_SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400,
                 'w': 604800, 'y': 31536000}


def parse_duration(spec):
    """Parse a duration into seconds. Bare integer = seconds; a trailing
    s/m/h/d/w/y unit multiplies accordingly. Used directly for -j (jitter)."""
    spec = spec.strip()
    if not spec:
        raise SignerError("empty duration")
    unit = spec[-1]
    if unit in _UNIT_SECONDS:
        value = spec[:-1]
        mult = _UNIT_SECONDS[unit]
    else:
        value = spec
        mult = 1
    try:
        return int(value) * mult
    except ValueError as exc:
        raise SignerError(f"bad duration {spec!r}") from exc


def parse_time(spec, now):
    """Resolve an -e/-i time spec to an absolute epoch (int seconds, UTC).

    - 14-digit YYYYMMDDHHMMSS  -> that absolute UTC instant.
    - leading '+' or unsigned  -> now + parse_duration(rest).
    - leading '-'              -> now - parse_duration(rest).
    """
    spec = spec.strip()
    if len(spec) == 14 and spec.isdigit():
        struct = time.strptime(spec, "%Y%m%d%H%M%S")
        return calendar.timegm(struct)
    if spec.startswith('-'):
        return now - parse_duration(spec[1:])
    if spec.startswith('+'):
        return now + parse_duration(spec[1:])
    return now + parse_duration(spec)
```

- [ ] **Step 4: Run time tests to verify pass**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py -k "parse_" -v`
Expected: PASS

- [ ] **Step 5: Write failing tests for key discovery + strip**

Add to `tests/pytest/test_signzone.py`:

```python
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
```

- [ ] **Step 6: Implement discovery, strip, output, and the sign_zone stub**

Append to `signzone.py`:

```python
KeyInfo = collections.namedtuple(
    "KeyInfo", ["dnskey_rdata", "keytag", "algorithm", "is_sep", "private_key"])

SEP_BIT = 0x0001


def discover_keys(zone, keydir):
    """Return a KeyInfo per apex DNSKEY. For each, compute the keytag and look
    for <keydir>/<zone>+<alg>+<keytag>.pem; load it if present (active), else
    the key is publish-only (private_key=None). Errors if the zone has no
    DNSKEY, or if no DNSKEY has a matching PEM (nothing to sign with)."""
    dnskey_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.DNSKEY)
    if not dnskey_rdataset:
        raise SignerError("zone has no apex DNSKEY RRset")
    zonename = zone.origin.to_text().rstrip('.')
    keys = []
    for rdata in dnskey_rdataset:
        keytag = dns.dnssec.key_id(rdata)
        pem = os.path.join(keydir,
                           key_basename(zonename, rdata.algorithm, keytag)
                           + ".pem")
        private_key = load_private_key(pem) if os.path.exists(pem) else None
        keys.append(KeyInfo(rdata, keytag, rdata.algorithm,
                            bool(rdata.flags & SEP_BIT), private_key))
    if not any(k.private_key is not None for k in keys):
        raise SignerError(
            f"no private key found in {keydir!r} for any DNSKEY of "
            f"{zonename} (looked for {zonename}+<alg>+<keytag>.pem)")
    return keys


def strip_dnssec(zone):
    """Remove all RRSIG/NSEC/NSEC3 rdatasets in place; keep DNSKEY/NSEC3PARAM."""
    doomed = (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
    for _name, node in zone.nodes.items():
        for rdtype in doomed:
            existing = node.get_rdataset(dns.rdataclass.IN, rdtype)
            if existing is not None:
                node.rdatasets.remove(existing)
            # RRSIG rdatasets are keyed by covered type; remove all of them.
        node.rdatasets = [rds for rds in node.rdatasets
                          if rds.rdtype not in doomed]


def write_zone(zone, output_path):
    """Serialize the (signed) zone. Absolute names (relativize=False). Writes
    to a temp file in the destination dir then atomically renames, so a failure
    leaves no partial .signed. output_path '-' writes to stdout."""
    text = zone.to_text(relativize=False)
    if output_path == '-':
        sys.stdout.write(text)
        return
    directory = os.path.dirname(os.path.abspath(output_path))
    tmp = os.path.join(directory, f".{os.path.basename(output_path)}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, output_path)


def sign_zone(zone, keys, inception, base_expiration, jitter):
    """Add RRSIGs and an NSEC chain to the stripped zone. Implemented in the
    next task."""
    raise NotImplementedError
```

Note on `strip_dnssec`: `dns.node.Node.get_rdataset` for RRSIG needs a `covers`; the reliable removal is the final list-comprehension filter (RRSIG/NSEC/NSEC3 rdatasets by `rdtype`). Keep only that filter — drop the earlier per-type `get_rdataset`/`remove` lines if they prove redundant during implementation; the reviewer will confirm no DNSSEC rdataset survives.

- [ ] **Step 7: Run discovery/strip tests**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py -k "discover or strip" -v`
Expected: PASS

- [ ] **Step 8: Add `main()` (argparse per Signer.md §2) and the `__main__` guard**

Append to `signzone.py`:

```python
def make_arg_parser():
    """Build the signzone.py argument parser (Signer.md §2)."""
    parser = argparse.ArgumentParser(
        description="Offline DNSSEC zone signer (NSEC, single CSK).")
    parser.add_argument("zonename", help="zone origin (e.g. example.com)")
    parser.add_argument("zonefile", help="unsigned zone file")
    parser.add_argument("-K", "--keydir", default=".",
                        help="directory of keytag-named PEM keys (default: .)")
    parser.add_argument("-o", "--output", default=None,
                        help="output file ('-' = stdout); "
                             "default <zonefile>.signed")
    parser.add_argument("-e", "--expiration", default="+30d",
                        help="RRSIG expiration (default: +30d)")
    parser.add_argument("-i", "--inception", default="-1h",
                        help="RRSIG inception (default: -1h)")
    parser.add_argument("-j", "--jitter", default="6h",
                        help="+/- jitter applied per-RRSIG (default: 6h)")
    parser.add_argument("--bump", action="store_true",
                        help="increment the SOA serial")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="per-RRset signing trace to stderr")
    return parser


def bump_serial(zone):
    """Increment the apex SOA serial (RFC 1982 wrap not handled; +1)."""
    soa_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    soa_rdataset[0].serial = (soa_rdataset[0].serial + 1) & 0xFFFFFFFF


def main(argv=None):
    """CLI entry point. Returns an exit code."""
    args = make_arg_parser().parse_args(argv)
    now = int(time.time())
    try:
        inception = parse_time(args.inception, now)
        expiration = parse_time(args.expiration, now)
        jitter = parse_duration(args.jitter)
        zone = zone_from_file(dns.name.from_text(args.zonename), args.zonefile)
        keys = discover_keys(zone, args.keydir)
        strip_dnssec(zone)
        if args.bump:
            bump_serial(zone)
        sign_zone(zone, keys, inception, expiration, jitter)
        output = args.output or (args.zonefile + ".signed")
        write_zone(zone, output)
    except SignerError as exc:
        print(f"signzone: {exc}", file=sys.stderr)
        return 1
    except dns.exception.DNSException as exc:
        print(f"signzone: zone load/parse error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
```

Add `import dns.exception` to the import block.

- [ ] **Step 9: Lint and commit**

```bash
cd /Users/shuque/git/adns_server
python3 -m pylint --rcfile=pylintrc signzone.py
python3 -m pytest tests/pytest/test_signzone.py -v
git add signzone.py tests/pytest/test_signzone.py
git commit -m "signzone Stage 1: CLI, time parsing, key discovery, strip, atomic output"
```

---

### Task 4: `signzone.py` — NSEC signing engine

**Files:**
- Modify: `signzone.py` (implement `sign_zone` + helpers)
- Test: `tests/pytest/test_signzone.py` (round-trip cryptographic validation)

**Interfaces:**
- Consumes: `KeyInfo`, `strip_dnssec`, `AUTH_IN_PARENT_RRTYPES`, `make_nsec_rrset`, `dns.dnssec.sign`.
- Produces: a fully populated `sign_zone(zone, keys, inception, base_expiration, jitter)` that mutates the stripped zone in place — appends RRSIG rdatasets to every authoritative RRset (respecting the cut rule) and builds a closed NSEC chain over authoritative owners (excluding ENTs and occluded glue).
- Produces helpers used by tests: `rrsig_rdata(rrset, private_key, signer, dnskey, inception, expiration)`, `classify_signers(keys) -> (dnskey_signers, rest_signers)`, `authoritative_owners(zone) -> list[dns.name.Name]` (sorted, chain owners), `is_occluded(name, cut_names) -> bool`.

- [ ] **Step 1: Write the failing round-trip test**

Add to `tests/pytest/test_signzone.py`:

```python
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
            dns.dnssec.validate(rrset, rrsig, {origin: dnskey_rrset})
            checked += 1
    assert checked >= 6      # apex SOA/NS/DNSKEY + A's + DS + NSECs


def test_cut_authority_rule():
    zone, _keys = _sign_fixture()
    sub = dns.name.from_text("sub." + NSEC_ZONE_NAME + ".")
    node = zone.get_node(sub)
    covers = {r.covers for r in node.rdatasets
              if r.rdtype == dns.rdatatype.RRSIG}
    # DS and NSEC signed at the cut; NS is NOT.
    assert dns.rdatatype.DS in covers
    assert dns.rdatatype.NSEC in covers
    assert dns.rdatatype.NS not in covers
    # Occluded glue below the cut is neither signed nor NSEC'd.
    glue = dns.name.from_text("ns1.sub." + NSEC_ZONE_NAME + ".")
    gnode = zone.get_node(glue)
    gcovers = {r.rdtype for r in gnode.rdatasets}
    assert dns.rdatatype.RRSIG not in gcovers
    assert dns.rdatatype.NSEC not in gcovers


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
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py -k "signed_rrsets or cut_authority or nsec_chain or nsec_bitmap" -v`
Expected: FAIL — `NotImplementedError` in `sign_zone`.

- [ ] **Step 3: Implement the RRSIG helper and key classification**

Replace the `sign_zone` stub in `signzone.py`; first add the helpers above it:

```python
def rrsig_rdata(rrset, private_key, signer, dnskey, inception, expiration):
    """Uncached RRSIG generation with explicit absolute times -- the offline
    analog of the server's cached sign_rrset(). Returns RRSIG rdata."""
    return dns.dnssec.sign(rrset, private_key, signer, dnskey,
                           inception=inception, expiration=expiration)


def classify_signers(keys):
    """Return (dnskey_signers, rest_signers) from the active (PEM-bearing)
    keys. Invariant (Signer.md §§3-4): the DNSKEY RRset is signed by every SEP
    key that has a PEM; everything else by every non-SEP key that has a PEM. A
    single SEP key with no separate ZSK is a CSK and signs both."""
    active = [k for k in keys if k.private_key is not None]
    sep = [k for k in active if k.is_sep]
    zsk = [k for k in active if not k.is_sep]
    dnskey_signers = sep or zsk            # SEP signs DNSKEY; fall back to ZSK
    rest_signers = zsk or sep              # ZSK signs the rest; CSK fallback
    return dnskey_signers, rest_signers


def _jittered_expiration(base_expiration, jitter):
    """base_expiration +/- a uniform random offset in [-jitter, +jitter]."""
    if jitter <= 0:
        return base_expiration
    return base_expiration + random.randint(-jitter, jitter)
```

- [ ] **Step 4: Implement owner selection (authoritative vs ENT vs occluded)**

Add to `signzone.py`:

```python
def _cut_names(zone):
    """Owners (other than the apex) that are delegation cuts: they have NS
    and/or a Delegation Type (DELEG). Returned as a set of dns.name.Name."""
    cuts = set()
    for name, node in zone.nodes.items():
        if name == zone.origin:
            continue
        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS):
            cuts.add(name)
            continue
        for rdtype in AUTH_IN_PARENT_RRTYPES:
            if rdtype == dns.rdatatype.DS:
                continue
            if node.get_rdataset(dns.rdataclass.IN, rdtype):
                cuts.add(name)
                break
    return cuts


def is_occluded(name, cut_names):
    """True if name is strictly below some delegation cut (glue / occluded)."""
    for cut in cut_names:
        if name != cut and name.is_subdomain(cut):
            return True
    return False


def authoritative_owners(zone, cut_names):
    """Owners that get an NSEC, in canonical sorted order: every non-ENT,
    non-occluded owner that owned an RRset in the unsigned zone. ENT nodes are
    empty (no rdatasets) and excluded; occluded glue below a cut is excluded."""
    owners = []
    for name, node in zone.nodes.items():
        if not node.rdatasets:                 # ENT
            continue
        if is_occluded(name, cut_names):        # glue below a cut
            continue
        owners.append(name)
    return sorted(owners)
```

- [ ] **Step 5: Implement `sign_zone` (signing walk + NSEC chain)**

Add to `signzone.py`, replacing the stub:

```python
def _rrsets_to_sign(name, node, is_cut):
    """Yield the authoritative RRsets at a node. At a cut only the
    authoritative-in-parent types (DS/DELEG) are signed; NS and glue are not.
    Elsewhere every non-DNSSEC RRset is authoritative."""
    for rdataset in list(node.rdatasets):
        rdtype = rdataset.rdtype
        if rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                      dns.rdatatype.NSEC3):
            continue
        if is_cut and rdtype not in AUTH_IN_PARENT_RRTYPES:
            continue
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        rrset.update(rdataset)
        yield rrset


def _add_rrsig(node, rrset, rrsig):
    """Attach an RRSIG rdata (covering rrset.rdtype) to node."""
    rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                  covers=rrset.rdtype, create=True)
    rdataset.add(rrsig, ttl=rrset.ttl)


def sign_zone(zone, keys, inception, base_expiration, jitter):
    """Sign every authoritative RRset and build the NSEC chain in place."""
    dnskey_signers, rest_signers = classify_signers(keys)
    cut_names = _cut_names(zone)

    # 1. Sign authoritative RRsets (skip occluded glue entirely).
    for name, node in zone.nodes.items():
        if is_occluded(name, cut_names):
            continue
        is_cut = name in cut_names
        for rrset in _rrsets_to_sign(name, node, is_cut):
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                signers = dnskey_signers
            else:
                signers = rest_signers
            for key in signers:
                rrsig = rrsig_rdata(rrset, key.private_key, zone.origin,
                                    key.dnskey_rdata, inception,
                                    _jittered_expiration(base_expiration,
                                                         jitter))
                _add_rrsig(node, rrset, rrsig)

    # 2. Build the NSEC chain over authoritative owners (ENTs/glue excluded).
    owners = authoritative_owners(zone, cut_names)
    for i, owner in enumerate(owners):
        node = zone.get_node(owner)
        nextname = owners[(i + 1) % len(owners)]
        present = {rds.rdtype for rds in node.rdatasets
                   if rds.rdtype != dns.rdatatype.NSEC}
        present.add(dns.rdatatype.NSEC)
        present.add(dns.rdatatype.RRSIG)
        ttl = zone.soa_min_ttl
        nsec_rrset = make_nsec_rrset(owner, nextname, sorted(present), ttl)
        nsec_rdataset = nsec_rrset.to_rdataset()
        node.rdatasets.append(nsec_rdataset)
        # Sign the NSEC with the same keys as ordinary data.
        for key in rest_signers:
            rrsig = rrsig_rdata(nsec_rrset, key.private_key, zone.origin,
                                key.dnskey_rdata, inception,
                                _jittered_expiration(base_expiration, jitter))
            _add_rrsig(node, nsec_rrset, rrsig)
```

Notes for the implementer:
- `dns.rrset.RRset.to_rdataset()` returns the rdataset to append to the node; if unavailable in dnspython 2.7.0 (the shipped ceiling), build the rdataset directly as `make_nsec_rrset` does internally and append it. Verify against 2.7.0 and use whichever is correct.
- The NSEC TTL uses `zone.soa_min_ttl` (set by `zone_from_file`), matching the server's authenticated-denial TTL policy.
- `present` is computed AFTER step 1, so RRSIG is already on the node for signed types; the explicit `add(RRSIG)`/`add(NSEC)` guarantees both bits regardless (e.g. an insecure NS-only cut whose only signature is its own NSEC's RRSIG).

- [ ] **Step 6: Run the round-trip tests**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone.py -k "signed_rrsets or cut_authority or nsec_chain or nsec_bitmap" -v`
Expected: PASS

- [ ] **Step 7: Full signer test run + lint**

Run:
```bash
cd /Users/shuque/git/adns_server
python3 -m pytest tests/pytest/test_signzone.py -v
python3 -m pylint --rcfile=pylintrc signzone.py
```
Expected: all pass; pylint ≥9.5.

- [ ] **Step 8: Commit**

```bash
git add signzone.py tests/pytest/test_signzone.py
git commit -m "signzone Stage 1: NSEC signing engine (cut rule, glue occlusion, NSEC chain)"
```

---

### Task 5: BIND oracle cross-check + determinism

**Files:**
- Create: `tests/pytest/test_signzone_oracle.py`

**Interfaces:**
- Consumes: `signzone.main()` via subprocess (produces a real `.signed` file), BIND `dnssec-verify` / `dnssec-signzone`.
- Produces: independent-oracle validation and a determinism guarantee. Tests `skip` (not fail) if the BIND tools are absent, so the suite still runs on machines without BIND.

- [ ] **Step 1: Write the oracle + determinism tests**

Create `tests/pytest/test_signzone_oracle.py`:

```python
"""Independent-oracle checks for signzone.py: BIND dnssec-verify and byte-for-
byte determinism. Skipped gracefully where BIND is unavailable."""
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SIGNZONE = os.path.join(REPO_ROOT, "signzone.py")
ZONE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_zones")
FIXTURE_DIR = os.path.join(ZONE_DIR, "signer-nsec.test")
ZONE_NAME = "signer-nsec.test"

DNSSEC_VERIFY = shutil.which("dnssec-verify") or "/opt/homebrew/bin/dnssec-verify"


def _run_signzone(tmp_path, extra=()):
    """Copy the fixture into tmp_path, sign it there, return the .signed path."""
    work = tmp_path / "signer-nsec.test"
    shutil.copytree(FIXTURE_DIR, work)
    # $INCLUDE in the zonefile is 'signer-nsec.test/dnskey.txt' relative to cwd,
    # so run from tmp_path with the same layout.
    out = str(work / "zonefile.signed")
    cmd = [sys.executable, SIGNZONE, ZONE_NAME, "signer-nsec.test/zonefile",
           "-K", "signer-nsec.test", "-o", out, *extra]
    res = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True,
                         text=True, check=False)
    assert res.returncode == 0, res.stderr
    return out


@pytest.mark.skipif(not os.path.exists(DNSSEC_VERIFY),
                    reason="BIND dnssec-verify not installed")
def test_dnssec_verify_accepts_signed_zone(tmp_path):
    signed = _run_signzone(tmp_path)
    res = subprocess.run([DNSSEC_VERIFY, "-o", ZONE_NAME, signed],
                         capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr


def test_determinism_byte_identical(tmp_path):
    # Fixed absolute inception/expiration + -j 0 => byte-identical output.
    a = _run_signzone(tmp_path / "a",
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    b = _run_signzone(tmp_path / "b",
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    with open(a, "rb") as fa, open(b, "rb") as fb:
        assert fa.read() == fb.read()
```

Note: `tmp_path / "a"` and `tmp_path / "b"` must exist before `copytree`; have `_run_signzone` create the parent (`os.makedirs(tmp_path, exist_ok=True)` before `copytree`, or `copytree` the parent). Adjust `_run_signzone` to `os.makedirs(str(tmp_path), exist_ok=True)` at entry so nested `a`/`b` roots work.

- [ ] **Step 2: Run the oracle tests**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_signzone_oracle.py -v`
Expected: `test_dnssec_verify_accepts_signed_zone` PASS (BIND 9.20.26 present); `test_determinism_byte_identical` PASS.

- [ ] **Step 3: Full regression + lint**

Run:
```bash
cd /Users/shuque/git/adns_server
python3 -m pytest tests/pytest/ -q
python3 -m pylint --rcfile=pylintrc signzone.py dnssec_util.py genkey.py
```
Expected: full suite green (Stage 0's 139 + new signer tests); pylint clean.

- [ ] **Step 4: Commit**

```bash
git add tests/pytest/test_signzone_oracle.py
git commit -m "signzone Stage 1: BIND dnssec-verify oracle + determinism tests"
```

---

## Self-Review

**1. Spec coverage (Signer.md §2–3, §6 Stage 1):**
- CLI/flags (§2 table): Task 3 `make_arg_parser` — `-K/-o/-e/-i/-j/--bump/-v` ✓
- Time syntax (§2): Task 3 `parse_duration`/`parse_time` (units, signed relative, 14-digit absolute) ✓
- Output `<zonefile>.signed`, `-o -`=stdout, temp+atomic rename (§2): Task 3 `write_zone`, `main` ✓
- Key discovery exact `<zone>+<alg>+<keytag>.pem`, publish-only, no-PEM error (§2): Task 3 `discover_keys` ✓
- `genkey.py --keydir` triple (§2): Task 1 ✓ (`--prepublish` explicitly deferred to Stage 3)
- Strip-and-re-sign (§2): Task 3 `strip_dnssec` ✓
- Key classification / CSK (§3.1): Task 4 `classify_signers` ✓
- Absolute time window + per-RRSIG jitter (§3.2): Task 4 `_jittered_expiration` ✓
- Signing walk + cut rule (§3.3): Task 4 `_rrsets_to_sign`, `_cut_names`, `is_occluded` ✓
- NSEC chain closed loop + bitmap, ENTs excluded (§3.4): Task 4 `authoritative_owners`, `sign_zone` step 2 ✓
- Uncached RRSIG helper (§3): Task 4 `rrsig_rdata` ✓
- Testing: round-trip validate (§7), dnssec-verify oracle (§7), determinism (§7): Tasks 4–5 ✓

Out of Stage 1 scope by design (deferred, not gaps): NSEC3 (Stage 2), multi-key/rollover + `--prepublish` (Stage 3), DELEG cuts (Stage 4), `dnssec-signzone` structural compare (folded into the later DELEG serve-through acceptance test), `pyproject.toml` `script-files += signzone.py` (packaging change deferred until the signer is feature-complete). The `classify_signers` invariant is implemented in full now so Stage 3 is mostly test-only.

**2. Placeholder scan:** No TBD/TODO; every code step carries actual code. Two implementer notes flag dnspython-API points to verify at implementation (`to_rdataset()` availability; redundant strip lines) — these are verification directives, not placeholders.

**3. Type consistency:** `KeyInfo` fields `(dnskey_rdata, keytag, algorithm, is_sep, private_key)` used consistently in `discover_keys`, `classify_signers`, `sign_zone`. `key_basename(zonename, algorithm, keytag)` signature identical in Task 1 definition and Task 3 `discover_keys` call. `sign_zone(zone, keys, inception, base_expiration, jitter)` signature matches its stub (Task 3), `main` call (Task 3), and implementation (Task 4). `parse_time(spec, now)` / `parse_duration(spec)` consistent across Task 3 tests and impl.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-11-signzone-nsec-mvp.md`.

Recommended execution: **Subagent-Driven** (superpowers:subagent-driven-development) — fresh implementer per task, diff + tests reviewed between tasks, per-task commit — matching the Stage 0 cadence.
