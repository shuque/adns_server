# dnssec_util.py Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the zone model and pure DNSSEC helper functions from `adns_server.py` into a new importable module `dnssec_util.py`, with zero behavior change, so a future offline signer (`signzone.py`) can share them.

**Architecture:** Move a clean, self-contained cluster of symbols (the `Zone` class, NSEC/NSEC3 name+hash helpers, the `RRtype` enum, a few small utilities) into `dnssec_util.py`. `adns_server.py` then imports those symbols back and **re-exports** them (`from dnssec_util import Zone, successor_name, ...`) so every existing internal reference and every direct-import test continues to resolve `adns_server.<symbol>` unchanged. The 135-test pytest suite is the regression oracle — it must pass identically before and after.

**Tech Stack:** Python 3.9+ (guvnor floor), dnspython ≥2.5, sortedcontainers, cryptography; pytest for tests; setuptools/`pyproject.toml` for packaging.

## Global Constraints

- Python floor is **3.9** (guvnor runs 3.9); do not use 3.10+ syntax (no `match`, no `X | Y` type unions in annotations that execute).
- **Zero behavior change.** This is a pure move + re-export. No logic edits, no renames of public symbols, no signature changes.
- Use `python3` (not `python`) on this macOS box.
- Work on a dedicated feature branch `signer` (branched from `master`); do **not** push — the user drives commits/pushes. Local commits per task are expected.
- The full 135-test suite (`python3 -m pytest tests/pytest/`) must pass after every task that changes importable code.
- pylint must stay clean (`pylintrc` present at repo root).
- New module name is exactly `dnssec_util.py`, at the repo root (sibling of `adns_server.py`).
- Do not modify `zones/`, `fly.yaml`, or any zonefile.

---

## File Structure

- **Create `dnssec_util.py`** (repo root) — the shared module. Responsibilities: the `RRtype` enum + `AUTH_IN_PARENT_RRTYPES`; NSEC3 hashing (`hashalg`, `nsec3hash`, `B32_TO_EXT_HEX`, `NSEC3HASH_SIZE_IN_OCTETS`); RFC 4470 name arithmetic (`predecessor_label_good/ideal`, `predecessor_name`, `successor_name`, and their constants `MAX_LABEL_OCTETS`, `PREDECESSOR_SENTINEL`); NSEC/NSEC3 rrset builders (`make_nsec_rrset`, `make_nsec3_rrset`); small utilities (`rrset_from_rdataset`, `load_private_key`); the `Zone` class and `zone_from_file`.
- **Modify `adns_server.py`** — delete the moved definitions; add `from dnssec_util import (...)` near the top (after the `dns.*` imports); keep everything else byte-for-byte. The imported names remain module attributes of `adns_server`, preserving `adns_server.Zone` etc. for tests and internal use.
- **Modify `pyproject.toml`** — add `py-modules = ["dnssec_util"]` so it installs to site-packages.
- **Test `tests/pytest/`** — unchanged; it is the regression net. One new tiny test file `tests/pytest/test_dnssec_util_import.py` asserts the module imports standalone and that `adns_server` re-exports the moved names (guards the re-export contract).

**What stays in `adns_server.py`** (server/online-only; do NOT move): `HashableRRset`, `sign_rrset` (online, `TTLCache`-wrapped), `make_nsec3_rrset_minimal`, `ZoneDict`, `Preferences`, `DNSquery`/`DNSresponse`, all config/socket/wire code.

**Move `Zone` intact** — verified it references only symbols that move with it (`nsec3hash`, `rrset_from_rdataset`, `successor_name`, `predecessor_name`, `RRtype`) plus dnspython; it touches no server globals, `sign_rrset`, or `DNSresponse`. Do not attempt to split online-serving methods (`nsec_covering`, `nsec3_covering`, `online_signing`) out of it in this plan — that is a later refactor.

---

## Task 1: Create the feature branch

**Files:** none (git only)

**Interfaces:**
- Consumes: nothing
- Produces: a `signer` branch checked out from `master`

- [ ] **Step 1: Confirm clean starting point on master**

Run: `git -C /Users/shuque/git/adns_server status --short && git -C /Users/shuque/git/adns_server branch --show-current`
Expected: current branch `master`. (Untracked scratch files like `Review.md`, `Signer.md` may be listed — that is fine; they carry over.)

- [ ] **Step 2: Create and switch to the feature branch**

```bash
cd /Users/shuque/git/adns_server
git checkout -b signer
```

- [ ] **Step 3: Verify**

Run: `git branch --show-current`
Expected: `signer`

(No commit — branch creation is the deliverable. Subsequent tasks commit onto it.)

---

## Task 2: Baseline the regression oracle

**Files:** none (verification only)

**Interfaces:**
- Consumes: `signer` branch
- Produces: a recorded green baseline (135 passing tests) to compare against after the move

- [ ] **Step 1: Run the full suite on the untouched code**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/ -q`
Expected: all tests pass (135 collected). Record the exact pass count from the summary line.

- [ ] **Step 2: Record pylint baseline for the file being split**

Run: `cd /Users/shuque/git/adns_server && python3 -m pylint --rcfile=pylintrc adns_server.py | tail -5`
Expected: note the score/any pre-existing warnings, so post-extraction pylint can be compared (goal: no *new* warnings).

(No commit.)

---

## Task 3: Create dnssec_util.py with the moved symbols

**Files:**
- Create: `dnssec_util.py`
- Test: `tests/pytest/test_dnssec_util_import.py`

**Interfaces:**
- Consumes: `signer` branch
- Produces (module `dnssec_util`, exact names/signatures copied verbatim from `adns_server.py`):
  - `class RRtype(enum.IntEnum)` with `NXNAME=128, DELEG=61440, DELEGPARAM=65433`
  - `AUTH_IN_PARENT_RRTYPES = [dns.rdatatype.DS, RRtype.DELEG]`
  - `MAX_LABEL_OCTETS = 63`, `PREDECESSOR_SENTINEL = 0x7e`
  - `B32_TO_EXT_HEX`, `NSEC3HASH_SIZE_IN_OCTETS = 20`
  - `def hashalg(algnum)`, `def nsec3hash(name, algnum, wire_salt, iterations, binary_out=False)`
  - `def predecessor_label_good(label)`, `def predecessor_label_ideal(label)`
  - `def predecessor_name(name, ideal=False)`, `def successor_name(name)`
  - `def rrset_from_rdataset(name, rdataset)`
  - `def make_nsec_rrset(owner, nextname, rrtypes, ttl)`, `def make_nsec3_rrset(params, owner, nextname, rrtypes, ttl)`
  - `def load_private_key(keyfile)`
  - `class Zone(dns.zone.Zone)` with `node_factory`, `map_factory=SortedDict`, and methods `__init__, __hash__, init_dnssec, init_key, set_soa_min_ttl, online_signing, get_ent_nodes, add_ent_nodes, nsec_matching, nsec_covering, covering_predecessor, covering_successor, nsec3_hash, nsec3_hashed_owner, nsec3_matching, nsec3_covering, reject_wildcard_deleg, __str__`
  - `def zone_from_file(name, zonefile)`

- [ ] **Step 1: Write the failing import test**

Create `tests/pytest/test_dnssec_util_import.py`:

```python
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_dnssec_util_import.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'dnssec_util'`.

- [ ] **Step 3: Create dnssec_util.py**

Create `dnssec_util.py` at the repo root. Start with a module docstring and the imports the moved code needs, then paste each moved definition **verbatim** from `adns_server.py` (from the line ranges below — copy exactly, do not edit logic):

Header + imports:

```python
#!/usr/bin/env python3

"""
Shared DNSSEC / zone-model utilities for adns_server and the offline signer.

Contains the sorted, ENT-aware Zone model plus pure NSEC/NSEC3 name and hash
helpers. Kept free of server-only concerns (config, sockets, online signing
cache) so both adns_server.py and signzone.py can import it. See Signer.md §1a.
"""

import hashlib
import base64
import enum

import dns.zone
import dns.name
import dns.node
import dns.rrset
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
import dns.dnssec
from dns.rdtypes.ANY import NSEC
from dns.rdtypes.ANY import NSEC3
from sortedcontainers import SortedDict
from cryptography.hazmat.primitives.serialization import load_pem_private_key
```

Then paste, in this order, copying the exact current text from `adns_server.py`:
1. `class RRtype(enum.IntEnum)` — currently lines 88–92.
2. `AUTH_IN_PARENT_RRTYPES = [dns.rdatatype.DS, RRtype.DELEG]` — line 95.
3. `def load_private_key(keyfile)` — lines 608–613.
4. `class Zone(dns.zone.Zone)` — lines 652–862 (the whole class through `__str__`). NOTE: `Zone.nsec3_hash` calls `nsec3hash(...)`, and `nsec3_covering` calls `rrset_from_rdataset(...)`, and `covering_*` call `successor_name`/`predecessor_name` — all of which are defined below in this same module, so ordering within the file is fine at call time (methods resolve names at call, not def, time).
5. `def zone_from_file(name, zonefile)` — lines 865–874.
6. `B32_TO_EXT_HEX = ...` and `NSEC3HASH_SIZE_IN_OCTETS = 20` — lines 904–906.
7. `def hashalg(algnum)` — lines 908–913.
8. `def nsec3hash(...)` — lines 916–932.
9. `def rrset_from_rdataset(name, rdataset)` — lines 950–958.
10. `def make_nsec_rrset(...)` — lines 985–1001.
11. `def make_nsec3_rrset(...)` — lines 1003–1023. (Do NOT move `make_nsec3_rrset_minimal` at 1025 — it stays in the server.)
12. `MAX_LABEL_OCTETS = 63` and `PREDECESSOR_SENTINEL = 0x7e` — lines 1051–1052.
13. `def predecessor_label_good(label)` — lines 1055–1069.
14. `def predecessor_label_ideal(label)` — lines 1072–1083.
15. `def predecessor_name(name, ideal=False)` — lines 1086–1097.
16. `def successor_name(name)` — lines 1100–1130.

Preserve each definition's docstring and comments exactly. Do not reorder within a definition; only the top-to-bottom placement above matters.

- [ ] **Step 4: Run the import test to verify it passes**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_dnssec_util_import.py -q`
Expected: PASS (3 tests). If `test_successor_appends_zero_octet` fails, the `successor_name` body was altered during copy — re-copy verbatim.

- [ ] **Step 5: Sanity-check standalone import and pylint**

Run: `cd /Users/shuque/git/adns_server && python3 -c "import dnssec_util; print(dnssec_util.Zone, dnssec_util.successor_name)"`
Expected: prints the class and function objects, no ImportError.
Run: `cd /Users/shuque/git/adns_server && python3 -m pylint --rcfile=pylintrc dnssec_util.py | tail -5`
Expected: no errors (warnings comparable to the server baseline are acceptable; fix any `unused-import` by removing the specific unused `dns.*` import).

- [ ] **Step 6: Commit**

```bash
cd /Users/shuque/git/adns_server
git add dnssec_util.py tests/pytest/test_dnssec_util_import.py
git commit -m "Add dnssec_util.py with extracted zone model and DNSSEC helpers"
```

(At this point the symbols exist in BOTH files — `adns_server.py` is untouched and still defines its own copies. The suite still passes because nothing changed there. Task 4 removes the duplicates and wires up the re-export.)

---

## Task 4: Remove duplicates from adns_server.py and re-export from dnssec_util

**Files:**
- Modify: `adns_server.py` (delete moved definitions ~lines 88–95, 608–613, 652–874, 904–932, 950–958, 985–1023, 1051–1130; add one import block near line 51)
- Test: `tests/pytest/test_dnssec_util_import.py` (extend to assert re-export)

**Interfaces:**
- Consumes: `dnssec_util` (Task 3) — all symbols listed in Task 3's Produces block
- Produces: `adns_server` module with the moved names available as attributes (via re-export), unchanged for all callers and tests

- [ ] **Step 1: Extend the guard test to assert adns_server re-exports the names (write the failing assertion first)**

Append to `tests/pytest/test_dnssec_util_import.py`:

```python
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
```

- [ ] **Step 2: Run it — the identity assertions should fail (still separate copies)**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_dnssec_util_import.py::test_adns_server_reexports_moved_symbols -q`
Expected: FAIL on `adns_server.Zone is dnssec_util.Zone` (they are two distinct class objects until we wire the re-export).

- [ ] **Step 3: Add the import/re-export block to adns_server.py**

In `adns_server.py`, immediately after the `from sortedcontainers import SortedDict` line (currently line 51), add:

```python
from dnssec_util import (
    RRtype,
    AUTH_IN_PARENT_RRTYPES,
    MAX_LABEL_OCTETS,
    PREDECESSOR_SENTINEL,
    B32_TO_EXT_HEX,
    NSEC3HASH_SIZE_IN_OCTETS,
    hashalg,
    nsec3hash,
    predecessor_label_good,
    predecessor_label_ideal,
    predecessor_name,
    successor_name,
    rrset_from_rdataset,
    make_nsec_rrset,
    make_nsec3_rrset,
    load_private_key,
    Zone,
    zone_from_file,
)
```

- [ ] **Step 4: Delete the now-duplicated definitions from adns_server.py**

Delete each of these definitions from `adns_server.py` (they now live in `dnssec_util.py`). Work bottom-to-top so earlier line numbers stay valid while editing:
- `def successor_name` (1100–1130)
- `def predecessor_name` (1086–1097)
- `def predecessor_label_ideal` (1072–1083)
- `def predecessor_label_good` (1055–1069)
- `MAX_LABEL_OCTETS` / `PREDECESSOR_SENTINEL` (1051–1052)
- `def make_nsec3_rrset` (1003–1023) — but KEEP `make_nsec3_rrset_minimal` (1025+)
- `def make_nsec_rrset` (985–1001)
- `def rrset_from_rdataset` (950–958)
- `def nsec3hash` (916–932)
- `def hashalg` (908–913)
- `B32_TO_EXT_HEX` / `NSEC3HASH_SIZE_IN_OCTETS` (904–906)
- `def zone_from_file` (865–874)
- `class Zone` (652–862)
- `def load_private_key` (608–613)
- `AUTH_IN_PARENT_RRTYPES` (95)
- `class RRtype` (88–92)

Do NOT delete: `HashableRRset` (616–649), `ZoneDict` (877–901), `make_nsec3_rrset_minimal` (1025+), `sign_rrset`, or anything else.

Also remove any imports in `adns_server.py` that are now unused *only* because the moved code left (check with pylint in Step 6 — e.g. if `NSEC`/`NSEC3`/`load_pem_private_key`/`SortedDict` are no longer referenced by the remaining server code, remove those specific import lines). Verify each is truly unused before removing (e.g. `SortedDict` may still be referenced elsewhere; grep first).

- [ ] **Step 5: Run the guard test — re-export identity now holds**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/test_dnssec_util_import.py -q`
Expected: PASS (all tests, including the `is` identity checks).

- [ ] **Step 6: Run the FULL suite — the real regression gate**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/ -q`
Expected: same pass count as the Task 2 baseline (135), zero failures. If anything fails with `NameError`/`AttributeError` for a moved symbol, a reference was missed — add it to the re-export import block in Step 3.

- [ ] **Step 7: pylint both files**

Run: `cd /Users/shuque/git/adns_server && python3 -m pylint --rcfile=pylintrc adns_server.py dnssec_util.py | tail -8`
Expected: no *new* errors vs. the Task 2 baseline. Fix only regressions introduced by the move (typically `unused-import` in `adns_server.py`); do not refactor unrelated warnings.

- [ ] **Step 8: Commit**

```bash
cd /Users/shuque/git/adns_server
git add adns_server.py tests/pytest/test_dnssec_util_import.py
git commit -m "Move zone model and DNSSEC helpers to dnssec_util; re-export for compatibility"
```

---

## Task 5: Wire dnssec_util into packaging

**Files:**
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `dnssec_util.py` at repo root
- Produces: an installable module declaration so `dnssec_util` lands in site-packages alongside the `bin/` scripts

- [ ] **Step 1: Add py-modules to the setuptools table**

In `pyproject.toml`, change the `[tool.setuptools]` table from:

```toml
[tool.setuptools]
py-modules = []
script-files = ['adns_server.py']
```

to:

```toml
[tool.setuptools]
py-modules = ["dnssec_util"]
script-files = ['adns_server.py']
```

(Leave `script-files` as just `adns_server.py` for now — `signzone.py` does not exist yet and is added in a later plan. The dynamic `version = {attr = "adns_server.__version__"}` line is unaffected.)

- [ ] **Step 2: Verify the project metadata still resolves**

Run: `cd /Users/shuque/git/adns_server && python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(d['tool']['setuptools']['py-modules'])"`
Expected: `['dnssec_util']`. (Python 3.9 lacks `tomllib`; if this errors with ImportError on the laptop, skip — the assertion is cosmetic. On 3.11+ it works. Do not add a dependency for this check.)

- [ ] **Step 3: Verify an editable/sdist build sees the module (best-effort)**

Run: `cd /Users/shuque/git/adns_server && python3 -m build --sdist 2>/dev/null && tar tzf dist/*.tar.gz | grep -E "dnssec_util|adns_server" | head` (if `build` is installed)
Expected: both `dnssec_util.py` and `adns_server.py` appear in the sdist file list. If `python3 -m build` is not available, skip this step — the `py-modules` entry is the deliverable and is verified structurally in Step 2.
Cleanup if you built: `rm -rf dist/ *.egg-info/build 2>/dev/null` (note: repo already gitignores `build/` and `adns_server.egg-info/`).

- [ ] **Step 4: Commit**

```bash
cd /Users/shuque/git/adns_server
git add pyproject.toml
git commit -m "Package dnssec_util as an installable module"
```

---

## Task 6: Final verification of the extraction

**Files:** none (verification only)

**Interfaces:**
- Consumes: all prior tasks
- Produces: confidence that the extraction is behavior-preserving and complete

- [ ] **Step 1: Full suite, verbose summary**

Run: `cd /Users/shuque/git/adns_server && python3 -m pytest tests/pytest/ -q`
Expected: identical pass count to Task 2 baseline (135 passing), 0 failed, 0 errored.

- [ ] **Step 2: Server still starts and serves (smoke test)**

Run: `cd /Users/shuque/git/adns_server && ./runtestserver-laptop.sh &` then, after ~1s, `dig -p 5309 @127.0.0.1 deleg.huque.com SOA +dnssec +ednsflags=0x2000 +norecurse` ; then stop the backgrounded server (`kill %1` or find its pid).
Expected: a NOERROR answer with an RRSIG over the SOA (proves online signing still works after the move). If the runtestserver script backgrounds itself, adapt accordingly; the point is one live query succeeds.

- [ ] **Step 3: Confirm no leftover duplicate definitions**

Run: `cd /Users/shuque/git/adns_server && grep -nE "^class Zone|^def successor_name|^def predecessor_name|^class RRtype|^def nsec3hash|^def zone_from_file" adns_server.py`
Expected: NO output (all moved). If any line prints, a duplicate was left in `adns_server.py` — delete it and re-run the suite.

- [ ] **Step 4: Confirm the moved symbols resolve from both modules**

Run: `cd /Users/shuque/git/adns_server && python3 -c "import adns_server, dnssec_util; assert adns_server.Zone is dnssec_util.Zone; assert adns_server.successor_name is dnssec_util.successor_name; print('re-export OK')"`
Expected: `re-export OK`.

- [ ] **Step 5: Final pylint pass**

Run: `cd /Users/shuque/git/adns_server && python3 -m pylint --rcfile=pylintrc adns_server.py dnssec_util.py | tail -8`
Expected: no new errors vs. baseline.

(No commit — verification only. The branch `signer` now holds the completed extraction across Tasks 3–5's commits, ready for the signer-implementation plan to build on.)

---

## Self-Review

**Spec coverage** (against `Signer.md §1a`):
- Extract `Zone` + ENT/covering methods + `zone_from_file` → Task 3 (item 4/5), Task 4.
- Extract pure helpers (`successor_name`, `nsec3hash`+`hashalg`, `make_nsec_rrset`, NSEC3 builder, `load_private_key`, `rrset_from_rdataset`) → Task 3 (items 3,6–16).
- Extract `RRtype`, `AUTH_IN_PARENT_RRTYPES` → Task 3 (items 1–2).
- Do NOT extract `sign_rrset`, `DNSresponse.*`, config/socket code → enforced by explicit "what stays" list + Task 4 Step 4 "Do NOT delete".
- `make_nsec3_rrset_minimal` stays (it is online-only, calls into per-query state) → called out in Task 3 item 11 and Task 4 Step 4.
- Packaging: `py-modules = ["dnssec_util"]` → Task 5.
- Regression net = existing pytest suite green → Tasks 2, 4 (Step 6), 6.
- Feature branch `signer` → Task 1.

**Placeholder scan:** No TBD/TODO. Every code step shows exact code or exact line ranges to copy. Line numbers are current-state references (verified against the file); if the implementer finds drift, the symbol names + `grep` anchors disambiguate.

**Type consistency:** Symbol names are identical across Task 3 (Produces), Task 4 (import block), and the guard tests — `successor_name`, `predecessor_name`, `predecessor_label_good/ideal`, `Zone`, `zone_from_file`, `nsec3hash`, `make_nsec_rrset`, `make_nsec3_rrset`, `rrset_from_rdataset`, `load_private_key`, `RRtype`, `AUTH_IN_PARENT_RRTYPES`. The re-export identity checks (`is`) guarantee no accidental shadow copies.

**Note on line numbers:** All line references are from `adns_server.py` at the time of planning (version 0.10.0). If they have drifted, rely on the `grep -n` anchors in Task 3 to locate each definition; the *set* of symbols to move is authoritative, not the exact lines.
