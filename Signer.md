# DELEG-aware Offline Zone Signer Design

Finalized design for an offline DNSSEC zone signer (`signzone.py`) for
adns_server, with incremental delivery. The DELEG support is a small addition
on top of a conventional offline signer.

## 1. Scope and deliverables

Two artifacts, implemented in order:

**1a. `dnssec_util.py` — shared module extraction (prerequisite).**
A targeted refactor that pulls the zone model + pure DNSSEC helpers out of
`adns_server.py` into a new module both programs import. This is *not* the full
"break the monolith" reorg (§1.1 in Review.md); it is the smallest coherent
slice that (a) is exactly what the signer needs and (b) is a sane first step of
the eventual split. The full split stays deferred and will inform itself from
having two consumers of the shared code.

Extracted surface (final surface confirmed during Stage 0 implementation):
- `Zone(dns.zone.Zone)` — the `SortedDict`-backed, ENT-aware subclass, plus
  `add_ent_nodes()`, `covering_predecessor()`, `covering_successor()`,
  `set_soa_min_ttl()`, and `zone_from_file()`. Online-only fields on
  `Zone.__init__` (e.g. `privatekey`, `signing_dnskey`, `compact_denial`,
  `require_server_cookie`) are server concerns; lean toward keeping the shared
  `Zone` minimal and leaving online-only state in the server (evaluate at
  implementation time).
- Pure functions: `successor_name()`, `nsec3hash()` + `hashalg()`,
  `make_nsec_rrset()` and the NSEC3 rrset/bitmap builder, `load_private_key()`,
  `rrset_from_rdataset()`.
- Constants/enums: `RRtype` (NXNAME/DELEG/DELEGPARAM), `AUTH_IN_PARENT_RRTYPES`
  (`[DS, DELEG]`).

**Not** extracted: `sign_rrset()` (online, `TTLCache`-wrapped, single-key,
now-relative times — the signer needs its own RRSIG helper), the
`DNSresponse.*` methods, config/socket/wire code.

Regression safety net: the existing `tests/pytest/` suite must stay green after
the extraction (no behavior change).

**1b. `signzone.py` — the offline signer** (the rest of this document).

### Packaging

`pyproject.toml` currently installs the server via `script-files` (copies the
file verbatim into the environment's `bin/`, which is *not* on `sys.path`). The
shared module must go to `site-packages`, so add it to `py-modules`:

```toml
[tool.setuptools]
py-modules = ["dnssec_util"]                        # -> site-packages (importable)
script-files = ['adns_server.py', 'signzone.py']    # -> bin/ (on PATH)
```

`purelib` (site-packages) and `scripts` (bin) are resolved from the *same*
`sysconfig` install scheme, so the pairing is always internally consistent: the
`bin/` script finds its module in `site-packages` regardless of scheme. Verify
whether `deleg_rdata.py` also needs `py-modules` treatment once the signer's
imports are finalized.

From the repo (dev), no config is needed: `adns_server.py`, `signzone.py`, and
`dnssec_util.py` sit side by side and import each other directly (script dir is
`sys.path[0]`). **Verified deployment target (guvnor):** root runs the server in
a venv (`$VIRTUAL_ENV=/root/virt/misc`), so `dnssec_util.py` installs to
`/root/virt/misc/lib/python3.9/site-packages/` and both scripts to
`/root/virt/misc/bin/`.

Future work (not now): replace `script-files` with `[project.scripts]` console
entry points (`main()` wrappers) — the natural end state of the monolith split.

## 2. `signzone.py` — CLI and I/O contract

**Invocation:** `signzone.py [options] <zonename> <zonefile>` — zone name
explicit (matches `zone_from_file()`; no `$ORIGIN` guessing).

**Output:** `<zonefile>.signed` by default; `-o FILE` (`-o -` = stdout) to
override. Never overwrite the input in place. Written to a temp file and
atomically renamed on success, so a failed run leaves no partial `.signed`.

| Flag | Meaning | Default |
|------|---------|---------|
| `-K, --keydir DIR` | directory of keytag-named PEM private keys | `.` |
| `-o, --output FILE` | output file (`-` = stdout) | `<zonefile>.signed` |
| `-e, --expiration T` | RRSIG expiration | `+30d` (2592000 s) |
| `-i, --inception T` | RRSIG inception | `-1h` (now − 3600 s) |
| `-j, --jitter N` | ± window applied per-RRSIG to expiration | `6h` (21600 s) |
| `--bump` | increment SOA serial | off |
| `-v, --verbose` | per-RRset signing trace | off |

**Time syntax** (`-e`, `-i`, `-j`): bare integer = seconds; unit suffixes
`s/m/h/d/w/y` accepted (`m`=60, `h`=3600, `d`=86400, `w`=604800,
`y`=31536000), e.g. `30d`, `12h`. `-e`/`-i` also accept a signed relative form
(`+30d`, `-1h`) and a 14-digit absolute `YYYYMMDDHHMMSS` (BIND-compatible) for
pinning an exact time. So `-e +30d`, `-e 30d`, and `-e +2592000` are
equivalent.

**Key discovery:** DNSKEYs come from the zonefile. For each DNSKEY, compute its
keytag and load `<keydir>/<zone>+<alg>+<keytag>.pem` (PEM PKCS8, as
`load_private_key()` reads). The match is on the **exact** filename
`<zone>+<alg>+<keytag>.pem` — *not* a loose `*.pem` glob — so that
differently-suffixed PEMs in the same keydir (e.g. `.prepublish.pem` below) are
deliberately ignored. A DNSKEY with no matching PEM is **publish-only** (kept in
the RRset, not used to sign). No PEM for *any* DNSKEY → hard error. This
publish-only rule is the entire rollover mechanism (§4).

**Pre-publish keys.** A pre-published ZSK is, to the signer, simply a DNSKEY in
the zone with no matching `<zone>+<alg>+<keytag>.pem` — it needs no special
handling. For operator convenience, `adnskeygen.py` (below) can park a pre-publish
key's private material under the altered name `<zone>+<alg>+<keytag>.prepublish.pem`
so it lives alongside the active keys but is skipped by the exact-match
discovery above. **Activation is a rename** (`.prepublish.pem` →
`.pem`); retiring the previously-active key is deleting (or re-suffixing) its
`.pem`. Greppable and auditable, and the signer needs zero pre-publish logic.

Companion change: `adnskeygen.py` gains a `--keydir DIR` option (opt-in; absent it
keeps its current stdout-only behavior). When given, it writes a self-consistent
keytag-named triple into the keydir, and also keeps printing DNSKEY/DS to stdout:
- `<zone>+<alg>+<keytag>.pem` — PEM PKCS8 private key (the signer's input).
- `<zone>+<alg>+<keytag>.dnskey` — the full DNSKEY RR (ready to `$INCLUDE` or
  paste into the zonefile), not bare base64.
- `<zone>+<alg>+<keytag>.ds` — the DS RR for the parent (alg 2 / SHA-256).

This keytag-based scheme is what the multi-key signer needs; it is additive and
does not disturb the existing per-zone `privkey.pem` / `pubkey.key` / `dsset-*`
files the running server uses.

`adnskeygen.py` also gains a `--prepublish` flag: it writes the private key as
`<zone>+<alg>+<keytag>.prepublish.pem` (still emitting the `.dnskey`/`.ds`
companions normally) so the DNSKEY can be added to the zone and pre-published
while the signer ignores the altered-suffix PEM until it is renamed to activate
(§2).

**ADT flag — no code change.** For a DELEG-enabled zone the operator sets the
DNSKEY-ADT bit on the SEP key (KSK or CSK) to get full downgrade resistance
(see DELEG.md). This is already accommodated by `adnskeygen.py -f`: `-f 259`
(ZONE 256 + SEP 1 + ADT 2) generates such a key. The signer treats the DNSKEY
generically — it classifies keys on the SEP bit and signs the DNSKEY RRset with
every SEP key that has a PEM, irrespective of the ADT bit — so no `signzone.py`
change is needed to support ADT zones.

**Input normalization (strip-and-re-sign):** on load, discard all RRSIG, NSEC,
NSEC3 records; **retain** DNSKEY and NSEC3PARAM as inputs. Signing is
idempotent: signing the same file twice yields identical output modulo
jitter/inception timestamps (and byte-identical with fixed times + `-j 0`).

**SOA serial:** unchanged by default (zonefile is the source of truth);
`--bump` opts into incrementing it. `--bump` mutates only the in-memory zone
that becomes the signed output — `signzone.py` never writes back to the input
zonefile. The increment is therefore relative to the *input's* serial: two
consecutive `--bump` runs from the same unedited source both emit serial N+1
(not N+1 then N+2).

### Operator zone-update models

The signer supports two workflows; the SOA-serial behavior above is deliberate
in both.

- **(i) Unsigned zone as source of truth (recommended default).** The operator
  edits the small, hand-readable unsigned file and regenerates the `.signed`
  file on every change; the signed file is a pure derived build artifact that
  can be deleted and regenerated at will. `--bump` is a convenience so the
  operator need not hand-edit the serial on each re-sign. Caveat: because
  `--bump` is source-relative, it yields a monotonic served serial only if every
  publish goes through it against a stable source serial. For anything that
  compares serials over time across restarts (e.g. AXFR to secondaries),
  advance the *source* serial rather than relying on `--bump`.

- **(ii) Re-feed the signed zone (`strip_dnssec` path).** Feeding a previously
  signed zone back in strips its DNSSEC RRs (retaining DNSKEY/NSEC3PARAM) and
  re-signs. This is the right tool for re-signing on key rollover or expiry
  refresh, or when the only on-disk form is the signed one. It is the wrong tool
  for editing zone *contents*: the signed file is large and unwieldy to
  hand-edit, and `--bump` on it walks the serial forward from the signed value.

Recommended posture: treat (i) as the documented operator workflow and (ii) as
a maintenance/re-sign mode. (A durable monotonic serial without editing the
source — e.g. a `YYYYMMDDnn` datestamp scheme, or reading the previous
`.signed` serial and incrementing — would be a separate feature, not the
current `--bump` behavior.)

**Exit codes:** 0 on success; nonzero with a clear stderr message on any key,
parse, or semantic error. No partial output on error.

## 3. Core signing engine (NSEC)

Pipeline over the loaded `Zone`:

1. **Load & classify keys.** Parse the apex DNSKEY RRset; classify each key by
   the SEP bit (flags bit 15 / 257 = KSK or CSK; 256 = ZSK). Load matching PEMs.
   Roles:
   - **CSK** (single SEP key, no separate ZSK): signs everything.
   - **KSK + ZSK:** KSK signs *only* the DNSKEY RRset; ZSK signs everything else.
   - Keys without a PEM are publish-only (not used to sign; noted under `-v`).

2. **Resolve the RRSIG time window once.** Compute absolute inception and
   expiration at startup so the whole zone shares a base window. Inception is
   shared (no jitter). **Jitter is applied per-RRSIG**: each RRSIG expiration =
   base_expiration + uniform random offset in ±jitter, so signatures do not all
   expire simultaneously.

3. **Walk the zone in sorted canonical order** (`SortedDict` provides it). For
   each owner node, each RRset:
   - Skip DNSSEC records (already stripped).
   - Delegation cut = node has NS and/or DELEG. At a cut, only DS and DELEG are
     authoritative-in-parent and get signed; **NS and glue A/AAAA are not
     signed** (strict RFC 4035). Elsewhere, all RRsets are authoritative.
   - Sign each authoritative RRset with the applicable key(s) → append RRSIG(s).

4. **Build the NSEC chain.** Enumerate the owners that get an NSEC in canonical
   order; link each owner's NSEC `next` to the following owner, last → apex
   (closed loop). Bitmap = types present at the owner, plus NSEC and RRSIG; at a
   cut the bitmap naturally includes NS/DS/DELEG as present. Sign each NSEC with
   ZSK/CSK.

   **ENTs are EXCLUDED from the NSEC chain** (RFC 4035 §2.3, verified):
   > "Each owner name in the zone that has authoritative data or a delegation
   > point NS RRset MUST have an NSEC resource record. ... the signing process
   > MUST NOT create NSEC or RRSIG RRs for owner name nodes that were not the
   > owner name of any RRset before the zone was signed."

   An empty non-terminal owns no RRset, so it gets **no** NSEC and is skipped in
   the chain. This is the opposite of NSEC3 (§4), where every ENT gets an NSEC3.
   `add_ent_nodes()` adds ENT nodes to the `SortedDict` for the server's
   NODATA-vs-NXDOMAIN logic, so the NSEC pass must positively select only
   nodes that owned an RRset in the *unsigned* zone (has authoritative data or a
   delegation NS/DELEG cut) — i.e. exclude synthesized ENT nodes — rather than
   iterate all `SortedDict` keys.

5. **Serialize** in stable owner-sorted order to the output file.

**Apex:** DNSKEY signed by KSK/CSK; SOA/NS/other apex RRsets by ZSK/CSK;
NSEC3PARAM (NSEC3 mode) is authoritative and signed.

**New RRSIG helper** (in `signzone.py`, not `dnssec_util.py`): a plain function
`(rrset, private_key, dnskey, inception, expiration) -> RRSIG rdata`, wrapping
`dns.dnssec.sign` with explicit absolute times and **no cache** (unlike the
server's online `sign_rrset()`).

Zone-signing references: RFC 4035 §2 (NSEC), RFC 5155 §7.1 (NSEC3).

## 4. NSEC3 mode, multi-key, and rollover

**NSEC3 mode is data-driven:** if the unsigned zone's apex has an NSEC3PARAM
record, the signer builds an NSEC3 chain (its hash alg / flags / iterations /
salt come from that record). No CLI toggle — the record *is* the switch.
Mirrors `Zone.init_dnssec()`; enforces the "only one NSEC3PARAM" rule.

**NSEC3 chain construction:**
0. **ENTs ARE INCLUDED** here — the reverse of NSEC (§3.4). RFC 5155 §7.1
   (verified): "Each empty non-terminal MUST have a corresponding NSEC3 RR"
   (barring opt-out, which is out of scope). So the NSEC3 pass hashes every ENT
   node too. This is why `add_ent_nodes()`' ENT nodes matter here but must be
   filtered out in the NSEC pass.
1. For every owner needing authenticated denial (all nodes incl. ENTs), compute
   `nsec3hash(name, alg, salt, iterations)`.
2. Build one NSEC3 per hashed owner: owner = `<base32hash>.<zone>`, bitmap =
   the original name's present types (+ RRSIG; the NSEC3 bit is not set on the
   node itself, per RFC 5155), `next hashed owner` = next hash in **sorted hash
   order** (wrapping to smallest — closed loop).
3. Sign each NSEC3 RRset and the apex NSEC3PARAM with ZSK/CSK.

Because NSEC3 sorts by *hash*, the chain is a separate sorted-by-hash pass, not
the name-sorted signing walk.

**Multi-key / rollover — emergent from key classification (§3.1), no separate
feature code:**
- **ZSK pre-publish rollover:** two ZSKs in the DNSKEY RRset; only those with a
  PEM actively sign. The pre-published ZSK is publish-only. Activate by adding
  its PEM; retire the old one by removing its PEM.
- **KSK double-signature rollover:** two KSKs both with PEMs → both sign the
  DNSKEY RRset (two RRSIGs over DNSKEY).
- **CSK:** single SEP key signing everything; CSK rollover likewise expressed by
  which PEMs are present.

The invariant: **sign the DNSKEY RRset with every SEP key that has a PEM; sign
everything else with every non-SEP key that has a PEM** (a CSK counts as both).

## 5. DELEG signing

The offline signer treats DELEG purely as **DS-like authoritative parent data**;
none of the serving-time referral/occlusion logic lives here. It needs three
things, all already accommodated by §§3–4:

1. **Sign the DELEG RRset at the cut.** The §3 cut-authority rule classifies
   DELEG (alongside DS) as authoritative-in-parent → it gets an RRSIG from
   ZSK/CSK. No special case.
2. **DELEG bit in the cut's NSEC/NSEC3 bitmap.** The bitmap is built from types
   present at the owner, so a DELEG-only cut (DELEG, no NS) or a combined cut
   (NS + DELEG) lists DELEG automatically.
3. **Parse/serialize DELEG & DELEGPARAM.** DELEG (61440) and DELEGPARAM (65433)
   are unregistered dnspython types, handled as RFC 3597 generic rdata
   (`\# len hex`). **Verified** (2026-08-10): `dns.zone.from_text` loads both;
   `to_digestable()` yields correct canonical wire for signing; and
   `NSEC.Bitmap.from_rdtypes()` accepts the numeric 61440 and builds bitmap
   windows. So no type registration is required. (Re-run the same check for
   `NSEC3.Bitmap` during Stage 4 — expected to behave identically, confirm not
   assume.)

**DELEGPARAM** is just an ordinary generic data type at whatever owner it
appears on (e.g. a config name) — signed like any other RRset, no cut/bitmap
subtlety, no DELEGPARAM-specific code.

DELEG-specific *code* reduces to: the cut predicate recognizes `RRtype.DELEG`,
and the "authoritative at a cut" set is `AUTH_IN_PARENT_RRTYPES = [DS, DELEG]`
(the existing constant, moved to `dnssec_util.py`). Everything else is the
generic engine.

A DELEG-only cut (no NS, no glue) has its authoritative DELEG covered by RRSIG
and otherwise looks like a normal signed node with an NSEC/NSEC3 — the intended
on-the-wire result, matching what the running server serves.

Reference: DELEG records are signed like DS (authoritative at the delegation
point). See DELEG.md for the serving-side semantics.

## 6. Incremental delivery

Development happens on a dedicated feature branch (proposed name `signer`),
branched from `master`; each stage is a commit on it, merged back to `master`
with `--no-ff` when the signer is complete (or per-stage if preferred). Each
stage is independently testable and committable.

- **Stage 0 — `dnssec_util.py` extraction.** Move the shared surface; server
  imports it; full pytest suite green. No new functionality. (Own short design
  doc.)
- **Stage 1 — NSEC signer, single CSK.** CLI, key discovery, strip-and-re-sign,
  authoritative-RRset signing, NSEC chain, `.signed` output. The MVP.
- **Stage 2 — NSEC3 signer.** NSEC3PARAM-driven mode; hash-sorted chain.
- **Stage 3 — Multi-key / rollover.** KSK+ZSK split, double-KSK, ZSK
  pre-publish — mostly emergent from Stage 1 key classification.
- **Stage 4 — DELEG.** Cut predicate includes DELEG; verify bitmap + RRSIG at
  cuts.

## 7. Testing

Fits the existing `tests/pytest/` harness.

- **Round-trip validation (primary oracle):** sign a zone, validate every RRSIG
  with `dns.dnssec.validate` against the zone DNSKEY; verify the NSEC/NSEC3
  chain is complete — every owner covered, `next` pointers form a single closed
  loop, bitmaps match present types.
- **Cross-check against BIND `dnssec-signzone`** (BIND 9.20.x at
  `/opt/homebrew/bin/dnssec-signzone`): sign the same simple zone with both and
  compare *structure* (not bytes — jitter/timestamps differ): chain shape,
  bitmaps, and which RRsets carry RRSIGs should match.
- **`dnssec-verify` (BIND 9.20.x, Homebrew) as an independent oracle:** run it
  on our `.signed` output to confirm complete RRSIG coverage and a valid chain
  of denial, verified by a mature implementation independent of our own
  round-trip checks. (Note: `dnssec-verify` predates DELEG and won't understand
  DELEG cuts; use it on standard NSEC/NSEC3 zones, and rely on the
  serve-through-`adns_server.py` + dnsviz path for the DELEG-specific checks.)
- **DELEG-specific:** sign `deleg.huque.com`; confirm each cut's DELEG RRset has
  an RRSIG and the cut's NSEC/NSEC3 bitmap has the DELEG bit; then **serve the
  signed zone through `adns_server.py` and run the pytest suite + dnsviz** — the
  real acceptance test (closes the loop with the running server).
- **Determinism:** signing twice with fixed inception/expiration + `-j 0`
  produces byte-identical output.

## 8. Error handling

Fail-fast, no partial output (temp file + atomic rename on success):
- No PEM for *any* key, unparseable key, no DNSKEY in zone, malformed zonefile,
  >1 NSEC3PARAM → clear stderr message, nonzero exit, no `.signed` written.
- Publish-only keys (DNSKEY present, no PEM) → not an error; noted under `-v`.
- Zone load failure → propagate dnspython's parse error with file/line context.

## 9. Non-goals

Stated explicitly:
- **NSEC3 opt-out** — out of scope entirely (not deferred). Useful mainly to
  large delegation-centric TLDs, not this server's target audience (small/medium
  authoritative zones, DELEG experimentation). Every delegation gets an NSEC3.
- **CDOE / black-lie generation** — CDOE (RFC 9824) is an online/dynamic
  technique; a static signer produces conventional NSEC/NSEC3 only.
- **Incremental / partial re-signing** — always strip-and-re-sign fresh.
- **Serial management policy** beyond optional `--bump`.
- **Key generation** — stays in `adnskeygen.py` (which gains the keytag-named-PEM
  companion option).
- **Multi-algorithm zones** — out of scope for now (initial stages assume a
  single algorithm across the DNSKEY RRset). Noted here for when they are added:
  the signer will **deliberately not enforce** RFC 4035 §2.2, which requires
  that each RRset be signed by at least one key of *every* algorithm present in
  the DNSKEY RRset. That rule is too rigid for multi-provider / multi-signer
  configurations (each provider using distinct algorithms), provider/algorithm
  transitions, and pre-publication of trust anchors with different algorithms.
  Our code is forward-looking and aligns with the relaxation proposed in
  draft-huque-dnsop-multi-alg-rules (`-08`,
  https://www.ietf.org/archive/id/draft-huque-dnsop-multi-alg-rules-08.txt).
  Concretely: when multi-algorithm support lands, the signer signs each RRset
  with the key(s) it is told to use and does **not** add the "one signature per
  algorithm per RRset" completeness check. (The current single-algorithm scope
  conforms trivially; the point is not to introduce the strict §2.2 enforcement
  later.)
