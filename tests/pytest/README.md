# Automated test suite for adns_server

An automated, self-contained pytest suite that launches a private instance of
`adns_server.py` and drives it with real DNS queries, asserting on the
semantics of the responses (rcode, flags, sections, EDE codes) and, for signed
zones, **cryptographically validating** the DNSSEC signatures and NSEC/NSEC3
proofs.

This replaces the visual review of the `tests/dotests-*.sh` transcript scripts
with precise, deterministic assertions. It ignores the volatile parts of a
response (signatures bytes, timestamps, message IDs, RR ordering) by asserting
on structure and validity rather than diffing text.

## Running

From the repository root:

```
pip install -e '.[test]'      # installs pytest
pytest                        # runs tests/pytest/
```

Or directly:

```
python3 -m pytest tests/pytest -v
```

Set `ADNS_TEST_KEEP_LOG=1` to print the server log on teardown when debugging a
startup failure.

## Layout

- `conftest.py` — fixtures: a session-scoped server launched on an ephemeral
  loopback port (`server`), a `query(...)` helper (DO/DE/CO flags, cookies,
  TCP, 0x20 case randomization), and a cached `dnskey(zone)` trust anchor.
- `dnsutil.py` — assertion vocabulary: rcode/flags/section inspection,
  `validate_all()` (DNSSEC signature validation), NSEC/NSEC3 coverage and
  matching, type-bitmap and EDE helpers.
- `test_zones/` — purpose-built minimal zones with online-signing keys, plus
  `test.yaml`. Signatures are generated at runtime, so no pre-signed data is
  checked in.
- `test_deleg.py` — DELEG DE=1/DE=0 referral and occlusion matrix.
- `test_zerox20.py` — 0x20 case-randomization and signature-cache regression.
- `test_dnssec` / `test_nsec3.py` — denial-of-existence proofs.
- `test_basic.py` — positive answers, wildcards, ENT, NODATA/NXDOMAIN.
- `test_edns.py` — EDNS/DE-flag echo, meta types, ANY.

## Test zones

- `deleg.test` — NSEC + compact denial, DELEG enabled, DNSKEY-ADT set. Carries
  the sub1..sub7 delegation matrix (NS/DS/DELEG combinations).
- `nsec3.test` — NSEC3, DELEG enabled. Has a DELEG-only cut (`degonly`).
- `unsigned.test` — unsigned, DELEG enabled.

To regenerate a zone's key (if ever needed), see `genkey.py` in the repo root;
the suite's keys live under `test_zones/<zone>/privkey.pem` with the matching
DNSKEY in `dnskey.txt`.
