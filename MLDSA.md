# ML-DSA (post-quantum) DNSSEC support in adns_server

Design notes and technical findings for adding DNSSEC algorithm **18
(ML-DSA-44)** to adns_server. This is a planning + progress document: it records
what the spec requires, what the software libraries and deployment platforms
actually provide (verified, not assumed), and a phased outline of the
implementation work. **Phase 1 (key generation) is DONE and merged (v0.14.0),
and phase 2 (offline signer) is DONE and merged (v0.15.0);** the
online-signing/serving phase remains.

## Specification

- **draft-westerbaan-dnssec-mldsa-04** — "Algorithm for ML-DSA for DNSSEC".
  Defines a single DNSSEC algorithm number for the smallest ML-DSA parameter
  set:

  - **Algorithm 18 = ML-DSA-44** (mnemonic `MLDSA44`), NIST security
    category 2. This draft defines *only* ML-DSA-44 for DNSSEC; the larger
    ML-DSA-65 / ML-DSA-87 parameter sets are not assigned DNSSEC algorithm
    numbers here. The codepoint was assigned by IANA against draft -03; -04 is
    compatible.

ML-DSA itself is **FIPS 204** (Module-Lattice-Based Digital Signature
Standard). The relevant sections: KeyGen §5.1, Sign §5.2, Verify §5.3, byte
encoding §7.2, and the hedged-vs-deterministic guidance in §3.4 / §3.6.

### Wire format (draft §3–§5)

- **DNSKEY public key:** the 1312-octet raw public key from ML-DSA.KeyGen,
  carried directly as the DNSKEY public-key field (FIPS 204 §7.2 byte encoding,
  no wrapper or prefix).
- **RRSIG signature:** the 2420-octet raw signature from ML-DSA.Sign, carried
  directly as the RRSIG signature field.
- **Signing mode:** "pure" ML-DSA (**not** the pre-hash HashML-DSA variant),
  with an **empty context string** (ctx of zero length). The message signed is
  the ordinary RFC 4034 §3.1.8.1 data-to-be-signed (RRSIG RDATA without the
  signature, followed by the canonical RRset).
- **DS:** entirely standard DNSSEC. DS is computed over `owner-name-wire ||
  DNSKEY-RDATA` with the chosen digest algorithm; nothing about DS is
  ML-DSA-specific. The draft's example uses SHA-256 (digest type 2).

### Section 6 example (byte-reproducible)

The draft ships a fully worked example whose key and DS are deterministic from
a published 32-octet seed, which makes it a hard test vector:

- Seed (`PrivateKey` field, base64) `AAECAwQF…HB8=` = octets `00 01 02 … 1f`.
- Key generated deterministically from that seed.
- `example.com. DNSKEY 257 3 18 (…1312-octet base64…)`.
- `example.com. DS 59829 18 2 812cb1a2…9264b4bfa` — **keytag 59829**, SHA-256.
- RRSIG over an MX RRset, produced with the **deterministic** ML-DSA variant
  (`rnd` all zeroes) so the signature bytes are reproducible in the draft.

## Library support — verified

Target library: **`cryptography` 50.0.0**, module
`cryptography.hazmat.primitives.asymmetric.mldsa`. The relevant surface:

| Need | API | Notes |
|---|---|---|
| Seed-based deterministic keygen | `MLDSA44PrivateKey.from_seed_bytes(seed)` | 32-octet seed; reproduces the Section 6 key exactly |
| Random keygen | `MLDSA44PrivateKey.generate()` | for the online/dynamic CSK case |
| DNSKEY public-key body | `pub.public_bytes_raw()` | returns the 1312-octet raw key |
| Reload public key | `MLDSA44PublicKey.from_public_bytes(raw)` | |
| Private key on disk (seed) | `priv.private_bytes_raw()` | 32-octet seed form |
| Private key on disk (PKCS8) | `priv.private_bytes(PEM/DER, PKCS8, NoEncryption)` | round-trips on the target (below) |
| Sign | `priv.sign(data, context=None)` | 2420-octet signature; `context=None` == empty context == "pure" ML-DSA |
| Verify | `pub.verify(sig, data, context=None)` | |

**Verified against the Section 6 vector** (laptop and deployment target, see
below): seed → `from_seed_bytes` → `public_bytes_raw()` reproduces the example
DNSKEY byte-for-byte; the SHA-256 DS over the DNSKEY RDATA equals
`812cb1a2…4bfa`; the RFC 4034 App. B keytag equals 59829; and the draft's
Section 6 **RRSIG verifies** with `pub.verify(sig, signed_data, context=None)`,
confirming that `context=None` is exactly the pure/empty-context mode the spec
mandates.

### Two constraints that shape the implementation

1. **dnspython 2.7.0 gaps for algorithm 18 — but only the crypto-aware
   helpers.** The functions that must understand the key's cryptography differ
   from the ones that only manipulate wire/presentation format:

   - **Gated (reject alg 18):** `dns.dnssec.make_dnskey(public_key, ...)` (needs
     to serialize a `cryptography` public-key object) raises
     `UnsupportedAlgorithm`; likewise the `dns.dnssec` **sign / validate**
     helpers.
   - **Work fine (algorithm-agnostic):** `dns.rdata.from_text(... DNSKEY ...)`
     parses an alg-18 DNSKEY from presentation text, and `dns.dnssec.key_id`
     and `dns.dnssec.make_ds` then compute the correct keytag (59829) and DS
     from that rdata. Verified against the Section 6 vector.

   Practical consequence:

   - **Keygen / DS / keytag** need no hand-rolling. Instead of
     `make_dnskey(public_key, 18, ...)`, build the DNSKEY rdata from text —
     `dns.rdata.from_text(IN, DNSKEY, f"{flags} 3 18 {base64(pub_raw)}")` — and
     reuse the existing `key_id` / `make_ds` calls unchanged.
   - **Signing (offline + online)** is the part that must call `cryptography`
     directly: for alg 18 we build the RFC 4034 §3.1.8.1 signing input and the
     RRSIG wire format ourselves and call `priv.sign(input)`, in place of
     `dns.dnssec.sign`. `adns/signer.py` (`rrsig_rdata`) and `adns/crypto.py`
     (`sign_rrset`) use `dns.dnssec.sign` today; `discover_keys` uses
     `dns.dnssec.key_id`, which is fine.

2. **No deterministic-signing knob.** `cryptography`'s `sign(data,
   context=None)` is **hedged (randomized)**; two calls over the same message
   differ, and there is no `deterministic=` parameter. Consequences:

   - We **cannot** byte-reproduce the Section 6 *RRSIG* (it used `rnd`=0). We
     reproduce only the deterministic halves — the DNSKEY and DS. This is fine:
     a hedged signature is fully valid and verifies.
   - Hedged signing is what draft §7.1 / FIPS 204 §3.4 actually **prefer** for
     online signing (side-channel resistance), so hedged is the right default
     for our dynamic-signing path anyway.
   - Any test oracle for the signature must therefore be **verify-based**
     (sign → verify round-trips), not a fixed-vector byte comparison. Fixed
     vectors are still usable for DNSKEY, keytag, and DS.

## Platform support — verified

The gating factor for ML-DSA is **not the Python version and not the host's
system OpenSSL** — it is the OpenSSL that `cryptography` is actually linked
against. Confirmed on three hosts:

| Host | OS | Python | cryptography | OpenSSL (via cryptography) | System `openssl` | Result |
|---|---|---|---|---|---|---|
| Laptop (adnstest venv) | macOS | 3.12.9 | 50.0.0 | 4.0.1 | (not measured) | all probes pass |
| **guvnor (`adns` venv)** | **AL2023** | **3.9.16** | 50.0.0 | 4.0.1 | **3.0.8** | all probes pass |
| toolbox (`adns` venv) | RHEL9 | 3.9.25 | 50.0.0 | 4.0.1 | **3.5.5** | all probes pass |

The **System `openssl`** column is the distro CLI (`openssl version`), shown to
underline how far it diverges from the wheel-bundled 4.0.1. AL2023 ships OpenSSL
3.0.8 (Feb 2023) and RHEL9's toolbox ships 3.5.5 — neither has ML-DSA in a form
`cryptography` uses, yet both hosts pass, because the wheel does not use them.

guvnor is the real deployment target. It runs Python 3.9.16 — so the
shipped-code floor remains **Python 3.9** — but all probes pass there,
**including both PKCS8 PEM and PKCS8 DER private-key serialization
round-trips**, so the on-disk key format is a free choice rather than a forced
one.

### Why the OpenSSL versions differ, and what actually gates ML-DSA

`cryptography` is installed here from the PyPI **manylinux/macOS binary
wheels**, and those wheels **statically bundle their own OpenSSL** (4.0.1 for
cryptography 50.0.0) inside the extension module. The library calls into that
vendored copy and never touches the host's system OpenSSL. That is why:

- On toolbox the distro CLI `openssl version` reports **3.5.5** while the probe
  reports **4.0.1** — they are two entirely different OpenSSL builds in the same
  environment. The stdlib `ssl` module links the *system* OpenSSL (3.5.5); the
  `cryptography` C extension links its own bundled 4.0.1. You can see both:

  ```
  python3 -c "import ssl; print('stdlib ssl ->', ssl.OPENSSL_VERSION)"
  python3 -c "from cryptography.hazmat.backends.openssl.backend import backend; \
              print('cryptography ->', backend.openssl_version_text())"
  ```

- All three hosts report the identical bundled 4.0.1 despite different OSes,
  Python versions, and (on toolbox) an older *system* OpenSSL.

So the real platform requirement reduces to a single thing: **`cryptography` at
a version whose bundled OpenSSL includes ML-DSA** — 50.0.0 (OpenSSL 4.0.1) is
confirmed good. The host OS and system OpenSSL are irrelevant when the wheel is
used.

**Caveat for deployment:** this holds only for the PyPI binary wheels. A host
that instead installs a `cryptography` linked against *system* OpenSSL would
then depend on the host OpenSSL and could lack ML-DSA (e.g. guvnor's system
3.0.8 or toolbox's 3.5.5). By default `pip` prefers a compatible binary wheel
and only falls back to a source build (which links system OpenSSL) when no wheel
matches the platform tag, so the realistic ways to end up on system OpenSSL are:

- **Installing the distro package instead of pip** — `dnf`/`apt`
  `python3-cryptography` is deliberately built against system OpenSSL (that is
  the distro's security-update model), as is a base container image that
  pre-seeds it. This is the most likely real-world trap.
- **Forcing a source build** — `pip install --no-binary cryptography`, or
  `PIP_NO_BINARY` set in the environment/config.
- **No compatible wheel for the platform** — genuinely uncommon here:
  non-glibc/musl or exotic architectures (ppc64le, s390x, riscv64, 32-bit ARM),
  glibc older than the manylinux baseline, or a non-Linux/mac/Windows OS
  (\*BSD, Solaris, AIX). `cryptography` uses the `abi3` tag, so a merely-new
  Python version rarely triggers this. The deployment targets here (x86_64 /
  aarch64 glibc Linux, macOS) are all well within wheel coverage.

The venvs here all `pip install` the wheel into a venv, so this is not a current
concern; it is the first thing to check if a future host mysteriously reports
algorithm 18 as unsupported. The practical guard is simply: install
`cryptography` via `pip` into the venv, not via the system package manager.

The probe script is `scratch/mldsa_probe.py` (uncommitted). It prints the
interpreter version and the OpenSSL `cryptography` is linked against, checks the
raw seed / public-byte surfaces, reproduces the Section 6 DNSKEY / DS / keytag,
does a hedged sign→verify round-trip, and exercises PKCS8 round-tripping.

## Rough outline of work

Roughly in dependency order. Merged in three coherent phases (one `master`
merge each), not five separate branches: keygen; offline signer (with the
near-empty key-loading cut folded in); online signing + serve/validate.

1. **Key generation (`adns/keygen.py`)** — *first cut, DONE (v0.14.0,
   merged 2026-08-14).* Added algorithm 18 to `-a`, generate the key with
   `MLDSA44PrivateKey.generate()` (random; no `--seed` flag — the seed form is
   test-only, as the Section 6 oracle), and build the DNSKEY from presentation
   text via a `dnskey_rdata_for()` helper (`f"{flags} 3 18 {base64(pub_raw)}"`)
   rather than `dns.dnssec.make_dnskey` (which rejects alg 18); the existing
   `key_id` and `make_ds` calls work unchanged. **On-disk private-key format
   decided: PKCS8 PEM** — it loads through `adns/crypto.py load_private_key`
   with zero changes and keeps the `.pem` triple uniform with alg 8/13/15.
   (The 32-octet seed via `private_bytes_raw()` is smaller and
   provider-independent, but would need a bespoke loader branch and break the
   "every `.pem` is PKCS8" invariant; deferred as a possible future archival
   format, not precluded.) The `mldsa` import is lazy (inside the alg-18
   branch) so alg 8/13/15 keygen still works below the cryptography ML-DSA
   floor.

2. **Private-key loading (`adns/crypto.py`)** — *DONE (empty cut, folded into
   phase 2).* PKCS8 PEM already loads unchanged (confirmed by the keygen
   round-trip test), so `load_private_key` needed no change for the chosen
   format; `discover_keys` keeps `dns.dnssec.key_id` (works for alg 18). The
   `key_basename` `<zone>+<alg>+<keytag>` triple convention is unchanged.

3. **Offline signing (`adns/signer.py`)** — *DONE (v0.15.0, merged
   2026-08-15).* `rrsig_rdata` branches on the DNSKEY algorithm and delegates
   alg 18 to `_rrsig_rdata_mldsa`, which reconstructs what `dns.dnssec._sign`
   does internally: build the RRSIG rdata with an empty signature, obtain the
   RFC 4034 §3.1.8.1 data-to-be-signed via dnspython's algorithm-agnostic
   (private) `_make_rrsig_signature_data`, sign with pure ML-DSA
   (`context=None`, hedged), and splice the 2420-octet signature in. A
   signing-time guard raises `SignerError` if that private helper is absent,
   keeping alg 8/13/15 signing decoupled from it. `discover_keys`,
   `classify_signers`, the NSEC/NSEC3 chain builders, occlusion, jitter, and
   zone writing are algorithm-independent and untouched. End-to-end test:
   generated alg-18 CSK signs the `signer-mldsa.test` fixture through the real
   `discover_keys → sign_zone` path, every RRSIG verified with an independent
   `MLDSA44PublicKey.verify()` reconstruction (verify-based oracle; hedged
   signing precludes a fixed vector and `dns.dnssec.validate` rejects alg 18).

4. **Online signing (`adns/crypto.py` `sign_rrset`)** — the same alg-18 signing
   path on the dynamic/response side, so a CSK zone can serve alg-18 RRSIGs
   live. The signature cache and CSK model are unchanged.

5. **Serving / validation** — confirm the server serves alg-18 DNSKEY / RRSIG /
   DS correctly and that a validating resolver (or `dnspython` if/when it gains
   alg 18, else an external validator) accepts the chain. Add alg-18 test zones
   to the local matrix, mirroring the existing alg8/13/15 offline+dynamic pairs.

Phase mapping: item 1 = phase 1 (done); items 2–3 = phase 2 (offline signer,
done); items 4–5 = phase 3 (online signing + serve/validate). Items 4 and 5 merge
together — dynamic signing exists so the server can serve live RRSIGs, and the
serving path can't be validated without it.

Version bumps follow the usual rule: alg 18 is new wire/CLI surface, so each
phase is a minor bump (not a patch), moving both `__version__` and the pinned
`@vX.Y.Z` tag in README.md together. Phase 1 shipped **0.14.0**; phase 2
shipped **0.15.0**.
