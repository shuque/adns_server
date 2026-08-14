# adns_server

This is a fully functional authoritative DNS server written in Python.
It serves DNS zones in master file format. I mainly use it for functional
testing and prototyping new protocol features. It is not intended for
production use or high performance applications.

For a detailed technical design document, see **[Design.md](Design.md)**.

## DNSSEC Support

The server implements the DNSSEC protocol extensions. It can serve
pre-signed master file format zones, both NSEC and NSEC3 (e.g. zones
generated with an offline signer like BIND's dnssec-signzone). It can
also perform online signing with a combined signing key. For online
signing it supports several methods of denial of existence:

* [Compact Denial of Existence](https://datatracker.ietf.org/doc/rfc9824/)
  (RFC 9824), using either NSEC or NSEC3. This is enabled per zone with
  'compact_denial: true'.
* [Minimally Covering NSEC records](https://datatracker.ietf.org/doc/rfc4470/)
  (RFC 4470), sometimes called NSEC "white lies": per-query synthesized NSEC
  records covering the smallest interval that proves nonexistence, so no real
  zone contents are exposed and the zone cannot be walked. This is the default
  for an online-signed NSEC zone (i.e. Compact Denial not enabled, and no
  NSEC3PARAM record in the zone). An 'nsec_ideal_predecessor' preference selects
  the ideal (63-octet) predecessor form; the default is a shorter,
  human-readable sentinel form.
* Traditional
  [NSEC3 White Lies](https://www.rfc-editor.org/rfc/rfc7129.html#appendix-B)
  (RFC 7129, Appendix B).

The 'dnssec: true' parameter must be specified in the configuration file
for signed zones. The 'dynamic_signing: true' and 'private_key: /path/to/privatekey.pem'
options are needed for online signing.

## DELEG Support

The server implements the authoritative-server behavior for DELEG, a newly
proposed mechanism for extensible delegation capabilities in the DNS. The
implementation follows
[draft-ietf-deleg-10](https://datatracker.ietf.org/doc/draft-ietf-deleg/) and
[draft-ietf-dnsop-delext-08](https://datatracker.ietf.org/doc/draft-ietf-dnsop-delext/).
DELEG is modeled on the DS record: a DELEG record appears in the parent zone at
the delegation point, is authoritative in the parent, and creates a zone cut.
It uses the (pre-standardization) RR type code 61440 (`TYPE61440`); the
associated DELEGPARAM indirection type uses code 65433.

DELEG handling is always active: any `TYPE61440` RRset in a served zone is
treated as a delegation type. DELEG-aware resolvers negotiate the feature with
the EDNS(0) DE (Delegation Extensions) flag; the server tailors its referral and
occlusion behavior to whether that flag is set. DELEG is supported in both
signed and unsigned zones, and in referrals to signed or unsigned child zones.

For signed zones, DELEG works with both the online signing modes and pre-signed
zones. Most third-party tools that generate pre-signed zones do not understand
that DELEG is a delegation type that must be signed at the parent's delegation
point (they treat it as non-authoritative glue and do not sign it, or
mis-generate the delegation-point NSEC/NSEC3 bitmaps). With online signing, this
program recognizes the DELEG record, places it in the referral for the
corresponding delegation, and generates the signature dynamically.

For offline signing, the package includes a DELEG-aware zone signer,
`signzone` (`adns/signer.py`), which signs the DELEG RRset at the cut and sets the DELEG bit in
the delegation-point NSEC/NSEC3 bitmap, so the program can serve pre-signed
zones with DELEG. See the offline-signer section of **[Design.md](Design.md)**
(§8).

For the full details of the implementation — type codes and EDNS signaling, the
DE=1 and DE=0 referral/occlusion behavior, the DNSSEC proofs used, the relevant
functions in the code, and specific tweaks needed to support Compact Denial of
Existence — see **[DELEG.md](DELEG.md)**.

### Pre-requisites

* Python 3
* Python Cryptography module
* The dnspython module, version 2.3 or greater
* sortedcontainers
* PyYAML module
* siphash module (for DNS cookie support)
* cachetools (for online signature cache)

### Installation

To install from a local copy of this repository:

```
pip3 install .
```

To install from the git repo directly:

```
pip3 install git+https://github.com/shuque/adns_server.git
```

To install a specific released version, append the tag, e.g.
`...adns_server.git@v0.13.0`.

For development, install in editable mode from a local checkout so that the
console scripts (`adns-server`, `signzone`, `adnskeygen`) point back at your
working tree and pick up edits without reinstalling:

```
pip3 install -e .
```

Installing into a virtualenv does not require activating it first: invoking
the venv's interpreter directly (e.g. `/path/to/venv/bin/python3 -m pip
install -e .`) installs into that environment regardless. Activation
(`. /path/to/venv/bin/activate`) only puts the venv's `bin/` on your `PATH` —
so activate the environment (or use the full path to each script) before
running the installed `adns-server`/`signzone`/`adnskeygen` commands.

Without any install, the entry points can also be run directly from the repo
as modules: `python3 -m adns`, `python3 -m adns.signer`, `python3 -m
adns.keygen`.

### Usage

```
$ adns-server -h
usage: adns-server [-h] [--version] [-c FILE] [-w DIR] [-d] [-p N]
                   [-s ADDR] [-u USER] [-g GROUP] [-4 | -6] [-f] [-e N]

adns-server version X.Y.Z - An authoritative DNS server

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
  -c FILE     Configuration file (default: adnsconfig.yaml)
  -w DIR      Working directory (overrides config workdir)
  -d          Turn on debugging
  -p N        Listen on port N (default: 53)
  -s ADDR     Bind to server address (default: wildcard)
  -u USER     Drop privileges to UID of specified user (if started as root)
  -g GROUP    Drop privileges to GID of specified group (if started as root)
  -4          Use IPv4 only
  -6          Use IPv6 only
  -f          Remain attached to foreground
  -e N        Max EDNS bufsize in octets for responses we send out (-e 0
              disables EDNS support)

Note: a configuration file that minimally specifies the zones to load must be present.
```

### Configuration file

An example configuration file looks like the following. At a minimum
it needs so specify the "zones:" section, defining the zone names and
zone files for each zone that the server will serve.

The configuration file supports additional options beyond what can
be specified via command line switches. Such as contents of the NSID
option, DNSSEC parameters, etc.

```
config:
  port: 5309
  user: "named"
  group: "named"
  edns: 1432
  minimal_any: false
  nsid: "dnstest.example.com"
zones:
  - name: "example.com"
    file: "zonefile.example"
  - name: "signedzone.com"
    dnssec: true
    file: "zonefile.signedzone"
  - name "onlinesigning.com"
    dnssec: true
    file "zonefile.onlinesigning"
    dynamic_signing: true
    private_key: "/path/to/privatekey.pem"
```

### Key Generation for DNSSEC Signing

This package also includes a small console script, `adnskeygen` (`adns/keygen.py`,
also runnable as `python3 -m adns.keygen`), to help generate DNSSEC keys, used
for both online signing configurations and offline signing with the `signzone`
tool.

```
$ adnskeygen -h
usage: adnskeygen [-h] [-a N] [-b N] [-f N] [-K DIR] [--prepublish] zone

positional arguments:
  zone                  DNS zone name

options:
  -h, --help            show this help message and exit
  -a N                  DNSSEC algorithm number: 8 (RSASHA256),
                        13 (ECDSAP256SHA256), 15 (ED25519) (default: 13)
  -b N, --bits N        RSA key size in bits for algorithm 8; ignored for
                        13/15 (default: 1280, minimum: 1280)
  -f N                  Value of DNSKEY flags field (default: 257)
  -K DIR, --keydir DIR  write keytag-named .pem/.dnskey/.ds triple here
  --prepublish          write the private key as .prepublish.pem so the
                        DNSKEY can be pre-published while signzone ignores
                        it until it is renamed to .pem (requires -K)
  ```

  An example usage to generate an ECDSA NIST P256 (algorithm 13)
  key for example.com follows.

  ```
  $ adnskeygen example.com
### Private Key file contents:
-----BEGIN PRIVATE KEY-----
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++++++++++XXXXXXXX
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++++++++++XXXXXXXX
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++XXXXXXXX
-----END PRIVATE KEY-----

### DNSKEY RDATA:
257 3 13 oBQvOkuVPdp7Wes6EcWra7UlyI3u9EeM nRd79CSmq4ggIobc7oVPxTq3NhespdTC hZ4gArRqrftxjsUxjP0dOQ==
### DNSKEY keytag: 56959

### DNSKEY RRset:
example.com. 7200 IN DNSKEY 257 3 13 oBQvOkuVPdp7Wes6EcWra7UlyI3u9EeM nRd79CSmq4ggIobc7oVPxTq3NhespdTC hZ4gArRqrftxjsUxjP0dOQ==

### DS record
56959 13 2 ac2c59edcb0d9021d6898e2824cd63fd67c3d8c0b6da69943121b5b5263bdbad
```

`adnskeygen` generates keys for algorithms 8 (RSASHA256), 13 (ECDSAP256SHA256),
and 15 (ED25519) — the set marked RECOMMENDED for signing in the IANA DNSSEC
Algorithm Numbers registry. For algorithm 8, `-b/--bits` sets the RSA modulus
(default and minimum 1280 bits; a small default keeps NSEC3 negative responses
under the common path-MTU). The server itself imposes no algorithm allowlist
for serving or online signing: it serves zones pre-signed with any algorithm
supported by dnspython/`cryptography` (e.g. RSA zones signed by BIND's
`dnssec-signzone`) and can online-sign with algorithm 8 as well.

## Generating DELEG / DELEGPARAM Records

The package includes a console script, `deleg-rdata` (`adns/deleg_rdata.py`,
also runnable as `python3 -m adns.deleg_rdata`), that generates a DELEG or
DELEGPARAM resource record in RFC 3597 generic (`\#`) presentation format from
a set of DelegInfo `key=value` pairs. The RDATA is the DelegInfos list of
draft-ietf-deleg Section 3, which reuses the SVCB SvcParams wire encoding
(RFC 9460). The reusable codec lives in the `adns.deleg` library module.

```
$ deleg-rdata child.example. server-ipv4=192.0.2.1 server-ipv6=2001:db8::1
child.example. IN TYPE61440 \# 28 00010004c00002010002001020010db8000000000000000000000001

$ deleg-rdata --type DELEGPARAM -v cfg.example. \
              server-name=ns1.example.,ns2.example.
cfg.example. IN TYPE65433 \# ...
```

Use `--type DELEGPARAM` (default is `DELEG`) or a numeric type code, `--ttl` to
include a TTL, `--origin` to resolve relative names in
`server-name`/`include-delegparam` values, `--strict` to treat Section 3.4/3.5
semantic violations as errors instead of warnings, and `-v` for an octet-level
breakdown of the RDATA on stderr.

## Testing

An automated test suite lives under `tests/pytest/`. It launches a private
instance of the server on an ephemeral loopback port, tests it with real DNS
queries via dnspython, and asserts on the semantics of the responses (RCODE,
flags, sections, Extended DNS Errors). For signed zones it also cryptographically
validates the DNSSEC signatures and NSEC/NSEC3 proofs.

The suite is self-contained: it manages the server process and uses its own
purpose-built zones under `tests/pytest/test_zones/` (online signed at runtime),
so no manual setup or pre-signed data is required.

To install the test dependency (pytest) and run the suite:

```
pip3 install -e '.[test]'
pytest
```

Or run it directly without installing the extra:

```
python3 -m pytest tests/pytest -v
```

Set `ADNS_TEST_KEEP_LOG=1` to print the server log on teardown when debugging a
startup failure. See `tests/pytest/README.md` for details on the fixtures,
assertion helpers, and test zones.

### Running a subset of the tests

The suite defines pytest markers so functional areas can be run in isolation
with `-m`:

| Marker   | Selects                                                      |
| -------- | ----------------------------------------------------------- |
| `signer` | offline zone signer (`adns.signer`) tests — no running server |
| `deleg`  | DELEG delegation-extension behavior tests                   |

```
python3 -m pytest tests/pytest -m signer    # just the signer tests
python3 -m pytest tests/pytest -m deleg     # just the DELEG tests
python3 -m pytest tests/pytest -m "not deleg"
```

The `signer` set is self-contained and never launches the server, so it runs
in a fraction of the full-suite time. `pytest --markers` lists the registered
markers. You can also select by path (`tests/pytest/test_signzone*.py`) or by
node-name substring (`-k signzone`).
