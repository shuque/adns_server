# adns_server

This is a fully functional authoritative DNS server written in Python.
It serves DNS zones in master file format. I mainly use it for functional
testing and prototyping new protocol features. It is not intended for
production use or high performance applications.

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
* Traditional NSEC3 White Lies.

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

A per-zone configuration flag `deleg_enabled: true` is required to enable DELEG
handling for a zone. DELEG-aware resolvers negotiate the feature with the
EDNS(0) DE (Delegation Extensions) flag; the server tailors its referral and
occlusion behavior to whether that flag is set. DELEG is supported in both
signed and unsigned zones, and in referrals to signed or unsigned child zones.

For signed zones, DELEG can currently only be used with the online signing
modes. This is because most tools that generate pre-signed zones do not
understand that DELEG is a delegation type that must be signed at the parent's
delegation point (they treat it as non-authoritative glue and do not sign it,
or mis-generate the delegation-point NSEC/NSEC3 bitmaps). This program
recognizes the DELEG record, places it in the referral for the corresponding
delegation, and generates the signature dynamically. (A future DELEG-aware
zone signer would let the program also serve pre-signed zones with DELEG.)

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
`...adns_server.git@v0.10.0`.

### Usage

```
$ adns_server.py -h
usage: adns_server.py [-h] [--version] [-c FILE] [-w DIR] [-d] [-p N]
                      [-s ADDR] [-u USER] [-g GROUP] [-4 | -6] [-f] [-e N]

adns_server.py version X.Y.Z - An authoritative DNS server

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

### Key Generation for Online Signing

This repo also includes a small script, genkey.py, to help generate
DNSSEC keys used for online signing configurations.

```
$ ./genkey.py -h
usage: genkey.py [-h] [-a N] [-f N] zone

positional arguments:
  zone        DNS zone name

optional arguments:
  -h, --help  show this help message and exit
  -a N        DNSSEC algorithm number (default: 13)
  -f N        Value of DNSKEY flags field (default: 257)
  ```

  An example usage to generate an ECDSA NIST P256 (algorithm 13)
  key for example.com follows.

  ```
  $ ./genkey.py example.com
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
