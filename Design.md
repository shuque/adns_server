# adns_server — Architecture and Design

This document describes the architecture of `adns_server`: the authoritative DNS
server (`adns/server.py`, entrypoint `adns/__main__.py`), the offline DNSSEC
zone signer (`adns/signer.py`), and the key generator (`adns/keygen.py`), all
built on a shared zone/DNSSEC model (`adns/zone.py`). This reflects the
post-module-split layout (§10, now fully implemented); earlier sections that
still describe file paths in the pre-split single-file form (`adns_server.py`,
`signzone.py`, `adnskeygen.py`, `dnssec_util.py`) are historical and superseded
by §10.

It is a descriptive reference for the code as it stands. §10 documents the
`adns/` package architecture and records, task by task, how the earlier
single-file layout was split into it.

Companion documents:
- **DELEG.md** — serving-side DELEG semantics (type codes, DE-flag signaling,
  DE=1/DE=0 referral and occlusion behavior, the DNSSEC proofs, the
  Compact-Denial interaction). This document does not restate that material; §5
  references it.
- **README.md** — user-facing feature summary, installation, configuration, and
  usage.

---

## 1. Overview and scope

`adns_server` is a functional, authoritative DNS server written in Python.
Its main purpose is prototyping and protocol-conformance experimentation —
DELEG, Compact Denial of Existence, online signing, DNS cookies — not
production serving or high throughput.

The package comprises three programs over one shared library, all inside the
`adns/` package (console scripts `adns-server`/`signzone`/`adnskeygen`; see
§10 for the full module layout):

| Program | Role |
|---|---|
| `adns/server.py` (+ `adns/__main__.py`) | The authoritative server: loads zones, answers queries, signs online. |
| `adns/signer.py` | Offline DNSSEC signer: strip-and-re-sign a zone to a `.signed` file. |
| `adns/keygen.py` | DNSSEC key generator: emits keytag-named PEM / DNSKEY / DS files. |
| `adns/zone.py` | Shared model: the `Zone` subclass, NSEC/NSEC3 helpers, `RRtype`. |

**What the server does:** serves zones in master-file format; supports unsigned
zones, pre-signed zones (NSEC and NSEC3), and online (dynamic) signing with a
combined signing key. For online signing it offers three denial-of-existence
styles — Compact Denial (RFC 9824), RFC 4470 minimally-covering NSEC ("white
lies"), and traditional NSEC3 white lies.

**DELEG support:** It also supports the DELEG protocol (in-progress work in the
IETF). No special server or zone configuration is needed for this. If a served
zone contains DELEG records, the server will automatically employ DELEG protocol
compliant behavior for serving such delegations.

**Not yet supported:** Features not supported today, but which might be
implemented in the future, include Zone Transfer (AXFR/IXFR), Dynamic Update,
persistent TCP connections, Secure Transport (DoT or DoQ), etc.

**Runtime shape:** one multi-threaded process with a `select()`-driven accept
loop that dispatches each query to a short-lived worker thread, capped by a bounded
semaphore. State is held in a `ServerContext` passed explicitly down the query
path; the only process-wide singletons are the logging facility and the online
signature cache.

---

## 2. Data model

The data model is the foundation the rest of the system builds on, and it lives
in `adns/zone.py` so both the server and the offline signer share the same
notion of what a zone is. (`load_private_key`/`key_basename` live in
`adns/crypto.py`; see §10.2. The pre-split `dnssec_util.py` compatibility shim
that used to re-export these has been retired — Task 9, §10.2.)

### 2.1 The `Zone` subclass and its `SortedDict` backend

`Zone(dns.zone.Zone)` overrides dnspython's node map with a `SortedDict`
(`map_factory = SortedDict`) from the `sortedcontainers` package instead of the
default `dict`. This allows the server to correctly and efficiently implement
DNSSEC functions.

DNSSEC authenticated denial is fundamentally about *ordering*: NSEC proves
nonexistence by naming the canonically-adjacent owners that bracket a gap, and
NSEC3 does the same over hashed owners. A plain hash map gives O(1) lookup but
no notion of "the name just below X" or "the next name after Y." A sorted
container gives both: `SortedDict.bisect_left` / `bisect_right` / `peekitem`
locate the predecessor or successor of an arbitrary (even nonexistent) name in
O(log n), which is exactly the primitive the covering-NSEC and covering-NSEC3
searches need.

Concretely, the sorted dictionary backend powers:
- `nsec_covering(name)` — walk left from `bisect_left(name) - 1` to the nearest
  owner that actually has an NSEC RRset.
- `nsec3_covering(name)` — the same over hashed owner names (NSEC3 sorts by
  hash, so the zone's sorted order *is* the NSEC3 chain order once owners are
  hashed).
- `covering_predecessor(name, ideal)` / `covering_successor(name)` — the RFC
  4470 white-lie synthesis, which must find the real floor/ceiling around a
  synthetic name to guarantee the synthesized owner neither collides with nor
  spans a real name.

`zone_from_file()` loads the zone with dnspython — whose reader honors the
`Zone.map_factory`, so `zone.nodes` comes back as a `SortedDict` directly — then
runs the ENT pass and computes the SOA minimum TTL. (A dnspython 2.0-era
regression once remapped the node dict back to a plain `dict`, fixed well before
our 2.7.0 floor; the invariant is guarded by
`test_zone_nodes_use_map_factory` rather than a runtime re-wrap.)

Names are stored **fully qualified, non-relativized** (`relativize=False`).
Relativized names would break canonical ordering and the label surgery used
throughout NSEC synthesis.

Note that dnspython version 2.8 now supports a btree zone implementation
("dns/btreezone.py provides another zone versioned implementation built on
top of a B-tree. It maintains DNSSEC sort order, labels nodes as delegation
points or glue, and can find the “bounds” of a name."). However, it needs
Python 3.10, which exceeds our current required ceiling of Python 3.9, the
version of Python that ships on popular platforms like RHEL 9 and Amazon
Linux 2023.


### 2.2 Empty non-terminals (ENT synthesis)

An empty non-terminal is a name that owns no RRset but has descendants (e.g.
`b.example.` when only `a.b.example.` exists) that do.

`add_ent_nodes()` (called at load time by `zone_from_file()`) walks every owner
up toward the apex and inserts an explicit empty `Node` into the `SortedDict`
for each missing interior name. This makes ENTs first-class nodes so
`get_node()` distinguishes "exists but empty" (NODATA) from "does not exist"
(NXDOMAIN) with a single lookup, and so covering searches see the ENT in sorted
order. (An alternative future design could forego this pre-population in favor
of dynamically detecting ENT nodes at the cost of a few more runtime lookups
into the Zone database.)

ENTs interact with the two denial styles oppositely, and this asymmetry is a
recurring subtlety (see §5 and the signer):
- **NSEC:** ENTs get **no** NSEC record (RFC 4035 §2.3 — only names that owned
  an RRset before signing get an NSEC). The signer's NSEC pass must therefore
  positively select real-data / delegation owners and skip synthesized ENTs.
- **NSEC3:** every ENT **does** get an NSEC3 (RFC 5155 §7.1). The signer's
  NSEC3 pass hashes ENT nodes too.

### 2.3 `HashableRRset`

`dns.rrset.RRset` is not hashable, but the online signature cache needs RRsets
as dictionary keys. `HashableRRset` wraps an RRset and derives a hash/equality
key from the owner name, type, **and** a canonical order-independent
representation of the RDATA (`frozenset` of each rdata's `to_digestable()`).

Keying on RDATA — not just name+type — is essential: synthesized records
(an NSEC with a computed next-name, or a minimal NSEC3) can share an owner name
and type while carrying different RDATA across different responses. Keying on
RDATA prevents the cache from returning a signature computed over one variant
for a different one.

### 2.4 `AUTH_IN_PARENT_RRTYPES` and `RRtype`

`RRtype` is an `IntEnum` of type codes the system uses that are not (yet)
available as named constants in dnspython: `NXNAME = 128` (Compact Denial),
`DELEG = 61440`, `DELEGPARAM = 65433`. These fall into two distinct categories:

- `NXNAME` **is standardized** — it is defined by RFC 9824 (Compact Denial of
  Existence). It appears here only because the installed dnspython release does
  not yet recognize it; once dnspython catches up this entry becomes redundant.
- `DELEG` and `DELEGPARAM` are **not yet standardized**. Their code points are
  pre-standardization placeholders agreed with collaborators
  (`DELEG = 0xF000`, in the proposed delegation-TYPE range; `DELEGPARAM =
  65433`) and will change if/when IANA assigns them.

`AUTH_IN_PARENT_RRTYPES = [DS, DELEG]` is the set of types that are
authoritative *in the parent* at a delegation cut. The server uses it to
decide when a query at a cut is answered locally versus referred, and the signer
uses it to decide which RRsets at a cut get signed (DS and DELEG yes; NS and
glue no).

### 2.5 `ZoneDict`

`ZoneDict` maps zone origins to `Zone` objects and answers "which zone is
authoritative for this qname?" via `find()`, which scans a reverse-sorted zone
list so the longest (most specific) enclosing origin wins. It is a plain dict
plus a cached sorted name list.

---

## 3. Zone and configuration mechanism

### 3.1 Configuration sources and precedence

Server configuration comes from three sources, in strict precedence order:
**command line > config file > `Preferences` defaults.**

- `Preferences` is a dataclass holding every tunable with its default value. It
  is deliberately constructed with no argparse defaults for options that can
  also be set in the config file, so an unsupplied CLI option stays `None` and
  does not clobber a config-file value.
- `init_config()` reads the YAML config, applying `config:` keys onto
  `Preferences` and loading the `zones:` list.
- `process_args()` parses the command line and overlays only the options that
  were actually given.

`ServerContext` bundles the resolved `Preferences`, the loaded `ZoneDict`, the
DNS-cookie secret, and the socket dispatch table. It is passed explicitly into
the query path rather than held globally, so the request machinery has no hidden
dependencies (which also makes it directly unit-testable — see the test suite's
`ctx` modality).

The one intentional exception is logging: `log_message()` and its state are a
process-wide singleton because logging must work before any context exists
(early startup, argument parsing) and is global regardless of how many zones are
served.

### 3.2 Per-zone loading

`make_single_zone()` builds each `Zone`:
1. `zone_from_file()` parses the master file (fully-qualified, ENT-augmented,
   SOA-min-TTL computed).
2. If `dnssec: true`, `init_dnssec()` records the DNSSEC posture and captures
   the apex NSEC3PARAM (enforcing a single-NSEC3PARAM rule); the presence or
   absence of that record is the NSEC3-vs-NSEC switch, data-driven with no
   separate flag.
3. If `dynamic_signing: true`, the private key is loaded and `init_key()`
   records it plus the signing DNSKEY and its keytag; `compact_denial` is read.
4. `reject_wildcard_deleg()` enforces delext §4.4 (no Delegation Types at a
   wildcard owner) at load time — the same invariant the signer enforces.
5. Per-zone serving flags (`udp_truncate_all`, `require_server_cookie`) are
   recorded.

Relative zone/key paths are resolved against the working directory; a `-w` on
the command line wins over the config `workdir` and keeps winning across SIGHUP
re-reads (`workdir_cli`).

### 3.3 Reload and Termination

SIGHUP re-runs `init_config()` and clears the online signature cache, so zone
edits and config changes take effect without a restart. Zone *files* are the
source of truth; the server never writes them back.

SIGTERM cleanly terminates the server, and in background mode, deletes the
pid file.

---

## 4. Query-processing pipeline

A query's life, from wire to wire:

1. **Ingress** (`handle_connection_udp` / `handle_connection_tcp`) reads the
   datagram or the length-prefixed TCP message and constructs a `DNSquery`,
   which parses the wire message, extracts qname/qtype/qclass, and logs it. TCP
   reads are governed by a whole-transaction deadline (§7).
2. **`DNSresponse.__init__`** builds the response skeleton via
   `make_response()`, canonicalizes (downcases) the qname for internal
   processing — critical so synthesized owner names and NSEC next-names stay in
   canonical case and online signatures match regardless of 0x20 case
   randomization — clears AA, and calls `prepare_response()`.
3. **`prepare_response()`** is the top-level dispatcher: it handles opcode
   (NOTIFY/UPDATE/non-QUERY early-outs), EDNS negotiation (`do_edns_init`,
   version check, cookie processing), the BADCOOKIE and header-only paths, the
   QCLASS and meta-type checks, then calls `find_answer()`. Finally it emits the
   EDNS OPT RR (`do_edns_final`) and sets AA on authoritative NOERROR/NXDOMAIN
   answers.
4. **`find_answer()`** selects the zone from the `ZoneDict` (REFUSED with an EDE
   if none), then applies pre-serving gates: force-truncate zones, and the
   require-server-cookie gate. Otherwise it calls `find_answer_in_zone()`.
5. **`find_answer_in_zone()` / `process_name()`** is the descent down the DNS
   tree from apex toward the qname, one label at a time. At each interior name
   `process_name()` checks, in order: does the node exist (else wildcard or
   NXDOMAIN); is there a DNAME (redirect); is there a delegation cut (NS and/or
   DELEG → referral or occlusion, per DE flag — see §5 and DELEG.md). When the
   search name reaches the qname, `find_rrtype()` produces the answer.
   This roughly follows the algorithm specified in RFC 1034, Section 4.3.2,
   enhanced to incorporate DNAME and DELEG processing.
6. **`find_rrtype()`** resolves the terminal outcome: ANY handling, CNAME
   chasing, the exact-type answer, or NODATA (which triggers the denial machinery
   in §5).
7. **Egress** (`to_wire`) serializes with the computed max size, truncating
   (TC=1) if the response overflows the UDP budget.

CNAME and DNAME chains are followed within `find_answer` with loop detection
(owner lists → SERVFAIL on a loop). The descent returns a boolean "finished"
signal so the caller knows whether to append the next label or stop.

---

## 5. DNSSEC

This section covers the server's online (dynamic) DNSSEC: on-demand signing, the
denial-of-existence matrix, and DELEG signing. The offline signer and key
generator are described separately in §8 and §9. The serving-side DELEG
*semantics* (DE=1/DE=0 referral and occlusion, the Compact-Denial interaction)
live in **DELEG.md**.

### 5.1 Online signing and the signature cache

When a zone has `dynamic_signing: true`, RRsets are signed on demand as
responses are built. `sign_rrset(zone, h_rrset)`, defined in `adns/crypto.py`,
wraps `dns.dnssec.sign` with inception/expiration derived from the current
time (`RRSIG_INCEPTION_OFFSET`, `RRSIG_LIFETIME`) and returns an RRSIG RRset.

It is wrapped in a `cachetools.TTLCache` (keyed by zone + `HashableRRset`, §2.3)
because the same RRset is frequently re-signed across queries, and public-key
signing is the server's dominant cost. The cache TTL is set below the signature
lifetime so cached signatures never approach expiry. SIGHUP clears the cache.

`add_rrset()` is the choke point through which every RRset reaches a response
section: it dedups, then — for DO queries — either signs online, fetches a
precomputed RRSIG from a pre-signed zone, or does nothing (unsigned). It also
handles the RFC 2308 / RFC 4034 §3 TTL subtlety for SOA-in-negative-responses
(lower the wire TTL to the SOA minimum without disturbing the RRSIG Original
TTL).

### 5.2 The denial-of-existence matrix

Denial of existence is the most intricate part of the response machinery, because
the server supports several styles and each has an NSEC and an NSEC3 form, times
NXDOMAIN vs NODATA, times online vs pre-signed. The dispatch is centralized in
`nxdomain()` and `nodata()`, which branch on `online_signing()`, `nsec3param`,
and `compact_denial`:

| Style | NXDOMAIN | NODATA |
|---|---|---|
| Online NSEC, white lies (RFC 4470) | `nxdomain_nsec_online` — covering NSEC around the next-closer + wildcard | `nodata_nsec_online` — matching NSEC |
| Online NSEC, Compact Denial | `nxdomain_nsec_online_compact` — NXNAME black lie | `nodata_nsec_online` |
| Online NSEC3, white lies | `nxdomain_nsec3_online` — closest-encloser proof | `nodata_nsec3_online` |
| Online NSEC3, Compact Denial | `nxdomain_nsec3_online_compact` — NXNAME black lie | `nodata_nsec3_online_compact` |
| Pre-signed NSEC | `nxdomain_nsec` | `nodata_nsec` |
| Pre-signed NSEC3 | `nxdomain_nsec3` | `nodata_nsec3` |

The two **online white-lie** constructions — `nxdomain_nsec_online` (RFC 4470)
and `nxdomain_nsec3_online` — are the subtlest code in this area. Both
synthesize *minimal* covering records on the fly whose intervals must
reconstruct the correct closest encloser / next-closer for a strict validator,
without colliding with or spanning a real name. The NSEC form synthesizes two
NSECs (one covering the queried name, one covering the relevant wildcard) with
owner/next names built around the *next-closer* name rather than the full qname;
the `successor_name` / `covering_predecessor` / `covering_successor` helpers
(`adns/zone.py`) implement the interval endpoints and collision-avoidance
rules, documented at length in their docstrings and in the `rfc4470-white-lies`
design note. The NSEC3 form is arguably more involved: it assembles the full
closest-encloser proof from three minimal NSEC3 records — closest-encloser
match, next-closer cover, and wildcard cover — each over hashed owner names.

**Compact Denial** (RFC 9824) replaces a conventional NXDOMAIN response with a
NODATA response that contains a single NXNAME-bearing "black lie" NSEC/NSEC3 at
the queried name, and sets NXDOMAIN in the RCODE only when the client signaled
Compact-Answers-OK.
The DELEG-occlusion path deliberately does **not** downgrade to a black lie even
in Compact-Denial zones — see DELEG.md for that rationale (keeping the DELEG bit
visible for downgrade detection).

### 5.3 DELEG signing (online)

For online-signed zones the DELEG record at a cut is recognized, placed in the
referral, and signed dynamically like any authoritative RRset, because
`AUTH_IN_PARENT_RRTYPES` classifies it as authoritative-in-parent (§2.4). The
delegation-point NSEC/NSEC3 bitmap includes the DELEG bit because it is built
from the node's actual present types. `add_nsec_online()`'s special
covering-next-name form (`owner` → `owner\000`) is triggered by NS **or** DELEG
at the cut, so a DELEG-only cut gets the same covering NSEC a classic NS
delegation would.

### 5.4 Supported signature algorithms

The **key-generation tool (`adnskeygen`, §9) is restricted to algorithms 8
(RSASHA256), 13 (ECDSAP256SHA256), and 15 (ED25519)** — the set marked
RECOMMENDED for signing in the IANA DNSSEC Algorithm Numbers registry, plus
the pre-standard post-quantum algorithm 18 (MLDSA; for details, see §11).
ECDSA/EdDSA remain the natural choice for online signing (cheap public-key
operations); RSASHA256 is supported primarily for precomputed offline
signatures and interoperability with the large installed base of RSA-signed
zones. For algorithm 8 the RSA modulus is set by `adnskeygen -b/--bits`
(default and floor 1280 bits — deliberately small so NSEC3 negative responses
stay under the common Internet path-MTU and avoid fragmentation/TCP retry).

**Serving and online signing impose no algorithm allowlist.** The serving path
emits DNSKEY/RRSIG/NSEC(3) rdata opaquely, and online signing delegates hash
selection to `dns.dnssec.sign()` via the DNSKEY's algorithm. So any signature
algorithm whose keys or precomputed signatures are present and supported by the
underlying dnspython and `cryptography` packages will be served (and, if a
matching private key is configured, online-signed) correctly — independent of
`adnskeygen`'s narrower generation set.

---

## 6. Network and runtime

### 6.1 Sockets and the event loop

`setup_sockets()` opens UDP and TCP listeners for the configured address
family/families and returns a dispatch dict keyed by `fileno` →
`(sock, handler, is_tcp)`. Keying on fileno lets `select()` consume the dict's
keys as its read list and lets the loop look up a ready descriptor directly.

`run_event_loop()` is a classic `select()` accept loop: wait for readable
descriptors, and for each, acquire a worker slot and dispatch. It is
single-threaded at the accept layer; concurrency comes from handing each query
to a worker thread.

### 6.2 Worker threads

Each accepted query runs in its own thread (`spawn_worker`), created as a
**daemon thread** so a worker still blocked at shutdown (e.g. a TCP thread in
`recv()` on a stalled client) does not delay interpreter exit — non-daemon
threads would be joined by `threading._shutdown()`, making SIGTERM hang and
defeating the atexit pidfile cleanup. The worker wrapper releases its semaphore
slot in a `finally` so the slot returns however the handler exits.

### 6.3 Daemonization, privileges, signals

- `daemon()` does the double-fork/setsid dance, writes the pidfile (registering
  an atexit remover), closes inherited descriptors via a bounded helper
  (`close_range` where available), and reopens 0/1/2 to `/dev/null`.
- `drop_privs()` drops to a configured uid/gid when started as root.
- Signal handlers: SIGTERM exits cleanly (letting atexit run); SIGHUP re-reads
  config/zones and clears the signature cache. `handle_sighup` closes over the
  context to reach `prefs`/`zonedict`, since `signal.signal` handlers take a
  fixed `(signum, frame)` signature.

---

## 7. Resource limiting and hardening

These mechanisms bound local resource consumption under load. They are not, and
are not intended to be, defenses against spoofed-source or amplification
attacks — that is out of scope for a prototype (`run_event_loop`'s docstring
states this explicitly).

- **Concurrency cap.** A `BoundedSemaphore(max_workers)` (default 256) caps
  concurrent worker threads. When the cap is hit the loop *sheds* the event
  rather than blocking the accept loop: for UDP it reads and drops the datagram;
  for TCP it accepts and immediately closes. Both consume the readable event so
  `select()` does not re-fire on the same fd and spin.
- **Slow-client protection.** TCP reads use a whole-transaction deadline
  (`tcp_timeout`, default 5s, RFC 7766 §8): the socket timeout is reset to the
  remaining budget before each `recv()`, so a client that dribbles bytes cannot
  reset the clock and hold a worker indefinitely. On timeout the connection is
  dropped (no SERVFAIL to a peer that is not reading).
- **DNS cookies** (RFC 7873, SipHash-2-4). The server computes a server cookie
  over the client cookie, client IP, and a timestamp under a per-process secret,
  with drift and recalculation windows. Zones may set `require_server_cookie` to
  gate answers on a verified cookie (BADCOOKIE otherwise), mitigating
  off-path spoofing and amplification for cookie-capable clients. There is no
  capability yet however to require cookies selectively (e.g. under conditions
  of duress).
- **Rate-limited logging.** `RateLimitedLog` emits at most one message per
  interval with a suppressed-since count, so events that recur at
  attacker-controlled rates (request shedding under the worker cap) cannot turn
  the log itself into an amplification/DoS vector.
- **Response size / truncation.** `max_size()` computes the UDP budget from the
  EDNS payload negotiation; `truncate()` sets TC and empties sections when a
  response overflows. Zones may force truncation (`udp_truncate_all`) to test
  TCP fallback.

---

## 8. The offline signer (`adns/signer.py`)

The offline signer produces a conventional pre-signed zone (`.signed`) that the
server — or any RFC 4035/5155 authoritative server — can serve. It exists so
DELEG zones can be served pre-signed, which current third-party signers mostly
can't do (they treat DELEG as non-authoritative glue and neither sign it nor set
its bitmap bit). It shares the entire zone/DNSSEC model with the server via
`adns/zone.py` (plus `adns/crypto.py` for key loading and `adns/constants.py`
for `AUTH_IN_PARENT_RRTYPES`), so its output matches the server's serving
semantics by construction. It ships as the `signzone` console script
(`adns.signer:main`), and is also runnable as `python3 -m adns.signer`.

**CLI and I/O contract.** `signzone [options] <zonename> <zonefile>`; zone
name is explicit (no `$ORIGIN` guessing). Output is `<zonefile>.signed` by
default (`-o -` for stdout), written to a temp file and atomically renamed on
success so a failed run leaves no partial output and never overwrites the input.

| Flag | Meaning | Default |
|---|---|---|
| `-K, --keydir DIR` | directory of keytag-named PEM private keys | `.` |
| `-o, --output FILE` | output file (`-` = stdout) | `<zonefile>.signed` |
| `-e, --expiration T` | RRSIG expiration | `+30d` |
| `-i, --inception T` | RRSIG inception | `-1h` |
| `-j, --jitter N` | ± window applied per-RRSIG to expiration | `6h` |
| `--bump` | increment SOA serial (in-memory only) | off |
| `-v, --verbose` | per-RRset signing trace | off |

Time syntax accepts bare seconds, `s/m/h/d/w/y` suffixes, signed relative forms
(`+30d`, `-1h`), and a 14-digit absolute `YYYYMMDDHHMMSS` (BIND-compatible).

**Key discovery.** DNSKEYs come from the zonefile. For each, the signer computes
the keytag and loads `<keydir>/<zone>+<alg>+<keytag>.pem` by **exact** filename
(not a `*.pem` glob), so differently-suffixed PEM files (e.g. `.prepublish.pem`)
are deliberately ignored. A DNSKEY with no matching PEM is **publish-only** (kept
in the RRset, not used to sign); no PEM for *any* DNSKEY is a hard error. This
publish-only rule enables key rollover.

**Key classification and roles** (SEP bit, `dns.rdtypes.dnskeybase.SEP`):
- **CSK** (single SEP key, no separate ZSK) signs everything.
- **KSK + ZSK:** the KSK signs only the DNSKEY RRset; the ZSK signs everything
  else.
- Invariant: sign the DNSKEY RRset with every SEP key that has a PEM; sign
  everything else with every non-SEP key that has a PEM (a CSK counts as both).

This makes multi-key rollover possible: two ZSKs where one is publish-only
is a pre-publish ZSK roll; two KSKs both with PEMs is a double-signature KSK
roll.

**Signing pipeline.** Strip all existing RRSIG/NSEC/NSEC3 (retain DNSKEY and
NSEC3PARAM); resolve one absolute RRSIG window (shared inception, per-RRSIG
jitter on expiration); walk the zone in sorted canonical order signing each
authoritative RRset — at a cut only DS and DELEG are signed, never NS or glue;
then build the denial chain. NSEC mode links each real-data/delegation owner's
NSEC to the next in canonical order (ENTs excluded, §2.2); NSEC3 mode
(data-driven from apex NSEC3PARAM) hashes every owner **including ENTs**, sorts
by hash, and links the hash-ordered chain. The signing RRSIG helper is a plain,
un-cached function in `adns/signer.py` (distinct from the server's cached
`sign_rrset`).

**DELEG in the signer** reduces to: the cut predicate recognizes
`RRtype.DELEG`, and the authoritative-at-a-cut set is `AUTH_IN_PARENT_RRTYPES`.
Everything else is the generic engine. DELEG and DELEGPARAM are handled as RFC
3597 generic rdata; dnspython loads, digests, and builds NSEC/NSEC3 bitmaps for
the numeric types without registration. `reject_wildcard_deleg()` runs first
and fails the run (nonzero, no output) on a wildcard-DELEG violation. The
DNSKEY-ADT bit needs no signer code: `adnskeygen -f 259` generates such a
key and the signer treats it generically.

**Operator workflows.** (i) *Unsigned zone as source of truth* (recommended):
edit the small unsigned file, regenerate `.signed` on each change; `--bump` is a
convenience (source-relative, so for durable monotonic serials advance the
source serial). (ii) *Re-feed the signed zone*: feeding a `.signed` file back in
strips and re-signs — the right tool for rollover / expiry refresh, the wrong
tool for editing contents.

**Non-goals** (explicit): NSEC3 opt-out; online/dynamic black-lie generation
(CDOE is an online technique); incremental/partial re-signing; serial policy
beyond `--bump`; key generation (that is `adns/keygen.py`).

**Deferred:** Multi-algorithm zone support will be implemented in the future.
The plan will be to deliberately *not* enforce the strict RFC 4035 §2.2 "one
signature per algorithm per RRset" rule, aligning instead with the relaxation
in draft-huque-dnsop-multi-alg-rules.

---

## 9. Key generation (`adns/keygen.py`)

`adns/keygen.py` (console script `adnskeygen`, `adns.keygen:main`; also
runnable as `python3 -m adns.keygen`) generates an ECDSA P-256 (alg 13) or
Ed25519 (alg 15) key and prints the private PEM, the DNSKEY RDATA/keytag, and
the DNSKEY RRset. With `-K DIR` it writes the keytag-named triple the signer
consumes: `<zone>+<alg>+<keytag>.{pem,dnskey}`, plus `.ds` **only for SEP keys**
(KSK/CSK) — a plain ZSK gets no DS, matching common operator practice.
`--prepublish` writes the private key as `.prepublish.pem` so the DNSKEY can be
pre-published while the signer ignores it until it is activated by renaming to
`.pem`.

---

## 10. Module architecture (`adns/` package)

**Status: implemented (0.12.0).** The system was originally a single
~2000-line `adns_server.py` module (plus the standalone `signzone.py`,
`adnskeygen.py`, and the shared `dnssec_util.py`). Review.md §1.1 flagged the
monolith; the shared-model extraction into `dnssec_util.py` was its first step,
and the full split into the `adns/` package followed. This section describes
the resulting architecture and records how the split was carried out, task by
task — the per-task "**Status:** …" notes below are that history, not pending
work.

### 10.1 Packaging

Packaging moved from `script-files` (which copied scripts verbatim into `bin/`,
off `sys.path`) plus a single `py-modules` entry to a proper importable package
with console-script entrypoints:

```toml
[project.scripts]
adns-server = "adns.__main__:main"
signzone = "adns.signer:main"
adnskeygen = "adns.keygen:main"
```

Deployment stays `pip install` into a venv (as guvnor already does); the
single-file convenience was dropped. The console scripts are thin `main()`
wrappers over the package.

**Status: Task 8 done.** `adns/__main__.py` is now the real entrypoint
(`ServerContext`/`Preferences`/`process_args` from `adns.config`, `ZoneDict`
from `adns.zone`, `init_logging` from `adns.log`, `setup_server`/
`run_event_loop` from `adns.server`), and `adns_server.py` — the legacy
top-level module it used to shim through — is deleted. `pyproject.toml`
installs `adns` as a package and registers the `adns-server =
"adns.__main__:main"` console script; it still kept `dnssec_util`, `signzone`,
and `adnskeygen` as top-level `py-modules` at that point (still consumed by
`signzone.py`/`adnskeygen.py`, which had not yet moved into the package).
`script-files` is gone. The package version (`adns.__version__`) is `0.12.0`.

**Status: Task 9 done.** `signzone.py` and `adnskeygen.py` moved into the
package verbatim as `adns/signer.py` and `adns/keygen.py`, and `dnssec_util.py`
is deleted outright (not merely deprecated — its consumers, the signer and
keygen, now import `adns.zone`/`adns.crypto`/`adns.constants` directly).
`pyproject.toml`'s `py-modules` is now empty; `[project.scripts]` adds
`signzone = "adns.signer:main"` and `adnskeygen = "adns.keygen:main"` alongside
`adns-server`. No top-level modules remain outside the `adns/` package.

### 10.2 Module layout (`adns/` package)

| Module | Responsibility |
|---|---|
| `adns/log.py` | process-wide logging singleton (`log_message`, `log_fatal`, `RateLimitedLog`, `init_logging`); bottom leaf, imports nothing internal |
| `adns/__init__.py` | `__version__`, package exports |
| `adns/constants.py` | `RRtype`, `AUTH_IN_PARENT_RRTYPES`, `EdnsFlag`, `EDECode`; leaf, imports nothing internal |
| `adns/zone.py` | `Zone`, `ZoneDict`, `HashableRRset`, ENT synthesis, NSEC/NSEC3 name+hash helpers, all three record-builders, `zone_from_file`, predecessor/successor helpers |
| `adns/crypto.py` | `sign_rrset` + signature cache, `load_private_key`, `key_basename` |
| `adns/response.py` | `DNSquery`, `DNSresponse` + the 4 mixins |
| `adns/config.py` | `Preferences`, `ServerContext`, YAML/zone/CLI-arg functions |
| `adns/server.py` | sockets, event loop, worker pool, daemon/privdrop/pidfile, signals |
| `adns/__main__.py` | `main()` glue |
| `adns/signer.py` | offline signer (moved from the former top-level `signzone.py`) |
| `adns/keygen.py` | key generator (moved from the former top-level `adnskeygen.py`) |
| `adns/deleg.py` | DelegInfo (draft-ietf-deleg §3) wire codec: key registry, SvcParam-style encode/decode, §3.4/§3.5 validators, RR-line and octet-breakdown formatters; imports `constants` only, I/O-free |
| `adns/deleg_rdata.py` | thin CLI front end over `adns/deleg.py` (the `deleg-rdata` console script) |

All three NSEC/NSEC3 record-builders (`make_nsec_rrset`, `make_nsec3_rrset`,
`make_nsec3_rrset_minimal`) live in `adns/zone.py`, alongside the other
zone/DNSSEC data-model code that the former `dnssec_util.py` used to hold, plus
`ZoneDict` and `HashableRRset` (absorbed from `adns_server.py`);
`adns/crypto.py` is narrowly scoped to signing (`sign_rrset` + its cache) and
private-key loading (`load_private_key`, `key_basename`).

**Status: `adns/log.py` done.** The logging singleton (`init_logging`,
`log_message`, `log_fatal`, `RateLimitedLog`, plus the `_LOG_LOCK`/
`_LOG_DAEMON`/`_LOG_PRI` module state) moved out of `adns_server.py` into
`adns/log.py`, verbatim. It is the bottom leaf of the import DAG — it imports
nothing internal — so it sits below `constants` and everything else can
depend on it, including the code that will land in `adns/response.py` next.

**Status: `adns/zone.py` done.** The former `dnssec_util.py`'s content (except
`load_private_key`/`key_basename`, which were Task 4's) landed in
`adns/zone.py`, verbatim, along with `ZoneDict`/`HashableRRset`/
`make_nsec3_rrset_minimal` moved out of `adns_server.py`.

**Status: `adns/crypto.py` done.** `sign_rrset` (plus its four cache/signing
constants, `RRSIG_INCEPTION_OFFSET`/`RRSIG_LIFETIME`/`CACHE_SIZE`/
`CACHE_TTL`) moved out of `adns_server.py`, and `load_private_key`/
`key_basename` moved out of the former `dnssec_util.py`, into `adns/crypto.py`,
verbatim.

**Status: `dnssec_util.py` retired (Task 9).** After Task 4 it was a thin
re-export shim (`load_private_key`/`key_basename` re-exported from
`adns.crypto`, everything else re-exported from `adns.zone`), kept only so the
still-top-level `signzone.py`/`adnskeygen.py` and their tests kept working.
Task 9 moved both of those consumers into the package and repointed their
imports directly at `adns.zone`/`adns.crypto`/`adns.constants`, so the shim had
no remaining callers and was deleted outright (`git rm dnssec_util.py`); it is
not merely deprecated, it no longer exists.

Import DAG (acyclic, low to high): `log → constants → zone → crypto →
response → config → server → __main__`. `adns/signer.py` depends on `zone`,
`crypto`, and `constants`; `adns/keygen.py` depends on `constants` (or nothing
internal). `adns/deleg.py` depends on `constants` only, and
`adns/deleg_rdata.py` on `adns/deleg.py` and `__version__` — a self-contained
`constants → deleg → deleg_rdata` side branch that the server/response path
does not import.

**Status: `adns/config.py` done.** `Preferences`, `ServerContext`,
`make_arg_parser`, `init_config`, `load_zones`, `make_single_zone`,
`set_server_af`, `process_args`, and the `PROGNAME`/`CONFIG_DEFAULT`/
`TCP_TIMEOUT`/`MAX_WORKERS` constants moved out of `adns_server.py` into
`adns/config.py`, verbatim. It imports `__version__` from `adns` (not a local
redefinition — `adns_server.py` keeps its own separate `__version__ = '0.11.1'`
for now; Task 8 unifies the two), `ZoneDict`/`zone_from_file` from `adns.zone`,
and `load_private_key` from `adns.crypto` directly (no `dnssec_util` shim
hop). `adns_server.py` re-imports the full symbol set (plus `PROGNAME`) for
backward compatibility, following the same re-export idiom as the
`adns.constants`/`adns.zone` groups; `ServerContext`/`Preferences`/
`process_args` are also used directly by the `__main__` block that still
lives there. `adns_server.py`'s now-unused top-level imports (`argparse`,
`yaml`, `dataclasses.dataclass`/`field`, `typing.Optional`, and the
`dnssec_util.load_private_key` import) were removed.

**Status: `PROGNAME` hardcoded (Task 9).** `PROGNAME` was originally
`os.path.basename(sys.argv[0])`, computed once at import time. Under the
canonical `python3 -m adns` invocation `sys.argv[0]` is the path to
`__main__.py`, so `PROGNAME` leaked as `"__main__.py"` into `--version`/`-h`
banners, the startup log line, the `/tmp/{PROGNAME}.pid` fallback path, and
`syslog.openlog()`. Task 9 hardcoded it to the literal `"adns-server"` instead,
giving a stable program name for both `-m adns` and the installed
`adns-server` console script; `os`/`sys` remain used elsewhere in
`adns/config.py` (`os.path.join`, `sys.exit`) so this did not orphan either
import.

**Status: `adns/server.py` done.** The runtime/networking layer —
`handle_sigterm`/`install_signal_handlers`, the pidfile helpers
(`get_pid_file`/`remove_pidfile`), daemonization (`close_inherited_fds`/
`daemon`/`drop_privs`), the socket factories (`udp4socket`/`udp6socket`/
`tcp4socket`/`tcp6socket`), the query path (`send_socket`/`recv_socket`/
`handle_query`/`send_servfail`/`handle_connection_udp`/`handle_connection_tcp`),
and the event loop (`setup_sockets`/`setup_server`/`spawn_worker`/
`run_event_loop`) — moved out of `adns_server.py` into `adns/server.py`,
verbatim (AST-diff-confirmed identical against the pre-move source for all 21
functions). Logging was already extracted to `adns/log.py` in Task 5a, so
`adns/server.py` imports `log_message`/`log_fatal`/`RateLimitedLog` from there
rather than re-moving them; it also imports `sign_rrset` from `adns.crypto`
(for the SIGHUP cache clear), `DNSquery`/`DNSresponse` from `adns.response`,
`PROGNAME`/`init_config` from `adns.config`, and `__version__` from `adns`
(for the startup log line) — no cycle, since none of those modules import
`server`. `adns_server.py` is now an explicit-re-export compat module: it
keeps the constants/zone/crypto/log/response/config re-export groups plus a
new `adns.server` re-export group (all runtime callables, `# pylint:
disable=unused-import`), and retains its `if __name__ == '__main__':` block
unchanged. Its now-dead top-level imports (`pwd`, `grp`, `resource`,
`syslog`, `struct`, `socket`, `atexit`, `select`, `threading`, `signal`,
`time`, `random`, `binascii`, `traceback`, `dns.zone`, `dns.message`,
`dns.rcode`) and the local `__version__ = '0.11.1'` were removed — the
runtime region that referenced them moved to `adns/server.py`, and
`adns/server.py` now owns the version log line via `adns.__version__`.
Real `main()` wiring (unifying the version and retiring this shim) is
deferred to Task 8.

**Status: Task 8 done.** `adns_server.py` (the re-export shim described in
the two paragraphs above) is deleted. The real `main()` now lives in
`adns/__main__.py`, wired to the `adns-server` console script; the version
comes solely from `adns.__version__` (`0.12.0`).

### 10.3 Decomposing `DNSresponse` with mixins

`DNSresponse` is the dominant mass (~45 methods, ~970 lines) and its methods
form one cohesive request-handling algorithm that communicates entirely through
shared `self.` state (`self.response`, `self.query`, `self.qname`,
`self.edns_options`, …). The goal of the split was **testability and
navigation, not decoupling** — the methods are legitimately entangled through
that shared state, so a decomposition that pretended otherwise (free functions,
collaborator objects) would have fought the code.

Mixins fit exactly this shape: multiple inheritance composes grouped method sets
onto one object, `self` stays shared across all of them, and the move was close
to cut-and-paste. The class is:

```python
class DNSresponse(DenialMixin, ReferralMixin, ResolveMixin, EdnsCookieMixin):
    # Core plumbing stays on the class itself:
    #   __init__, to_wire, max_size, truncate, add_rrset, add_soa,
    #   prepare_response, dnssec_ok, need_edns
```

| Mixin | Methods |
|---|---|
| `DenialMixin` | `nxdomain`, `nxdomain_nsec_online_compact`, `nxdomain_nsec_online`, `nxdomain_nsec3_online`, `nxdomain_nsec3_online_compact`, `nxdomain_nsec`, `nxdomain_nsec3`, `nodata`, `nodata_nsec_online`, `nodata_nsec3_online`, `nodata_nsec3_online_compact`, `nodata_nsec`, `nodata_nsec3`, `wildcard_no_closer_match`, `add_nsec_matching`, `add_nsec_online` — the §5.2 denial matrix (largest cluster) |
| `ReferralMixin` | `do_referral`, `do_referral_traditional`, `do_referral_deleg`, `get_glue`, `add_new_delegation_only_ede`, `next_closer_name`, `occluded_nxdomain`, `occluded_nxdomain_nsec3` — referral + DELEG occlusion |
| `ResolveMixin` | `process_any_metatype`, `find_rrtype`, `process_cname`, `process_dname`, `process_name`, `find_answer_in_zone`, `find_answer` — the name-resolution walk |
| `EdnsCookieMixin` | `add_cookie_option`, `verify_server_cookie`, `calculate_server_cookie`, `process_cookie`, `do_edns_init`, `do_edns_final` — EDNS + cookies |

Each mixin's docstring names the `self.` attributes and sibling methods it
relies on — the written contract that compensates for the implicit dependencies
inherent to mixins. If a cluster later proves genuinely separable in state (a
candidate: denial-of-existence), it can graduate to a collaborator object; the
mixin split does not preclude that.

**Status: `adns/response.py` done.** `DNSquery` and `DNSresponse` (split into
`DenialMixin`/`ReferralMixin`/`ResolveMixin`/`EdnsCookieMixin` exactly per the
table above, plus core plumbing on the `DNSresponse` class body) moved out of
`adns_server.py`, verbatim, along with the three predicate helpers
(`query_meta_type`, `compact_answer_ok`, `deleg_ext_ok`) and the
cookie/message-size constants they and the moved methods depend on
(`METATYPE_MIN`/`MAX`, `COOKIE_TIMESTAMP_DRIFT`, `COOKIE_RECALCULATE_TIME`,
`UDP_MAXSIZE_NOEDNS`, `TCP_MAXSIZE`). `adns_server.py` now imports
`DNSquery`/`DNSresponse` from `adns.response` and re-exports them (plus
`RRtype`/`AUTH_IN_PARENT_RRTYPES`, kept as a compatibility re-export for the
same reason as the `adns.zone` symbols in the paragraph above).

### 10.4 What did not change

Wire behavior, config format, and the test suite's black-box assertions are
identical across the split — it was a pure internal reorganization by itself.
The direct-import (`ctx`) test modality's import paths changed to `adns.*` (e.g.
`adns.response.DNSresponse`, `adns.zone.Zone`), in lockstep with each
extraction task; the black-box modality (subprocess + real DNS queries) is
unaffected in what it asserts, though its launch *mechanism* changed in Task 8
(below).

**Status: Task 8 done — the server-side split is complete.** `adns_server.py`
is deleted; there is no longer a top-level compat shim. `adns/__main__.py` is
the real entrypoint (`ServerContext`/`Preferences`/`process_args` from
`adns.config`, `ZoneDict` from `adns.zone`, `init_logging` from `adns.log`,
`setup_server`/`run_event_loop` from `adns.server`), wired to the
`adns-server` console script via `[project.scripts]`. The direct-import test
modality now imports `adns.config`/`adns.zone`/`adns.response`/`adns.server`
directly rather than through the `adns_server` re-export aggregator (which no
longer exists) — `test_zone_module.py`'s
`test_adns_server_reexports_moved_symbols` was deleted along with it, since it
only guarded that now-gone re-export surface. The black-box modality's launch
mechanism (the earlier deferred note here) is resolved: `conftest.py` and
`test_daemon.py` now launch the server as `python3 -m adns ...` instead of
`python3 adns_server.py ...`, with `PYTHONPATH` set on the subprocess `env` so
the child can resolve the `adns` package (the parent's `sys.path.insert` does
not propagate to a child process). At this point (end of Task 8) `dnssec_util.py`
and its consumers (`signzone.py`, `adnskeygen.py`) were unchanged and
deliberately deferred to Task 9.

**Status: Task 9 done — the signer/keygen move and shim retirement are
complete.** `signzone.py` and `adnskeygen.py` moved into the package verbatim
as `adns/signer.py` and `adns/keygen.py`, with their `dnssec_util` imports
repointed to `adns.zone`/`adns.crypto`/`adns.constants`. `dnssec_util.py` had
no remaining callers once that move landed, so it was deleted outright
(`git rm dnssec_util.py`) rather than left as a shim. No top-level `.py`
modules remain outside the `adns/` package; `pyproject.toml`'s `py-modules` is
empty.

**Version.** The split lands as `0.12.0` — a minor bump, not a patch. The
internal reorganization is semver-invisible on its own, but the CLI surface
does change: `adns_server.py`/`signzone.py`/`adnskeygen.py` become
`adns-server`/`signzone`/`adnskeygen` console scripts (no `.py` suffix, per
§10.1), and that packaging/CLI-surface change is what makes this a minor bump
rather than a patch. `adns-server` (via `adns.__main__:main`) shipped in Task
8; `signzone`/`adnskeygen` (via `adns.signer:main`/`adns.keygen:main`) shipped
in Task 9, completing the console-script surface with no further version bump
(per the Task 9 brief: the CLI-surface minor bump to `0.12.0` already covers
this).

---

## 11. ML-DSA-44 (DNSSEC algorithm 18)

The server supports **ML-DSA-44** (DNSSEC algorithm 18), the post-quantum
signature scheme of FIPS 204, tracking **draft-westerbaan-dnssec-mldsa**
(committed in `specs/`). Only ML-DSA-44 is defined for DNSSEC; the larger
parameter sets (65, 87) are not. Support spans all three DNSSEC surfaces —
key generation (§9), offline signing (§8), and online signing (§5.1) — and the
server serves and (given a private key) online-signs alg-18 zones just as it
does alg 8/13/15.

An alg-18 DNSKEY carries the 1312-octet FIPS 204 raw public key; an RRSIG
carries a 2420-octet signature. Both are far larger than the classical
algorithms', so alg-18 responses routinely exceed the common path-MTU and the
server's EDNS budget; the ordinary `max_size()`/`truncate()` machinery (§7)
handles this by setting TC and forcing TCP fallback — there is no alg-18-specific
size handling.

### 11.1 The dnspython gap

ML-DSA is pre-standardization, and **dnspython 2.7.0 does not implement
algorithm 18**: `dns.dnssec.make_dnskey()`, `sign()`, and `validate()` all raise
`UnsupportedAlgorithm` for it. The cryptographic primitive itself lives in the
`cryptography` package (`cryptography.hazmat.primitives.asymmetric.mldsa`,
requiring a build whose bundled OpenSSL has ML-DSA — 50.0.0 is known good).
The implementation therefore bridges the gap by calling `cryptography` directly
for the parts dnspython refuses, while reusing every dnspython helper that *is*
algorithm-agnostic. Three helpers turn out to work unchanged for alg 18 —
`dns.dnssec.key_id()` (keytag) and `dns.dnssec.make_ds()` (DS digest), which
operate on the DNSKEY RDATA opaquely, and PKCS8 PEM key loading via
`crypto.load_private_key()`.

Because `mldsa` needs a much newer `cryptography` than the project's floor
(`cryptography>=43.0.0`), it is imported **lazily**, inside the alg-18 branch,
never at module top level — a top-level import would `ImportError` on the floor
and break alg 8/13/15 for everyone. The `mldsa` import in `keygen.py` carries a
`pylint: disable=import-outside-toplevel` for this reason.

### 11.2 Key generation

`adnskeygen -a 18` (§9) generates a random key with
`mldsa.MLDSA44PrivateKey.generate()` and writes it as a **PKCS8 PEM** — the same
on-disk format as the other algorithms, so the keytag-named `.pem` triple stays
uniform and `crypto.load_private_key()` reads it with no special case. Since
`make_dnskey()` rejects alg 18, `dnskey_rdata_for()` builds the DNSKEY from
presentation text (`f"{flags} 3 18 {base64(pub.public_bytes_raw())}"`) and then
reuses the unchanged `key_id()`/`make_ds()` on the resulting RDATA.

### 11.3 Signing (offline and online)

Both the offline signer and the online signing path route alg-18 signing through
a single shared builder, `crypto.mldsa_rrsig_rdata(rrset, private_key, signer,
dnskey, inception, expiration)`. It reconstructs what `dns.dnssec.sign()` does
internally, but with the signature computed by `cryptography`:

1. Build an RRSIG rdata template with an **empty** signature (labels =
   `len(name) - 1`, minus one more for a wildcard; `key_tag = key_id(dnskey)`).
2. Obtain the RFC 4034 §3.1.8.1 data-to-be-signed via dnspython's
   algorithm-agnostic **private** helper
   `dns.dnssec._make_rrsig_signature_data(rrset, template, None)`.
3. Sign with `private_key.sign(data, context=None)` — pure ML-DSA with the
   spec's empty context — yielding the 2420-octet signature.
4. Splice it in with `template.replace(signature=...)`.

`crypto.sign_rrset()` branches on `zone.signing_dnskey.algorithm == 18` to call
this builder instead of `dns.dnssec.sign()`; the offline signer's
`rrsig_rdata()` branches identically. Everything downstream — the signature
cache, the response machinery, the denial-of-existence constructions — is
algorithm-independent and unchanged. A CSK is the natural fit for online alg-18
signing (§5.1).

**Signing is hedged (randomized).** `cryptography` exposes no deterministic
ML-DSA option, so the same RRset signed twice yields two different, both-valid
signatures — which is exactly what draft-westerbaan-dnssec-mldsa prefers for
online signing. The process-wide signature cache (§5.1) is what makes repeated
online answers byte-stable despite this.

**The `_make_rrsig_signature_data` dependency is guarded at signing time.** It
is a private dnspython API; a future dnspython could remove it. The builder
checks `hasattr(dns.dnssec, "_make_rrsig_signature_data")` on each call and
raises `crypto.DnssecUnsupported` (a `RuntimeError`, not `SignerError` — the
check lives in `crypto.py`, which `signer.py` imports, so it cannot depend on
`signer.py` without a circular import). Checking at signing time rather than
import time preserves the property that a missing private helper breaks only
alg-18 signing, never alg 8/13/15. The offline signer's CLI catches
`(SignerError, DnssecUnsupported)` so the abort is a clean error message; on the
online path a fired guard degrades to SERVFAIL via the response handler's
exception path.

### 11.4 Validation and testing

dnspython cannot **validate** alg 18 either, so the test suite never calls
`dns.dnssec.validate()` for it. Instead the alg-18 tests
(`tests/pytest/test_mldsa_serving.py`, `test_mldsa_online.py`, and the signer
tests) use a self-contained oracle: they rebuild the §3.1.8.1 signing input from
a fresh empty-signature RRSIG template and verify with
`MLDSA44PublicKey.from_public_bytes(pub).verify(sig, data, context=None)`. This
matches the suite's minimize-external-tool-dependencies philosophy and, because
hedged signatures are not reproducible, is verify-based rather than
fixed-vector. Keys are generated at test time (no key material is committed);
the modules are guarded with `pytest.importorskip` on the `mldsa` primitive so
they skip cleanly where `cryptography` lacks it.
