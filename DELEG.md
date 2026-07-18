# DELEG support in adns_server

Implementation notes for the DELEG delegation mechanism in `adns_server.py`.

## Specifications

This server implements the authoritative-server behavior described in:

- **draft-ietf-deleg-10** — the DELEG record and delegation semantics.
- **draft-ietf-dnsop-delext-08** — the EDNS(0) DE flag, the Delegation Type
  code range, and the DNSKEY-ADT flag.

Note: the copies checked into `specs/` are `draft-ietf-deleg-10.txt` and
`draft-ietf-dnsop-delext-07.txt`. Where deleg-10 and delext-07 disagreed on
`DE=0, QTYPE=DELEG` with an NS RRset present, delext-08 resolved the
contradiction in favor of "when DE=0 the server treats Delegation Types as
ordinary Data Types," which is the behavior implemented here.

## Type codes and signaling

These are pre-standardization placeholders, agreed with collaborators, and are
defined in the `RRtype` and `EdnsFlag` enums:

- **DELEG = 61440** (`0xF000`, from the proposed delext Delegation-Type range).
  Creates a zone cut; modeled on DS (authoritative at the delegation point,
  signed there). Represented in zone files as `TYPE61440` in RFC 3597 generic
  format.
- **DELEGPARAM = 65433** — indirection target reached via `include-delegparam`.
  This server treats it as an opaque ordinary data type (returned as-is when
  queried); it has no special handling yet.
- **EDNS(0) DE flag** (Delegation Extensions), bit 2 = `0x2000`, enum
  `EdnsFlag.DELEG_EXT_OK`. A DELEG-aware client sets it; the server echoes it in
  responses. Tested by `deleg_ext_ok(message)`.
- **EDE "New Delegation Only"** — `EDECode.NEW_DELEGATION_ONLY` (provisional
  value 31; IANA-TBD / INFO-CODE TBD3). Added to DE=0 responses for a
  DELEG-only cut (deleg-10 5.2.2.1).

A zone opts in to DELEG handling with `deleg_enabled: true` in the config
(`Zone.deleg_enabled`). Without it, DELEG records are just opaque data.

## Functional summary

The DELEG record defines a zone cut much like NS, but with DS-like semantics.
A DELEG-aware client (DE=1) is served according to the DELEG rules; a
DELEG-unaware client (DE=0) is served exactly as a non-DELEG server would,
i.e. Delegation Types are treated as ordinary data types.

### DE=1 (DELEG-aware client) — deleg-10 5.2.1

Handled by `do_referral_deleg()`:

- **DELEG RRset present** (with or without NS): the DELEG RRset goes into the
  Authority section and the **NS RRset is NOT included**. If a DS RRset is
  present it is added (secure delegation); otherwise an NSEC/NSEC3 matching the
  cut proves DS absence (insecure delegation).
- **NS present, no DELEG**: a legacy NS referral (via
  `do_referral_traditional()`), **plus** an NSEC/NSEC3 matching the cut to prove
  the absence of the DELEG RRset (deleg-10 5.2.1.3). In practice the same
  record proves both DS and DELEG (non)existence.

RRSIGs are attached to authoritative RRsets when DO=1, per RFC 4035.

### DE=0 (DELEG-unaware client) — deleg-10 5.2.2

Handled in `process_name()`:

- **NS present** (with or without DELEG): NS occludes the DELEG RRset; a normal
  legacy referral is produced (`do_referral_traditional()`). This is the
  delext-08 "treat Delegation Types as Data Types" rule.
- **DELEG-only cut** (DELEG present, no NS): the child zone is invisible to the
  client. A query *for the cut name itself* falls through to normal record
  lookup (`find_rrtype()`) — returning the DELEG/DS RRset as ordinary data, or
  NODATA. A query *below the cut* returns an authoritative NXDOMAIN
  (`occluded_nxdomain()`). In both cases a "New Delegation Only" EDE is added
  (`add_new_delegation_only_ede()`).

Because the DE=0 occlusion path uses NODATA / NXDOMAIN (never a referral), the
Authoritative Answer (AA) bit is set — the parent is authoritative for these
answers.

## Relevant functions and symbols

| Symbol | Role |
|--------|------|
| `RRtype.DELEG`, `RRtype.DELEGPARAM` | DELEG (61440) and DELEGPARAM (65433) type codes |
| `EdnsFlag.DELEG_EXT_OK` | EDNS(0) DE flag (bit 2) |
| `EDECode.NEW_DELEGATION_ONLY` | "New Delegation Only" EDE (provisional) |
| `AUTH_IN_PARENT_RRTYPES` | `[DS, DELEG]` — types answered at the cut instead of referred |
| `deleg_ext_ok(message)` | Is the DE flag set on the query? |
| `Zone.deleg_enabled` | Per-zone opt-in to DELEG handling |
| `process_name()` | Detects the cut (NS and/or DELEG); routes DE=1 vs DE=0; handles DE=0 occlusion |
| `do_referral()` | Referral dispatch: DELEG-aware vs traditional |
| `do_referral_deleg()` | DE=1 referral (DELEG RRset, DS-or-NSEC, DELEG-absence proof) |
| `do_referral_traditional()` | Legacy NS + glue + DS/NSEC referral |
| `occluded_nxdomain()`, `occluded_nxdomain_nsec3()` | DE=0 below-cut authoritative NXDOMAIN with DELEG-bit-preserving proof |
| `add_new_delegation_only_ede()` | Adds the "New Delegation Only" EDE |
| `add_nsec_matching()`, `add_nsec_online()` | NSEC/NSEC3 matching a name; the covering next-name form fires on NS **or** DELEG at a cut |

## Divergence from the specifications

The one place this implementation makes a choice not dictated by the drafts is
the interaction between **Compact Denial of Existence** and **DELEG occlusion**
on the DE=0 below-cut NXDOMAIN. The drafts are silent on it; the decision and
its rationale are documented in the next section.

## Compact Denial of Existence (CDOE) and DELEG occlusion

When a DELEG-unaware client (EDNS DE flag = 0) queries a name *below* a
DELEG-only delegation cut (a name that has a DELEG RRset but no NS RRset),
deleg-10 §5.2.2.1 requires the delegating (parent) server to return an
authoritative NXDOMAIN — AA=1, parent SOA — because the DELEG-only child zone
is invisible to a DELEG-unaware client. deleg-10 Appendix A.4.2.3 shows the
DNSSEC proof as the NSEC record *matching the cut*, carrying the DELEG type
bit, e.g.:

    test.  NSEC  . RRSIG NSEC DELEG

**The drafts are silent on how this interacts with Compact Denial of Existence
(RFC 9824).** (To be raised with the authors.) This server resolves it as
follows:

- The occlusion NXDOMAIN is proven with the NSEC/NSEC3 record **matching the
  cut**, whose type bitmap includes the **DELEG** bit. We do **not** emit a
  Compact-Denial black lie (an NXNAME-bearing NSEC at the queried name).

- Rationale:
  1. NXNAME asserts that the *owner of the NSEC* is a nonexistent name. The cut
     name genuinely exists (it has a DELEG RRset), so placing NXNAME on it —
     next to the DELEG bit — is self-contradictory.
  2. The proof does not need NXNAME. For NSEC zones the cut's NSEC uses the
     special covering next-name form (`sub5` → `sub5\000`), which already
     covers all names below the cut; for NSEC3 zones the standard
     closest-encloser proof covers the next-closer name. Both are genuine
     covering proofs, not black lies.
  3. Most importantly, the one time a DELEG-*aware* validator sees this
     nominally-DE=0 response is under a DE-bit-stripping downgrade attack
     (delext §8.2.2). The DELEG bit in the cut's NSEC bitmap is exactly what
     lets such a validator (with the DNSKEY-ADT flag set) detect the downgrade
     and treat the answer as bogus. A Compact-Denial black lie at the queried
     name would drop the DELEG bit and defeat that detection.

- Construction by signing mode (see `occluded_nxdomain()`):
  - **Online NSEC (incl. compact-denial zones):** NSEC matching the cut, with
    the special covering next-name (`owner` → `owner\000`) and a type bitmap of
    the cut node's actual RR types (which includes DELEG). This is what
    `add_nsec_online()` produces, with its special-next-name condition widened
    from "NS present" to "NS or DELEG present".
  - **Online NSEC3 (incl. compact-denial zones):** the standard closest-encloser
    proof — closest-encloser NSEC3 matching the cut (bitmap includes DELEG) +
    next-closer covering + wildcard covering (`occluded_nxdomain_nsec3()`), NOT
    the compact NXNAME black lie.

In short: for DELEG occlusion of DE=0 clients we always prove nonexistence in
a way that keeps the DELEG bit visible, regardless of whether the zone
otherwise uses Compact Denial.
