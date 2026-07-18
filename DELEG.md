# DELEG support in adns_server

Implementation notes for draft-ietf-deleg / draft-ietf-dnsop-delext.

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

- Construction by signing mode:
  - **Online NSEC (incl. compact-denial zones):** NSEC matching the cut, with
    the special covering next-name (`owner` → `owner\000`) and a type bitmap of
    the cut node's actual RR types (which includes DELEG). This is what
    `add_nsec_online()` already produces once its special-next-name condition
    is widened from "NS present" to "NS or DELEG present".
  - **Online NSEC3 (incl. compact-denial zones):** the standard closest-encloser
    proof — closest-encloser NSEC3 matching the cut (bitmap includes DELEG) +
    next-closer covering + wildcard covering — i.e. the existing
    `nxdomain_nsec3_online` construction, NOT the compact NXNAME black lie.

In short: for DELEG occlusion of DE=0 clients we always prove nonexistence in
a way that keeps the DELEG bit visible, regardless of whether the zone
otherwise uses Compact Denial.
