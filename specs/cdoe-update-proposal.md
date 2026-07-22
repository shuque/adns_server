# Issue: Compact Denial of Existence and DE=0 DELEG-only occlusion NXDOMAIN

## Problem

When a DELEG-unaware client (EDNS DE flag = 0) queries a name *below* a
delegation point that has Delegation Type RRsets but no NS RRset (a "DELEG-only"
cut), the authoritative server must return an authoritative NXDOMAIN
(delext-08 Section 4.1 and Section 8.4; deleg-10 Section 5.2.2.1), and for a
signed zone this NXDOMAIN must carry an NSEC/NSEC3 proof showing delegation
types present at the delegation point. All existing examples
(deleg-10 Appendix A.4.2) assume a conventional signer:

    test.  NSEC  . RRSIG NSEC DELEG

Neither draft specifies what a **Compact Denial of Existence (CDOE)** signer
[RFC9824] does in this case, and CDOE's normal behavior conflicts with the
requirement in two ways:

1. **RCODE.** A CDOE signer returns the NXDOMAIN rcode only when the client sets
   the Compact Answers OK (CO) flag; otherwise it returns NOERROR with an
   NXNAME-based response. In the general case, DE=0 clients cannot be expected to
   set CO=1 and Section 4.1 / Section 8.4 require an NXDOMAIN. The NXDOMAIN must
   therefore be emitted **regardless of the CO flag** — an intentional exception
   to [RFC9824], with an accompanying actual proof of NXDOMAIN. But setting
   CO=1 alone would not be sufficient. See (2) below.

2. **Proof style.** CDOE proves nonexistence with a NODATA style response with
   an NXNAME-bearing NSEC/NSEC3 record *matching the queried name*. That cannot
   satisfy delext-08 Section 6.2 / Section 8.4: the downgrade-detection signal a
   validator relies on is the Delegation Type bit in the NSEC/NSEC3 that **matches
   the delegation point** (an ancestor of the queried name). An NXNAME response
   matching the queried name carries the NXNAME pseudo-type, not the Delegation
   Type bit, and its owner lies below the cut in the invisible child namespace; it
   therefore discloses nothing about the cut and defeats the ADT detection of delext-08
   Section 6.2.

The fix: for this specific case a CDOE signer must fall back to a conventional
Name Error proof and set NXDOMAIN independent of CO.

Without this fix, a normal CDOE response would not be able to satisfy the downgrade resistance property of DELEG in the face of a DE flag stripping (or MITM) adversary.

## Proposed edit 1 — delext-08 Section 4.1

Append after the existing paragraph that begins "Note that when the DE flag is
clear (i.e., set to 0), and no NS RRset exists at a delegation point ...":

> When the delegating zone employs Compact Denial of Existence [RFC9824], the
> NXDOMAIN response required above is an exception to that method: it MUST be
> generated as a conventional Name Error proof ([RFC4035], or [RFC5155] for
> NSEC3) rather than as an NXNAME-based NODATA response, and it MUST be returned
> regardless of whether the query sets the Compact Answers OK (CO) flag
> [RFC9824].
>
> For an NSEC zone, a single NSEC record whose owner name matches the delegation
> point satisfies both aspects of the Name Error proof at once — it covers both
> the queried name and the wildcard at the closest encloser — while its Type Bit
> Maps field conveys the Delegation Type(s) present at the delegation point.
>
> For an NSEC3 zone, the proof is the usual closest-encloser construction of
> [RFC5155]: the NSEC3 record matching the delegation point (whose Type Bit Map
> conveys the Delegation Type(s) present there), the NSEC3 record covering the
> next closer name, and the NSEC3 record covering the source of synthesis
> (wildcard) at the closest encloser. Unlike the NSEC case, these are in general
> three distinct records, because NSEC3 hashing does not preserve the name
> hierarchy.
>
> Returning an NXNAME-based response matching the queried name would not convey
> the presence of Delegation Types at the delegation point and would prevent the
> downgrade detection described in Section 6.2 and Section 8.4.

---

Optionally, append a short non-normative note (or place it in Section 8.5):

> Note: for an NSEC3 zone this is the one case in which Compact Denial of
> Existence does not retain its usual single-record negative response; the
> closest-encloser construction requires up to three NSEC3 records (and their
> signatures) instead of one. This affects only NSEC3 CDOE zones that publish
> DELEG-only delegation points and receive DE=0 queries for names beneath them,
> and does not change the single-record behavior of NSEC CDOE.

---

## Proposed edit 2 — delext-08 Section 8.4

Append to the paragraph that begins "However, a resolver that sets the DE flag
expects NSEC or NSEC3 proof ...":

> Authoritative servers that employ Compact Denial of Existence [RFC9824] for
> a delegating zone MUST NOT satisfy this proof with an NXNAME-based response
> matching the queried name, because such a response omits the Delegation Type
> bit at the delegation point on which this detection relies. They MUST instead
> return a conventional Name Error proof as described in Section 4.1.

---

## Proposed edit 3 — deleg-10 Section 5.2.2.1 (informative)

Append after "NSEC and DS records are returned following the existing rules in
[RFC4035].":

> If the delegating zone employs Compact Denial of Existence [RFC9824], see
> [I-D.ietf-dnsop-delext] Section 4.1 for how this NXDOMAIN and its proof are
> constructed: a conventional Name Error proof is used rather than an
> NXNAME-based response, and the NXDOMAIN is returned regardless of the Compact
> Answers OK (CO) flag.

This edit requires adding an **informative reference to [RFC9824]** in deleg-10.
(deleg-10 already references [I-D.ietf-dnsop-delext].)

---

## Notes for the authors

- **EDE name mismatch between the drafts.** deleg-10 Section 5.2.2.1 / Section
  (IANA) names this Extended DNS Error "New Delegation Only" (INFO-CODE TBD3),
  while delext-08 Section 9.5 names it "Delegation Extension Support Required"
  (INFO-CODE TBD). The two should be reconciled to a single name/registration.

- **NSEC vs NSEC3 record count.** In the NSEC case a single record does double
  duty (qname cover + wildcard cover) because names sort hierarchically and the
  next-name form `<cut>\000` encloses the whole subtree. In the NSEC3 case the
  hierarchy is destroyed by hashing, so the closest-encloser, next-closer, and
  wildcard hashes are unrelated and the proof needs three records. This has been
  verified against a running implementation (adns_server).

- **Impact on the CDOE "single record" property.** A design appeal of Compact
  Denial is that negative responses need only one NSEC/NSEC3 record and one
  signature, reducing packet size and (for online signers) signing cost. This
  proposal preserves that for NSEC CDOE but not for the NSEC3 CDOE occlusion
  case, which regresses to up to three records/signatures. The note above states
  this explicitly. The regression is confined to a narrow corner case (NSEC3
  CDOE zones with DELEG-only cuts answering DE=0 queries below the cut); NSEC3
  CDOE itself has very few implementations today (Oracle DNS, plus the
  noire.huque.com test zone), so the practical impact is expected to be small.

- **"Regardless of CO" is the crux.** This is the one genuinely new normative
  statement; it is deliberately a MUST, since it is an intentional exception to
  the CO-gated NXDOMAIN behavior of [RFC9824].
