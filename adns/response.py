"""
Response assembly: DNSquery parsing and DNSresponse construction.

DNSresponse is the dominant mass of the server's request-handling logic
(~45 methods forming one cohesive algorithm that communicates entirely
through shared ``self.`` state). Rather than pretend those methods are
decoupled, the class is split across four mixins that all operate on that
shared state -- DenialMixin (the DNSSEC denial-of-existence matrix),
ReferralMixin (referrals and DELEG occlusion), ResolveMixin (the
name-resolution walk), and EdnsCookieMixin (EDNS negotiation and DNS
Cookies) -- while core plumbing (__init__, wire serialization, add_rrset,
prepare_response) stays on the DNSresponse class body. See Design.md
section 10.3 for the decomposition rationale and the full method table.
"""

import copy
import struct
import time

import siphash

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdataset
import dns.rdatatype

from adns.constants import RRtype, AUTH_IN_PARENT_RRTYPES, EdnsFlag, EDECode
from adns.zone import (
    HashableRRset,
    make_nsec_rrset,
    make_nsec3_rrset_minimal,
    rrset_from_rdataset,
)
from adns.crypto import sign_rrset
from adns.log import log_message


# QTYPE / Meta-TYPE range (RFC 6895 section 3.1): 128-255 are Q and Meta
# types. 255 (ANY) is handled separately, so the meta-type test excludes it.
METATYPE_MIN = 128
METATYPE_MAX = 254

# Cookie parameters
COOKIE_TIMESTAMP_DRIFT = 86400        # Allowed DNS Cookie timestamp drift (secs)
COOKIE_RECALCULATE_TIME = 21600

# Message size limits (octets)
UDP_MAXSIZE_NOEDNS = 512              # RFC 1035 UDP payload limit without EDNS
TCP_MAXSIZE = 65533                   # 65535 max DNS message - 2-octet TCP length prefix


def query_meta_type(qtype):
    """Is given query type a meta type (except ANY)?"""
    return METATYPE_MIN <= qtype <= METATYPE_MAX


def compact_answer_ok(message):
    """Does DNS message have Compact Answers OK EDNS header flag set?"""
    return message.ednsflags & EdnsFlag.COMPACT_OK == EdnsFlag.COMPACT_OK


def deleg_ext_ok(message):
    """Does DNS message have the EDNS(0) DE (Delegation Extensions) flag set?"""
    return message.ednsflags & EdnsFlag.DELEG_EXT_OK == EdnsFlag.DELEG_EXT_OK


class DNSquery:
    """DNS query object"""

    def __init__(self, data, cliaddr, cliport, tcp=False):

        self.cliaddr = cliaddr
        self.cliport = cliport
        self.headeronly = False

        self.tcp = tcp
        if self.tcp:
            self.msg_len, = struct.unpack('!H', data[:2])
            self.wire_message = data[2:2+self.msg_len]
        else:
            self.wire_message = data
            self.msg_len = len(data)

        try:
            self.message = dns.message.from_wire(self.wire_message)
        except dns.exception.DNSException as exc_info:
            log_message(f"error: can't parse query: {type(exc_info)}: {exc_info}")
            self.message = None
        else:
            if not self.message.question:
                self.headeronly = True
            else:
                self.qname = self.message.question[0].name
                self.qtype = self.message.question[0].rdtype
                self.qclass = self.message.question[0].rdclass
            self.log_query()

    def edns_log_info(self):
        """Return string of EDNS parameters for logging purposes"""
        edns_version = self.message.edns
        if edns_version == -1:
            return ""
        flags = f'0x{self.message.ednsflags:04x}'
        options = ",".join([str(int(x.otype)) for x in self.message.options])
        result = f"edns=v{edns_version}/{flags}/{self.message.payload}"
        if options:
            result += f"/{options}"
        return result

    def log_query(self):
        """Log information about incoming DNS query"""
        transport = "TCP" if self.tcp else "UDP"
        opcode = dns.opcode.to_text(self.message.opcode()).lower()
        if self.headeronly:
            msg = (f'{opcode}: {transport} header-only '
                   f'from: {self.cliaddr},{self.cliport} size={self.msg_len}')
        else:
            msg = (f'{opcode}: {transport} '
                   f'{self.qname} '
                   f'{dns.rdatatype.to_text(self.qtype)} '
                   f'{dns.rdataclass.to_text(self.qclass)} '
                   f'from: {self.cliaddr},{self.cliport} size={self.msg_len}')
        edns_log_message = self.edns_log_info()
        if edns_log_message:
            msg = msg + " " + edns_log_message
        log_message(msg)


class DenialMixin:
    # pylint: disable=no-member
    """
    The DNSSEC denial-of-existence matrix (Design.md section 5.2):
    NXDOMAIN/NODATA generation across online-signed white-lie, online-signed
    Compact Denial, and pre-signed NSEC/NSEC3 styles.

    Relies on sibling/core state and methods set up by DNSresponse.__init__
    and defined on the DNSresponse class body: self.qname, self.response,
    self.query, self.ctx, self.dnssec_ok(), self.add_rrset(), self.add_soa().

    The no-member disable is needed because pylint analyzes this class in
    isolation: every self.<attr>/self.<method>() referenced here is defined
    by DNSresponse.__init__ or by a sibling mixin, and only resolves at
    runtime through the combined DNSresponse MRO (Design.md section 10.3).
    """

    def nxdomain(self, zobj, sname):
        """Generate NXDOMAIN response"""

        if not zobj.online_signing():
            self.response.set_rcode(dns.rcode.NXDOMAIN)

        self.add_soa(zobj)
        if not self.dnssec_ok():
            return

        if zobj.online_signing():
            if zobj.nsec3param:
                if zobj.compact_denial:
                    self.nxdomain_nsec3_online_compact(zobj)
                else:
                    self.nxdomain_nsec3_online(zobj, sname)
            elif zobj.compact_denial:
                self.nxdomain_nsec_online_compact(zobj)
            else:
                self.nxdomain_nsec_online(zobj, sname)
            return

        if zobj.dnssec:
            if zobj.nsec3param is None:
                self.nxdomain_nsec(zobj, sname)
            else:
                self.nxdomain_nsec3(zobj, sname)

    def nxdomain_nsec_online_compact(self, zobj):
        """
        Generate online NSEC NXDOMAIN response using Compact Denial
        """

        if compact_answer_ok(self.query.message):
            self.response.set_rcode(dns.rcode.NXDOMAIN)

        rrtypes = [dns.rdatatype.RRSIG, dns.rdatatype.NSEC, RRtype.NXNAME]
        nextname = dns.name.Name((b'\x00',) + self.qname.labels)
        nsec_rrset = make_nsec_rrset(self.qname, nextname, rrtypes, zobj.soa_min_ttl)
        self.add_rrset(zobj, self.response.authority, nsec_rrset)

    def nxdomain_nsec_online(self, zobj, sname):
        """
        Generate online NSEC NXDOMAIN response using RFC 4470 minimally
        covering NSEC records ("white lies").

        Two NSECs are synthesized: one whose interval covers the queried name,
        and one covering the relevant wildcard (*.<closest-encloser>) to prove
        no wildcard would have matched. Both owner names are collision-checked
        against the real zone (Zone.covering_predecessor / covering_successor)
        so a synthetic name never spans or denies an existing name.

        The covering interval for the qname is built around the next-closer
        name (sname = closest-encloser plus one label toward the qname), NOT the
        full qname: (predecessor(sname), successor(sname)). A strict validator
        reconstructs the closest encloser as the longest suffix the queried name
        shares with the NSEC's owner OR next name (RFC 4035 5.4, RFC 7129);
        both endpoints here are same-parent siblings of sname, so that longest
        shared suffix is exactly sname.parent() == the closest encloser. Using
        the full qname (which is a subdomain of sname when the qname is several
        labels below the closest encloser) would leak extra shared labels into
        the next name and make the validator derive too deep a closest encloser,
        then demand a wildcard NSEC we never send -> SERVFAIL. The interval
        (predecessor(sname), successor(sname)) still covers the whole qname,
        since every subdomain of sname sorts between sname's predecessor and
        successor.
        """
        self.response.set_rcode(dns.rcode.NXDOMAIN)
        ideal = self.ctx.prefs.nsec_ideal_predecessor
        rrtypes = [dns.rdatatype.RRSIG, dns.rdatatype.NSEC]

        nsec_qname = make_nsec_rrset(
            zobj.covering_predecessor(sname, ideal=ideal),
            zobj.covering_successor(sname),
            rrtypes, zobj.soa_min_ttl)
        self.add_rrset(zobj, self.response.authority, nsec_qname)

        wildcard = dns.name.Name((b'*',) + sname.parent().labels)
        nsec_wildcard = make_nsec_rrset(
            zobj.covering_predecessor(wildcard, ideal=ideal),
            zobj.covering_successor(wildcard),
            rrtypes, zobj.soa_min_ttl)
        self.add_rrset(zobj, self.response.authority, nsec_wildcard)

    def nxdomain_nsec3_online(self, zobj, sname):
        """
        Generate online NSEC3 NXDOMAIN response using White Lies
        """

        self.response.set_rcode(dns.rcode.NXDOMAIN)

        closest_encloser = sname.parent()
        node = zobj.find_node(closest_encloser)
        closest_encloser_rrtypes = [x.rdtype for x in node.rdatasets] + [dns.rdatatype.RRSIG]
        n3_closest_encloser = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            closest_encloser, closest_encloser_rrtypes,
            zobj.soa_min_ttl, covering=False)
        self.add_rrset(zobj, self.response.authority, n3_closest_encloser)

        next_closer = sname
        n3_next_closer = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            next_closer, [],
            zobj.soa_min_ttl, covering=True)
        self.add_rrset(zobj, self.response.authority, n3_next_closer)

        wildcard = dns.name.Name((b'*',) + sname.parent().labels)
        n3_wildcard = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            wildcard, [],
            zobj.soa_min_ttl, covering=True)
        self.add_rrset(zobj, self.response.authority, n3_wildcard)

    def nxdomain_nsec3_online_compact(self, zobj):
        """
        Generate online NSEC3 NXDOMAIN response using Compact Denial
        """

        if compact_answer_ok(self.query.message):
            self.response.set_rcode(dns.rcode.NXDOMAIN)

        rrtypes = [RRtype.NXNAME]
        n3_rrset = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            self.qname, rrtypes,
            zobj.soa_min_ttl, covering=False)
        self.add_rrset(zobj, self.response.authority, n3_rrset)

    def nxdomain_nsec(self, zobj, sname):
        """Generate NSEC NXDOMAIN response"""

        qname_cover = zobj.nsec_covering(sname)
        if qname_cover:
            self.add_rrset(zobj, self.response.authority, qname_cover)
        wildcard = dns.name.Name((b'*',) + sname.parent().labels)
        wildcard_cover = zobj.nsec_covering(wildcard)
        if wildcard_cover:
            self.add_rrset(zobj, self.response.authority, wildcard_cover)

    def nxdomain_nsec3(self, zobj, sname):
        """Generate NSEC3 NXDOMAIN response"""

        closest_encloser = sname.parent()
        n3_closest_encloser = zobj.nsec3_matching(closest_encloser)
        self.add_rrset(zobj, self.response.authority, n3_closest_encloser)

        next_closer = sname
        n3_next_closer = zobj.nsec3_covering(next_closer)
        self.add_rrset(zobj, self.response.authority, n3_next_closer)

        wildcard = dns.name.Name((b'*',) + sname.parent().labels)
        n3_wildcard = zobj.nsec3_covering(wildcard)
        self.add_rrset(zobj, self.response.authority, n3_wildcard)

    def nodata(self, zobj, sname, wildcard=None):
        """Generate NODATA response"""

        self.add_soa(zobj)
        if not self.dnssec_ok():
            return

        if zobj.online_signing():
            if zobj.nsec3param:
                if zobj.compact_denial:
                    self.nodata_nsec3_online_compact(zobj, sname, wildcard)
                else:
                    self.nodata_nsec3_online(zobj, sname, wildcard)
            else:
                self.nodata_nsec_online(zobj, sname, wildcard)
            return

        if zobj.dnssec:
            if zobj.nsec3param is None:
                self.nodata_nsec(zobj, sname, wildcard=wildcard)
            else:
                self.nodata_nsec3(zobj, sname, wildcard=wildcard)

    def nodata_nsec_online(self, zobj, sname, wildcard=None):
        """
        Generate online NSEC NODATA response.

        A NODATA answer proves the name exists but the type does not, so this
        is a plain *matching* NSEC (owner = the name, bitmap = its real types
        plus RRSIG and NSEC) -- no RFC 4470 predecessor synthesis. This is
        identical for Compact Denial and classic white-lie zones (the compact
        black lie applies only to NXDOMAIN, via the NXNAME bit), so a single
        function serves both modes. Empty non-terminals are handled naturally:
        find_node() yields an ENT's (empty) rdataset list, giving an NSEC+RRSIG
        bitmap.
        """

        if wildcard:
            nextname = dns.name.Name((b'\x00',) + self.qname.labels)
            owner = self.qname
        else:
            nextname = dns.name.Name((b'\x00',) + sname.labels)
            owner = sname
        node = zobj.find_node(sname)
        rrtypes = [x.rdtype for x in node.rdatasets] + \
            [dns.rdatatype.RRSIG, dns.rdatatype.NSEC]
        nsec_rrset = make_nsec_rrset(owner, nextname, rrtypes, zobj.soa_min_ttl)
        self.add_rrset(zobj, self.response.authority, nsec_rrset)

    def nodata_nsec3_online(self, zobj, sname, wildcard=None):
        """
        Generate online NSEC3 NODATA response using White Lies
        """

        owner = self.qname if wildcard else sname
        node = zobj.find_node(sname)
        rrtypes = [x.rdtype for x in node.rdatasets] + [dns.rdatatype.RRSIG]

        n3_nodata = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            owner, rrtypes,
            zobj.soa_min_ttl, covering=False)
        self.add_rrset(zobj, self.response.authority, n3_nodata)

    def nodata_nsec3_online_compact(self, zobj, sname, wildcard=None):
        """
        Generate online NSEC3 NODATA response using Compact Denial
        """

        owner = self.qname if wildcard else sname
        node = zobj.find_node(sname)
        rrtypes = [x.rdtype for x in node.rdatasets]

        n3_nodata = make_nsec3_rrset_minimal(
            zobj.nsec3param[0], zobj.origin,
            owner, rrtypes,
            zobj.soa_min_ttl, covering=False)
        self.add_rrset(zobj, self.response.authority, n3_nodata)

    def nodata_nsec(self, zobj, sname, wildcard=None):
        """Generate NSEC NODATA response"""

        nsec_rrset = zobj.nsec_matching(sname)
        if nsec_rrset:
            self.add_rrset(zobj, self.response.authority, nsec_rrset)
        else:
            # Empty Non-Terminal case
            nsec_rrset = zobj.nsec_covering(sname)
            if nsec_rrset:
                self.add_rrset(zobj, self.response.authority, nsec_rrset)

        if wildcard:
            no_closer = zobj.nsec_covering(wildcard)
            if no_closer:
                self.add_rrset(zobj, self.response.authority, no_closer)

    def nodata_nsec3(self, zobj, sname, wildcard=None):
        """Generate NSEC3 NODATA response"""

        n3_rrset = zobj.nsec3_matching(sname)
        if n3_rrset:
            self.add_rrset(zobj, self.response.authority, n3_rrset)
        if wildcard:
            n3_wild = zobj.nsec3_covering(wildcard)
            if n3_wild:
                self.add_rrset(zobj, self.response.authority, n3_wild)
            n3_closest = zobj.nsec3_matching(sname.parent())
            if n3_closest:
                self.add_rrset(zobj, self.response.authority, n3_closest)

    def wildcard_no_closer_match(self, zobj, wildcard, stype):
        """Wildcard no closer match proof"""

        _ = wildcard
        if zobj.dnssec and self.dnssec_ok():
            if zobj.nsec3param is None:
                n1_rrset = zobj.nsec_covering(stype)
                if n1_rrset:
                    self.add_rrset(zobj, self.response.authority, n1_rrset)
            else:
                n3_rrset = zobj.nsec3_covering(stype)
                if n3_rrset:
                    self.add_rrset(zobj, self.response.authority, n3_rrset)

    def add_nsec_matching(self, zobj, sname):
        """Add NSEC or NSEC3 record matching name"""

        if zobj.online_signing():
            self.add_nsec_online(zobj, sname)
        elif zobj.nsec3param is None:
            n1_rrset = zobj.nsec_matching(sname)
            if n1_rrset:
                self.add_rrset(zobj, self.response.authority, n1_rrset)
        else:
            n3_rrset = zobj.nsec3_matching(sname)
            if n3_rrset:
                self.add_rrset(zobj, self.response.authority, n3_rrset)

    def add_nsec_online(self, zobj, sname):
        """Generate online NSEC or NSEC3 RRset for given name"""

        node = zobj.find_node(sname)

        if not zobj.nsec3param:
            rrtypes = [x.rdtype for x in node.rdatasets] + \
                [dns.rdatatype.RRSIG, dns.rdatatype.NSEC]
            if sname != zobj.origin and \
                    (dns.rdatatype.NS in rrtypes or RRtype.DELEG in rrtypes):
                nextname = dns.name.Name(
                    (sname.labels[0] + b'\x00',) + sname.labels[1:])
            else:
                nextname = dns.name.Name((b'\x00',) + sname.labels)
            nsec_rrset = make_nsec_rrset(sname, nextname, rrtypes, zobj.soa_min_ttl)
            self.add_rrset(zobj, self.response.authority, nsec_rrset)
        else:
            rrtypes = [x.rdtype for x in node.rdatasets] + [dns.rdatatype.RRSIG]
            nsec3_rrset = make_nsec3_rrset_minimal(
                zobj.nsec3param[0], zobj.origin,
                sname, rrtypes,
                zobj.soa_min_ttl, covering=False)
            self.add_rrset(zobj, self.response.authority, nsec3_rrset)


class ReferralMixin:
    # pylint: disable=no-member
    """
    Referral generation (traditional NS and DELEG-aware) and DELEG-only
    occlusion of a DE=0 (DELEG-unaware) client's view below a DELEG-only cut.

    Relies on sibling/core state and methods set up by DNSresponse.__init__
    and defined on the DNSresponse class body or DenialMixin: self.response,
    self.query, self.is_referral, self.edns_options, self.dnssec_ok(),
    self.add_rrset(), self.add_soa(), self.add_nsec_matching().

    The no-member disable is needed because pylint analyzes this class in
    isolation: every self.<attr>/self.<method>() referenced here is defined
    by DNSresponse.__init__ or by a sibling mixin, and only resolves at
    runtime through the combined DNSresponse MRO (Design.md section 10.3).
    """

    def do_referral(self, zobj, sname, rdataset):
        """Generate referral response to child zone"""

        self.is_referral = True
        if deleg_ext_ok(self.query.message):
            self.do_referral_deleg(zobj, sname)
            return

        self.do_referral_traditional(zobj, sname, rdataset)

    def do_referral_traditional(self, zobj, sname, rdataset):
        """Generate traditional referral response (NS + glue + DS/NSEC)"""

        ns_rrset = rrset_from_rdataset(sname, rdataset)
        self.add_rrset(zobj, self.response.authority, ns_rrset, authoritative=False)
        self.get_glue(zobj, sname, rdataset)

        if zobj.dnssec and self.dnssec_ok():
            ds_rrset = zobj.get_rrset(sname, dns.rdatatype.DS)
            if ds_rrset:
                self.add_rrset(zobj, self.response.authority, ds_rrset)
            else:
                # Insecure referral - add NSEC record matching delegation name
                self.add_nsec_matching(zobj, sname)

    def do_referral_deleg(self, zobj, sname):
        """
        Generate DELEG-aware referral response (DE=1) to child zone.

        deleg-10 5.2.1: if the delegation has a DELEG RRset, it goes into
        the Authority section and the NS RRset MUST NOT be included; DS is
        included when present. delext-10 6.2 additionally requires the
        matching NSEC/NSEC3 -- its type bitmap listing the Delegation Types
        -- so a validator can confirm the DELEG RRset was not stripped; this
        proof accompanies every secure referral with a DELEG RRset,
        independent of DS (and, when DS is absent, also proves DS absence).
        If there is no DELEG RRset, this is a legacy NS referral, but the
        absence of the DELEG RRset MUST additionally be proven (5.2.1.3).
        """

        deleg_rrset = zobj.get_rrset(sname, RRtype.DELEG)
        if deleg_rrset:
            self.add_rrset(zobj, self.response.authority, deleg_rrset)
            if zobj.dnssec and self.dnssec_ok():
                ds_rrset = zobj.get_rrset(sname, dns.rdatatype.DS)
                if ds_rrset:
                    self.add_rrset(zobj, self.response.authority, ds_rrset)
                # delext-10 6.2: the matching NSEC/NSEC3 MUST accompany the
                # referral to prove the Delegation Types are present (and,
                # with DS absent, that DS is not). Add unconditionally -- the
                # requirement is keyed to the delegating zone's ADT flag,
                # which is the validator's concern; an authoritative server
                # is under no obligation to inspect its own ADT flag, and the
                # proof is harmless when ADT is clear.
                self.add_nsec_matching(zobj, sname)
            return

        # No DELEG RRset: legacy NS referral, plus proof of DELEG absence.
        ns_rdataset = zobj.get_rdataset(sname, dns.rdatatype.NS)
        self.do_referral_traditional(zobj, sname, ns_rdataset)
        if zobj.dnssec and self.dnssec_ok():
            self.add_nsec_matching(zobj, sname)

    def get_glue(self, zobj, sname, rdataset):
        """Add glue records if needed"""

        for rdata in rdataset:
            if not rdata.target.is_subdomain(sname):
                continue
            for rrtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                rdataset = zobj.get_rdataset(rdata.target, rrtype)
                if rdataset:
                    self.add_rrset(zobj, self.response.additional,
                                   rrset_from_rdataset(rdata.target, rdataset),
                                   authoritative=False)

    def add_new_delegation_only_ede(self):
        """
        Add "New Delegation Only" Extended DNS Error (deleg-10 5.2.2.1) to a
        DE=0 response for a name at or below a DELEG-only delegation cut.
        """
        if self.query.message.edns == -1:
            return
        self.edns_options.append(
            dns.edns.EDEOption(EDECode.NEW_DELEGATION_ONLY,
                               "New Delegation Only"))

    @staticmethod
    def next_closer_name(qname, cut):
        """Return the name one label below the closest encloser (cut)."""
        extra = len(qname.labels) - len(cut.labels)
        return dns.name.Name((qname.labels[extra - 1],) + cut.labels)

    def occluded_nxdomain(self, zobj, qname, cut):
        """
        Generate authoritative NXDOMAIN for a DE=0 query below a DELEG-only
        cut (deleg-10 5.2.2.1). The child zone is invisible to a DELEG-unaware
        client. The nonexistence proof deliberately keeps the DELEG bit visible
        (matching NSEC / closest-encloser NSEC3) rather than using a Compact
        Denial black lie -- see DELEG.md.
        """
        self.response.set_rcode(dns.rcode.NXDOMAIN)
        self.add_soa(zobj)
        if not self.dnssec_ok():
            return
        if not zobj.nsec3param:
            # NSEC: the cut's NSEC uses the special covering next-name form
            # (cut -> cut\000), which covers all names below the cut.
            self.add_nsec_matching(zobj, cut)
        else:
            self.occluded_nxdomain_nsec3(zobj, qname, cut)

    def occluded_nxdomain_nsec3(self, zobj, qname, cut):
        """NSEC3 closest-encloser proof for a DELEG-only occlusion NXDOMAIN"""

        next_closer = self.next_closer_name(qname, cut)
        wildcard = dns.name.Name((b'*',) + cut.labels)

        if zobj.online_signing():
            params = zobj.nsec3param[0]
            node = zobj.find_node(cut)
            ce_rrtypes = [x.rdtype for x in node.rdatasets] + \
                [dns.rdatatype.RRSIG]
            n3_ce = make_nsec3_rrset_minimal(
                params, zobj.origin, cut, ce_rrtypes,
                zobj.soa_min_ttl, covering=False)
            self.add_rrset(zobj, self.response.authority, n3_ce)
            n3_next = make_nsec3_rrset_minimal(
                params, zobj.origin, next_closer, [],
                zobj.soa_min_ttl, covering=True)
            self.add_rrset(zobj, self.response.authority, n3_next)
            n3_wild = make_nsec3_rrset_minimal(
                params, zobj.origin, wildcard, [],
                zobj.soa_min_ttl, covering=True)
            self.add_rrset(zobj, self.response.authority, n3_wild)
            return

        n3_ce = zobj.nsec3_matching(cut)
        if n3_ce:
            self.add_rrset(zobj, self.response.authority, n3_ce)
        n3_next = zobj.nsec3_covering(next_closer)
        if n3_next:
            self.add_rrset(zobj, self.response.authority, n3_next)
        n3_wild = zobj.nsec3_covering(wildcard)
        if n3_wild:
            self.add_rrset(zobj, self.response.authority, n3_wild)


class ResolveMixin:
    # pylint: disable=no-member
    """
    The name-resolution walk: descend the zone from apex to qname
    (find_answer / find_answer_in_zone / process_name), then resolve the
    terminal outcome at the qname (find_rrtype), including ANY, CNAME, and
    DNAME handling.

    Relies on sibling/core state and methods set up by DNSresponse.__init__
    and defined on the DNSresponse class body, DenialMixin, or ReferralMixin:
    self.qname, self.response, self.query, self.ctx, self.cname_owner_list,
    self.dname_owner_list, self.is_nodata, self.is_referral,
    self.need_to_truncate, self.badcookie, self.server_cookie_verified,
    self.add_rrset(), self.nodata(), self.nxdomain(), self.do_referral(),
    self.occluded_nxdomain(), self.add_new_delegation_only_ede(),
    self.wildcard_no_closer_match().

    The no-member disable is needed because pylint analyzes this class in
    isolation: every self.<attr>/self.<method>() referenced here is defined
    by DNSresponse.__init__ or by a sibling mixin, and only resolves at
    runtime through the combined DNSresponse MRO (Design.md section 10.3).
    """

    def process_any_metatype(self, zobj, sname, wildcard):
        """Process ANY meta query"""

        rrname = wildcard if wildcard else sname
        rdatasets = zobj.get_node(sname).rdatasets
        if not rdatasets:
            self.is_nodata = True
            self.nodata(zobj, sname, wildcard)
            return

        if self.ctx.prefs.minimal_any:
            for rdataset in rdatasets:
                if rdataset.rdtype == dns.rdatatype.RRSIG:
                    continue
                self.add_rrset(zobj, self.response.answer,
                               rrset_from_rdataset(rrname, rdataset))
                return

        for rdataset in rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue
            self.add_rrset(zobj, self.response.answer,
                           rrset_from_rdataset(rrname, rdataset))

    def find_rrtype(self, zobj, sname, stype, wildcard=None):
        """Find RRtype for given name, with CNAME processing if needed"""

        rrname = self.qname if wildcard else sname

        # ANY
        if stype == dns.rdatatype.ANY:
            self.process_any_metatype(zobj, sname, wildcard)
            return

        # If not CNAME, look for CNAME, and process it if found.
        if stype != dns.rdatatype.CNAME:
            rdataset = zobj.get_rdataset(sname, dns.rdatatype.CNAME)
            if rdataset:
                self.process_cname(zobj, rrname, sname, stype, rdataset,
                                   wildcard=wildcard)
                return

        # Special case processing of queries for owners of NSEC3 records
        if (zobj.nsec3param is not None) and (not zobj.online_signing()):
            if zobj.get_rdataset(sname, dns.rdatatype.NSEC3):
                self.nxdomain(zobj, sname)
                return

        # Look for requested RRtype
        rdataset = zobj.get_rdataset(sname, stype)
        if rdataset:
            self.add_rrset(zobj, self.response.answer,
                           rrset_from_rdataset(rrname, rdataset),
                           wildcard=sname if wildcard else None)
            return

        # NODATA - add SOA
        self.is_nodata = True
        self.nodata(zobj, sname, wildcard)

    def process_cname(self,  # pylint: disable=too-many-positional-arguments
                      zobj, rrname, sname, stype, cname_rdataset,
                      wildcard=None):
        """Process CNAME"""

        if sname in self.cname_owner_list:
            log_message(f"error: CNAME loop detected at {sname}")
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.cname_owner_list.append(sname)
        self.add_rrset(zobj, self.response.answer,
                       rrset_from_rdataset(rrname, cname_rdataset),
                       wildcard=sname if wildcard else None)
        self.find_answer(cname_rdataset[0].target, stype)

    def process_dname(self, zobj, qname, sname, stype, dname_rdataset):
        """Process DNAME"""

        if sname in self.dname_owner_list:
            log_message(f"error: DNAME loop detected at {sname}")
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.dname_owner_list.append(sname)
        self.add_rrset(zobj, self.response.answer,
                       rrset_from_rdataset(sname, dname_rdataset))

        dname_target = dname_rdataset[0].target
        try:
            cname_target = dns.name.Name(
                qname.relativize(sname).labels + dname_target.labels)
        except dns.name.NameTooLong:
            self.response.set_rcode(dns.rcode.YXDOMAIN)
            return

        rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN,
                                         dns.rdatatype.CNAME)
        rdataset.update_ttl(dname_rdataset.ttl)
        cname_rdata = dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN,
                                                  dns.rdatatype.CNAME,
                                                  cname_target)
        rdataset.add(cname_rdata)
        self.process_cname(zobj, qname, qname, stype, rdataset)

    def process_name(self, zobj, qname, sname, stype):
        """
        Process name and type. This function is called iteratively by
        find_answer_in_zone() to find the answer to the qname. At the given
        search name (sname), if the name doesn't exist, we look for a wildcard;
        otherwise we look for a DNAME or delegation. Otherwise, we indicate
        that the search hasn't finished, and the caller will append the next
        label towards the qname and call us again.

        Returns a bool signalling whether the descent down the DNS tree is
        complete: True means this step produced a terminal outcome and the
        caller should stop -- an answer or NODATA (find_rrtype), a wildcard
        match, a DNAME redirection, a referral, or a denial (NXDOMAIN /
        occlusion). False means sname is an existing interior node short of
        the qname, so the caller appends the next label and calls again.
        """

        node = zobj.get_node(sname)
        if node is None:
            # Look for wildcard
            wildcard_name = dns.name.Name((b'*',) + sname.labels[1:])
            if zobj.get_node(wildcard_name) is not None:
                self.find_rrtype(zobj, wildcard_name, stype, wildcard=sname)
                if not zobj.online_signing():
                    self.wildcard_no_closer_match(zobj, wildcard_name, sname)
                return True
            self.nxdomain(zobj, sname)
            return True

        # Look for DNAME
        dname_rdataset = zobj.get_rdataset(sname, dns.rdatatype.DNAME)
        if dname_rdataset:
            self.process_dname(zobj, qname, sname, stype, dname_rdataset)
            return True

        # Look for delegation. A delegation point has an NS RRset and/or a
        # DELEG RRset. A DELEG-aware client (DE=1) gets a DELEG-aware referral;
        # a DELEG-unaware client (DE=0) is served per non-DELEG specifications,
        # i.e. NS occludes DELEG, and a DELEG-only cut (no NS) is an
        # invisible/occluded namespace.
        if sname != zobj.origin:
            ns_rdataset = zobj.get_rdataset(sname, dns.rdatatype.NS)
            deleg_rrset = zobj.get_rrset(sname, RRtype.DELEG)
            de_aware = deleg_ext_ok(self.query.message)
            is_cut = bool(ns_rdataset) or bool(deleg_rrset)
            if is_cut and ((qname != sname) or
                           (stype not in AUTH_IN_PARENT_RRTYPES)):
                if de_aware:
                    self.do_referral(zobj, sname, ns_rdataset)
                    return True
                if ns_rdataset:
                    # DE=0 with NS present: NS occludes DELEG -> legacy referral
                    self.do_referral(zobj, sname, ns_rdataset)
                    return True
                # DE=0, DELEG-only cut: namespace is invisible to this client
                self.add_new_delegation_only_ede()
                if qname != sname:
                    self.occluded_nxdomain(zobj, qname, sname)
                    return True
                # qname == sname: fall through to answer DELEG/DS as ordinary
                # data or return NODATA (deleg-10 5.2.2.1 / 5.2.2.2).

        if sname == qname:
            self.find_rrtype(zobj, sname, stype)
            return True

        return False

    def find_answer_in_zone(self, zobj, qname, qtype):
        """
        Find answer for name and type in given zone. Calls process_name()
        iteratively to search zone from zone apex name to qname, appending
        successive labels til we reach the qname, or we are diverted by a
        wildcard, dname, or delegation.
        """

        zone_name = zobj.origin
        label_list = list(qname.relativize(zone_name).labels)

        current_name = zone_name
        while True:
            finished = self.process_name(zobj, qname, current_name, qtype)
            if finished or (not label_list):
                break
            label = label_list.pop()
            current_name = dns.name.Name((label,) + current_name.labels)

    def find_answer(self, qname, qtype):
        """Find answer for name and type"""

        zobj = self.ctx.zonedict.find(qname)
        if zobj is None:
            if not self.response.answer:
                self.response.set_rcode(dns.rcode.REFUSED)
                if self.query.message.edns != -1:
                    option = dns.edns.EDEOption(
                        dns.edns.EDECode.NOT_AUTHORITATIVE,
                        "Not authoritative for queried zone")
                    self.edns_options.append(option)
            return
        if not self.query.tcp and zobj.udp_truncate_all:
            self.need_to_truncate = True
        elif zobj.require_server_cookie and (not self.server_cookie_verified):
            self.badcookie = True
        else:
            self.find_answer_in_zone(zobj, qname, qtype)


class EdnsCookieMixin:
    # pylint: disable=no-member
    """
    EDNS negotiation (initial option processing, final OPT RR emission) and
    RFC 7873 DNS Cookie generation/verification.

    Relies on sibling/core state and methods set up by DNSresponse.__init__
    and defined on the DNSresponse class body: self.query, self.ctx,
    self.edns_flags, self.edns_options, self.badcookie,
    self.server_cookie_verified, self.response, self.dnssec_ok().

    The no-member disable is needed because pylint analyzes this class in
    isolation: every self.<attr>/self.<method>() referenced here is defined
    by DNSresponse.__init__ or by a sibling mixin, and only resolves at
    runtime through the combined DNSresponse MRO (Design.md section 10.3).
    """

    def add_cookie_option(self, data):
        """Add EDNS Cookie option with given cookie data"""
        option = dns.edns.GenericOption(dns.edns.COOKIE, data)
        self.edns_options.append(option)

    def verify_server_cookie(self, cookiedata):
        """
        Verify received cookie. Returns a tuple of (boolean, cookiedata).
        boolean is true if the cookie validates properly, false otherwise.
        cookiedata contains the cookie to return to the client, which is
        either the same one, or a re-generated one if we are passed the
        re-generation interval.
        """

        clientcookie = cookiedata[:8]
        servercookie_received = cookiedata[8:]
        timestamp = servercookie_received[4:8]
        current_time = time.time()
        cookie_time, = struct.unpack('!I', timestamp)
        time_delta = current_time - cookie_time
        if cookie_time > current_time or time_delta > COOKIE_TIMESTAMP_DRIFT:
            log_message(f"Cookie timestamp too old from {self.query.cliaddr}")
            return False, None
        expected = self.calculate_server_cookie(clientcookie, b'\x00\x00\x00', timestamp)
        if servercookie_received != expected:
            log_message(f"Invalid server cookie from {self.query.cliaddr}")
            return False, None
        if time_delta < COOKIE_RECALCULATE_TIME:
            return True, cookiedata
        log_message(f"Re-calculating cookie for {self.query.cliaddr}")
        newcookie = clientcookie + \
            self.calculate_server_cookie(clientcookie,
                                         b'\x00\x00\x00',
                                         struct.pack('!I', int(time.time())))
        return True, newcookie

    def calculate_server_cookie(self, clientcookie, reserved, timestamp):
        """Calculate Server Cookie"""

        clientip = self.query.cliaddr
        version = b'\x01'
        sip = siphash.SipHash_2_4(self.ctx.cookie_secret)
        sip.update(clientcookie + version + reserved + timestamp + bytes(clientip, 'ascii'))
        return version + reserved + timestamp + sip.digest()

    def process_cookie(self, cookiedata):
        "Process DNS cookie received in query"

        cookiedatalen = len(cookiedata)

        if cookiedatalen < 8:
            self.response.set_rcode(dns.rcode.FORMERR)
            return

        clientcookie = cookiedata[0:8]
        timestamp = struct.pack('!I', int(time.time()))
        servercookie = self.calculate_server_cookie(clientcookie,
                                                    b'\x00\x00\x00',
                                                    timestamp)
        if cookiedatalen == 8:
            self.add_cookie_option(cookiedata + servercookie)
            return
        if cookiedatalen != 24:
            log_message(f"bad cookie length={cookiedatalen} from {self.query.cliaddr}")
            self.add_cookie_option(clientcookie + servercookie)
            self.badcookie = True
            return
        verified, returncookie = self.verify_server_cookie(cookiedata)
        if not verified:
            log_message(f"bad cookie from {self.query.cliaddr}")
            self.add_cookie_option(clientcookie + servercookie)
            self.badcookie = True
            return
        self.server_cookie_verified = True
        self.add_cookie_option(returncookie)

    def do_edns_init(self):
        """Generate initial EDNS response information"""

        if self.dnssec_ok():
            self.edns_flags = dns.flags.DO
            if compact_answer_ok(self.query.message):
                self.edns_flags |= EdnsFlag.COMPACT_OK

        if deleg_ext_ok(self.query.message):
            self.edns_flags |= EdnsFlag.DELEG_EXT_OK

        for option in self.query.message.options:
            if self.ctx.prefs.nsid and (option.otype == dns.edns.NSID):
                self.edns_options.append(dns.edns.GenericOption(
                    dns.edns.NSID, self.ctx.prefs.nsid))
            elif option.otype == dns.edns.COOKIE:
                if hasattr(option, 'data'):
                    self.process_cookie(option.data)
                else:
                    self.process_cookie(option.client + option.server)

    def do_edns_final(self):
        """Generate final EDNS OPT RR"""

        self.response.use_edns(edns=0,
                               ednsflags=self.edns_flags,
                               payload=self.ctx.prefs.edns_udp_adv,
                               request_payload=self.ctx.prefs.edns_udp_max,
                               options=self.edns_options)


class DNSresponse(DenialMixin, ReferralMixin, ResolveMixin, EdnsCookieMixin):
    """
    Assemble a DNS response for one query. The request-handling algorithm is
    split across four mixins that all operate on shared ``self`` state; see
    Design.md section 10.3. Core plumbing lives on this class body.
    """

    def __init__(self, query, ctx):

        self.query = query
        self.ctx = ctx
        self.response = dns.message.make_response(
            query.message, our_payload=ctx.prefs.edns_udp_adv)

        if not self.query.headeronly:
            # Canonicalize (downcase) the query name for all internal
            # processing and answer construction. This keeps synthesized
            # owner names and, crucially, NSEC RDATA next-names (which are
            # NOT downcased during DNSSEC canonicalization, per RFC 6840
            # section 5.1) in canonical case, so that online signatures
            # match regardless of DNS 0x20 case randomization in the query.
            # The echoed question section retains the original case, since
            # make_response() copied it from the original query message.
            self.qname = query.message.question[0].name.canonicalize()
            self.qtype = query.message.question[0].rdtype
            self.qclass = query.message.question[0].rdclass

        self.is_referral = False
        self.cname_owner_list = []
        self.dname_owner_list = []
        self.is_nodata = False
        self.edns_flags = 0
        self.edns_options = []
        self.badcookie = False
        self.server_cookie_verified = False
        self.need_to_truncate = False

        self.response.set_rcode(dns.rcode.NOERROR)
        self.response.flags &= ~dns.flags.AA
        self.prepare_response()

    def to_wire(self):
        """Generate wire format DNS response"""

        if self.need_to_truncate:
            return self.truncate()

        payload_max = self.max_size()
        try:
            wire = self.response.to_wire(max_size=payload_max)
        except dns.exception.TooBig:
            wire = self.truncate()
        if self.query.tcp:
            msglen = struct.pack('!H', len(wire))
            wire = msglen + wire
        return wire

    def max_size(self):
        """Compute maximum permissible DNS response size"""

        if self.query.tcp:
            return TCP_MAXSIZE
        if (self.ctx.prefs.edns_udp_max == 0) or \
                (self.query.message.edns == -1):
            return UDP_MAXSIZE_NOEDNS
        return min(self.query.message.payload, self.ctx.prefs.edns_udp_max)

    def truncate(self):
        """Truncate response message"""

        self.response.flags |= dns.flags.TC
        self.response.answer = []
        self.response.authority = []
        self.response.additional = []
        return self.response.to_wire()

    def add_rrset(self,  # pylint: disable=too-many-positional-arguments
                  zobj, section, rrset, wildcard=None, authoritative=True,
                  ttl=None):
        """
        Add RRset to section, fetching RRsigs if needed.

        The ttl= parameter is for handling SOA in negative responses correctly.
        If ttl is not None, the RRset and its covering RRSIG are emitted with
        that wire TTL. For SOA additions in negative responses, this function is
        called with the ttl set to the SOA min TTL value. Per RFC 2308, the SOA
        record's TTL is then set to this value. For signed zones, per RFC 4034,
        Section 3, the SOA RRSIG RR's TTL is matched to this value (i.e. to the
        covering RRset's TTL). The RRset is signed (online) or its RRSIG fetched
        (precomputed) at the zone TTL first, so the RRSIG Original TTL field is
        unaffected; only the wire TTLs are lowered afterward.
        """

        if rrset in section:
            return
        section.append(rrset)

        if authoritative and self.dnssec_ok():
            rrsig = None
            if zobj.online_signing():
                rrsig = sign_rrset(zobj, HashableRRset(rrset))
                if self.ctx.prefs.cache_stats:
                    log_message(f"sigcache: {sign_rrset.cache_info()}")
            elif zobj.dnssec:
                rrname = wildcard if wildcard else rrset.name
                rdataset = zobj.get_rdataset(rrname, dns.rdatatype.RRSIG,
                                             covers=rrset.rdtype)
                if rdataset:
                    rrsig = rrset_from_rdataset(rrset.name, rdataset)
            if rrsig is not None:
                if ttl is not None:
                    # The online RRSIG is a shared, cached object (the cache
                    # key ignores TTL); copy before altering its wire TTL.
                    rrsig = copy.copy(rrsig)
                    rrsig.ttl = ttl
                section.append(rrsig)

        if ttl is not None:
            # After signing, so the RRSIG Original TTL field stays at the
            # zone TTL while the emitted wire TTL is the reduced value.
            rrset.ttl = ttl

    def add_soa(self, zobj):
        """
        Add SOA record to authority for negative responses. Obtain the
        zone's SOA record, and pass it to add_rrset() along with the 
        SOA min TTL value.
        """

        soa_rrset = zobj.get_rrset(zobj.origin, dns.rdatatype.SOA)
        self.add_rrset(zobj, self.response.authority, soa_rrset,
                       ttl=zobj.soa_min_ttl)

    def dnssec_ok(self):
        """Does requestor have the DO flag set?"""

        return self.query.message.ednsflags & dns.flags.DO == dns.flags.DO

    def need_edns(self):
        """Do we need to add EDNS Opt RR?"""

        return (self.ctx.prefs.edns_udp_max != 0) and \
            (self.query.message.edns != -1)

    def prepare_response(self):
        """Prepare DNS response message"""

        opcode = self.query.message.opcode()
        if opcode == dns.opcode.NOTIFY:
            return
        if opcode == dns.opcode.UPDATE:
            self.response.set_rcode(dns.rcode.REFUSED)
            return
        if opcode != dns.opcode.QUERY:
            self.response.set_rcode(dns.rcode.NOTIMP)
            return

        if self.need_edns():
            if self.query.message.edns > 0:
                self.response.set_rcode(dns.rcode.BADVERS)
                return
            self.do_edns_init()
        else:
            self.response.use_edns(edns=False)

        if self.response.rcode() == dns.rcode.FORMERR:
            return

        if self.badcookie:
            self.do_edns_final()
            self.response.set_rcode(dns.rcode.BADCOOKIE)
            return

        if self.query.headeronly:

            if dns.edns.COOKIE not in [x.otype for x in self.edns_options]:
                self.response.set_rcode(dns.rcode.FORMERR)
                self.response.use_edns(edns=False)
                return

        else:

            if self.qclass != dns.rdataclass.IN:
                self.response.set_rcode(dns.rcode.REFUSED)
                return

            if query_meta_type(self.qtype):
                self.response.set_rcode(dns.rcode.FORMERR)
                if self.query.message.edns != -1:
                    option = dns.edns.EDEOption(EDECode.INVALID_QTYPE,
                                                "Invalid Query Type")
                    self.edns_options.append(option)
                    self.do_edns_final()
                return

            self.find_answer(self.qname, self.qtype)

        if self.need_edns():
            self.do_edns_final()
            if self.badcookie:
                self.response.set_rcode(dns.rcode.BADCOOKIE)

        if self.response.rcode() in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
            if (not self.is_referral) or self.response.answer:
                self.response.flags |= dns.flags.AA
