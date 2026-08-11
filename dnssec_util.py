#!/usr/bin/env python3

"""
Shared DNSSEC / zone-model utilities for adns_server and the offline signer.

Contains the sorted, ENT-aware Zone model plus pure NSEC/NSEC3 name and hash
helpers. Kept free of server-only concerns (config, sockets, online signing
cache) so both adns_server.py and signzone.py can import it. See Signer.md §1a.
"""

import hashlib
import base64
import enum

import dns.zone
import dns.name
import dns.node
import dns.rrset
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
import dns.dnssec
from dns.rdtypes.ANY import NSEC
from dns.rdtypes.ANY import NSEC3
from sortedcontainers import SortedDict
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class RRtype(enum.IntEnum):
    """Resource Record types"""
    NXNAME = 128
    DELEG = 61440
    DELEGPARAM = 65433

## RR types that are authoritative in the parent zone
AUTH_IN_PARENT_RRTYPES = [dns.rdatatype.DS, RRtype.DELEG]


def load_private_key(keyfile):
    """
    Load DNSSEC private key from PEM format file for online signing.
    """
    with open(keyfile, 'rb') as fkeyfile:
        return load_pem_private_key(fkeyfile.read(), password=None)


def key_basename(zonename, algorithm, keytag):
    """Return the keytag-named base filename (no extension) shared by genkey
    and signzone: '<zonename>+<alg:03d>+<keytag:05d>'. zonename must be the
    origin text with any trailing dot stripped. Matches BIND's +%03d+%05d
    convention so the files are greppable and self-describing."""
    return f"{zonename}+{algorithm:03d}+{keytag:05d}"


class Zone(dns.zone.Zone):

    """
    Modified dns.zone.Zone class.

    The nodes dictionary uses the SortedDict class from sortedcontainers,
    rather than the standard dict class. This maintains a sorted keylist,
    which makes it easier and more efficient to implement DNSSEC functions.

    When add_ent_nodes() is called, it will iterate through the zone and
    add all empty non-terminals as explicit nodes in the dictionary.

    Fully qualified origin must be specified. Doesn't support relativized
    names.
    """

    node_factory = dns.node.Node
    map_factory = SortedDict

    def __init__(self, origin, rdclass=dns.rdataclass.IN, relativize=False):
        """Initialize a zone object."""

        super().__init__(origin, rdclass, relativize=relativize)
        self.nodes = self.map_factory()
        self.ent_nodes = {}
        self.dnssec = False
        self.privatekey = None
        self.signing_dnskey = None
        self.compact_denial = False
        self.deleg_enabled = False
        self.udp_truncate_all = False
        self.require_server_cookie = False
        self.keytag = None
        self.nsec3param = None
        self.soa_min_ttl = None

    def __hash__(self):
        return hash((self.origin, self.rdclass))

    def init_dnssec(self):
        """set DNSSEC parameters"""

        self.dnssec = True
        rdataset = self.get_rdataset(self.origin, dns.rdatatype.NSEC3PARAM)
        if rdataset and len(rdataset) > 1:
            raise ValueError("Only 1 NSEC3PARAM record is supported")
        self.nsec3param = rdataset

    def init_key(self, privatekey):
        """Initialize key for online signing"""
        self.privatekey = privatekey
        self.signing_dnskey = self.get_rdataset(self.origin,
                                                dns.rdatatype.DNSKEY)[0]
        self.keytag = dns.dnssec.key_id(self.signing_dnskey)

    def set_soa_min_ttl(self):
        """Calculate SOA min TTL value"""
        soa_rrset = self.get_rrset(self.origin, dns.rdatatype.SOA)
        self.soa_min_ttl = min(soa_rrset.ttl, soa_rrset[0].minimum)

    def online_signing(self):
        """Does this zone utilize online signing?"""
        return self.dnssec and (self.privatekey is not None)

    def get_ent_nodes(self):
        """Find all empty non-terminals in the zone"""

        seen = {}
        for name in self.keys():
            if name == self.origin:
                continue
            current_name = name
            while current_name not in seen:
                seen[current_name] = 1
                parent = current_name.parent()
                if parent == self.origin:
                    break
                if self.get_node(parent) is None:
                    self.ent_nodes[parent] = 1
                current_name = parent

    def add_ent_nodes(self):
        """Add all empty non-terminals as explicits nodes in the Dict"""

        self.get_ent_nodes()
        for entry in self.ent_nodes:
            node = self.node_factory()
            self.nodes[entry] = node

    def nsec_matching(self, name):
        """Return NSEC RRset matching the name"""

        return self.get_rrset(name, dns.rdatatype.NSEC)

    def nsec_covering(self, name):
        """Return NSEC RRset covering the name"""

        position = self.nodes.bisect_left(name) - 1
        while True:
            nsec_name = self.nodes.peekitem(position)[0]
            nsec_rrset = self.get_rrset(nsec_name, dns.rdatatype.NSEC)
            if nsec_rrset:
                return nsec_rrset
            position -= 1

    def covering_predecessor(self, name, ideal=False):
        """
        Return an RFC 4470 minimally-covering predecessor of `name` that is
        guaranteed not to collide with, or span across, any existing name in
        the zone. The result P satisfies floor < P < name, where floor is the
        greatest existing owner name strictly less than `name`.

        The syntactic predecessor (predecessor_name) is used when it sorts
        above the real floor; otherwise it would span or land on a real name,
        so we snap to successor_name(floor) -- the smallest name strictly
        greater than the real predecessor and still below `name`. With the
        default '~' sentinel this snap can only happen when a real name
        contains a '~'-or-higher octet at the relevant position, so normal
        zones never snap and never reveal a real name.
        """
        candidate = predecessor_name(name, ideal=ideal)
        index = self.nodes.bisect_left(name) - 1
        if index < 0:
            return candidate                      # nothing below name; safe
        floor = self.nodes.peekitem(index)[0]
        if candidate <= floor:
            # Synthetic predecessor would span or hit a real name; snap to the
            # successor of the real floor (floor < \000.floor < name).
            return successor_name(floor)
        return candidate

    def covering_successor(self, name):
        """
        Return the successor of `name` for RFC 4470 covering NSECs, guarding
        the (pathological) case where the literal successor already exists in
        the zone. The literal successor is whatever successor_name() computes --
        normally `name` with a 0x00 octet appended to its leftmost label
        (name\\000), a same-parent sibling. Such synthetic owners are
        effectively nonexistent in real zones, so this is a cheap existence
        check with a defensive fallback rather than an iterative search: if the
        literal successor already exists, fall back to the predecessor of the
        next real name above it, which still sits strictly above `name`.
        """
        successor = successor_name(name)
        if self.nodes.get(successor) is None:
            return successor
        index = self.nodes.bisect_right(successor)
        if index < len(self.nodes):
            ceiling = self.nodes.peekitem(index)[0]
            return predecessor_name(ceiling)
        return successor                           # nothing above; use it anyway

    def nsec3_hash(self, name):
        """Return NSEC3 hash of name"""

        params = self.nsec3param[0]
        return nsec3hash(name,
                         params.algorithm, params.salt, params.iterations)

    def nsec3_hashed_owner(self, name):
        """Return NSEC3 hashed owner name"""

        n3hash = self.nsec3_hash(name)
        owner = dns.name.Name((n3hash.encode(),) + self.origin.labels)
        return owner

    def nsec3_matching(self, name):
        """Return NSEC3 RRset matching the name"""

        if not self.nsec3param:
            return None
        owner = self.nsec3_hashed_owner(name)
        return self.get_rrset(owner, dns.rdatatype.NSEC3)

    def nsec3_covering(self, name):
        """Return NSEC3 RRset covering the name"""

        if not self.nsec3param:
            return None

        owner = self.nsec3_hashed_owner(name)
        search_index = self.nodes.bisect(owner) - 1
        while True:
            name, node = self.nodes.peekitem(search_index)
            rdataset = node.get_rdataset(dns.rdataclass.IN,
                                         dns.rdatatype.NSEC3)
            if rdataset:
                return rrset_from_rdataset(name, rdataset)
            search_index -= 1
            if search_index < 0:
                break
        return None

    def reject_wildcard_deleg(self):
        """
        Enforce delext-10 4.4: a wildcard owner name MUST NOT have Delegation
        Types. Wildcard expansion (RFC 4592) does not create delegation points,
        so a DELEG RRset at a '*' owner is prohibited. Raises ValueError on the
        first offending owner. Only meaningful when deleg_enabled is set (else
        DELEG is opaque data); the caller gates on that.
        """
        for name, node in self.nodes.items():
            if name.labels[0] != b'*':
                continue
            if node.get_rdataset(dns.rdataclass.IN, RRtype.DELEG):
                raise ValueError(
                    f"wildcard owner {name} has a DELEG RRset; delext-10 4.4 "
                    f"prohibits Delegation Types at a wildcard domain name")

    def __str__(self):
        return f"<Zone: {self.origin}>"


def zone_from_file(name, zonefile):
    """Obtain Zone object from zone name and file"""

    zone = dns.zone.from_file(zonefile, origin=name, zone_factory=Zone,
                              relativize=False)
    if not isinstance(zone.nodes, zone.map_factory):
        zone.nodes = zone.map_factory(zone.nodes)
    zone.add_ent_nodes()
    zone.set_soa_min_ttl()
    return zone


B32_TO_EXT_HEX = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')
NSEC3HASH_SIZE_IN_OCTETS = 20

def hashalg(algnum):
    """Return hash function corresponding to hash algorithm number"""

    if algnum == 1:
        return hashlib.sha1
    raise ValueError(f"unsupported NSEC3 hash algorithm {algnum}")


def nsec3hash(name, algnum, wire_salt, iterations, binary_out=False):

    """Compute NSEC3 hash for given domain name and parameters"""

    if iterations < 0:
        raise ValueError("iterations must be >= 0")
    wire_name = name.to_digestable()
    hashfunc = hashalg(algnum)
    digest = wire_name
    while iterations >= 0:
        digest = hashfunc(digest + wire_salt).digest()
        iterations -= 1
    if binary_out:
        return digest
    output = base64.b32encode(digest)
    output = output.translate(B32_TO_EXT_HEX).decode()
    return output


def rrset_from_rdataset(name, rdataset):
    """Build an RRset with the given owner name from an existing rdataset.

    The RRset's type is taken from the rdataset (rdataset.rdtype), so callers
    can't accidentally pair a name/type with a mismatched rdataset. Replaces
    the repeated RRset(name, IN, type); rrset.update(rdataset) idiom."""
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdataset.rdtype)
    rrset.update(rdataset)
    return rrset


def make_nsec_rrset(owner, nextname, rrtypes, ttl):
    """Create NSEC RRset from components"""

    rdata = NSEC.NSEC(rdclass=dns.rdataclass.IN,
                      rdtype=dns.rdatatype.NSEC,
                      next=nextname,
                      windows=NSEC.Bitmap.from_rdtypes(rrtypes))
    rrset = dns.rrset.RRset(owner,
                            dns.rdataclass.IN,
                            dns.rdatatype.NSEC)
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN,
                                     dns.rdatatype.NSEC,
                                     ttl=ttl)
    rdataset.add(rdata)
    rrset.update(rdataset)
    return rrset


def make_nsec3_rrset(params, owner, nextname, rrtypes, ttl):
    """Create NSEC3 RRset from components"""

    rdata = NSEC3.NSEC3(rdclass=dns.rdataclass.IN,
                        rdtype=dns.rdatatype.NSEC3,
                        algorithm=params.algorithm,
                        flags=params.flags,
                        iterations=params.iterations,
                        salt=params.salt,
                        next=nextname,
                        windows=NSEC3.Bitmap.from_rdtypes(rrtypes))
    rrset = dns.rrset.RRset(owner,
                            dns.rdataclass.IN,
                            dns.rdatatype.NSEC3)
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN,
                                     dns.rdatatype.NSEC3,
                                     ttl=ttl)
    rdataset.add(rdata)
    rrset.update(rdataset)
    return rrset


MAX_LABEL_OCTETS = 63
PREDECESSOR_SENTINEL = 0x7e            # '~': sorts above LDH, '_', '*', digits


def predecessor_label_good(label):
    """
    Good-enough RFC 4470 predecessor of a label: decrement the last octet and
    append a single sentinel octet ('~', 0x7e). '~' sorts canonically above
    every octet used in conventional labels (letters, digits, '-', '_', '*'),
    so the resulting synthetic name excludes all normal host names while
    printing cleanly (e.g. "fon~" rather than "fon\\255"). If the last octet is
    already 0x00 there is no smaller value, so the label is dropped entirely
    (the predecessor is the parent name).
    """
    ordinal = label[-1]
    if ordinal == 0:
        return label[:-1]
    return label[:-1] + bytes([ordinal - 1, PREDECESSOR_SENTINEL])


def predecessor_label_ideal(label):
    """
    Ideal (tightest) RFC 4470 predecessor of a label: decrement the last octet
    and pad with 0xff octets out to the 63-octet maximum. This yields the
    smallest possible covering interval but produces long, ugly owner names and
    larger packets, so it is opt-in (see the nsec_ideal_predecessor preference).
    """
    ordinal = label[-1]
    if ordinal == 0:
        return label[:-1]
    return label[:-1] + bytes([ordinal - 1]) + \
        b'\xff' * (MAX_LABEL_OCTETS - len(label))


def predecessor_name(name, ideal=False):
    """
    Return the (syntactic) predecessor of a domain name for RFC 4470 minimally
    covering NSEC records. Only the first (leftmost) label is altered. This is
    a pure name computation; collision with real zone names is resolved
    separately by Zone.covering_predecessor().
    """
    fn = predecessor_label_ideal if ideal else predecessor_label_good
    labels = name.labels
    newlabel = fn(labels[0])
    if not newlabel:
        return dns.name.Name(labels[1:])
    return dns.name.Name((newlabel,) + labels[1:])


def successor_name(name):
    """
    Return the immediate successor of a domain name: the smallest name strictly
    greater than it that shares the same parent, formed by appending a 0x00
    octet to the leftmost label (RFC 4470/4471 "successor").

    We must NOT prepend a 0x00 *label* (\\000.name) here: that makes `name` a
    proper suffix of the successor. Since the covering NSEC's next name is
    proven to exist, so is its ancestor `name` -- so the NSEC inadvertently
    proves `name` exists (as an empty non-terminal) even as it denies it. A
    strict validator reconstructing the closest encloser from the NSEC then
    concludes the closest encloser is `name` itself and demands a wildcard NSEC
    at *.name rather than *.<real-closest-encloser> -- yielding SERVFAIL /
    "Missing NSEC record". (Closest encloser is defined in RFC 4592 3.3.1; for
    plain NSEC there is no explicit derivation algorithm in the specs, so the
    behavior is that of deployed validators -- confirmed in unbound's
    val_nsec.c, whose nsec_closest_encloser() takes the longest common suffix
    of the qname with the NSEC owner and next names, so a next name of which the
    qname is a suffix yields closest-encloser = qname. See RFC 7129 for a
    tutorial treatment.) Appending an octet keeps the label count identical, so
    the successor stays a sibling and the closest-encloser derivation is
    unaffected.

    In the (pathological) case of a 63-octet leftmost label there is no room to
    append; fall back to prepending a 0x00 label, which is still a valid strict
    successor (only the closest-encloser subtlety above is at stake, and a
    63-octet synthetic label cannot occur from predecessor/wildcard synthesis).
    """
    first = name.labels[0]
    if len(first) < MAX_LABEL_OCTETS:
        return dns.name.Name((first + b'\x00',) + name.labels[1:])
    return dns.name.Name((b'\x00',) + name.labels)
