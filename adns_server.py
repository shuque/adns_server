#!/usr/bin/env python3

"""
An Authoritative DNS server for prototyping and experimentation.

Author: Shumon Huque <shuque@gmail.com>

"""

import os
import sys
import getopt
import pwd
import grp
import syslog
import struct
import socket
import atexit
import select
import threading
import signal
import hashlib
import base64
import time
import enum
import random
import binascii
import yaml
import siphash

import dns.zone
import dns.name
import dns.message
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.edns
import dns.dnssec
from dns.rdtypes.ANY import NSEC
from dns.rdtypes.ANY import NSEC3

from sortedcontainers import SortedDict

from cryptography.hazmat.primitives.serialization import load_pem_private_key


PROGNAME = os.path.basename(sys.argv[0])
VERSION = '0.5.0'
CONFIG_DEFAULT = 'adnsconfig.yaml'

# Parameters for online signing
RRSIG_INCEPTION_OFFSET = 3600
RRSIG_LIFETIME = 172800

# Cookie parameters
COOKIE_TIMESTAMP_DRIFT = 86400        # Allowed DNS Cookie timestamp drift (secs)
COOKIE_RECALCULATE_TIME = 21600

class RRtype(enum.IntEnum):
    """Resource Record types"""
    NXNAME = 65283
    DELEG = 65287

class EdnsFlag(enum.IntFlag):
    """EDNS Header Flags"""
    DNSSEC_OK = 0x8000
    COMPACT_OK = 0x4000
    DELEG_OK = 0x2000

class Finished(enum.Flag):
    """Finished Boolean enum"""
    TRUE = True
    FALSE = False


class Preferences:
    """Preferences"""

    config = CONFIG_DEFAULT           # -c: Configuration file
    debug = False                     # -d: Print debugging output
    server = ''                       # -s: server listening address
    server_af = None                  # server's address family if -s set
    port = 53                         # -p: port
    username = None                   # username to switch to (if root)
    groupname = None                  # group to switch to (if root)
    daemon = True                     # Become daemon (-f: foreground)
    syslog_fac = syslog.LOG_DAEMON    # Syslog facility
    syslog_pri = syslog.LOG_INFO      # Syslog priority
    workdir = None                    # Working directory to change to
    pidfile = None                    # PID file
    edns_udp_max = 1432               # -e: Max EDNS UDP payload we send
    edns_udp_adv = 1232               # Max EDNS UDP payload we advertise
    nsid = None                       # NSID option string
    minimal_any = False               # Minimal ANY (RFC 8482)
    cookie_secret = None              # Secret for DNS cookie generation

    def __str__(self):
        return "<Preferences object>"


def usage(msg=None):
    """Print usage string and exit"""

    if msg is not None:
        print("ERROR: {}\n".format(msg))

    print("""\
{0} version {1}
Usage: {0} [<Options>]

Options:
       -h:        Print usage string
       -c file:   Configuration file (default '{2}')
       -d:        Turn on debugging
       -p N:      Listen on port N (default 53)
       -s A:      Bind to server address A (default wildcard address)
       -u uname:  Drop privileges to UID of specified username
                  (if server started running as root)
       -g group:  Drop provileges to GID of specified groupname
                  (if server started running as root)
       -4:        Use IPv4 only
       -6:        Use IPv6 only
       -f:        Remain attached to foreground (default don't)
       -e N:      Max EDNS bufsize in octets for responses we send out.
                  (-e 0 will disable EDNS support)
       -x file:   Name of file to write the PID      

Note: a configuration file that minimally specifies the zones to load
must be present.
""".format(PROGNAME, VERSION, CONFIG_DEFAULT))
    sys.exit(1)


def init_config(prefs, zonedict, only_zones=False):
    """Initialize parameters and zone files from config file"""

    with open(prefs.config, 'r') as configfile:
        ydoc = yaml.safe_load(configfile)

    if not only_zones:
        if "config" in ydoc:
            for key, val in ydoc['config'].items():
                if key == 'port':
                    prefs.port = val
                elif key == 'workdir':
                    prefs.workdir = val
                elif key == 'pidfile':
                    prefs.pidfile = val
                elif key == 'edns':
                    prefs.edns_udp_max = val
                elif key == 'user':
                    prefs.username = val
                elif key == 'group':
                    prefs.groupname = val
                elif key == 'nsid':
                    prefs.nsid = val.encode()
                elif key == 'minimal_any':
                    prefs.minimal_any = val
                else:
                    print("error: unrecognized config option: {}".format(key))
                    sys.exit(1)

    if "zones" in ydoc:
        load_zones(prefs, zonedict, ydoc['zones'])

    if not zonedict.get_zonelist():
        print("error: no zones defined.")
        sys.exit(1)


def load_zones(prefs, zonedict, zoneconfig):
    """Load zones"""

    for entry in zoneconfig:
        zonename = entry['name']
        zonefile = entry['file']
        if not zonefile.startswith('/') and prefs.workdir:
            zonefile = os.path.join(prefs.workdir, zonefile)
        dnssec = entry.get('dnssec', False)
        dynamic_signing = entry.get('dynamic_signing', False)
        deleg_enabled = entry.get('deleg_enabled', False)
        if dnssec and dynamic_signing:
            privatekey_path = entry['private_key']
            if not privatekey_path.startswith('/') and prefs.workdir:
                privatekey_path = os.path.join(prefs.workdir, privatekey_path)
            privatekey = load_private_key(privatekey_path)
        else:
            privatekey = None
        try:
            zonedict.add(zonename, zonefile,
                         dnssec=dnssec, key=privatekey,
                         deleg_enabled=deleg_enabled)
        except dns.exception.DNSException as exc_info:
            print("error: load zone {} failed: {}".format(
                zonename, exc_info))
            sys.exit(1)
    zonedict.set_zonelist()


def set_server_af(prefs, address):
    """Set server's address family"""

    if address.find('.') != -1:
        prefs.server_af = 'IPv4'
    elif address.find(':') != -1:
        prefs.server_af = 'IPv6'
    else:
        raise ValueError("{} isn't a valid address".format(address))


def process_args(prefs, zonedict, arguments):
    """Process all command line arguments"""

    try:
        (options, args) = getopt.getopt(arguments, 'hc:dp:s:z:u:g:46fe:x:')
    except getopt.GetoptError as error_info:
        usage(str(error_info))

    if args:
        usage("No additional arguments allowed: {}".format(" ".join(args)))

    help_requested = [x for x in options if x[0] == '-h']
    if help_requested:
        usage()

    config_supplied = [x for x in options if x[0] == '-c']
    if config_supplied:
        prefs.config = config_supplied[0][1]
    print("Reading config from: {}".format(PREFS.config))
    init_config(prefs, zonedict)

    for (opt, optval) in options:
        if opt == "-d":
            prefs.debug = True
        elif opt == "-p":
            prefs.port = int(optval)
        elif opt == "-s":
            prefs.server = optval
            set_server_af(PREFS, optval)
        elif opt == "-u":
            prefs.username = optval
        elif opt == "-g":
            prefs.groupname = optval
        elif opt == "-4":
            prefs.server_af = 'IPv4'
        elif opt == "-6":
            prefs.server_af = 'IPv6'
        elif opt == "-f":
            prefs.daemon = False
        elif opt == "-e":
            prefs.edns_udp_max = int(optval)
        elif opt == "-x":
            prefs.pidfile = optval


def log_message(msg):
    """log informational message"""

    if PREFS.daemon:
        syslog.syslog(PREFS.syslog_pri, msg)
    else:
        with tlock:
            print(msg)


def log_fatal(msg):
    """log fatal error message and bail out"""
    log_message(msg)
    sys.exit(1)


def handle_sighup(signum, frame):
    """handle SIGHUP - re-read configuration and zone files"""
    _, _ = signum, frame
    log_message('control: caught SIGHUP .. re-reading config and zones.')
    init_config(PREFS, ZONEDICT)


def handle_sigterm(signum, frame):
    """handle SIGTERM - exit program"""
    _, _ = signum, frame
    log_message('control: caught SIGTERM .. exiting.')
    sys.exit(0)


def install_signal_handlers():
    """Install handlers for HUP and TERM signals"""
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, handle_sighup)


def get_pid_file():
    """Get name of PID file to create"""

    if PREFS.pidfile:
        return PREFS.pidfile
    if PREFS.workdir:
        return os.path.join(PREFS.workdir, 'daemon.pid')
    return f'/tmp/{PROGNAME}.pid'


def daemon(dirname=None, syslog_fac=syslog.LOG_DAEMON):
    """Turn into daemon"""

    pidfile = get_pid_file()
    if os.path.exists(pidfile):
        print(f"File {pidfile} already exists.")
        sys.exit(1)

    umask_value = 0o022

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as einfo:
        print("fork() #1 failed: %s" % einfo)
        sys.exit(1)

    if dirname:
        os.chdir(dirname)

    os.umask(umask_value)
    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as einfo:
        print("fork() #2 failed: %s" % einfo)
        sys.exit(1)

    with open(pidfile, 'w') as pid_f:
        pid_f.write(f'{os.getpid()}\n')
    atexit.register(lambda: os.remove(pidfile))

    for file_desc in range(0, os.sysconf("SC_OPEN_MAX")):
        try:
            os.close(file_desc)
        except OSError:
            pass

    syslog.openlog(PROGNAME, syslog.LOG_PID, syslog_fac)


def drop_privs(uname, gname):
    """If run as root, drop privileges to specified uid and gid"""

    if os.geteuid() != 0:
        log_message("warning: Program didn't start as root. Can't change id.")
    else:
        os.setgroups([])
        if gname:
            gid = grp.getgrnam(gname).gr_gid
            os.setgid(gid)
            os.setegid(gid)
        if uname:
            uid = pwd.getpwnam(uname).pw_uid
            os.setuid(uid)
            os.seteuid(uid)


def udp4socket(host, port):
    """Create IPv4 UDP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    return sock


def udp6socket(host, port):
    """Create IPv6 UDP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    return sock


def tcp4socket(host, port):
    """Create IPv4 TCP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def tcp6socket(host, port):
    """Create IPv6 TCP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def send_socket(sock, message):
    """Send message on a connected socket"""
    try:
        octets_sent = 0
        while octets_sent < len(message):
            sentn = sock.send(message[octets_sent:])
            if sentn == 0:
                log_message("error: send() returned 0 bytes")
                raise ValueError("send() returned 0 bytes")
            octets_sent += sentn
    except OSError as diag:
        log_message("error: sendSocket() exception: {}".format(diag))
        return False
    else:
        return True


def recv_socket(sock, num_octets):
    """Read and return num_octets of data from a connected socket"""
    response = ""
    octets_read = 0
    while octets_read < num_octets:
        chunk = sock.recv(num_octets - octets_read)
        chunklen = len(chunk)
        if chunklen == 0:
            return ""
        octets_read += chunklen
        response += chunk
    return response


def load_private_key(keyfile):
    """
    Load DNSSEC private key from PEM format file for online signing.
    """
    with open(keyfile, 'rb') as fkeyfile:
        return load_pem_private_key(fkeyfile.read(), password=None)
    return None


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

    __slots__ = [
        'ent_nodes',
        'dnssec',
        'privatekey',
        'signing_dnskey',
        'keytag',
        'nsec3param',
        'deleg_enabled'
    ]

    def __init__(self, origin, rdclass=dns.rdataclass.IN, relativize=False):
        """Initialize a zone object."""

        super().__init__(origin, rdclass, relativize=relativize)
        self.nodes = self.map_factory()
        self.ent_nodes = {}
        self.dnssec = False
        self.privatekey = None
        self.signing_dnskey = None
        self.deleg_enabled = False
        self.keytag = None
        self.nsec3param = None
        self.soa_min_ttl = None

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

    def set_deleg(self, deleg_enabled):
        """Set deleg_enabled flag"""
        self.deleg_enabled = deleg_enabled

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
            while True:
                if current_name in seen:
                    break
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
                rrset = dns.rrset.RRset(name, dns.rdataclass.IN,
                                        rdataset.rdtype)
                rrset.update(rdataset)
                return rrset
            search_index -= 1
            if search_index < 0:
                break
        return None

    def __str__(self):
        return "<Zone: {}>".format(self.origin)


def zone_from_file(name, zonefile, dnssec=False, key=None, deleg_enabled=False):
    """Obtain Zone object from zone name and file"""

    zone = dns.zone.from_file(zonefile, origin=name, zone_factory=Zone,
                              relativize=False)

    # My custom Zone factory class converts the nodes attribute to a
    # SortedDict (to make it easier to implement DNSSEC functions).
    # Unfortunately dnspython 2.x undoes that conversion back to a dict.
    # So we need to perform this hack to convert it back. This appears to
    # be fixed in dnspython 2.5 (not released yet) via the new map_factory
    # attribute.
    if not isinstance(zone.nodes, zone.map_factory):
        zone.nodes = zone.map_factory(zone.nodes)

    zone.add_ent_nodes()
    zone.set_soa_min_ttl()
    if dnssec:
        zone.init_dnssec()
        if key is not None:
            zone.init_key(key)
    zone.set_deleg(deleg_enabled)
    return zone


class ZoneDict:
    """Zone Dictionary object: zone names -> zone objects"""

    def __init__(self):
        self.data = {}
        self.zonelist = None

    def set_zonelist(self):
        """Create list of zone names"""
        self.zonelist = list(reversed(sorted(self.data.keys())))

    def get_zonelist(self):
        """Return zone list"""
        return self.zonelist

    def add(self, zonename, zonefile, dnssec=False, key=None, deleg_enabled=False):
        """Create and add zonename->zone object"""
        zonename = dns.name.from_text(zonename)
        self.data[zonename] = zone_from_file(zonename, zonefile, dnssec, key, deleg_enabled)

    def find(self, qname):
        """Return closest enclosing zone object for the qname"""
        for zname in self.zonelist:
            if qname.is_subdomain(zname):
                return self.data[zname]
        return None


B32_TO_EXT_HEX = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')
NSEC3HASH_SIZE_IN_OCTETS = 20

def hashalg(algnum):
    """Return hash function corresponding to hash algorithm number"""

    if algnum == 1:
        return hashlib.sha1
    raise ValueError("unsupported NSEC3 hash algorithm {}".format(algnum))


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


def query_meta_type(qtype):
    """Is given query type a meta type (except ANY)?"""
    return 128 <= qtype <= 254


def compact_answer_ok(message):
    """Does DNS message have Compact Answers OK EDNS header flag set?"""
    return message.ednsflags & EdnsFlag.COMPACT_OK == EdnsFlag.COMPACT_OK


def deleg_ok(message):
    """Does DNS message have DELEG OK EDNS header flag set"""
    return message.ednsflags & EdnsFlag.DELEG_OK == EdnsFlag.DELEG_OK


def sign_rrset(zone, rrset):
    """Sign RRset with zone's private key and return RRSIG record"""
    rrsig_rdata = dns.dnssec.sign(rrset,
                                  zone.privatekey,
                                  zone.origin,
                                  zone.signing_dnskey,
                                  inception=int(time.time() - RRSIG_INCEPTION_OFFSET),
                                  lifetime=RRSIG_LIFETIME)
    rrsig = dns.rrset.RRset(rrset.name,
                            dns.rdataclass.IN,
                            dns.rdatatype.RRSIG)
    rrsig_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN,
                                           dns.rdatatype.RRSIG,
                                           ttl=rrset.ttl)
    rrsig_rdataset.add(rrsig_rdata)
    rrsig.update(rrsig_rdataset)
    return rrsig


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


def make_nsec3_rrset_minimal(params, zone, owner, rrtypes, ttl, covering=False):
    """
    Create minimal NSEC3 RRset. If "covering" is True, then the NSEC3
    record will cover the given owner name, otherwise it will match it.
    """

    owner_hash = nsec3hash(owner,
                           params.algorithm, params.salt, params.iterations,
                           binary_out=True)
    hash_owner_int = int.from_bytes(owner_hash, byteorder='big')

    owner_int = (hash_owner_int - 1) if covering else hash_owner_int
    owner_bytes = owner_int.to_bytes(NSEC3HASH_SIZE_IN_OCTETS, 'big')
    owner_hash = base64.b32encode(owner_bytes).translate(NSEC3.b32_normal_to_hex)
    new_owner = dns.name.Name((owner_hash,) + zone.labels)

    next_int = hash_owner_int + 1
    next_bytes = next_int.to_bytes(NSEC3HASH_SIZE_IN_OCTETS, 'big')

    return make_nsec3_rrset(params,
                            new_owner,
                            next_bytes,
                            rrtypes,
                            ttl)


class DNSquery:
    """DNS query object"""

    def __init__(self, data, cliaddr, cliport, tcp=False):

        self.malformed = False
        self.cliaddr = cliaddr
        self.cliport = cliport
        self.headeronly = False
        self.malformed = None

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
            log_message("error: can't parse query: {}: {}".format(
                type(exc_info), exc_info))
            self.message = None
            self.malformed = True
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
        flags = "0x%04x" % self.message.ednsflags
        options = ",".join([str(int(x.otype)) for x in self.message.options])
        result = f"edns=v{edns_version}/{flags}/{self.message.payload}"
        if options:
            result += f"/{options}"
        return result

    def log_query(self):
        """Log information about incoming DNS query"""
        transport = "TCP" if self.tcp else "UDP"
        if self.headeronly:
            msg = 'query: %s header-only from: %s,%d size=%d' % \
                    (transport,
                     self.cliaddr, self.cliport, self.msg_len)
        else:
            msg = 'query: %s %s %s %s from: %s,%d size=%d' % \
                    (transport,
                     self.qname,
                     dns.rdatatype.to_text(self.qtype),
                     dns.rdataclass.to_text(self.qclass),
                     self.cliaddr, self.cliport, self.msg_len)
        edns_log_message = self.edns_log_info()
        if edns_log_message:
            msg = msg + " " + edns_log_message
        log_message(msg)


class DNSresponse:
    """DNS response object"""

    def __init__(self, query):

        self.query = query
        self.response = dns.message.make_response(query.message,
                                                  our_payload=PREFS.edns_udp_adv)

        if not self.query.headeronly:
            self.qname = query.message.question[0].name
            self.qtype = query.message.question[0].rdtype
            self.qclass = query.message.question[0].rdclass

        self.is_referral = False
        self.cname_owner_list = []
        self.dname_owner_list = []
        self.is_nodata = False
        self.edns_flags = 0
        self.edns_options = []
        self.badcookie = False

        self.response.set_rcode(dns.rcode.NOERROR)
        self.response.flags &= ~dns.flags.AA
        self.prepare_response()

    def to_wire(self):
        """Generate wire format DNS response"""

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
            return 65533
        if (PREFS.edns_udp_max == 0) or (self.query.message.edns == -1):
            return 512
        return min(self.query.message.payload, PREFS.edns_udp_max)

    def truncate(self):
        """Truncate response message"""

        self.response.flags |= dns.flags.TC
        self.response.answer = []
        self.response.authority = []
        self.response.additional = []
        return self.response.to_wire()

    def add_rrset(self, zobj, section, rrset, wildcard=None, authoritative=True):
        """Add RRset to section, fetching RRsigs if needed"""

        if rrset in section:
            return
        section.append(rrset)

        if not authoritative or not self.dnssec_ok():
            return

        if zobj.online_signing():
            section.append(sign_rrset(zobj, rrset))
            return

        if zobj.dnssec:
            rrname = wildcard if wildcard else rrset.name
            rdataset = zobj.get_rdataset(rrname,
                                         dns.rdatatype.RRSIG, covers=rrset.rdtype)
            if rdataset:
                rrsig = dns.rrset.RRset(rrset.name,
                                        dns.rdataclass.IN, rdataset.rdtype)
                rrsig.update(rdataset)
                section.append(rrsig)

    def add_soa(self, zobj):
        """Add SOA record to authority for negative responses"""

        soa_rrset = zobj.get_rrset(zobj.origin, dns.rdatatype.SOA)
        soa_rrset.ttl = zobj.soa_min_ttl
        self.add_rrset(zobj, self.response.authority, soa_rrset)

    def nxdomain(self, zobj, sname):
        """Generate NXDOMAIN response"""

        if not zobj.online_signing():
            self.response.set_rcode(dns.rcode.NXDOMAIN)

        self.add_soa(zobj)
        if not self.dnssec_ok():
            return

        if zobj.online_signing():
            if zobj.nsec3param:
                self.nxdomain_online_nsec3(zobj, sname)
            else:
                self.nxdomain_online_compact(zobj)
            return

        if zobj.dnssec:
            if zobj.nsec3param is None:
                self.nxdomain_nsec(zobj, sname)
            else:
                self.nxdomain_nsec3(zobj, sname)

    def nxdomain_online_compact(self, zobj):
        """
        Generate online NSEC NXDOMAIN response using Compact Denial
        """

        if compact_answer_ok(self.query.message):
            self.response.set_rcode(dns.rcode.NXDOMAIN)

        rrtypes = [dns.rdatatype.RRSIG, dns.rdatatype.NSEC, RRtype.NXNAME]
        nextname = dns.name.Name((b'\x00',) + self.qname.labels)
        nsec_rrset = make_nsec_rrset(self.qname, nextname, rrtypes, zobj.soa_min_ttl)
        self.add_rrset(zobj, self.response.authority, nsec_rrset)

    def nxdomain_online_nsec3(self, zobj, sname):
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
                self.nodata_online_nsec3(zobj, sname, wildcard)
            else:
                self.nodata_online_compact(zobj, sname, wildcard)
            return

        if zobj.dnssec:
            if zobj.nsec3param is None:
                self.nodata_nsec(zobj, sname, wildcard=wildcard)
            else:
                self.nodata_nsec3(zobj, sname, wildcard=wildcard)

    def nodata_online_compact(self, zobj, sname, wildcard=None):
        """
        Generate online NSEC NODATA response
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

    def nodata_online_nsec3(self, zobj, sname, wildcard=None):
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

    def process_any_metatype(self, zobj, sname, wildcard):
        """Process ANY meta query"""

        rrname = wildcard if wildcard else sname
        rdatasets = zobj.get_node(sname).rdatasets
        if not rdatasets:
            self.is_nodata = True
            self.nodata(zobj, sname, wildcard)
            return

        if PREFS.minimal_any:
            for rdataset in rdatasets:
                if rdataset.rdtype == dns.rdatatype.RRSIG:
                    continue
                rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN,
                                        rdataset.rdtype)
                rrset.update(rdataset)
                self.add_rrset(zobj, self.response.answer, rrset)
                return

        for rdataset in rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                continue
            rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, rdataset.rdtype)
            rrset.update(rdataset)
            self.add_rrset(zobj, self.response.answer, rrset)

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
            rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, stype)
            rrset.update(rdataset)
            self.add_rrset(zobj, self.response.answer, rrset,
                           wildcard=sname if wildcard else None)
            return

        # NODATA - add SOA
        self.is_nodata = True
        self.nodata(zobj, sname, wildcard)
        return

    def do_referral(self, zobj, sname, rdataset):
        """Generate referral response to child zone"""

        self.is_referral = True
        if zobj.deleg_enabled:
            self.do_referral_deleg(zobj, sname, rdataset)
            return

        ns_rrset = dns.rrset.RRset(sname, dns.rdataclass.IN, dns.rdatatype.NS)
        ns_rrset.update(rdataset)
        self.add_rrset(zobj, self.response.authority, ns_rrset, authoritative=False)
        self.get_glue(zobj, sname, rdataset)

        if zobj.dnssec:
            ds_rrset = zobj.get_rrset(sname, dns.rdatatype.DS)
            if ds_rrset:
                self.add_rrset(zobj, self.response.authority, ds_rrset)
            else:
                # Insecure referral - add NSEC record matching delegation name
                self.add_nsec_matching(zobj, sname)

    def do_referral_deleg(self, zobj, sname, rdataset):
        """Generate DELEG enabled referral response to child zone"""

        deleg_rrset = zobj.get_rrset(sname, RRtype.DELEG)
        if deleg_rrset and deleg_ok(self.query.message):
            self.add_rrset(zobj, self.response.authority, deleg_rrset)
            # If we decide to always add NSEC, uncomment this
            #if (zobj.dnssec and self.dnssec_ok()):
            #    self.add_nsec_matching(zobj, sname)
            return

        self.is_referral = True
        ns_rrset = dns.rrset.RRset(sname, dns.rdataclass.IN, dns.rdatatype.NS)
        ns_rrset.update(rdataset)
        self.add_rrset(zobj, self.response.authority, ns_rrset, authoritative=False)
        self.get_glue(zobj, sname, rdataset)

        # For unsigned zones or DO=0 queries, return DELEG (if present) and return
        if not (zobj.dnssec and self.dnssec_ok()):
            if deleg_rrset:
                self.add_rrset(zobj, self.response.authority, deleg_rrset)
            return

        ds_rrset = zobj.get_rrset(sname, dns.rdatatype.DS)
        if ds_rrset:
            self.add_rrset(zobj, self.response.authority, ds_rrset)

        if deleg_rrset:
            self.add_rrset(zobj, self.response.authority, deleg_rrset)

        if not (ds_rrset and deleg_rrset):
            # Insecure referral or only one of {DS,DELEG}. Add NSEC matching sname
            self.add_nsec_matching(zobj, sname)

    def do_referral_deleg_only(self, zobj, sname, deleg_rrset):
        """Do DELEG-only referral - future looking"""

        self.is_referral = True
        self.add_rrset(zobj, self.response.authority, deleg_rrset)

        # if DS exists, return it too (may have DS shim signal)
        ds_rrset = zobj.get_rrset(sname, dns.rdatatype.DS)
        if ds_rrset:
            self.add_rrset(zobj, self.response.authority, ds_rrset)

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

    def get_glue(self, zobj, sname, rdataset):
        """Add glue records if needed"""

        for rdata in rdataset:
            if not rdata.target.is_subdomain(sname):
                continue
            for rrtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                rdataset = zobj.get_rdataset(rdata.target, rrtype)
                if rdataset:
                    rrset = dns.rrset.RRset(rdata.target,
                                            dns.rdataclass.IN, rrtype)
                    rrset.update(rdataset)
                    self.add_rrset(zobj, self.response.additional, rrset, authoritative=False)

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
            nextname = dns.name.Name((b'\x00',) + sname.labels)
            rrtypes = [x.rdtype for x in node.rdatasets] + \
                [dns.rdatatype.RRSIG, dns.rdatatype.NSEC]
            nsec_rrset = make_nsec_rrset(sname, nextname, rrtypes, zobj.soa_min_ttl)
            self.add_rrset(zobj, self.response.authority, nsec_rrset)
        else:
            rrtypes = [x.rdtype for x in node.rdatasets] + [dns.rdatatype.RRSIG]
            nsec3_rrset = make_nsec3_rrset_minimal(
                zobj.nsec3param[0], zobj.origin,
                sname, rrtypes,
                zobj.soa_min_ttl, covering=False)
            self.add_rrset(zobj, self.response.authority, nsec3_rrset)

    def process_cname(self, zobj, rrname, sname, stype, cname_rdataset,
                      wildcard=None):
        """Process CNAME"""

        if sname in self.cname_owner_list:
            log_message("error: CNAME loop detected at {}".format(sname))
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.cname_owner_list.append(sname)
        rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN,
                                dns.rdatatype.CNAME)
        rrset.update(cname_rdataset)
        self.add_rrset(zobj, self.response.answer, rrset,
                       wildcard=sname if wildcard else None)
        self.find_answer(cname_rdataset[0].target, stype)

    def process_dname(self, zobj, qname, sname, stype, dname_rdataset):
        """Process DNAME"""

        if sname in self.dname_owner_list:
            log_message("error: DNAME loop detected at {}".format(sname))
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.dname_owner_list.append(sname)
        rrset = dns.rrset.RRset(sname, dns.rdataclass.IN, dns.rdatatype.DNAME)
        rrset.update(dname_rdataset)
        self.add_rrset(zobj, self.response.answer, rrset)

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
        return

    def process_name(self, zobj, qname, sname, stype):
        """
        Process name and type. This function is called iteratively by
        find_answer_in_zone() to find the answer to the qname. At the given
        search name (sname), if the name doesn't exist, we look for a wildcard;
        otherwise we look for a DNAME or delegation. Otherwise, we indicate
        that the search hasn't finished, and the caller will append the next
        label towards the qname and call us again.
        """

        node = zobj.get_node(sname)
        if node is None:
            # Look for wildcard
            wildcard_name = dns.name.Name((b'*',) + sname.labels[1:])
            if zobj.get_node(wildcard_name) is not None:
                self.find_rrtype(zobj, wildcard_name, stype, wildcard=sname)
                if not zobj.online_signing():
                    self.wildcard_no_closer_match(zobj, wildcard_name, sname)
                return Finished.TRUE
            self.nxdomain(zobj, sname)
            return Finished.TRUE

        # Look for DNAME
        dname_rdataset = zobj.get_rdataset(sname, dns.rdatatype.DNAME)
        if dname_rdataset:
            self.process_dname(zobj, qname, sname, stype, dname_rdataset)
            return Finished.TRUE

        # Look for delegation
        if sname != zobj.origin:
            rdataset = zobj.get_rdataset(sname, dns.rdatatype.NS)
            if rdataset:
                if (qname != sname) or (stype not in [dns.rdatatype.DS, RRtype.DELEG]):
                    self.do_referral(zobj, sname, rdataset)
                    return Finished.TRUE
            if zobj.deleg_enabled and deleg_ok(self.query.message):
                deleg_rrset = zobj.get_rrset(sname, RRtype.DELEG)
                if deleg_rrset:
                    if (qname != sname) or (stype not in [dns.rdatatype.DS, RRtype.DELEG]):
                        self.do_referral_deleg_only(zobj, sname, deleg_rrset)
                        return Finished.TRUE

        if sname == qname:
            self.find_rrtype(zobj, sname, stype)
            return Finished.TRUE

        return Finished.FALSE

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

        zobj = ZONEDICT.find(qname)
        if zobj is None:
            if not self.response.answer:
                self.response.set_rcode(dns.rcode.REFUSED)
                if self.query.message.edns != -1:
                    option = dns.edns.EDEOption(
                        dns.edns.EDECode.NOT_AUTHORITATIVE,
                        "Not authoritative for queried zone")
                    self.edns_options.append(option)
            return
        self.find_answer_in_zone(zobj, qname, qtype)

    def dnssec_ok(self):
        """Does requestor have the DO flag set?"""

        return self.query.message.ednsflags & dns.flags.DO == dns.flags.DO

    def need_edns(self):
        """Do we need to add EDNS Opt RR?"""

        return (PREFS.edns_udp_max != 0) and (self.query.message.edns != -1)

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
        log_message("Re-calculating cookie for {self.query.cliaddr}")
        newcookie = clientcookie + \
            self.calculate_server_cookie(clientcookie,
                                         b'\x00\x00\x00',
                                         struct.pack('!I', int(time.time())))
        return True, newcookie

    def calculate_server_cookie(self, clientcookie, reserved, timestamp):
        """Calculate Server Cookie"""

        clientip = self.query.cliaddr
        version = b'\x01'
        sip = siphash.SipHash_2_4(PREFS.cookie_secret)
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
        self.add_cookie_option(returncookie)

    def do_edns_init(self):
        """Generate initial EDNS response information"""

        if self.dnssec_ok():
            self.edns_flags = dns.flags.DO
            if compact_answer_ok(self.query.message):
                self.edns_flags |= EdnsFlag.COMPACT_OK

        if deleg_ok(self.query.message):
            self.edns_flags |= EdnsFlag.DELEG_OK

        for option in self.query.message.options:
            if PREFS.nsid and (option.otype == dns.edns.NSID):
                self.edns_options.append(dns.edns.GenericOption(dns.edns.NSID,
                                                      PREFS.nsid))
            elif option.otype == dns.edns.COOKIE:
                self.process_cookie(option.data)

    def do_edns_final(self):
        """Generate final EDNS OPT RR"""

        self.response.use_edns(edns=0,
                               ednsflags=self.edns_flags,
                               payload=PREFS.edns_udp_adv,
                               request_payload=PREFS.edns_udp_max,
                               options=self.edns_options)

    def prepare_response(self):
        """Prepare DNS response message"""

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

            if query_meta_type(self.qtype) or self.qtype == RRtype.NXNAME:
                self.response.set_rcode(dns.rcode.REFUSED)
                return

            self.find_answer(self.qname, self.qtype)

        if self.need_edns():
            self.do_edns_final()

        if self.response.rcode() in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
            if (not self.is_referral) or self.response.answer:
                self.response.flags |= dns.flags.AA


def handle_query(query, sock):
    """Handle incoming query"""

    if not query.message:
        return

    response = DNSresponse(query)
    if not response.response:
        return

    if query.tcp:
        send_socket(sock, response.to_wire())
    else:
        sock.sendto(response.to_wire(),
                    (query.cliaddr, query.cliport))


def handle_connection_udp(sock, rbufsize=2048):
    """Handle UDP connection"""

    data, addrport = sock.recvfrom(rbufsize)
    cliaddr, cliport = addrport[0:2]
    if PREFS.debug:
        log_message("connect: UDP from (%s, %d) msgsize=%d" %
                    (cliaddr, cliport, len(data)))
    query = DNSquery(data, cliaddr=cliaddr, cliport=cliport)
    handle_query(query, sock)


def handle_connection_tcp(sock, addr, rbufsize=2048):
    """Handle TCP connection"""

    data = sock.recv(rbufsize)
    cliaddr, cliport = addr[0:2]
    if PREFS.debug:
        log_message("connect: TCP from (%s, %d) msgsize=%d" %
                    (cliaddr, cliport, len(data)))
    query = DNSquery(data, cliaddr=cliaddr, cliport=cliport, tcp=True)
    handle_query(query, sock)
    sock.close()


def setup_sockets(family, server, port):
    """Setup sockets for connection types and address families we handle"""

    fd_read = []
    dispatch = {} # dict: socket -> (handler, is_tcp)

    if family is None or family == 'IPv4':
        s_udp4 = udp4socket(server, port)
        fd_read.append(s_udp4.fileno())
        dispatch[s_udp4] = (handle_connection_udp, False)
        s_tcp4 = tcp4socket(server, port)
        fd_read.append(s_tcp4.fileno())
        dispatch[s_tcp4] = (handle_connection_tcp, True)

    if family is None or family == 'IPv6':
        s_udp6 = udp6socket(server, port)
        fd_read.append(s_udp6.fileno())
        dispatch[s_udp6] = (handle_connection_udp, False)
        s_tcp6 = tcp6socket(server, port)
        fd_read.append(s_tcp6.fileno())
        dispatch[s_tcp6] = (handle_connection_tcp, True)

    return fd_read, dispatch


def setup_server():
    """Setup server ..."""

    PREFS.cookie_secret = binascii.hexlify(random.randbytes(8))

    if PREFS.daemon:
        daemon(dirname=PREFS.workdir)
    install_signal_handlers()
    log_message("info: {} version {}: running".format(PROGNAME, VERSION))

    try:
        fd_read, dispatch = setup_sockets(PREFS.server_af,
                                          PREFS.server, PREFS.port)
    except PermissionError as exc_info:
        log_fatal("Error setting up sockets: {}".format(exc_info))

    if PREFS.username or PREFS.groupname:
        drop_privs(PREFS.username, PREFS.groupname)

    log_message("info: Listening on UDP and TCP port %d" % PREFS.port)
    return fd_read, dispatch


def run_event_loop(fd_read, dispatch):
    """Run main event loop ..."""

    while True:
        try:
            (ready_r, _, _) = select.select(fd_read, [], [], 5)
        except OSError as exc_info:
            log_fatal("error: from select(): {}".format(exc_info))
        if not ready_r:
            continue

        for file_desc in ready_r:
            for (sock, (handler, is_tcp)) in dispatch.items():
                if file_desc == sock.fileno():
                    if is_tcp:
                        conn, addr = sock.accept()
                        threading.Thread(target=handler,
                                         args=(conn, addr)).start()
                    else:
                        threading.Thread(target=handler,
                                         args=(sock,)).start()


if __name__ == '__main__':

    tlock = threading.Lock()
    PREFS = Preferences()
    ZONEDICT = ZoneDict()
    process_args(PREFS, ZONEDICT, sys.argv[1:])
    FD_READ, DISPATCH = setup_server()
    run_event_loop(FD_READ, DISPATCH)
