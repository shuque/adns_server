#!/usr/bin/env python3

"""
A Toy Authoritative DNS server for experimentation.

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
import select
import threading
import signal
import yaml

import dns.zone
import dns.name
import dns.message
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.edns

from sortedcontainers import SortedDict


PROGNAME = os.path.basename(sys.argv[0])
VERSION = '0.2.2'
CONFIG_DEFAULT = 'adnsconfig.yaml'


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
    edns_udp_max = 1432               # -e: Max EDNS UDP payload we send
    edns_udp_adv = 1232               # Max EDNS UDP payload we advertise
    nsid = None                       # NSID option string

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

Note: a configuration file that minimally specifies the zones to load
must be present.
""".format(PROGNAME, VERSION, CONFIG_DEFAULT))
    sys.exit(1)


def init_config(only_zones=False):
    """Initialize parameters and zone files from config file"""

    global PREFS, ZONEDICT

    try:
        ydoc = yaml.load(open(PREFS.config).read(), Loader=yaml.SafeLoader)
    except FileNotFoundError as exc_info:
        print("error: {}".format(exc_info))
        sys.exit(1)

    if not only_zones:
        if "config" in ydoc:
            for key, val in ydoc['config'].items():
                if key == 'port':
                    PREFS.port = val
                elif key == 'edns':
                    PREFS.edns_udp_max = val
                elif key == 'user':
                    PREFS.username = val
                elif key == 'group':
                    PREFS.groupname = val
                elif key == 'nsid':
                    PREFS.nsid = val.encode()
    if "zones" in ydoc:
        for entry in ydoc['zones']:
            zonename = entry['name']
            zonefile = entry['file']
            try:
                ZONEDICT.add(zonename, zonefile)
            except dns.exception.DNSException as exc_info:
                print("ERROR: load zone {} failed: {}".format(
                    zonename, exc_info))
                sys.exit(1)
        ZONEDICT.set_zonelist()
    if not ZONEDICT.get_zonelist():
        print("ERROR: no zones defined.")
        sys.exit(1)


def set_server_af(address):
    """Set server's address family"""

    global PREFS

    if address.find('.') != -1:
        PREFS.server_af = 'IPv4'
    elif address.find(':') != -1:
        PREFS.server_af = 'IPv6'
    else:
        raise ValueError("{} isn't a valid address".format(address))


def process_args(arguments):
    """Process all command line arguments"""

    global PREFS

    try:
        (options, args) = getopt.getopt(arguments, 'hc:dp:s:z:u:g:46fe:')
    except getopt.GetoptError as error_info:
        usage(str(error_info))

    if args:
        usage("No additional arguments allowed: {}".format(" ".join(args)))

    config_supplied = [x for x in options if x[0] == '-c']
    if config_supplied:
        PREFS.config = config_supplied[0][1]
    print("Reading config from: {}".format(PREFS.config))
    init_config()

    for (opt, optval) in options:
        if opt == "-h":
            usage()
        elif opt == "-d":
            PREFS.debug = True
        elif opt == "-p":
            PREFS.port = int(optval)
        elif opt == "-s":
            PREFS.server = optval
            set_server_af(optval)
        elif opt == "-u":
            PREFS.username = optval
        elif opt == "-g":
            PREFS.groupname = optval
        elif opt == "-4":
            PREFS.server_af = 'IPv4'
        elif opt == "-6":
            PREFS.server_af = 'IPv6'
        elif opt == "-f":
            PREFS.daemon = False
        elif opt == "-e":
            PREFS.edns_udp_max = int(optval)


def log_message(msg):
    """log informational message"""
    global PREFS

    if PREFS.daemon:
        syslog.syslog(PREFS.syslog_pri, msg)
    else:
        tlock.acquire()
        print(msg)
        tlock.release()


def log_fatal(msg):
    """log fatal error message and bail out"""
    log_message(msg)
    sys.exit(1)


def handle_sighup(signum, frame):
    """handle SIGHUP - re-read zone files"""
    _, _ = signum, frame
    log_message('control: caught SIGHUP .. re-reading zone file.')
    init_config(only_zones=True)


def handle_sigterm(signum, frame):
    """handle SIGTERM - exit program"""
    _, _ = signum, frame
    log_message('control: caught SIGTERM .. exiting.')
    sys.exit(0)


def install_signal_handlers():
    """Install handlers for HUP and TERM signals"""
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, handle_sighup)


def daemon(dirname=None, syslog_fac=syslog.LOG_DAEMON):
    """Turn into daemon"""

    umask_value = 0o022

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as einfo:
        print("fork() failed: %s" % einfo)
        sys.exit(1)
    else:
        if dirname:
            os.chdir(dirname)
        os.umask(umask_value)
        os.setsid()

        for fd in range(0, os.sysconf("SC_OPEN_MAX")):
            try:
                os.close(fd)
            except OSError:
                pass

        syslog.openlog(PROGNAME, syslog.LOG_PID, syslog_fac)
        return


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


class Zone(dns.zone.Zone):

    """
    Modified dns.zone.Zone class.
    It uses the SortedDict class from sortedcontainers, rather than the
    standard dict class. This maintains a sorted keylist, which makes
    it easier to implement DNSSEC functions.
    When add_ent_nodes() is called, it will iterate through the zone and
    add all empty non-terminals as explicit nodes in the dictionary.
    Fully qualified origin must be specified. Doesn't support relativized
    names.
    """

    node_factory = dns.node.Node

    __slots__ = ['rdclass', 'origin', 'nodes', 'relativize', 'ent_nodes']

    def __init__(self, origin, rdclass=dns.rdataclass.IN, relativize=False):
        """Initialize a zone object."""

        super().__init__(origin, rdclass, relativize=relativize)
        self.nodes = SortedDict()
        self.ent_nodes = {}

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

    def __str__(self):
        return "<Zone: {}>".format(self.origin)


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

    def add(self, zonename, zonefile):
        """Create and add zonename->zone object"""
        zonename = dns.name.from_text(zonename)
        self.data[zonename] = dns.zone.from_file(zonefile,
                                                 origin=zonename,
                                                 zone_factory=Zone,
                                                 relativize=False)
        self.data[zonename].add_ent_nodes()

    def find(self, qname):
        """Return closest enclosing zone object for the qname"""
        for zname in self.zonelist:
            if qname.is_subdomain(zname):
                return self.data[zname]
        return None


def query_meta_type(qtype):
    """Is given query type a meta type?"""
    return 128 <= qtype <= 255


class DNSquery:
    """DNS query object"""

    def __init__(self, data, cliaddr, cliport, tcp=False):

        self.malformed = False
        self.cliaddr = cliaddr
        self.cliport = cliport

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
            self.qname = self.message.question[0].name
            self.qtype = self.message.question[0].rdtype
            self.qclass = self.message.question[0].rdclass
            self.log_query()

    def log_query(self):
        """Log information about incoming DNS query"""
        transport = "TCP" if self.tcp else "UDP"
        log_message('query: %s %s %s %s from: %s,%d size=%d' % \
                        (transport,
                         self.qname,
                         dns.rdatatype.to_text(self.qtype),
                         dns.rdataclass.to_text(self.qclass),
                         self.cliaddr, self.cliport, self.msg_len))


class DNSresponse:
    """DNS response object"""

    def __init__(self, query):

        self.query = query
        self.qname = query.message.question[0].name
        self.qtype = query.message.question[0].rdtype
        self.qclass = query.message.question[0].rdclass

        self.response = dns.message.make_response(query.message)
        self.response.set_rcode(dns.rcode.NOERROR)
        self.is_referral = False
        self.cname_owner_list = []
        self.dname_owner_list = []

        self.prepare_response()
        ## self.wire_message = self.to_wire()

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

    def add_soa(self, zobj):
        """Add SOA record to authority for negative responses"""

        soa_rrset = zobj.get_rrset(zobj.origin, dns.rdatatype.SOA)
        soa_rrset.ttl = min(soa_rrset.ttl, soa_rrset[0].minimum)
        self.response.authority = [soa_rrset]

    def find_rrtype(self, zobj, sname, stype, wildcard_match=None):
        """Find RRtype for given name, with CNAME processing if needed"""

        rrname = wildcard_match if wildcard_match else sname

        # If not CNAME, look for CNAME, and process it if found.
        if stype != dns.rdatatype.CNAME:
            rdataset = zobj.get_rdataset(sname, dns.rdatatype.CNAME)
            if rdataset:
                self.process_cname(rrname, sname, stype, rdataset)
                return True

        # Look for requested RRtype
        rdataset = zobj.get_rdataset(sname, stype)
        if rdataset:
            rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, stype)
            rrset.update(rdataset)
            self.response.answer.append(rrset)
            return True

        # NODATA - add SOA
        self.add_soa(zobj)
        return True

    def do_referral(self, zobj, sname, rdataset):
        """Generate referral response to child zone"""

        self.is_referral = True
        ns_rrset = dns.rrset.RRset(sname, dns.rdataclass.IN, dns.rdatatype.NS)
        ns_rrset.update(rdataset)
        self.response.authority.append(ns_rrset)
        for rdata in rdataset:
            if not rdata.target.is_subdomain(sname):
                continue
            for rrtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                rdataset = zobj.get_rdataset(rdata.target, rrtype)
                if rdataset:
                    rrset = dns.rrset.RRset(rdata.target,
                                            dns.rdataclass.IN, rrtype)
                    rrset.update(rdataset)
                    self.response.additional.append(rrset)

    def process_cname(self, rrname, sname, stype, cname_rdataset):
        """Process CNAME"""

        if sname in self.cname_owner_list:
            log_message("error: CNAME loop detected at {}".format(sname))
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.cname_owner_list.append(sname)
        rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN,
                                dns.rdatatype.CNAME)
        rrset.update(cname_rdataset)
        self.response.answer.append(rrset)
        self.find_answer(cname_rdataset[0].target, stype)

    def process_dname(self, qname, sname, stype, dname_rdataset):
        """Process DNAME"""

        if sname in self.dname_owner_list:
            log_message("error: DNAME loop detected at {}".format(sname))
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.dname_owner_list.append(sname)
        rrset = dns.rrset.RRset(sname, dns.rdataclass.IN, dns.rdatatype.DNAME)
        rrset.update(dname_rdataset)
        self.response.answer.append(rrset)
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
        self.process_cname(qname, qname, stype, rdataset)
        return

    def process_name(self, zobj, qname, sname, stype):
        """Process name and type"""

        node = zobj.get_node(sname)
        if node is None:
            # Look for wildcard
            wildcard = dns.name.Name((b'*',) + sname.labels[1:])
            if zobj.get_node(wildcard) is not None:
                return self.find_rrtype(zobj, wildcard, stype,
                                        wildcard_match=sname)
            self.response.set_rcode(dns.rcode.NXDOMAIN)
            self.add_soa(zobj)
            return True

        # Look for DNAME
        dname_rdataset = zobj.get_rdataset(sname, dns.rdatatype.DNAME)
        if dname_rdataset:
            self.process_dname(qname, sname, stype, dname_rdataset)
            return True

        # Look for delegation
        if sname != zobj.origin:
            rdataset = zobj.get_rdataset(sname, dns.rdatatype.NS)
            if rdataset:
                self.do_referral(zobj, sname, rdataset)
                return True

        if sname != qname:
            return False

        return self.find_rrtype(zobj, sname, stype)

    def find_answer_in_zone(self, zobj, qname, qtype):
        """Find answer for name and type in given zone"""

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

        global ZONEDICT
        zobj = ZONEDICT.find(qname)
        if zobj is None:
            if not self.response.answer:
                self.response.set_rcode(dns.rcode.REFUSED)
            return
        self.find_answer_in_zone(zobj, qname, qtype)

    def need_edns(self):
        """Do we need to add EDNS Opt RR?"""

        return (PREFS.edns_udp_max != 0) and (self.query.message.edns != -1)

    def do_edns(self):
        """Generate EDNS response information"""

        options = []
        for option in self.query.message.options:
            if PREFS.nsid and (option.otype == dns.edns.NSID):
                options.append(dns.edns.GenericOption(dns.edns.NSID,
                                                      PREFS.nsid))
        self.response.use_edns(edns=0,
                               payload=PREFS.edns_udp_adv,
                               request_payload=PREFS.edns_udp_max,
                               options=options)

    def prepare_response(self):
        """Prepare DNS response message"""

        if self.need_edns():
            if self.query.message.edns > 0:
                self.response.set_rcode(dns.rcode.BADVERS)
                return
            self.do_edns()
        else:
            self.response.use_edns(edns=False)

        if self.qclass != dns.rdataclass.IN:
            self.response.set_rcode(dns.rcode.REFUSED)
            return

        if query_meta_type(self.qtype):
            self.response.set_rcode(dns.rcode.NOTIMP)

        self.find_answer(self.qname, self.qtype)
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
    dispatch = {}

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


def main(arguments):
    """Main function ..."""

    global PREFS

    process_args(arguments[1:])
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

    while True:

        try:
            (ready_r, _, _) = select.select(fd_read, [], [], 5)
        except OSError as exc_info:
            log_message("error: from select(): {}".format(exc_info))
            sys.exit(1)

        if not ready_r:
            continue

        for fd in ready_r:
            for sock in dispatch:
                handler, is_tcp = dispatch[sock]
                if fd == sock.fileno():
                    if is_tcp:
                        conn, addr = sock.accept()
                        threading.Thread(target=handler,
                                         args=(conn, addr)).start()
                    else:
                        threading.Thread(target=handler,
                                         args=(sock,)).start()

        # Do something in the main thread here if needed
        #log_message("Heartbeat.")


if __name__ == '__main__':

    # Globals
    PREFS = Preferences()
    ZONEDICT = ZoneDict()
    tlock = threading.Lock()

    main(sys.argv)
