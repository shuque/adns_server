#!/usr/bin/env python3

"""
    Toy Authoritative DNS server for experimentation.
    [Work in Progress ..]
    Author: Shumon Huque <shuque@gmail.com>
"""

import getopt, os, os.path, sys, pwd, grp, syslog
import struct, socket, select, errno, threading, signal
from binascii import hexlify
import dns.zone, dns.name, dns.message, dns.flags, dns.rcode
import dns.rdatatype, dns.rdataclass, dns.query, dns.edns


PROGNAME = os.path.basename(sys.argv[0])
VERSION  = '0.1'

class Prefs:
    """Preferences"""
    DEBUG      = False                # -d: Print debugging output
    SERVER     = ''                   # -s: server listening address
    SERVER_AF  = None                 # server's address family if -s set
    PORT       = 53                   # -p: port
    USERNAME   = None                 # username to switch to (if root)
    GROUPNAME  = None                 # group to switch to (if root)
    ZONEFILE   = 'zonefile'           # zone file (master zone file format)
    DAEMON     = True                 # Become daemon (-f: foreground)
    SYSLOG_FAC = syslog.LOG_DAEMON    # Syslog facility
    SYSLOG_PRI = syslog.LOG_INFO      # Syslog priority
    WORKDIR    = None                 # Working directory to change to
    EDNS       = True                 # Support EDNS (-e disables it)
    UDP_MAX    = 4096                 # Max EDNS UDP payload we send
    UDP_ADV    = 2048                 # Max EDNS UDP payload we advertise


def usage():
    """Print usage string and exit"""
    print("""\
%s version %s
Usage: %s [<Options>]

Options:
       -h:        Print usage string
       -d:        Turn on debugging
       -p N:      Listen on port N (default 53)
       -s A:      Bind to server address A (default wildcard address)
       -z file:   Load and serve specified zone file (default 'zonefile')
       -u uname:  Drop privileges to UID of specified username
                  (if server started running as root)
       -g group:  Drop provileges to GID of specified groupname
                  (if server started running as root)
       -4:        Use IPv4 only
       -6:        Use IPv6 only
       -f:        Remain attached to foreground (default don't)
       -e:        Disable EDNS0 support
""" % (PROGNAME, VERSION, PROGNAME))
    sys.exit(1)


def set_server_af(address):

    global Prefs

    if address.find('.') != -1: 
        Prefs.SERVER_AF = 'IPv4'
    elif address.find(':') != -1:
        Prefs.SERVER_AF = 'IPv6'
    else:
        raise ValueError("%s isn't a valid address" % address)


def process_args(arguments):
    """Process all command line arguments"""

    global Prefs

    try:
        (options, args) = getopt.getopt(arguments, 'hdp:s:z:u:g:46fe')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-h":
            usage()
        elif opt == "-d":
            Prefs.DEBUG = True
        elif opt == "-p":
            Prefs.PORT = int(optval)
        elif opt == "-s":
            Prefs.SERVER = optval
            set_server_af(optval)
        elif opt == "-z":
            Prefs.ZONEFILE = optval
        elif opt == "-u":
            Prefs.USERNAME = optval
        elif opt == "-g":
            Prefs.GROUPNAME = optval
        elif opt == "-4":
            Prefs.SERVER_AF = 'IPv4'
        elif opt == "-6":
            Prefs.SERVER_AF = 'IPv6'
        elif opt == "-f":
            Prefs.DAEMON = False
        elif opt == "-e":
            Prefs.EDNS = False

    return


def log_message(msg):
    if Prefs.DAEMON:
        syslog.syslog(Prefs.SYSLOG_PRI, msg)
    else:
        with tlock:
            print(msg)


def log_fatal(msg):
    log_message(msg)
    sys.exit(1)


def handle_sighup(signum, frame):
    global z
    log_message('Caught SIGHUP .. re-reading zone file.')
    z = Zone(Prefs.ZONEFILE)
    return


def handle_sigterm(signum, frame):
    log_message('Caught SIGTERM .. exiting.')
    sys.exit(0)


def install_signal_handlers():
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, handle_sighup)


def daemon(dirname=None, syslog_fac=syslog.LOG_DAEMON):

    UMASK = 0o022

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
        os.umask(UMASK)
        os.setsid()

        for fd in range(0, os.sysconf("SC_OPEN_MAX")):
            try:
                os.close(fd)
            except OSError:
                pass

        syslog.openlog(PROGNAME, syslog.LOG_PID, syslog_fac)
        return


def drop_privs(uname, gname):
    if os.geteuid() != 0:
        log_message("WARNING: Program didn't start as root. Can't change id.")
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
    return


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


def sendSocket(s, message):
    """Send message on a connected socket"""
    try:
        octetsSent = 0
        while (octetsSent < len(message)):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                log_message("ERROR: send() returned 0 bytes")
                raise(ValueError, "send() returned 0 bytes")
            octetsSent += sentn
    except Exception as diag:
        log_message("ERROR: sendSocket() exception: %s" % diag)
        return False
    else:
        return True


def recvSocket(s, numOctets):
    """Read and return numOctets of data from a connected socket"""
    response = ""
    octetsRead = 0
    while (octetsRead < numOctets):
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return ""
        octetsRead += chunklen
        response += chunk
    return response


def add_dict_key(d, k):
    """Add key k to dictionary d, if not already present"""
    if k not in d:
        d[k] = 1


class Zone:
    """
    Zone object: contains a dns.zone.Zone object, modified to include
    all empty non-terminals as explicit nodes. Otherwise, the dns.zone
    module's find_node() method returns the wrong results for empty
    non-terminals.
    """

    def __init__(self, filename):
        self.filename = filename
        self.zone = dns.zone.from_file(filename, relativize=False)
        self.add_nodes(self.get_ent_nodes())

    def get_ent_nodes(self):
        ent_nodes = {}
        for name, node in self.zone.items():
            if name == self.zone.origin:
                continue
            n = name
            while True:
                p = n.parent()
                if p == self.zone.origin:
                    break
                if self.zone.get_node(p) is None:
                    add_dict_key(ent_nodes, p)
                n = p
        return ent_nodes

    def add_nodes(self, nodelist):
        for entry in nodelist:
            _ = self.zone.get_node(entry, create=True)


def query_meta_type(qtype):
    return 128 <= qtype <= 255


class DNSquery:
    """DNS query object"""

    def __init__(self, data, cliaddr, cliport, tcp=False):

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
        except Exception as e:
            log_message("Unable to parse query: %s: %s" % (str(type(e)), e.message))
            self.message = None
        else:
            self.qname = self.message.question[0].name
            self.qtype = self.message.question[0].rdtype
            self.qclass = self.message.question[0].rdclass
            self.log_query()

    def log_query(self):
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

        self.answer_rrsets = []
        self.answer_resolved = False
        self.rcode = dns.rcode.NOERROR
        self.cname_list = []

        self.message = self.make_response()
        self.wire_message = self.to_wire()

    def to_wire(self):
        payload_max = self.max_size()
        try:
            wire = self.message.to_wire(max_size=payload_max)
        except dns.exception.TooBig:
            wire = self.truncate()
        if self.query.tcp:
            msglen = struct.pack('!H', len(wire))
            wire = msglen + wire
        return wire

    def max_size(self):
        if self.query.tcp:
            return 65533
        elif self.query.message.edns == -1:
            return 512
        else:
            return self.query.message.payload

    def truncate(self):
        self.message.flags |= dns.flags.TC
        self.message.answer = []
        self.message.authority = []
        self.message.additional = []
        return self.message.to_wire()

    def soa_rr(self):
        return z.zone.get_rrset(z.zone.origin, dns.rdatatype.SOA)

    def closest_encloser(self, qname):
        node = qname.parent()
        while True:
            if z.zone.get_node(node) is not None:
                return node
            else:
                node = dns.name.Name(node.labels[1:])

    def find_wildcard(self, qname):
        wildcard = dns.name.Name((b'*',) + self.closest_encloser(qname).labels)
        if z.zone.get_node(wildcard) is not None:
            return wildcard
        else:
            return None

    def synthesize_cname(self, qname, labels, dname_rdataset):
        dname = dname_rdataset[0].target
        try:
            cname = dns.name.Name(labels[::-1] + dname.labels)
        except dns.name.NameTooLong:
            self.rcode = dns.rcode.YXDOMAIN
            return
        rrset = dns.rrset.RRset(qname, self.qclass, dns.rdatatype.CNAME)
        rdataset = dns.rdataset.Rdataset(self.qclass, dns.rdatatype.CNAME)
        rdataset.update_ttl(dname_rdataset.ttl)
        cname_rdata = dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN,
                                                  dns.rdatatype.CNAME, cname)
        rdataset.add(cname_rdata)
        rrset.update(rdataset)
        self.answer_rrsets.append(rrset)
        self.cname_list.append(qname)
        if cname in self.cname_list:
            log_message("WARN: CNAME loop: %s." % self.cname_list)
            return
        if cname.is_subdomain(z.zone.origin):
            self.find_answers(cname, self.qtype)
        return

    def find_dname(self, qname):
        remaining_labels = qname.relativize(z.zone.origin)[::-1]
        candidate = z.zone.origin
        while remaining_labels and (candidate != qname):
            rdataset = z.zone.get_rdataset(candidate, dns.rdatatype.DNAME)
            if rdataset:
                rrset = dns.rrset.RRset(candidate, self.qclass, dns.rdatatype.DNAME)
                rrset.update(rdataset)
                self.answer_rrsets.append(rrset)
                self.synthesize_cname(qname, remaining_labels, rdataset)
                self.answer_resolved = True
                return True
            l = remaining_labels[0]
            remaining_labels = remaining_labels[1:]
            candidate = dns.name.Name((l,) + candidate.labels)
        else:
            return False

    def find_cname(self, name, wild=False):
        rdataset = z.zone.get_rdataset(name, dns.rdatatype.CNAME)
        if not rdataset:
            return None
        owner = self.qname if wild else name
        rrset = dns.rrset.RRset(owner, self.qclass, dns.rdatatype.CNAME)
        rrset.update(rdataset)
        self.answer_rrsets.append(rrset)
        cname = rdataset[0].target
        self.cname_list.append(owner)
        return cname

    def find_answers(self, qname, qtype, wild=False):

        if self.find_dname(qname):
            return

        if z.zone.get_node(qname) is None:
            wildcard = self.find_wildcard(qname)
            if wildcard is not None:
                self.find_answers(wildcard, qtype, wild=True)
            else:
                self.rcode = dns.rcode.NXDOMAIN
                return

        rdataset = z.zone.get_rdataset(qname, qtype)
        if rdataset:
            owner = self.qname if wild else qname
            rrset = dns.rrset.RRset(owner, self.qclass, qtype)
            rrset.update(rdataset)
            self.answer_rrsets.append(rrset)
            self.answer_resolved = True
            return
        else:
            cname = self.find_cname(qname, wild)
            if not cname:
                return
            if cname in self.cname_list:
                log_message("WARN: CNAME loop: %s." % self.cname_list)
                return
            if cname.is_subdomain(z.zone.origin):
                self.find_answers(cname, qtype)
            else:
                self.answer_resolved = True
                return

    def make_response(self):

        response = dns.message.make_response(self.query.message)
        if not Prefs.EDNS:
            response.use_edns(edns=False)
        else:
            if response.edns != -1:
                response.payload = Prefs.UDP_ADV
                if self.query.message.edns != 0:
                    response.set_rcode(dns.rcode.BADVERS)
                    return response

        if self.qclass != dns.rdataclass.IN:
            response.set_rcode(dns.rcode.REFUSED)
            return response

        if query_meta_type(self.qtype):
            response.set_rcode(dns.rcode.NOTIMP)
            return response

        if not self.qname.is_subdomain(z.zone.origin):
            response.set_rcode(dns.rcode.REFUSED)
            return response

        self.find_answers(self.qname, self.qtype)
        response.flags |= dns.flags.AA
        response.set_rcode(self.rcode)
        response.answer = self.answer_rrsets
        if not self.answer_resolved:
            response.authority = [self.soa_rr()]

        return response


def handle_query(query, sock):

    if not query.message:
        return

    response = DNSresponse(query)
    if not response.message:
        return

    if query.tcp:
        sendSocket(sock, response.wire_message)
    else:
        sock.sendto(response.wire_message,
                    (query.cliaddr, query.cliport))


def handle_connection_udp(sock, rbufsize=2048):
    data, addrport = sock.recvfrom(rbufsize)
    cliaddr, cliport = addrport[0:2]
    if Prefs.DEBUG:
        log_message("UDP connection from (%s, %d) msgsize=%d" %
                    (cliaddr, cliport, len(data)))
    q = DNSquery(data, cliaddr=cliaddr, cliport=cliport)
    handle_query(q, sock)


def handle_connection_tcp(sock, addr, rbufsize=2048):
    data = sock.recv(rbufsize)
    cliaddr, cliport = addr[0:2]
    if Prefs.DEBUG:
        log_message("TCP connection from (%s, %d) msgsize=%d" %
                    (cliaddr, cliport, len(data)))
    q = DNSquery(data, cliaddr=cliaddr, cliport=cliport, tcp=True)
    handle_query(q, sock)
    sock.close()


def setup_sockets(family, server, port):

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


if __name__ == '__main__':

    process_args(sys.argv[1:])
    z = Zone(Prefs.ZONEFILE)

    if Prefs.DAEMON:
        daemon(dirname=Prefs.WORKDIR)

    install_signal_handlers()

    tlock = threading.Lock()
    log_message("%s version %s: Serving DNS zone: %s" % \
                (PROGNAME, VERSION, z.zone.origin))

    try:
        fd_read, dispatch = setup_sockets(Prefs.SERVER_AF,
                                          Prefs.SERVER, Prefs.PORT)
    except PermissionError as e:
        log_fatal("Error setting up sockets: {}".format(e))

    if (Prefs.USERNAME or Prefs.GROUPNAME):
        drop_privs(Prefs.USERNAME, Prefs.GROUPNAME)

    log_message("Listening on UDP and TCP port %d" % Prefs.PORT)

    while True:

        try:
            (ready_r, ready_w, ready_e) = select.select(fd_read, [], [], 5)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            else:
                log_message("ERROR: from select(): %s" % e)
                sys.exit(1)

        if ready_r:
            for fd in ready_r:
                for s in dispatch:
                    if fd == s.fileno():
                        handler, tcp = dispatch[s]
                        if tcp:
                            conn, addr = s.accept()
                            threading.Thread(target=handler,
                                             args=(conn, addr)).start()
                        else:
                            threading.Thread(target=handler,
                                             args=(s,)).start()

        # Do something in the main thread here if needed
        #log_message("Heartbeat.")
