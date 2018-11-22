#!/usr/bin/env python3

"""
    Toy Authoritative DNS server for experimentation.
    [Work in Progress ..]
    Author: Shumon Huque <shuque@gmail.com>
"""

import getopt, os, os.path, sys, pwd, grp
import struct, socket, select, errno, threading
from binascii import hexlify
import dns.zone, dns.name, dns.message, dns.flags, dns.rcode
import dns.rdatatype, dns.rdataclass, dns.query, dns.edns


class Prefs:
    """Preferences"""
    DEBUG      = False                # -d: Print debugging output?
    SERVER     = ""                   # -s: server listening address
    SERVER_AF  = None                 # server's address family if -s set
    PORT       = 53                   # -p: port
    USERNAME   = 'named'              # username to run as
    GROUPNAME  = 'named'              # group to run as
    ZONEFILE   = 'zonefile'           # zone file (master zone file format)
    NO_EDNS    = True                 # Ignore EDNS in queries


def dprint(input):
    if Prefs.DEBUG:
        with tlock:
            print("DEBUG: %s" % input)
    return


def usage():
    """Usage string"""
    print("""\
Usage: %s [<options>]

Options:
       -h:        Print usage string
       -d:        Turn on debugging
       -p N:      Listen on port N (default 53)
       -s A:      Bind to server address A

""" % os.path.basename(sys.argv[0]))
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
        (options, args) = getopt.getopt(arguments, 'hds:p:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-h":
            usage()
        elif opt == "-d":
            Prefs.DEBUG = True
        elif opt == "-s":
            Prefs.SERVER = optval
            set_server_af(optval)
        elif opt == "-p":
            Prefs.PORT = int(optval)

    return


def drop_privs(uname=Prefs.USERNAME, gname=Prefs.GROUPNAME):
    if os.geteuid() != 0:
        print("INFO: Program did not start as root.")
    else:
        uid = pwd.getpwnam(uname).pw_uid
        gid = grp.getgrnam(gname).gr_gid
        os.setgroups([])
        os.setgid(gid)
        os.setegid(gid)
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
                raise(ValueError, "send() returned 0 bytes")
            octetsSent += sentn
    except Exception as diag:
        print("DEBUG: Exception: %s" % diag)
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


class DNSquery:
    """DNS query object"""

    def __init__(self, data, cliaddr, cliport, tcp=False):

        self.cliaddr = cliaddr
        self.cliport = cliport

        self.tcp = tcp
        if self.tcp:
            msg_len, = struct.unpack('!H', data[:2])
            self.wire_message = data[2:2+msg_len]
        else:
            self.wire_message = data

        try:
            self.message = dns.message.from_wire(self.wire_message)
        except Exception as e:
            dprint("Unable to Parse Query: %s: %s" % (str(type(e)), e.message))
            self.message = None


class DNSresponse:
    """DNS response object"""

    def __init__(self, query):

        self.query = query
        self.answer_rrsets = []
        self.answer_resolved = False
        self.rcode = dns.rcode.NOERROR
        self.message = self.make_response()
        self.wire_message = self.message.to_wire()
        if self.query.tcp:
            msglen = struct.pack('!H', len(self.wire_message))
            self.wire_message = msglen + self.wire_message

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

    def synthesize_cname(self, qname, labels, dname, dname_rdataset):
        cname = dns.name.Name(labels[::-1] + dname.labels)
        rrset = dns.rrset.RRset(qname, self.qclass, dns.rdatatype.CNAME)
        rdataset = dns.rdataset.Rdataset(self.qclass, dns.rdatatype.CNAME)
        rdataset.update_ttl(dname_rdataset.ttl)
        cname_rdata = dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN,
                                                  dns.rdatatype.CNAME, cname)
        rdataset.add(cname_rdata)
        rrset.update(rdataset)
        self.answer_rrsets.append(rrset)
        return

    def find_dname(self, qname):
        labels = qname.relativize(z.zone.origin)[::-1]
        candidate = z.zone.origin
        remaining_labels = labels
        while remaining_labels:
            if candidate == qname:
                return False
            rdataset = z.zone.get_rdataset(candidate, dns.rdatatype.DNAME)
            if rdataset:
                dname = rdataset[0].target
                rrset = dns.rrset.RRset(candidate, self.qclass, dns.rdatatype.DNAME)
                rrset.update(rdataset)
                self.answer_rrsets.append(rrset)
                self.synthesize_cname(qname, remaining_labels, dname, rdataset)
                self.answer_resolved = True
                return True
            l = remaining_labels[0]
            remaining_labels = remaining_labels[1:]
            candidate = dns.name.Name((l,) + candidate.labels)
        else:
            return False

    def find_answers(self, qname, qtype, wild=False):

        if self.find_dname(qname):
            return

        while True:
            if z.zone.get_node(qname) is None:
                wildcard = self.find_wildcard(qname)
                if wildcard is not None:
                    return self.find_answers(wildcard, qtype, wild=True)
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
                rdataset = z.zone.get_rdataset(qname, dns.rdatatype.CNAME)
                if not rdataset:
                    return
                owner = self.qname if wild else qname
                rrset = dns.rrset.RRset(owner, self.qclass, dns.rdatatype.CNAME)
                rrset.update(rdataset)
                self.answer_rrsets.append(rrset)
                cname = rdataset[0].target
                if cname.is_subdomain(z.zone.origin):
                    qname = cname
                else:
                    self.answer_resolved = True
                    return

    def make_response(self):

        response = dns.message.make_response(self.query.message)
        if Prefs.NO_EDNS:
            response.use_edns(edns=False)
        self.qname = self.query.message.question[0].name
        self.qtype = self.query.message.question[0].rdtype
        self.qclass = self.query.message.question[0].rdclass

        if self.qclass != dns.rdataclass.IN:
            response.set_rcode(dns.rcode.REFUSED)
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
    dprint("RECEIVE QUERY:\n%s" % query.message)

    if not query.message:
        return

    response = DNSresponse(query)
    if not response.message:
        return

    dprint("SEND RESPONSE:\n%s" % response.message)
    dprint(hexlify(response.wire_message))
    if query.tcp:
        sendSocket(sock, response.wire_message)
    else:
        sock.sendto(response.wire_message,
                    (query.cliaddr, query.cliport))


def handle_connection_udp(sock, rbufsize=2048):
    data, addrport = sock.recvfrom(rbufsize)
    cliaddr, cliport = addrport[0:2]
    dprint("UDP connection from (%s, %d) msgsize=%d" % 
           (cliaddr, cliport, len(data)))
    q = DNSquery(data, cliaddr=cliaddr, cliport=cliport)
    handle_query(q, sock)


def handle_connection_tcp(sock, addr, rbufsize=2048):
    data = sock.recv(rbufsize)
    cliaddr, cliport = addr[0:2]
    dprint("TCP connection from (%s, %d) msgsize=%d" %
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
    print("Serving DNS zone: %s" % z.zone.origin)

    fd_read, dispatch = setup_sockets(Prefs.SERVER_AF, Prefs.SERVER, Prefs.PORT)

    drop_privs()

    print("Listening on UDP and TCP port %d" % Prefs.PORT)

    tlock = threading.Lock()

    while True:

        try:
            (ready_r, ready_w, ready_e) = select.select(fd_read, [], [], 5)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            else:
                print("Fatal error from select(): %s" % e)
                sys.exit(1)
        except KeyboardInterrupt:
            print("Exiting.");
            os._exit(0)

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
        #dprint("Heartbeat.")
