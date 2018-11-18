#!/usr/bin/env python3

"""
    Toy Authoritative DNS server for experimentation.
    [Work in Progress ..]
    Author: Shumon Huque <shuque@gmail.com>
"""

import getopt, os, os.path, sys, pwd, grp
import struct, socket, select, errno, threading
from binascii import hexlify
import dns.message, dns.rdatatype, dns.rcode, dns.flags, dns.query, dns.edns
import dns.zone


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
    Zone object: contains a dns.zone.Zone object along with an
    additional dictionary containing all node names. The dns.zone
    module's find_node() method returns the wrong results for
    empty non-terminals.
    """

    def __init__(self, filename):
        self.filename = filename
        self.zone = dns.zone.from_file(filename, relativize=False)
        self.all_nodes = self.get_all_nodes()

    def get_all_nodes(self):
        """Return dictionary of all names _including_ empty non-terminals"""

        all_nodes = {}
        for name, node in self.zone.items():
            add_dict_key(all_nodes, name)
            if name == self.zone.origin:
                continue
            inZone = True
            n = name
            while inZone:
                p = n.parent()
                if p == self.zone.origin:
                    inZone = False
                else:
                    add_dict_key(all_nodes, p)
                    n = p
        return all_nodes


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
            dprint("BAD QUERY: %s: %s" % (str(type(e)), e.message))
            self.message = None


class DNSresponse:
    """DNS response object"""

    def __init__(self, query):

        self.query = query
        self.message = self.make_response()
        self.wire_message = self.message.to_wire()
        if self.query.tcp:
            msglen = struct.pack('!H', len(self.wire_message))
            self.wire_message = msglen + self.wire_message

    def soa_rr(self):
        return z.zone.find_rrset(z.zone.origin, dns.rdatatype.SOA)

    def make_response(self):

        response = dns.message.make_response(self.query.message)
        if Prefs.NO_EDNS:
            response.use_edns(edns=False)
        qname = self.query.message.question[0].name
        qtype = self.query.message.question[0].rdtype

        if not qname.is_subdomain(z.zone.origin):
            response.set_rcode(dns.rcode.REFUSED)
            return response

        response.flags |= dns.flags.AA                     # set AA=1
        if qname not in z.all_nodes:
            response.set_rcode(dns.rcode.NXDOMAIN)         # NXDOMAIN
            response.authority = [self.soa_rr()]
            return response
        try:
            rrs = z.zone.find_rrset(qname, qtype)
        except KeyError:
            response.authority = [self.soa_rr()]           # NODATA
        else:
            response.answer = [rrs]                        # Answer

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

def load_zone(zonefile):
    z_ent = {}
    z = dns.zone.from_file(zonefile, relativize=False)
    return z, z_ent


if __name__ == '__main__':

    process_args(sys.argv[1:])

    z = Zone(Prefs.ZONEFILE)
    print("Serving DNS zone: %s" % z.zone.origin)

    fd_read = []

    if Prefs.SERVER_AF is None or Prefs.SERVER_AF == 'IPv4':
        s_udp4 = udp4socket(Prefs.SERVER, Prefs.PORT)
        fd_read.append(s_udp4.fileno())
        s_tcp4 = tcp4socket(Prefs.SERVER, Prefs.PORT)
        fd_read.append(s_tcp4.fileno())

    if Prefs.SERVER_AF is None or Prefs.SERVER_AF == 'IPv6':
        s_udp6 = udp6socket(Prefs.SERVER, Prefs.PORT)
        fd_read.append(s_udp6.fileno())
        s_tcp6 = tcp6socket(Prefs.SERVER, Prefs.PORT)
        fd_read.append(s_tcp6.fileno())

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

                if Prefs.SERVER_AF is None or Prefs.SERVER_AF == 'IPv4':
                    if fd == s_tcp4.fileno():
                        s_conn4, addr = s_tcp4.accept()
                        threading.Thread(target=handle_connection_tcp, 
                                         args=(s_conn4, addr)).start()
                    elif fd == s_udp4.fileno():
                        threading.Thread(target=handle_connection_udp, 
                                         args=(s_udp4,)).start()

                if Prefs.SERVER_AF is None or Prefs.SERVER_AF == 'IPv6':
                    if fd == s_tcp6.fileno():
                        s_conn6, addr = s_tcp6.accept()
                        threading.Thread(target=handle_connection_tcp, 
                                         args=(s_conn6, addr)).start()
                    elif fd == s_udp6.fileno():
                        threading.Thread(target=handle_connection_udp, 
                                         args=(s_udp6,)).start()

        # Do something in the main thread here if needed
        #dprint("Heartbeat.")
