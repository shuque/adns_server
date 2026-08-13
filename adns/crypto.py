"""
Online-signing machinery for adns_server and the offline signer.

Holds the one process-wide signature cache (sign_rrset), private-key loading
(load_private_key), and the shared key-file naming helper (key_basename) used
by both the signer and the key generator.
"""

import threading
import time

import cachetools
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import dns.dnssec
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.rdataset

# Parameters for online signing
RRSIG_INCEPTION_OFFSET = 3600
RRSIG_LIFETIME = 172800

# Online Signature Cache parameters
CACHE_SIZE = 200
CACHE_TTL = RRSIG_LIFETIME - 2 * (RRSIG_INCEPTION_OFFSET)


@cachetools.cached(cache=cachetools.TTLCache(maxsize=CACHE_SIZE,
                                             ttl=CACHE_TTL),
                   info=True,
                   lock=threading.Lock())
def sign_rrset(zone, h_rrset):
    """Sign RRset with zone's private key and return RRSIG record"""
    rrset = h_rrset.rrset
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


def load_private_key(keyfile):
    """
    Load DNSSEC private key from PEM format file for online signing.
    """
    with open(keyfile, 'rb') as fkeyfile:
        return load_pem_private_key(fkeyfile.read(), password=None)


def key_basename(zonename, algorithm, keytag):
    """Return the keytag-named base filename (no extension) shared by adnskeygen
    and signzone: '<zonename>+<alg:03d>+<keytag:05d>'. zonename must be the
    origin text with any trailing dot stripped. Matches BIND's +%03d+%05d
    convention so the files are greppable and self-describing."""
    return f"{zonename}+{algorithm:03d}+{keytag:05d}"
