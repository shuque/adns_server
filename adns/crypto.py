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
import dns.rdtypes.ANY.RRSIG

# Parameters for online signing
RRSIG_INCEPTION_OFFSET = 3600
RRSIG_LIFETIME = 172800

# Online Signature Cache parameters
CACHE_SIZE = 200
CACHE_TTL = RRSIG_LIFETIME - 2 * (RRSIG_INCEPTION_OFFSET)


class DnssecUnsupported(RuntimeError):
    """
    Raised when alg-18 signing needs a dnspython facility this build lacks
    (the private _make_rrsig_signature_data). A RuntimeError (not a
    signer-domain error) so crypto.py has no dependency on signer.py.
    """


def mldsa_rrsig_rdata(rrset, private_key, signer,   # pylint: disable=too-many-positional-arguments
                      dnskey, inception, expiration):
    """
    Build an algorithm-18 (ML-DSA-44) RRSIG rdata.

    dns.dnssec.sign() raises UnsupportedAlgorithm for alg 18, so we assemble the
    RRSIG the way it does internally: an RRSIG rdata with an empty signature,
    the RFC 4034 3.1.8.1 data-to-be-signed from dnspython's (algorithm-agnostic)
    _make_rrsig_signature_data(), signed with pure ML-DSA (empty context ->
    context=None), and the 2420-octet signature spliced in. Signing is hedged (no
    deterministic option in cryptography); a hedged ML-DSA signature is valid and
    is what draft-westerbaan-dnssec-mldsa prefers.

    Callers pass absolute owner names and absolute POSIX-int times, so no origin
    derelativization or timestamp normalization is needed (origin=None). Shared
    by the server's cached sign_rrset() and the offline signer.

    Remove this helper once dnspython signs algorithm 18 natively.
    """
    # _make_rrsig_signature_data is a private dnspython API that only the
    # algorithm-18 path relies on; check it here, at signing time, so a future
    # dnspython that removes it fails loudly for alg 18 alone rather than
    # breaking import (and thus alg 8/13/15 signing) for the whole module.
    if not hasattr(dns.dnssec, "_make_rrsig_signature_data"):
        raise DnssecUnsupported(
            "algorithm-18 (ML-DSA-44) signing requires "
            "dns.dnssec._make_rrsig_signature_data; this dnspython build "
            "lacks it")
    rrname = rrset.name
    labels = len(rrname) - 1
    if rrname.is_wild():
        labels -= 1
    template = dns.rdtypes.ANY.RRSIG.RRSIG(
        rdclass=rrset.rdclass, rdtype=dns.rdatatype.RRSIG,
        type_covered=rrset.rdtype, algorithm=dnskey.algorithm, labels=labels,
        original_ttl=rrset.ttl, expiration=expiration, inception=inception,
        key_tag=dns.dnssec.key_id(dnskey), signer=signer, signature=b"")
    data = dns.dnssec._make_rrsig_signature_data(  # pylint: disable=protected-access
        rrset, template, None)
    signature = private_key.sign(data, context=None)
    return template.replace(signature=signature)


@cachetools.cached(cache=cachetools.TTLCache(maxsize=CACHE_SIZE,
                                             ttl=CACHE_TTL),
                   info=True,
                   lock=threading.Lock())
def sign_rrset(zone, h_rrset):
    """Sign RRset with zone's private key and return RRSIG record"""
    rrset = h_rrset.rrset
    inception = int(time.time() - RRSIG_INCEPTION_OFFSET)
    if zone.signing_dnskey.algorithm == 18:
        rrsig_rdata = mldsa_rrsig_rdata(rrset,
                                        zone.privatekey,
                                        zone.origin,
                                        zone.signing_dnskey,
                                        inception,
                                        inception + RRSIG_LIFETIME)
    else:
        rrsig_rdata = dns.dnssec.sign(rrset,
                                      zone.privatekey,
                                      zone.origin,
                                      zone.signing_dnskey,
                                      inception=inception,
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
