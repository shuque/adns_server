#!/usr/bin/env python3
#

"""
Generate DNSSEC keys and corresponding DNSKEY record data for use with
online DNSSEC signing.
"""

import argparse
import os
import dns.name
import dns.dnssec
import dns.rrset
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from dns.rdtypes.dnskeybase import SEP

from dnssec_util import key_basename


ECDSA_CURVE = ec.SECP256R1()
PROTOCOL = 3
TTL = 7200


def process_arguments():
    """Process command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument("zone", help="DNS zone name")
    parser.add_argument("-a", type=int, dest='algorithm', metavar='N',
                        default=13,
                        choices=[13, 15],
                        help="DNSSEC algorithm number (default: %(default)d)")
    parser.add_argument("-f", type=int, dest='flags', metavar='N',
                        default=257,
                        help="Value of DNSKEY flags field (default: %(default)d)")
    parser.add_argument("-K", "--keydir", metavar='DIR', default=None,
                        help="write keytag-named .pem/.dnskey/.ds triple here")
    parser.add_argument("--prepublish", action="store_true",
                        help="write the private key as .prepublish.pem so the "
                             "DNSKEY can be pre-published while signzone.py "
                             "ignores it until it is renamed to .pem (requires "
                             "-K)")
    return parser.parse_args()


def generate_key(algorithm):
    """Generate DNSSEC key for given algorithm"""

    if algorithm == 13:
        private_key = ec.generate_private_key(ECDSA_CURVE)
    elif algorithm == 15:
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported key algorithm: {algorithm}")
    public_key = private_key.public_key()
    return private_key, public_key


def pem_data_for_private_key(key):
    """Generate PEM PKCS8 string data for given private key"""

    serialized_private = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
    return serialized_private.decode()


def build_dnskey_rrset(zone, dnskey_rdata):
    """Build the apex DNSKEY RRset (single key) for printing / .dnskey output."""
    rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                     ttl=TTL)
    rdataset.add(dnskey_rdata)
    rrset.update(rdataset)
    return rrset


def write_key_triple(keydir, zone, algorithm, keytag, private_key,
                     dnskey_rrset, ds_rr, prepublish=False):
    """
    Write <basename>.pem/.dnskey into keydir, plus <basename>.ds when ds_rr is
    not None. zone is a dns.name.Name.

    The .ds file is written only for SEP keys (KSK/CSK); a ZSK is passed
    ds_rr=None and gets no DS file, since it is not a secure entry point in
    common operator practice.

    When prepublish is true the private key is written as
    <basename>.prepublish.pem instead of <basename>.pem, so signzone.py's
    exact-match key discovery ignores it (the DNSKEY is published but not used
    to sign) until an operator activates it by renaming to <basename>.pem. The
    .dnskey and .ds companions are written unchanged.
    """
    os.makedirs(keydir, exist_ok=True)
    basename = key_basename(zone.to_text().rstrip('.'), algorithm, keytag)
    pem_suffix = ".prepublish.pem" if prepublish else ".pem"
    pem_path = os.path.join(keydir, basename + pem_suffix)
    with open(pem_path, "w", encoding="utf-8") as f:
        f.write(pem_data_for_private_key(private_key))
    os.chmod(pem_path, 0o600)
    with open(os.path.join(keydir, basename + ".dnskey"), "w",
              encoding="utf-8") as f:
        f.write(dnskey_rrset.to_text() + "\n")
    if ds_rr is not None:
        with open(os.path.join(keydir, basename + ".ds"), "w",
                  encoding="utf-8") as f:
            f.write(f"{zone.to_text()} IN DS {ds_rr.to_text()}\n")
    return basename


if __name__ == '__main__':

    CONFIG = process_arguments()
    if CONFIG.prepublish and not CONFIG.keydir:
        raise SystemExit("adnskeygen.py: --prepublish requires -K/--keydir")
    ZONE = dns.name.from_text(CONFIG.zone)

    PRIVATE_KEY, PUBLIC_KEY = generate_key(CONFIG.algorithm)
    print("### Private Key file contents:")
    print(pem_data_for_private_key(PRIVATE_KEY))

    dnskey_rdata = dns.dnssec.make_dnskey(PUBLIC_KEY,
                                          CONFIG.algorithm,
                                          CONFIG.flags,
                                          PROTOCOL)
    print("### DNSKEY RDATA:")
    print(dnskey_rdata)
    keytag = dns.dnssec.key_id(dnskey_rdata)
    print("### DNSKEY keytag:", keytag)
    print('')

    DNSKEY_RRSET = build_dnskey_rrset(ZONE, dnskey_rdata)
    print("### DNSKEY RRset:")
    print(DNSKEY_RRSET)
    print('')

    # DS is only emitted for SEP keys (KSK/CSK): a plain ZONE-flag key (ZSK) is
    # not a secure entry point in common operator practice, so no DS is useful.
    # (SEP is advisory, so a ZSK *could* be secured by a DS in the parent; if
    # ever needed, its DS is easy to derive separately from the DNSKEY.)
    ds = (dns.dnssec.make_ds(ZONE, dnskey_rdata, algorithm=2)
          if CONFIG.flags & SEP else None)
    if ds is not None:
        print("### DS record")
        print(ds)

    if CONFIG.keydir:
        BASENAME = write_key_triple(CONFIG.keydir, ZONE, CONFIG.algorithm,
                                    keytag, PRIVATE_KEY, DNSKEY_RRSET, ds,
                                    prepublish=CONFIG.prepublish)
        PEM_SUFFIX = "prepublish.pem" if CONFIG.prepublish else "pem"
        FILES = f"{{{PEM_SUFFIX},dnskey,ds}}" if ds is not None \
            else f"{{{PEM_SUFFIX},dnskey}}"
        print('')
        print(f"### Wrote key files: {BASENAME}.{FILES}")
