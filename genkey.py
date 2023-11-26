#!/usr/bin/env python3
#

"""
Generate DNSSEC keys and corresponding DNSKEY record data for use with
online DNSSEC signing.
"""

import argparse
import dns.name
import dns.dnssec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519


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


if __name__ == '__main__':

    CONFIG = process_arguments()
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
    print("### DNSKEY keytag:", dns.dnssec.key_id(dnskey_rdata))
    print('')

    dnskey_rrset = dns.rrset.RRset(ZONE,
                                   dns.rdataclass.IN,
                                   dns.rdatatype.DNSKEY)
    dnskey_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN,
                                            dns.rdatatype.DNSKEY,
                                            ttl=TTL)
    dnskey_rdataset.add(dnskey_rdata)
    dnskey_rrset.update(dnskey_rdataset)
    print("### DNSKEY RRset:")
    print(dnskey_rrset)
    print('')

    ds = dns.dnssec.make_ds(ZONE, dnskey_rdata, algorithm=2)
    print("### DS record")
    print(ds)
