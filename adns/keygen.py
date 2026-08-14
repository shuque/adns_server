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
from cryptography.hazmat.primitives.asymmetric import rsa
from dns.rdtypes.dnskeybase import SEP

from adns.crypto import key_basename


ECDSA_CURVE = ec.SECP256R1()
RSA_BITS_FLOOR = 1280
RSA_BITS_DEFAULT = 1280
RSA_PUBLIC_EXPONENT = 65537
PROTOCOL = 3
TTL = 7200


def process_arguments():
    """Process command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument("zone", help="DNS zone name")
    parser.add_argument("-a", type=int, dest='algorithm', metavar='N',
                        default=13,
                        choices=[8, 13, 15],
                        help="DNSSEC algorithm number: 8 (RSASHA256), "
                             "13 (ECDSAP256SHA256), 15 (ED25519) "
                             "(default: %(default)d)")
    parser.add_argument("-b", "--bits", type=int, metavar='N',
                        default=RSA_BITS_DEFAULT,
                        help="RSA key size in bits for algorithm 8; ignored "
                             f"for 13/15 (default: %(default)d, "
                             f"minimum: {RSA_BITS_FLOOR})")
    parser.add_argument("-f", type=int, dest='flags', metavar='N',
                        default=257,
                        help="Value of DNSKEY flags field (default: %(default)d)")
    parser.add_argument("-K", "--keydir", metavar='DIR', default=None,
                        help="write keytag-named .pem/.dnskey/.ds triple here")
    parser.add_argument("--prepublish", action="store_true",
                        help="write the private key as .prepublish.pem so the "
                             "DNSKEY can be pre-published while signzone "
                             "ignores it until it is renamed to .pem (requires "
                             "-K)")
    return parser.parse_args()


def generate_key(algorithm, bits=RSA_BITS_DEFAULT):
    """
    Generate DNSSEC key for given algorithm.

    For algorithm 8 (RSASHA256), bits sets the RSA modulus size (minimum
    RSA_BITS_FLOOR); bits is ignored for 13/15, which have fixed key sizes.
    """
    if algorithm == 8:
        if bits < RSA_BITS_FLOOR:
            raise ValueError(
                f"RSA key size {bits} below minimum {RSA_BITS_FLOOR} bits")
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT, key_size=bits)
    elif algorithm == 13:
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


def write_key_triple(keydir, zone, algorithm, keytag, private_key,  # pylint: disable=too-many-positional-arguments
                     dnskey_rrset, ds_rr, prepublish=False):
    """
    Write <basename>.pem/.dnskey into keydir, plus <basename>.ds when ds_rr is
    not None. zone is a dns.name.Name.

    The .ds file is written only for SEP keys (KSK/CSK); a ZSK is passed
    ds_rr=None and gets no DS file, since it is not a secure entry point in
    common operator practice.

    When prepublish is true the private key is written as
    <basename>.prepublish.pem instead of <basename>.pem, so signzone's
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


def main():
    """CLI entry point."""

    config = process_arguments()
    if config.prepublish and not config.keydir:
        raise SystemExit("adnskeygen: --prepublish requires -K/--keydir")
    zone = dns.name.from_text(config.zone)

    try:
        private_key, public_key = generate_key(config.algorithm, config.bits)
    except ValueError as exc:
        raise SystemExit(f"adnskeygen: {exc}") from exc
    print("### Private Key file contents:")
    print(pem_data_for_private_key(private_key))

    dnskey_rdata = dns.dnssec.make_dnskey(public_key,
                                          config.algorithm,
                                          config.flags,
                                          PROTOCOL)
    print("### DNSKEY RDATA:")
    print(dnskey_rdata)
    keytag = dns.dnssec.key_id(dnskey_rdata)
    print("### DNSKEY keytag:", keytag)
    print('')

    dnskey_rrset = build_dnskey_rrset(zone, dnskey_rdata)
    print("### DNSKEY RRset:")
    print(dnskey_rrset)
    print('')

    # DS is only emitted for SEP keys (KSK/CSK): a plain ZONE-flag key (ZSK) is
    # not a secure entry point in common operator practice, so no DS is useful.
    # (SEP is advisory, so a ZSK *could* be secured by a DS in the parent; if
    # ever needed, its DS is easy to derive separately from the DNSKEY.)
    ds = (dns.dnssec.make_ds(zone, dnskey_rdata, algorithm=2)
          if config.flags & SEP else None)
    if ds is not None:
        print("### DS record")
        print(ds)

    if config.keydir:
        basename = write_key_triple(config.keydir, zone, config.algorithm,
                                    keytag, private_key, dnskey_rrset, ds,
                                    prepublish=config.prepublish)
        pem_suffix = "prepublish.pem" if config.prepublish else "pem"
        files = f"{{{pem_suffix},dnskey,ds}}" if ds is not None \
            else f"{{{pem_suffix},dnskey}}"
        print('')
        print(f"### Wrote key files: {basename}.{files}")


if __name__ == '__main__':
    main()
