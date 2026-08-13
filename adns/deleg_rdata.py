#!/usr/bin/env python3
#

"""
Generate a DELEG or DELEGPARAM resource record in RFC 3597 generic ("\\#")
presentation format from a set of DelegInfo key=value pairs.

Thin command-line front end over adns.deleg, which holds the DelegInfos wire
codec.

Example:

    $ deleg-rdata child.example. server-ipv4=192.0.2.1 \\
                  server-ipv6=2001:db8::1
    child.example. IN TYPE61440 \\# 28 000100040102030100...

    $ deleg-rdata --type DELEGPARAM cfg.example. \\
                  server-name=ns1.example.,ns2.example.
    cfg.example. IN TYPE65433 \\# ...
"""

import sys
import argparse

import dns.name

from adns import __version__
from adns import deleg


def process_arguments():
    """Process command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a DELEG/DELEGPARAM RR in RFC 3597 generic "
                    "format from DelegInfo key=value pairs.")
    parser.add_argument("owner", help="owner (domain) name of the record")
    parser.add_argument("pairs", nargs="*", metavar="key=value",
                        help="DelegInfo key=value pairs "
                             "(e.g. server-ipv4=192.0.2.1)")
    parser.add_argument("--type", dest="rrtype", default="DELEG",
                        help="record type: DELEG (default), DELEGPARAM, "
                             "or a numeric type code")
    parser.add_argument("--ttl", type=int, default=None,
                        help="TTL to include in the RR (default: omitted)")
    parser.add_argument("--origin", default=None,
                        help="origin for resolving relative names in "
                             "server-name/include-delegparam values "
                             "(default: root)")
    parser.add_argument("--strict", action="store_true",
                        help="treat Section 3.4/3.5 semantic violations as "
                             "errors instead of warnings")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print an octet-level breakdown of the RDATA "
                             "components to stderr")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser.parse_args()


def main():
    """Entry point."""
    config = process_arguments()
    try:
        rrtype_num = deleg.rrtype_number(config.rrtype)
        owner = dns.name.from_text(config.owner)
        origin = (dns.name.from_text(config.origin)
                  if config.origin else dns.name.root)
        pairs = deleg.parse_pairs(config.pairs)
        for problem in deleg.check_semantics(pairs, config.strict):
            print(f"warning: {problem}", file=sys.stderr)
        rdata = deleg.build_deleginfos(pairs, origin)
    except deleg.DelegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    print(deleg.format_rr(owner.to_text(), rrtype_num, rdata, ttl=config.ttl))
    if config.verbose:
        sys.stdout.flush()
        deleg.describe_rdata(rdata)


if __name__ == "__main__":
    main()
