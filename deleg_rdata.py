#!/usr/bin/env python3
#

"""
Generate a DELEG or DELEGPARAM resource record in RFC 3597 generic ("\\#")
presentation format from a set of DelegInfo key=value pairs.

The RDATA format is the DelegInfos list defined in draft-ietf-deleg Section 3,
which reuses the SvcParams wire encoding of SVCB [RFC9460] Section 2.2: a
sequence of (key, length, value) triples in strictly increasing key order with
no duplicate keys.

Example:

    $ deleg_rdata.py child.example. server-ipv4=192.0.2.1 \\
                     server-ipv6=2001:db8::1
    child.example. IN TYPE61440 \\# 28 000100040102030100...

    $ deleg_rdata.py --type DELEGPARAM cfg.example. \\
                     server-name=ns1.example.,ns2.example.
    cfg.example. IN TYPE65433 \\# ...
"""

import sys
import argparse
import socket
import struct

import dns.name
import dns.exception


__version__ = '0.2.0'

# Record type codes (pre-standardization; agreed with collaborators).
RRTYPE = {
    "DELEG": 61440,
    "DELEGPARAM": 65433,
}

# DelegInfo key registry (draft-ietf-deleg Section 8.2.2).
KEY_BY_NAME = {
    "mandatory": 0,
    "server-ipv4": 1,
    "server-ipv6": 2,
    "server-name": 3,
    "include-delegparam": 4,
}
NAME_BY_KEY = {num: name for name, num in KEY_BY_NAME.items()}

# The server-information keys; exactly one "shape" of these is permitted in a
# single record (Section 3.4).
SERVER_INFO_KEYS = {1, 2, 3, 4}


class DelegError(Exception):
    """Error building a DELEG/DELEGPARAM record."""


def key_name_to_number(token):
    """Map a DelegInfoKey presentation token to its numeric value.

    Accepts a registered name (e.g. "server-ipv4") or the RFC 9460 unknown-key
    form "keyNNNNN".
    """
    if token in KEY_BY_NAME:
        return KEY_BY_NAME[token]
    if token.startswith("key"):
        try:
            num = int(token[3:])
        except ValueError as exc:
            raise DelegError(f"invalid key token: {token}") from exc
        if 0 <= num <= 65535:
            return num
        raise DelegError(f"key number out of range: {token}")
    raise DelegError(f"unknown DelegInfoKey: {token}")


def split_escaped_list(value):
    """Split a comma-separated DelegInfoValue, honoring RFC 9460 Appendix A
    value-list escaping: a backslash escapes the following character (so "\\,"
    is a literal comma, not a separator)."""
    items = []
    current = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            current.append(char)
            current.append(value[i + 1])
            i += 2
            continue
        if char == ",":
            items.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    items.append("".join(current))
    return items


def encode_ipv4(value):
    """Encode server-ipv4: comma-separated IPv4 addresses -> 4 bytes each."""
    out = b""
    for addr in split_escaped_list(value):
        try:
            out += socket.inet_pton(socket.AF_INET, addr)
        except OSError as exc:
            raise DelegError(f"invalid IPv4 address: {addr}") from exc
    return out


def encode_ipv6(value):
    """Encode server-ipv6: comma-separated IPv6 addresses -> 16 bytes each."""
    out = b""
    for addr in split_escaped_list(value):
        try:
            out += socket.inet_pton(socket.AF_INET6, addr)
        except OSError as exc:
            raise DelegError(f"invalid IPv6 address: {addr}") from exc
    return out


def encode_names(value, origin):
    """Encode server-name / include-delegparam: comma-separated domain names
    as concatenated uncompressed wire-format names (Section 3.4)."""
    out = b""
    for name_text in split_escaped_list(value):
        try:
            name = dns.name.from_text(name_text, origin=origin)
        except dns.exception.DNSException as exc:
            raise DelegError(
                f"invalid domain name '{name_text}': {exc}") from exc
        out += name.to_wire()
    return out


def encode_mandatory(value):
    """Encode the mandatory key: comma-separated key tokens -> sequence of
    2-byte key numbers in strictly increasing order (Section 3.5)."""
    numbers = sorted({key_name_to_number(tok)
                      for tok in split_escaped_list(value)})
    return b"".join(struct.pack("!H", num) for num in numbers)


def encode_generic(value):
    """Encode an unknown key's value. The presentation value is treated as
    raw bytes with RFC 1035 char-string decimal escapes (\\DDD)."""
    out = bytearray()
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            nxt = value[i + 1:i + 4]
            if len(nxt) == 3 and nxt.isdigit():
                out.append(int(nxt))
                i += 4
                continue
            out.append(ord(value[i + 1]))
            i += 2
            continue
        out.append(ord(char))
        i += 1
    return bytes(out)


def encode_value(keynum, value, origin):
    """Encode a DelegInfoValue to wire bytes given its key number."""
    if keynum == 0:
        return encode_mandatory(value)
    if keynum == 1:
        return encode_ipv4(value)
    if keynum == 2:
        return encode_ipv6(value)
    if keynum in (3, 4):
        return encode_names(value, origin)
    return encode_generic(value)


def parse_pairs(args):
    """Parse "key=value" (and bare "key") CLI tokens into (keynum, name, value)
    tuples, preserving input order for error messages."""
    pairs = []
    for arg in args:
        if "=" in arg:
            name, value = arg.split("=", 1)
        else:
            name, value = arg, None
        keynum = key_name_to_number(name)
        pairs.append((keynum, name, value))
    return pairs


def build_deleginfos(pairs, origin):
    """Build the DelegInfos wire RDATA from parsed key=value pairs.

    Enforces the wire-format rules (no duplicate keys, strictly increasing key
    order). Returns the RDATA bytes.
    """
    seen = set()
    encoded = {}
    for keynum, name, value in pairs:
        if keynum in seen:
            raise DelegError(f"duplicate DelegInfoKey: {name}")
        seen.add(keynum)
        if value is None or value == "":
            # All keys defined in this document require a non-empty value.
            raise DelegError(f"key '{name}' requires a non-empty value")
        encoded[keynum] = encode_value(keynum, value, origin)

    rdata = b""
    for keynum in sorted(encoded):
        val = encoded[keynum]
        rdata += struct.pack("!HH", keynum, len(val)) + val
    return rdata


def check_semantics(pairs, strict):
    """Warn (or, with strict, error) on Section 3.4 / 3.5 semantic violations."""
    keynums = {keynum for keynum, _, _ in pairs}
    values = {keynum: value for keynum, _, value in pairs}
    problems = []

    # Section 3.4: exactly one server-information "shape" per record. The
    # allowed shapes are ipv4, ipv6, ipv4+ipv6, name, or include-delegparam.
    server_keys = keynums & SERVER_INFO_KEYS
    allowed_shapes = [{1}, {2}, {1, 2}, {3}, {4}]
    if server_keys and server_keys not in allowed_shapes:
        names = ", ".join(sorted(NAME_BY_KEY[k] for k in server_keys))
        problems.append(
            f"disallowed combination of server-information keys ({names}); "
            "a single record must carry exactly one of: server-ipv4, "
            "server-ipv6, server-ipv4+server-ipv6, server-name, or "
            "include-delegparam (Section 3.4)")

    # Section 3.5: every key named in "mandatory" must be present in the record.
    if 0 in keynums and values.get(0):
        for tok in split_escaped_list(values[0]):
            if key_name_to_number(tok) not in keynums:
                problems.append(
                    f"'mandatory' references key '{tok}' which is not present "
                    "in this record (Section 3.5)")

    for problem in problems:
        if strict:
            raise DelegError(problem)
        print(f"warning: {problem}", file=sys.stderr)


def format_rr(owner, rrtype_num, rdata, ttl=None):
    """Format the full RFC 3597 generic-format RR line."""
    ttl_field = f"{ttl} " if ttl is not None else ""
    hexdata = rdata.hex()
    return (f"{owner} {ttl_field}IN TYPE{rrtype_num} "
            f"\\# {len(rdata)} {hexdata}")


def _decode_names(value):
    """Decode concatenated uncompressed wire-format names into
    [(octets, name_text)] pairs."""
    out = []
    i = 0
    while i < len(value):
        start = i
        labels = []
        while True:
            if i >= len(value):
                # malformed; emit whatever remains as a raw chunk
                return out + [(value[start:], "<malformed>")]
            length = value[i]
            i += 1
            if length == 0:
                break
            labels.append(value[i:i + length].decode("latin-1"))
            i += length
        name = ".".join(labels) + "." if labels else "."
        out.append((value[start:i], name))
    return out


def _decode_addrs(value, family, size):
    """Decode concatenated fixed-size addresses into [(octets, text)] pairs."""
    out = []
    for i in range(0, len(value), size):
        chunk = value[i:i + size]
        try:
            text = socket.inet_ntop(family, chunk)
        except (OSError, ValueError):
            text = "<malformed>"
        out.append((chunk, text))
    return out


def _decode_mandatory(value):
    """Decode a mandatory value into a list of (number, name) key references."""
    out = []
    for i in range(0, len(value), 2):
        (num,) = struct.unpack_from("!H", value, i)
        out.append((num, NAME_BY_KEY.get(num, f"key{num}")))
    return out


def describe_rdata(rdata, out=sys.stderr):
    """Print an octet-level breakdown of DelegInfos RDATA to the given stream."""
    print(f"\nRDATA breakdown ({len(rdata)} octets):", file=out)
    i = 0
    while i + 4 <= len(rdata):
        keynum, vlen = struct.unpack_from("!HH", rdata, i)
        value = rdata[i + 4:i + 4 + vlen]
        name = NAME_BY_KEY.get(keynum, f"key{keynum}")
        print(f"  DelegInfo: {name} (key {keynum})", file=out)
        print(f"    key    [2] {rdata[i:i + 2].hex()}", file=out)
        print(f"    length [2] {rdata[i + 2:i + 4].hex()}  ({vlen})", file=out)
        print(f"    value [{vlen}] {value.hex()}", file=out)
        _describe_value(keynum, value, out)
        i += 4 + vlen


def _describe_value(keynum, value, out):
    """Print the decoded, per-element sub-breakdown of a DelegInfoValue."""
    if keynum == 0:
        refs = _decode_mandatory(value)
        pretty = ", ".join(f"{num} ({nm})" for num, nm in refs)
        print(f"             key numbers: {pretty}", file=out)
    elif keynum == 1:
        for chunk, text in _decode_addrs(value, socket.AF_INET, 4):
            print(f"               [{len(chunk)}] {chunk.hex()}  {text}",
                  file=out)
    elif keynum == 2:
        for chunk, text in _decode_addrs(value, socket.AF_INET6, 16):
            print(f"               [{len(chunk)}] {chunk.hex()}  {text}",
                  file=out)
    elif keynum in (3, 4):
        print("             wire names:", file=out)
        for chunk, text in _decode_names(value):
            print(f"               [{len(chunk)}] {chunk.hex()}  {text}",
                  file=out)
    else:
        # Unknown key: show the value as latin-1 text if printable.
        try:
            text = value.decode("ascii")
            if text.isprintable():
                print(f"             value text: {text}", file=out)
        except UnicodeDecodeError:
            pass


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


def rrtype_number(rrtype):
    """Resolve a --type argument to a numeric RR type code."""
    upper = rrtype.upper()
    if upper in RRTYPE:
        return RRTYPE[upper]
    try:
        num = int(rrtype)
    except ValueError as exc:
        raise DelegError(f"unknown record type: {rrtype}") from exc
    if 0 <= num <= 65535:
        return num
    raise DelegError(f"record type out of range: {rrtype}")


def main():
    """Entry point."""
    config = process_arguments()
    try:
        rrtype_num = rrtype_number(config.rrtype)
        owner = dns.name.from_text(config.owner)
        origin = (dns.name.from_text(config.origin)
                  if config.origin else dns.name.root)
        pairs = parse_pairs(config.pairs)
        check_semantics(pairs, config.strict)
        rdata = build_deleginfos(pairs, origin)
    except DelegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    print(format_rr(owner.to_text(), rrtype_num, rdata, ttl=config.ttl))
    if config.verbose:
        sys.stdout.flush()
        describe_rdata(rdata)


if __name__ == "__main__":
    main()
