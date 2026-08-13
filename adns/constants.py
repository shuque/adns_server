"""
Wire-level constants: RR type codes, EDNS flags, and Extended DNS Error codes.

Leaf module -- imports only stdlib and dnspython, never other adns.* modules,
so it can be imported anywhere without cycles.
"""

import enum

import dns.rdatatype


class RRtype(enum.IntEnum):
    """Resource Record types"""
    NXNAME = 128
    DELEG = 61440
    DELEGPARAM = 65433

## RR types that are authoritative in the parent zone
AUTH_IN_PARENT_RRTYPES = [dns.rdatatype.DS, RRtype.DELEG]


class EdnsFlag(enum.IntFlag):
    """EDNS Header Flags"""
    DNSSEC_OK = 0x8000
    COMPACT_OK = 0x4000
    DELEG_EXT_OK = 0x2000             # EDNS(0) DE flag (delext-08 5.1, bit 2)

class EDECode(enum.IntEnum):
    """Extended DNS Error Codes"""
    INVALID_QTYPE = 30
    # IANA-allocated INFO-CODE 34 (deleg-10 5.2.2.1)
    NEW_DELEGATION_ONLY = 34
