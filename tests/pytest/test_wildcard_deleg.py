"""
Wildcard-DELEG hardening -- delext-10 4.4.

"A wildcard owner name MUST NOT have Delegation Types." Wildcard expansion
(RFC 4592) does not create delegation points, so a DELEG RRset at a '*' owner
is prohibited. The server enforces this at zone-load time (Zone method
reject_wildcard_deleg, gated on deleg_enabled) and aborts startup on violation.

These are pure unit tests of the invariant against in-memory zones -- no server
subprocess -- so they are fast and independent of the live-server fixtures.
"""

import os
import sys

import pytest

import dns.name
import dns.zone

# Import the server module from the repository root.
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
import adns_server as adns   # noqa: E402

pytestmark = pytest.mark.deleg

# A syntactically valid DELEG RRset in RFC 3597 generic format
# (include-delegparam=config1234.example.com.), reused from the test zonefile.
DELEG_GENERIC = ("TYPE61440 \\# 26 "
                 "00000a636f6e66696731323334076578616d706c6503636f6d00")


def _zone(records, deleg_enabled=True):
    """Build a Zone from apex boilerplate plus the given record lines."""
    text = ("$ORIGIN wild.test.\n"
            "$TTL 3600\n"
            "@ IN SOA ns hostmaster 1 43200 3600 3628800 3600\n"
            "@ IN NS ns\n"
            + "\n".join(records) + "\n")
    zone = dns.zone.from_text(text, origin="wild.test.",
                              zone_factory=adns.Zone, relativize=False)
    zone.deleg_enabled = deleg_enabled
    return zone


def test_wildcard_deleg_is_rejected():
    """A DELEG RRset at a '*' owner raises (delext-10 4.4)."""
    zone = _zone([f"*.sub IN {DELEG_GENERIC}"])
    with pytest.raises(ValueError, match="4.4"):
        zone.reject_wildcard_deleg()


def test_bare_wildcard_deleg_is_rejected():
    """The wildcard directly under the apex is also rejected."""
    zone = _zone([f"* IN {DELEG_GENERIC}"])
    with pytest.raises(ValueError, match="wildcard"):
        zone.reject_wildcard_deleg()


def test_non_wildcard_deleg_is_allowed():
    """A DELEG at an ordinary (non-wildcard) owner is fine."""
    zone = _zone([f"sub5 IN {DELEG_GENERIC}"])
    zone.reject_wildcard_deleg()   # must not raise


def test_wildcard_non_deleg_is_allowed():
    """A wildcard carrying ordinary data (not a Delegation Type) is fine."""
    zone = _zone(["*.ok IN A 192.0.2.1"])
    zone.reject_wildcard_deleg()   # must not raise


def test_star_not_leftmost_is_not_a_wildcard():
    """'*' that is not the leftmost label is a literal label, not a wildcard,
    so a DELEG below it is not prohibited by 4.4."""
    zone = _zone([f"x.*.sub IN {DELEG_GENERIC}"])
    zone.reject_wildcard_deleg()   # must not raise


# --------------------------------------------------------------------------
# Load-time wiring: make_single_zone() aborts on a wildcard-DELEG zone, but
# only when the zone is deleg_enabled.
# --------------------------------------------------------------------------

ZONE_TEXT = ("$ORIGIN wild.test.\n"
             "$TTL 3600\n"
             "@ IN SOA ns hostmaster 1 43200 3600 3628800 3600\n"
             "@ IN NS ns\n"
             f"*.sub IN {DELEG_GENERIC}\n")


def _write_zone(tmp_path):
    zonefile = tmp_path / "wild.test.zone"
    zonefile.write_text(ZONE_TEXT)
    return str(zonefile)


def test_load_aborts_on_wildcard_deleg(tmp_path):
    """A deleg_enabled zone with a wildcard DELEG aborts startup (SystemExit)."""
    prefs = adns.Preferences()
    config = {"file": _write_zone(tmp_path), "deleg_enabled": True}
    with pytest.raises(SystemExit):
        adns.make_single_zone(prefs, dns.name.from_text("wild.test."), config)


def test_load_allows_wildcard_deleg_when_not_deleg_enabled(tmp_path):
    """
    Without deleg_enabled the same TYPE61440 record is opaque data, 4.4 does
    not apply, and the zone loads without error.
    """
    prefs = adns.Preferences()
    config = {"file": _write_zone(tmp_path)}   # deleg_enabled defaults to False
    zone = adns.make_single_zone(prefs, dns.name.from_text("wild.test."),
                                 config)
    assert zone.deleg_enabled is False
