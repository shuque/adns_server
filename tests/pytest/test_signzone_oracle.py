"""Independent-oracle checks for signzone.py: BIND dnssec-verify and byte-for-
byte determinism. Skipped gracefully where BIND is unavailable."""
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

pytestmark = pytest.mark.signer

SIGNZONE = os.path.join(REPO_ROOT, "signzone.py")
ZONE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_zones")

# (zone name, fixture subdir) for the NSEC and NSEC3 fixtures. Both use a
# single CSK; the NSEC3 fixture carries an apex NSEC3PARAM that switches modes.
FIXTURES = [
    ("signer-nsec.test", "signer-nsec.test"),
    ("signer-nsec3.test", "signer-nsec3.test"),
]

DNSSEC_VERIFY = shutil.which("dnssec-verify") or "/opt/homebrew/bin/dnssec-verify"


def _run_signzone(tmp_path, zone_name, subdir, extra=()):
    """Copy the fixture into tmp_path, sign it there, return the .signed path."""
    os.makedirs(str(tmp_path), exist_ok=True)
    work = tmp_path / subdir
    shutil.copytree(os.path.join(ZONE_DIR, subdir), work)
    # $INCLUDE in the zonefile is '<subdir>/dnskey.txt' relative to cwd, so run
    # from tmp_path with the same layout.
    out = str(work / "zonefile.signed")
    cmd = [sys.executable, SIGNZONE, zone_name, f"{subdir}/zonefile",
           "-K", subdir, "-o", out, *extra]
    res = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True,
                         text=True, check=False)
    assert res.returncode == 0, res.stderr
    return out


@pytest.mark.skipif(not os.path.exists(DNSSEC_VERIFY),
                    reason="BIND dnssec-verify not installed")
@pytest.mark.parametrize("zone_name,subdir", FIXTURES)
def test_dnssec_verify_accepts_signed_zone(tmp_path, zone_name, subdir):
    signed = _run_signzone(tmp_path, zone_name, subdir)
    # -z: the fixtures use a single CSK (SEP+ZONE bits set) that signs both
    # the DNSKEY RRset and everything else. Without -z, dnssec-verify assumes
    # the classic KSK/ZSK split and reports "Missing ZSK"; -z is BIND's
    # documented way to accept a single key serving both roles.
    res = subprocess.run([DNSSEC_VERIFY, "-z", "-o", zone_name, signed],
                         capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("zone_name,subdir", FIXTURES)
def test_determinism_byte_identical(tmp_path, zone_name, subdir):
    # Fixed absolute inception/expiration + -j 0 => byte-identical output.
    a = _run_signzone(tmp_path / "a", zone_name, subdir,
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    b = _run_signzone(tmp_path / "b", zone_name, subdir,
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    with open(a, "rb") as fa, open(b, "rb") as fb:
        assert fa.read() == fb.read()
