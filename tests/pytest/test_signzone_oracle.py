"""Independent-oracle checks for adns.signer: BIND dnssec-verify and byte-for-
byte determinism. Skipped gracefully where BIND is unavailable."""
import inspect
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

pytestmark = pytest.mark.signer

# `-m adns.signer` is a package import that a subprocess cannot resolve on its
# own -- this process's sys.path.insert(0, REPO_ROOT) above does not propagate
# to a child. Put the repo root on the child's PYTHONPATH explicitly (Task 8
# pattern).
SUBPROCESS_ENV = {**os.environ,
                  "PYTHONPATH": REPO_ROOT + os.pathsep +
                  os.environ.get("PYTHONPATH", "")}


def _deterministic_ecdsa_supported():
    """
    Byte-identical signing needs deterministic ECDSA (RFC 6979): cryptography
    >= 43.0.0 implements it, and dnspython (>= 2.6.0) must request it via the
    'deterministic' kwarg to dns.dnssec.sign. Without both, ECDSA picks a random
    k per signature and two signing runs of the same zone differ, so the
    determinism assertion cannot hold. The fixtures use ECDSAP256SHA256 (alg 13).
    """
    import cryptography  # pylint: disable=import-outside-toplevel
    import dns.dnssec    # pylint: disable=import-outside-toplevel
    ver = tuple(int(x) for x in cryptography.__version__.split(".")[:2])
    if ver < (43, 0):
        return False
    return "deterministic" in inspect.signature(dns.dnssec.sign).parameters


DETERMINISTIC_ECDSA = _deterministic_ecdsa_supported()

ZONE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_zones")

# (zone name, fixture subdir) for each fixture. The nsec/nsec3 fixtures use a
# single CSK; the nsec3 fixture carries an apex NSEC3PARAM that switches modes.
# The 2key fixture is the real BIND KSK(257)/ZSK(256) split (NSEC3 + salt +
# iterations) -- verified WITHOUT -z, the production two-key shape.
FIXTURES = [
    ("signer-nsec.test", "signer-nsec.test", True),
    ("signer-nsec3.test", "signer-nsec3.test", True),
    ("signer-2key.test", "signer-2key.test", False),
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
    cmd = [sys.executable, "-m", "adns.signer", zone_name, f"{subdir}/zonefile",
           "-K", subdir, "-o", out, *extra]
    res = subprocess.run(cmd, cwd=str(tmp_path), env=SUBPROCESS_ENV,
                         capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    return out


@pytest.mark.skipif(not os.path.exists(DNSSEC_VERIFY),
                    reason="BIND dnssec-verify not installed")
@pytest.mark.parametrize("zone_name,subdir,single_csk", FIXTURES)
def test_dnssec_verify_accepts_signed_zone(tmp_path, zone_name, subdir,
                                           single_csk):
    signed = _run_signzone(tmp_path, zone_name, subdir)
    # -z (single-CSK fixtures only): a CSK (SEP+ZONE bits) signs both the
    # DNSKEY RRset and everything else; without -z, dnssec-verify assumes the
    # classic KSK/ZSK split and reports "Missing ZSK". The 2key fixture is a
    # genuine KSK/ZSK split, so it is verified WITHOUT -z -- the stricter,
    # production two-key check.
    cmd = [DNSSEC_VERIFY]
    if single_csk:
        cmd.append("-z")
    cmd += ["-o", zone_name, signed]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.skipif(not DETERMINISTIC_ECDSA,
                    reason="deterministic ECDSA unavailable (needs cryptography "
                           ">= 43.0.0 and dnspython >= 2.6.0)")
@pytest.mark.parametrize("zone_name,subdir,single_csk", FIXTURES)
def test_determinism_byte_identical(tmp_path, zone_name, subdir,
                                    single_csk):  # pylint: disable=unused-argument
    # single_csk is unused here (determinism is key-role-independent) but the
    # parametrize tuple is shared with the verify test.
    # Fixed absolute inception/expiration + -j 0 => byte-identical output.
    a = _run_signzone(tmp_path / "a", zone_name, subdir,
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    b = _run_signzone(tmp_path / "b", zone_name, subdir,
                      extra=["-i", "20240101000000", "-e", "20240201000000",
                             "-j", "0"])
    with open(a, "rb") as fa, open(b, "rb") as fb:
        assert fa.read() == fb.read()
