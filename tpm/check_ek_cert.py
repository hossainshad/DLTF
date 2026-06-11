"""
tpm/check_ek_cert.py

Standalone diagnostic. Run on a target machine to find out which DLTF trust tier
it can reach. Reports whether the platform exposes a fetchable EK certificate and,
if a CA bundle is given, whether that certificate chains to it.

  EK cert present and chains to CA  -> Tier 1 HARDWARE      (rehab-eligible)
  no fetchable EK cert              -> Tier 2 TPM_RESIDENT   (activation only)

Requires tpm2-tools and runs machine-side; it is not part of the runnable
federation. AMD fTPMs commonly have no fetchable EK cert, which is expected.
"""
import sys
import argparse
import tempfile
import os

from tpm.common import run, verify_ek_certificate, sha256_hex

# EK certificate NV indices defined by the TCG EK credential profile.
EK_CERT_NV_INDICES = ["0x01C00002", "0x01C0000A"]


def fetch_ek_cert(tcti=None):
    suffix = (["-T", tcti] if tcti else [])
    out = os.path.join(tempfile.mkdtemp(prefix="dltf_ekcrt_"), "ek.crt")
    try:
        run(["tpm2_getekcertificate", "-o", out] + suffix)
        with open(out, "rb") as f:
            return f.read(), "tpm2_getekcertificate"
    except Exception:
        pass
    for nv in EK_CERT_NV_INDICES:
        try:
            data = run(["tpm2_nvread", nv] + suffix)
            if data:
                return data, f"nvread {nv}"
        except Exception:
            continue
    return None, None


def main(argv=None):
    ap = argparse.ArgumentParser(description="DLTF EK certificate / trust-tier diagnostic")
    ap.add_argument("--tcti", default=None, help="e.g. device:/dev/tpmrm0 or swtpm:...")
    ap.add_argument("--ca-bundle", default=None, help="manufacturer CA bundle (PEM) to verify against")
    args = ap.parse_args(argv)

    cert, source = fetch_ek_cert(args.tcti)
    if cert is None:
        print("EK certificate: NOT FOUND")
        print("Predicted tier: Tier 2 TPM_RESIDENT (credential activation only)")
        print("This is expected on many AMD fTPMs. Hardware-rooted bans are not")
        print("available on this platform; the device runs at weight cap 0.5.")
        return 2

    print(f"EK certificate: FOUND via {source} ({len(cert)} bytes)")
    print(f"EK cert sha256: {sha256_hex(cert)}")
    if args.ca_bundle:
        with open(args.ca_bundle, "rb") as f:
            bundle = f.read()
        if verify_ek_certificate(cert, bundle):
            print("Chain verification: PASS")
            print("Predicted tier: Tier 1 HARDWARE (rehabilitation-eligible)")
            return 0
        print("Chain verification: FAIL (cert does not chain to the given CA)")
        print("Predicted tier: Tier 2 TPM_RESIDENT")
        return 1
    print("No CA bundle supplied; pass --ca-bundle to confirm Tier 1 eligibility.")
    return 0


if __name__ == "__main__":
    sys.exit(main())