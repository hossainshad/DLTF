"""
tpm/common.py

Canonical TPM-side primitives shared by client and server. This is the source of
the Tier enum the rest of DLTF couples policy to.

Key pieces:
  - Tier / assess_tier : the tiering policy. A verifiable EK certificate is the
    ONLY thing that earns Tier 1; credential activation alone earns Tier 2;
    nothing earns Tier 3. swtpm satisfies activation for free, so it cannot
    exceed Tier 2. This is the honest boundary of the security claim.
  - verify_ek_certificate : chain-verify an EK cert to a manufacturer CA. The one
    check that distinguishes real silicon from a software TPM.
  - make_credential : server-side MakeCredential. The real path shells to
    tpm2_makecredential -T none (software, no TPM needed server-side); the mock
    path seals a secret under a per-device key the MockTPMSigner re-derives, so
    the local federation runs without hardware.
  - generate_test_ca / issue_ek_cert : a TEST manufacturer CA so eval/ can mint
    Tier-1 mock devices and exercise the sanction-and-rehabilitation lifecycle
    locally. Real deployments verify against real manufacturer roots instead.
"""
from enum import IntEnum
from dataclasses import dataclass
import subprocess
import hashlib
import hmac
import base64
import os
import datetime


class Tier(IntEnum):
    HARDWARE = 1
    TPM_RESIDENT = 2
    SOFTWARE = 3


TIER_BASE_WEIGHT = {Tier.HARDWARE: 1.0, Tier.TPM_RESIDENT: 0.5, Tier.SOFTWARE: 0.1}

MOCK_TAG = b"DLTF-MOCK|"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def b64e(data):
    return base64.b64encode(data).decode()


def b64d(s):
    return base64.b64decode(s)


def run(cmd, **kw):
    """Run a command, raise on non-zero exit, return stdout bytes."""
    p = subprocess.run(cmd, capture_output=True, **kw)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, cmd))} failed: "
                           f"{p.stderr.decode(errors='replace')}")
    return p.stdout


@dataclass
class TrustAssessment:
    tier: Tier
    ek_cert_verified: bool
    activation_passed: bool
    reason: str


def assess_tier(ek_cert_verified, activation_passed):
    if ek_cert_verified and activation_passed:
        return TrustAssessment(Tier.HARDWARE, True, True,
                               "EK cert chains to manufacturer CA and credential activation passed")
    if activation_passed:
        return TrustAssessment(Tier.TPM_RESIDENT, False, True,
                               "credential activation passed but no verifiable EK certificate")
    return TrustAssessment(Tier.SOFTWARE, False, False, "no hardware proof (TOFU)")


# ---- mock credential sealing (dev only, no real confidentiality) -------------

def mock_key(device_label):
    return hashlib.sha256(MOCK_TAG + device_label.encode()).digest()


def mock_ek_hash(device_label):
    return sha256_hex(b"DLTF-MOCK-EK|" + device_label.encode())


def make_credential(backend, secret=None, device_label=None,
                    ek_pub_path=None, ak_name=None, out_dir=None):
    """Server-side MakeCredential. Returns (credential_blob_b64, secret_bytes)."""
    if secret is None:
        secret = os.urandom(16)
    if backend == "mock":
        nonce = os.urandom(16)
        ks = hmac.new(mock_key(device_label), nonce, hashlib.sha256).digest()[:len(secret)]
        ct = bytes(a ^ b for a, b in zip(secret, ks))
        return b64e(nonce + ct), secret
    # real / swtpm: software MakeCredential via tpm2-tools (-T none needs no TPM)
    out_dir = out_dir or "."
    secret_path = os.path.join(out_dir, "challenge.secret")
    blob_path = os.path.join(out_dir, "challenge.blob")
    with open(secret_path, "wb") as f:
        f.write(secret)
    run(["tpm2_makecredential", "-T", "none", "-e", ek_pub_path,
         "-s", secret_path, "-n", ak_name, "-o", blob_path])
    with open(blob_path, "rb") as f:
        return b64e(f.read()), secret


# ---- EK certificate chain verification ---------------------------------------

def _load_pem_chain(pem_bytes):
    from cryptography import x509
    certs, chunk = [], b""
    for line in pem_bytes.splitlines(keepends=True):
        chunk += line
        if b"-----END CERTIFICATE-----" in line:
            try:
                certs.append(x509.load_pem_x509_certificate(chunk))
            except Exception:
                pass
            chunk = b""
    return certs


def _sig_ok(issuer_pub, cert):
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
    from cryptography.exceptions import UnsupportedAlgorithm
    try:
        if isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
            return True
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            # Try the cert's declared padding first, then the other RSA padding.
            try:
                pad = padding.PKCS1v15()
                if cert.signature_algorithm_oid._name and "pss" in \
                        cert.signature_algorithm_oid._name.lower():
                    pad = padding.PSS(mgf=padding.MGF1(cert.signature_hash_algorithm),
                                      salt_length=padding.PSS.AUTO)
                issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                                  pad, cert.signature_hash_algorithm)
                return True
            except Exception:
                alt = padding.PSS(mgf=padding.MGF1(cert.signature_hash_algorithm),
                                  salt_length=padding.PSS.AUTO)
                issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                                  alt, cert.signature_hash_algorithm)
                return True
        return False
    except Exception:
        return False



def _verify_with_openssl(ek_cert_bytes, ca_bundle_pem):
    """Fallback for certs the strict Python parser rejects (e.g. AMD fTPM EK certs
    encode a non-spec critical=FALSE field). openssl is lenient and is the same
    engine that validates these in practice. Returns True/False/None(unavailable)."""
    import shutil, tempfile, os, subprocess
    if shutil.which("openssl") is None:
        return None
    d = tempfile.mkdtemp(prefix="dltf_ossl_")
    ek_in = os.path.join(d, "ek.in")
    ek_pem = os.path.join(d, "ek.pem")
    ca = os.path.join(d, "ca.pem")
    with open(ek_in, "wb") as f:
        f.write(ek_cert_bytes)
    with open(ca, "wb") as f:
        f.write(ca_bundle_pem)
    # normalise EK to PEM (input may be DER or PEM)
    if subprocess.run(["openssl", "x509", "-in", ek_in, "-inform", "DER",
                       "-out", ek_pem], capture_output=True).returncode != 0:
        if subprocess.run(["openssl", "x509", "-in", ek_in, "-inform", "PEM",
                           "-out", ek_pem], capture_output=True).returncode != 0:
            return None
    r = subprocess.run(["openssl", "verify", "-partial_chain",
                        "-CAfile", ca, ek_pem], capture_output=True)
    return r.returncode == 0


def verify_ek_certificate(ek_cert_bytes, ca_bundle_pem):
    """Chain-verify an EK certificate to a CA bundle. Returns True iff it verifies
    up to a self-signed root present in the bundle. Simplified path validation
    (name chaining plus signature check); real deployments add revocation."""
    from cryptography import x509
    cert = None
    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try:
            cert = loader(ek_cert_bytes)
            break
        except Exception:
            continue
    if cert is None:
        # AMD fTPM EK certs can be technically malformed (non-spec DEFAULT
        # encoding); the strict parser rejects them though they are valid.
        result = _verify_with_openssl(ek_cert_bytes, ca_bundle_pem)
        return bool(result) if result is not None else False
    by_subject = {c.subject.rfc4514_string(): c for c in _load_pem_chain(ca_bundle_pem)}
    seen, cur = set(), cert
    for _ in range(8):
        issuer = by_subject.get(cur.issuer.rfc4514_string())
        if issuer is None or not _sig_ok(issuer.public_key(), cur):
            break
        if issuer.subject.rfc4514_string() == issuer.issuer.rfc4514_string():
            if _sig_ok(issuer.public_key(), issuer):
                return True
            break
        if cur.issuer.rfc4514_string() in seen:
            break
        seen.add(cur.issuer.rfc4514_string())
        cur = issuer
    # Python walk failed; AMD certs often only validate via lenient openssl.
    result = _verify_with_openssl(ek_cert_bytes, ca_bundle_pem)
    return bool(result) if result is not None else False


# ---- test manufacturer CA (eval harness, not for deployment) -----------------

def generate_test_ca(name="DLTF Test Manufacturer CA"):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name_obj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name_obj).issuer_name(name_obj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_ek_cert(ca_key, ca_cert, device_label):
    """Mint a test EK certificate for device_label, signed by the test CA.
    Returns (cert_der_bytes, ek_hash_hex)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    ek_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"EK {device_label}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(ek_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    pub_der = ek_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return der, sha256_hex(pub_der)


def ca_bundle_pem(ca_cert):
    from cryptography.hazmat.primitives import serialization
    return ca_cert.public_bytes(serialization.Encoding.PEM)


def _self_test():
    print("tpm/common.py self-test")

    assert TIER_BASE_WEIGHT[Tier.HARDWARE] == 1.0
    a = assess_tier(True, True);   assert a.tier == Tier.HARDWARE
    b = assess_tier(False, True);  assert b.tier == Tier.TPM_RESIDENT
    c = assess_tier(False, False); assert c.tier == Tier.SOFTWARE
    print("✓ tiering policy: cert+activation=HW, activation=TPM_RESIDENT, none=SOFTWARE")

    # mock credential round-trip (server seals, client re-derives)
    blob, secret = make_credential("mock", device_label="client3")
    raw = b64d(blob); nonce, ct = raw[:16], raw[16:]
    ks = hmac.new(mock_key("client3"), nonce, hashlib.sha256).digest()[:len(ct)]
    recovered = bytes(x ^ y for x, y in zip(ct, ks))
    assert recovered == secret
    # wrong device cannot recover
    ks_bad = hmac.new(mock_key("attacker"), nonce, hashlib.sha256).digest()[:len(ct)]
    assert bytes(x ^ y for x, y in zip(ct, ks_bad)) != secret
    print("✓ mock credential: correct device recovers secret, wrong device fails")

    # real EK-cert chain verification with a generated test CA
    ca_key, ca_cert = generate_test_ca()
    ek_der, ek_hash = issue_ek_cert(ca_key, ca_cert, "client0")
    bundle = ca_bundle_pem(ca_cert)
    assert verify_ek_certificate(ek_der, bundle) is True
    assert len(ek_hash) == 64
    print("✓ EK cert issued by test CA verifies against its bundle")

    # a cert from a different CA must be rejected
    other_key, other_cert = generate_test_ca("Rogue CA")
    assert verify_ek_certificate(ek_der, ca_bundle_pem(other_cert)) is False
    print("✓ EK cert is rejected against an unrelated CA bundle")

    assert mock_ek_hash("x") == mock_ek_hash("x") and len(mock_ek_hash("x")) == 64
    print("✓ mock EK identity is stable per device label")
    print("✓ all common self-tests passed")


if __name__ == "__main__":
    _self_test()