"""
Certificate Authority (CA) generator for DLP Proxy MITM interception.
Generates a self-signed CA cert that clients must trust.
"""

import os
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger("server.certs")


CERT_DIR = Path("certs")
CA_KEY_FILE = CERT_DIR / "ca.key"
CA_CERT_FILE = CERT_DIR / "ca.crt"
CA_CERT_DER_FILE = CERT_DIR / "ca.der"  # For Windows import
MITM_CA_PEM_FILE = CERT_DIR / "mitmproxy-ca.pem"
MITM_CA_CERT_PEM_FILE = CERT_DIR / "mitmproxy-ca-cert.pem"
MITM_CA_CERT_CER_FILE = CERT_DIR / "mitmproxy-ca-cert.cer"


def _write_mitmproxy_compat_files(cert_pem: bytes, cert_der: bytes, key_pem: bytes) -> None:
    """Expose our CA in filenames expected by mitmproxy's confdir."""
    MITM_CA_PEM_FILE.write_bytes(cert_pem + key_pem)
    MITM_CA_CERT_PEM_FILE.write_bytes(cert_pem)
    MITM_CA_CERT_CER_FILE.write_bytes(cert_der)


def generate_ca_certificate(
    common_name: str = "DLP Proxy CA",
    org_name: str = "DLP Security",
    validity_days: int = 3650,
    force_regenerate: bool = False,
) -> tuple[Path, Path]:
    """
    Generate a self-signed CA certificate and private key.

    Returns:
        Tuple of (cert_path, key_path)
    """
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CA_CERT_FILE.exists() and CA_KEY_FILE.exists() and not force_regenerate:
        cert_pem = CA_CERT_FILE.read_bytes()
        cert_der = CA_CERT_DER_FILE.read_bytes() if CA_CERT_DER_FILE.exists() else b""
        key_pem = CA_KEY_FILE.read_bytes()
        if not cert_der:
            cert = x509.load_pem_x509_certificate(cert_pem)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            CA_CERT_DER_FILE.write_bytes(cert_der)
        _write_mitmproxy_compat_files(cert_pem, cert_der, key_pem)
        logger.info(f"[CertGen] Найдены существующие сертификаты в {CERT_DIR}, пропускаем генерацию")
        return CA_CERT_FILE, CA_KEY_FILE

    logger.info("[CertGen] Генерация нового CA сертификата...")

    # ── Generate private key ──────────────────────────────────────────────────
    logger.debug("[CertGen] Генерация RSA-2048 ключа...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ── Build certificate ─────────────────────────────────────────────────────
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # ── Save private key ──────────────────────────────────────────────────────
    with open(CA_KEY_FILE, "wb") as f:
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        f.write(key_pem)
    logger.info(f"[CertGen] Приватный ключ сохранён: {CA_KEY_FILE}")

    # ── Save cert in PEM format ───────────────────────────────────────────────
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert_pem)
    logger.info(f"[CertGen] PEM сертификат сохранён: {CA_CERT_FILE}")

    # ── Save cert in DER format (for Windows certutil import) ─────────────────
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    with open(CA_CERT_DER_FILE, "wb") as f:
        f.write(cert_der)
    logger.info(f"[CertGen] DER сертификат сохранён: {CA_CERT_DER_FILE}")
    _write_mitmproxy_compat_files(cert_pem, cert_der, key_pem)

    logger.info(
        f"[CertGen] CA сертификат успешно создан. "
        f"CN={common_name}, срок={validity_days} дней"
    )
    return CA_CERT_FILE, CA_KEY_FILE


def get_cert_info() -> dict:
    """Return info about current CA certificate"""
    if not CA_CERT_FILE.exists():
        return {"exists": False}

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(CA_CERT_FILE, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    return {
        "exists": True,
        "subject": cert.subject.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
        "cert_file": str(CA_CERT_FILE.absolute()),
        "der_file": str(CA_CERT_DER_FILE.absolute()),
    }
