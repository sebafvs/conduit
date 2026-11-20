from __future__ import annotations

import datetime
import ipaddress
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import CaSource, Config, Leaf, LeafSource


def _build_ca_name(cfg: Config) -> x509.Name:
    s = cfg.pki.ca.subject
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, s.CN)]
    if s.O:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, s.O))
    if s.OU:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, s.OU))
    if s.C:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, s.C))
    if s.ST:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s.ST))
    if s.L:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, s.L))
    return x509.Name(attrs)


def _generate_ca(cfg: Config) -> tuple[bytes, bytes]:
    """Build a new self-signed CA. Returns (cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=cfg.pki.ca.key_size)
    name = _build_ca_name(cfg)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=cfg.pki.ca.validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _load_ca(cert_path: Path, key_path: Path) -> tuple[bytes, bytes]:
    return cert_path.read_bytes(), key_path.read_bytes()


def _resolve_ca(cfg: Config) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) based on pki.ca.source."""
    if cfg.pki.ca.source == CaSource.generate:
        return _generate_ca(cfg)
    if cfg.pki.ca.source == CaSource.shared:
        shared = cfg.pki.ca.shared_path
        if shared is None:
            raise ValueError("pki.ca.source=shared requires shared_path")
        return _load_ca(shared / "ca.crt", shared / "ca.key")
    if cfg.pki.ca.source == CaSource.import_:
        if cfg.pki.ca.import_cert is None or cfg.pki.ca.import_key is None:
            raise ValueError("pki.ca.source=import requires import_cert and import_key")
        return _load_ca(cfg.pki.ca.import_cert, cfg.pki.ca.import_key)
    raise ValueError(f"unknown CA source: {cfg.pki.ca.source}")


def _sign_leaf(ca_cert_pem: bytes, ca_key_pem: bytes, leaf: Leaf) -> tuple[bytes, bytes]:
    """Build a leaf cert signed by the given CA. Returns (cert_pem, key_pem)."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf.cn)])

    sans: list[x509.GeneralName] = []
    for dns in leaf.sans_dns:
        sans.append(x509.DNSName(dns))
    for ip in leaf.sans_ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(str(ip))))

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=leaf.validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_pki(cfg: Config, certs_dir: Path) -> list[Path]:
    """Materialize CA + every leaf into certs_dir. Returns written paths."""
    written: list[Path] = []
    certs_dir.mkdir(parents=True, exist_ok=True)

    ca_cert_pem, ca_key_pem = _resolve_ca(cfg)
    ca_cert_path = certs_dir / "ca.crt"
    ca_key_path = certs_dir / "ca.key"
    ca_cert_path.write_bytes(ca_cert_pem)
    ca_key_path.write_bytes(ca_key_pem)
    ca_key_path.chmod(0o600)
    written.extend([ca_cert_path, ca_key_path])

    leaves_dir = certs_dir / "leaves"
    leaves_dir.mkdir(exist_ok=True)

    for leaf in cfg.pki.leaves:
        crt_path = leaves_dir / f"{leaf.name}.crt"
        key_path = leaves_dir / f"{leaf.name}.key"
        chain_path = leaves_dir / f"{leaf.name}.chain.crt"

        if leaf.source == LeafSource.ca_signed:
            cert_pem, key_pem = _sign_leaf(ca_cert_pem, ca_key_pem, leaf)
            crt_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)
            key_path.chmod(0o600)
            chain_path.write_bytes(cert_pem + ca_cert_pem)
            written.extend([crt_path, key_path, chain_path])

        elif leaf.source == LeafSource.byo:
            if leaf.byo_cert is None or leaf.byo_key is None:
                raise ValueError(f"leaf '{leaf.name}' source=byo requires byo_cert and byo_key")
            shutil.copyfile(leaf.byo_cert, crt_path)
            shutil.copyfile(leaf.byo_key, key_path)
            key_path.chmod(0o600)
            if leaf.byo_chain:
                shutil.copyfile(leaf.byo_chain, chain_path)
                written.append(chain_path)
            written.extend([crt_path, key_path])

        elif leaf.source == LeafSource.letsencrypt:
            # Marker file only; actual cert is obtained by certbot at apply time
            # and dropped into leaves_dir/<name>.{crt,key,chain.crt} by the
            # apply phase.
            marker = leaves_dir / f"{leaf.name}.letsencrypt.pending"
            marker.write_text(
                f"domain={leaf.letsencrypt.domain if leaf.letsencrypt else ''}\n"
                f"email={leaf.letsencrypt.email if leaf.letsencrypt else ''}\n"
                f"challenge={leaf.letsencrypt.challenge if leaf.letsencrypt else 'http-01'}\n"
            )
            written.append(marker)

    return written
