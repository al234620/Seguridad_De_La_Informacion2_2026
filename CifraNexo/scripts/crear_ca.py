
import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parent.parent


def _clave(path: Path, key):
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    if os.name != 'nt':
        path.chmod(0o600)


def _cert(path: Path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _nombre(nombre):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'MX'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Proyecto Tienda Segura'),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
    ])


def crear(destino: Path, ips=(), renovar_ca=False):
    destino.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key_file, ca_cert_file = destino / 'ca.key', destino / 'ca.crt'
    if renovar_ca and (ca_key_file.exists() or ca_cert_file.exists()):
        raise ValueError('No se renueva una CA existente automaticamente. Haz copia segura y retira los archivos manualmente.')
    if ca_key_file.exists() != ca_cert_file.exists():
        raise ValueError('Falta uno de los archivos ca.key / ca.crt. No se sustituye una CA incompleta.')
    if not ca_key_file.exists():
        ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = _nombre('Tienda Segura CA Raiz')
        ca_cert = (x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name).public_key(ca_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_priv.public_key()), critical=False)
            .sign(ca_priv, hashes.SHA256()))
        _clave(ca_key_file, ca_priv)
        _cert(ca_cert_file, ca_cert)
    else:
        ca_priv = serialization.load_pem_private_key(ca_key_file.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read_bytes())
        if ca_priv.public_key().public_numbers() != ca_cert.public_key().public_numbers():
            raise ValueError('La clave de la CA no corresponde al certificado')

    san = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
    for ip in ips:
        item = x509.IPAddress(ipaddress.ip_address(ip))
        if item not in san:
            san.append(item)
    privada = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    certificado = (x509.CertificateBuilder()
        .subject_name(_nombre('localhost')).issuer_name(ca_cert.subject)
        .public_key(privada.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_priv.public_key()), critical=False)
        .sign(ca_priv, hashes.SHA256()))
    _clave(destino / 'servidor.key', privada)
    _cert(destino / 'servidor.crt', certificado)

    atacante = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    atacante_nombre = _nombre('Certificado NO confiable')
    falso = (x509.CertificateBuilder().subject_name(atacante_nombre).issuer_name(atacante_nombre)
        .public_key(atacante.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(atacante, hashes.SHA256()))
    _clave(destino / 'no_confiable.key', atacante)
    _cert(destino / 'no_confiable.crt', falso)
    print(f'CA: {ca_cert_file}')
    print(f'Certificado servidor: {destino / "servidor.crt"}')
    print('Nombres y direcciones SAN:', ', '.join(str(x.value) for x in san))
    print('OK: certificado del servidor firmado por la CA local.')
    return destino


def main():
    p = argparse.ArgumentParser(description='Crear CA local y certificado HTTPS para Windows/Tailscale')
    p.add_argument('--ip', action='append', default=[], help='IP actual Tailscale o LAN; se puede repetir')
    p.add_argument('--destino', type=Path, default=RAIZ / 'certificados')
    a = p.parse_args()
    crear(a.destino, a.ip)


if __name__ == '__main__':
    main()
