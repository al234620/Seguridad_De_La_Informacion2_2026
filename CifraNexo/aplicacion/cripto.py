
import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITMO_FIRMA = "RSA-PSS-SHA256-3072"
AAD_PRODUCTO = b"tienda-segura/producto/v1"


# ---------------------------------------------------------------- hashes
def sha256_bytes(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def sha256_archivo(ruta) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def hmac_sha256(clave: bytes, datos: bytes) -> str:
    return hmac.new(clave, datos, hashlib.sha256).hexdigest()


# --------------------------------------------------- claves simétricas
def generar_clave_simetrica(ruta: Path, n_bytes=32):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if ruta.exists():
        return
    ruta.write_bytes(secrets.token_bytes(n_bytes))
    os.chmod(ruta, 0o600)


def leer_clave(ruta) -> bytes:
    datos = Path(ruta).read_bytes()
    if len(datos) < 32:
        raise ValueError(f"Clave demasiado corta: {ruta}")
    return datos


# ------------------------------------------------------------ AES-GCM
def cifrar(datos: bytes, clave: bytes, aad: bytes = AAD_PRODUCTO) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(clave).encrypt(nonce, datos, aad)


def descifrar(blob: bytes, clave: bytes, aad: bytes = AAD_PRODUCTO) -> bytes:
    """Lanza ValueError si el archivo fue alterado (etiqueta GCM inválida)."""
    try:
        return AESGCM(clave).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as e:
        raise ValueError("Archivo cifrado alterado o clave incorrecta") from e


# ------------------------------------------------------- firma digital
def generar_par_firma(ruta_priv: Path, ruta_pub: Path, passphrase: str | None = None):
    ruta_priv.parent.mkdir(parents=True, exist_ok=True)
    ruta_pub.parent.mkdir(parents=True, exist_ok=True)
    if ruta_priv.exists():
        return
    clave = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cifrado = (serialization.BestAvailableEncryption(passphrase.encode())
               if passphrase else serialization.NoEncryption())
    ruta_priv.write_bytes(clave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, cifrado))
    os.chmod(ruta_priv, 0o600)
    ruta_pub.write_bytes(clave.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _cargar_privada(ruta, passphrase=None):
    return serialization.load_pem_private_key(
        Path(ruta).read_bytes(), password=passphrase.encode() if passphrase else None)


def id_clave_publica(pem: bytes) -> str:
    return sha256_bytes(pem)[:16]


def canonico(obj) -> bytes:
    """Serialización determinista: misma entrada -> mismos bytes -> mismo hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def firmar(datos: bytes, ruta_priv, passphrase=None) -> str:
    clave = _cargar_privada(ruta_priv, passphrase)
    firma = clave.sign(
        datos,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return base64.b64encode(firma).decode()


def verificar_firma(datos: bytes, firma_b64: str, pem_publica: bytes) -> bool:
    try:
        publica = serialization.load_pem_public_key(pem_publica)
        publica.verify(
            base64.b64decode(firma_b64, validate=True),
            datos,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
