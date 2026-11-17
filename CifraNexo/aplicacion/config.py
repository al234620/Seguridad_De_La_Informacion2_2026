
import os
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def _ruta(var, defecto):
    return Path(os.environ.get(var, RAIZ / defecto))


def configuracion_por_defecto():
    secretos = _ruta("TIENDA_SECRETOS", "secretos")
    return {
        "RAIZ": RAIZ,
        "DB_PATH": _ruta("TIENDA_DB", "base_de_datos/tienda.db"),
        "SCHEMA_PATH": RAIZ / "base_de_datos" / "schema.sql",
        "PRODUCTS_DIR": _ruta("TIENDA_PRODUCTOS", "productos"),
        "SECRETS_DIR": secretos,
        # Clave privada de firma de comprobantes (PEM, permisos 600).
        "SIGNING_KEY_PATH": secretos / "firma_privada.pem",
        "SIGNING_KEY_PASSPHRASE": os.environ.get("TIENDA_FIRMA_PASSPHRASE"),
        # Clave pública: SÍ se distribuye.
        "PUBLIC_KEY_PATH": _ruta("TIENDA_CLAVE_PUBLICA", "claves_publicas/firma_publica.pem"),
        # AES-256-GCM para archivos de producto en reposo.
        "DATA_KEY_PATH": secretos / "clave_datos.key",
        # HMAC-SHA256 para autenticar los fingerprints.
        "FP_KEY_PATH": secretos / "clave_huella.key",
        # Clave de la cookie firmada de Flask (solo token CSRF).
        "FLASK_KEY_PATH": secretos / "clave_flask.key",
        # Buzón simulado para correos de recuperación.
        "OUTBOX_DIR": _ruta("TIENDA_BUZON", "buzon"),
        "LOG_PATH": _ruta("TIENDA_LOG", "logs/seguridad.log"),
        # TLS
        "TLS_CERT": _ruta("TIENDA_CERT", "certificados/servidor.crt"),
        "TLS_KEY": _ruta("TIENDA_CERT_KEY", "certificados/servidor.key"),
        "MAX_CONTENT_LENGTH": 20 * 1024 * 1024,  # 20 MB por archivo subido
        "SESSION_COOKIE_NAME": "csrf_s",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "AUTH_COOKIE": "sid",
        "TESTING": False,
    }
