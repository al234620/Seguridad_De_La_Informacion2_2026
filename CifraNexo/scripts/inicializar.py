
import argparse
import io
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from reportlab.lib.pagesizes import letter  # noqa: E402
from reportlab.pdfgen import canvas  # noqa: E402

from aplicacion import cripto  # noqa: E402
from aplicacion.config import configuracion_por_defecto  # noqa: E402
from aplicacion.db import ahora, conectar, crear_esquema  # noqa: E402

# Contraseñas SOLO para el ambiente de prueba (documentadas en el README).
USUARIOS_PRUEBA = [
    ("cliente@demo.local", "Cliente Demo", "CLIENTE", "ClienteSeguro2026"),
    ("cliente2@demo.local", "Segundo Cliente", "CLIENTE", "OtroCliente2026"),
    ("operador@demo.local", "Operador Demo", "OPERADOR", "OperadorSeguro2026"),
    ("admin@demo.local", "Administrador Demo", "ADMINISTRADOR", "AdminSeguro2026x"),
]

PRODUCTOS_PRUEBA = [
    ("Manual de Seguridad Web", "Guía práctica de OWASP Top 10, validación de entradas y manejo de sesiones.", 24900,
     ["Manual de Seguridad Web", "Capítulo 1. Validación de entradas", "Capítulo 2. Sesiones y cookies",
      "Capítulo 3. Control de acceso"]),
    ("Guía de Criptografía Aplicada", "Hashes, cifrado simétrico, firmas digitales y PKI explicados con ejemplos.", 34900,
     ["Guía de Criptografía Aplicada", "1. Funciones hash", "2. AES-GCM", "3. RSA y firmas", "4. Certificados X.509"]),
    ("Apuntes de Redes Seguras", "TLS, SSH, VPN e IPSec: conceptos y configuración.", 14900,
     ["Apuntes de Redes Seguras", "TLS 1.3", "SSH con llaves", "VPN e IPSec en modo túnel"]),
]


def pdf_de_ejemplo(paginas):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setTitle(paginas[0])
    for i, titulo in enumerate(paginas, 1):
        c.setFont("Helvetica-Bold", 20)
        c.drawString(72, 700, titulo)
        c.setFont("Helvetica", 11)
        y = 660
        for _ in range(18):
            c.drawString(72, y, "Contenido de ejemplo del producto digital (material educativo de prueba).")
            y -= 18
        c.drawString(72, 60, f"Página {i} de {len(paginas)}")
        c.showPage()
    c.save()
    return buf.getvalue()


def generar_secretos(cfg):
    cfg["SECRETS_DIR"].mkdir(parents=True, exist_ok=True)
    cripto.generar_clave_simetrica(cfg["DATA_KEY_PATH"])
    cripto.generar_clave_simetrica(cfg["FP_KEY_PATH"])
    cripto.generar_clave_simetrica(cfg["FLASK_KEY_PATH"])
    cripto.generar_par_firma(cfg["SIGNING_KEY_PATH"], cfg["PUBLIC_KEY_PATH"], cfg["SIGNING_KEY_PASSPHRASE"])


def cargar_datos_prueba(cfg):
    from aplicacion.seguridad import hash_password
    conn = conectar(cfg["DB_PATH"])
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("  La base ya tiene datos; no se cargan datos de prueba.")
        return
    for email, nombre, rol, pwd in USUARIOS_PRUEBA:
        conn.execute("INSERT INTO users(email, password_hash, name, role, status, created_at) VALUES (?,?,?,?,'ACTIVO',?)",
                     (email, hash_password(pwd), nombre, rol, ahora()))
    clave = cripto.leer_clave(cfg["DATA_KEY_PATH"])
    cfg["PRODUCTS_DIR"].mkdir(parents=True, exist_ok=True)
    for i, (nombre, desc, precio, paginas) in enumerate(PRODUCTOS_PRUEBA, 1):
        pdf = pdf_de_ejemplo(paginas)
        archivo = f"producto_{i:03d}.pdf.enc"
        (cfg["PRODUCTS_DIR"] / archivo).write_bytes(cripto.cifrar(pdf, clave))
        conn.execute("INSERT INTO products(name, description, price, file_name, file_hash, status, created_at)"
                     " VALUES (?,?,?,?,?,'ACTIVO',?)", (nombre, desc, precio, archivo, cripto.sha256_bytes(pdf), ahora()))
    conn.commit()
    conn.close()
    print(f"  {len(USUARIOS_PRUEBA)} usuarios y {len(PRODUCTOS_PRUEBA)} productos de prueba cargados.")


def inicializar(cfg, reiniciar=False, datos=True):
    generar_secretos(cfg)
    cfg["DB_PATH"].parent.mkdir(parents=True, exist_ok=True)
    if reiniciar and cfg["DB_PATH"].exists():
        cfg["DB_PATH"].unlink()
        for f in cfg["PRODUCTS_DIR"].glob("*.enc"):
            f.unlink()
    crear_esquema(cfg["DB_PATH"], cfg["SCHEMA_PATH"])
    if datos:
        cargar_datos_prueba(cfg)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reiniciar", action="store_true", help="borra la base de datos y la recrea")
    args = ap.parse_args()
    cfg = configuracion_por_defecto()
    print("Inicializando…")
    inicializar(cfg, args.reiniciar)
    print("Listo. Siguiente paso: python scripts/crear_ca.py  y luego  python -m aplicacion.servidor")
