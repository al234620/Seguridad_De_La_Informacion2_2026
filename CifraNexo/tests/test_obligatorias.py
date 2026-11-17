
import json
import socket
import ssl
import subprocess
import sys
import threading

import pytest
import requests
from werkzeug.serving import make_server

from aplicacion import cripto, huella
from aplicacion.db import conectar
from aplicacion.servidor import contexto_tls
from scripts.respaldo import crear_respaldo, restaurar_respaldo

from .conftest import RAIZ, comprar, guardar_evidencia

ev = pytest.mark.evidencia


# 1 ----------------------------------------------------------------------
@ev(1, "Contraseña incorrecta", "Acceso rechazado.")
def test_01_password_incorrecta(nav, cfg):
    """Login con contraseña errónea -> 401, sin cookie de sesión y evento LOGIN_FAILED."""
    n = nav()
    r = n.login("cliente@demo.local", "ContraseñaEquivocada1")
    assert r.status_code == 401
    assert "sid" not in r.headers.get("Set-Cookie", "")
    assert n.get("/ordenes").status_code == 401
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT COUNT(*) FROM security_events WHERE event='LOGIN_FAILED'").fetchone()[0] == 1


# 2 ----------------------------------------------------------------------
@ev(2, "CLIENTE intenta una función administrativa", "Acceso rechazado.")
def test_02_cliente_funcion_admin(nav, cfg):
    """CLIENTE autenticado -> /admin/usuarios, cambiar rol y bitácora: 403 + evento ACCESS_DENIED."""
    n = nav()
    assert n.login("cliente@demo.local").status_code == 302
    assert n.get("/admin/usuarios").status_code == 403
    assert n.get("/admin/eventos").status_code == 403
    assert n.post("/admin/usuarios/1/rol", {"role": "ADMINISTRADOR"}, desde="/").status_code == 403
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT role FROM users WHERE email='cliente@demo.local'").fetchone()[0] == "CLIENTE"
    assert db.execute("SELECT COUNT(*) FROM security_events WHERE event='ACCESS_DENIED'").fetchone()[0] >= 3


# 3 ----------------------------------------------------------------------
@ev(3, "OPERADOR intenta cambiar roles", "Acceso rechazado.")
def test_03_operador_cambia_roles(nav, cfg):
    """OPERADOR -> POST /admin/usuarios/<id>/rol: 403 y el rol no cambia."""
    n = nav()
    n.login("operador@demo.local")
    r = n.post("/admin/usuarios/1/rol", {"role": "ADMINISTRADOR"}, desde="/operador/productos")
    assert r.status_code == 403
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT role FROM users WHERE id=1").fetchone()[0] == "CLIENTE"


# 4 ----------------------------------------------------------------------
@ev(4, "ADMINISTRADOR autorizado", "Operación permitida.")
def test_04_admin_autorizado(nav, cfg):
    """ADMINISTRADOR cambia el rol de un usuario: 302, rol actualizado, evento ROLE_CHANGED y sus sesiones revocadas."""
    n = nav()
    n.login("admin@demo.local")
    r = n.post("/admin/usuarios/2/rol", {"role": "OPERADOR"}, desde="/admin/usuarios")
    assert r.status_code == 302
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT role FROM users WHERE id=2").fetchone()[0] == "OPERADOR"
    assert db.execute("SELECT COUNT(*) FROM security_events WHERE event='ROLE_CHANGED'").fetchone()[0] == 1
    # La página del administrador no expone hashes de contraseñas.
    assert "$argon2id$" not in n.get("/admin/usuarios").get_data(as_text=True)


# 5 y 6: TLS --------------------------------------------------------------
def _puerto_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def pki(tmp_path):
    destino = tmp_path / "certs"
    subprocess.run([sys.executable, str(RAIZ / "scripts" / "crear_ca.py"), "--destino", str(destino)], check=True, capture_output=True)
    return destino


def _servidor(app, cert, key):
    puerto = _puerto_libre()
    srv = make_server("127.0.0.1", puerto, app, ssl_context=contexto_tls(cert, key), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, puerto


def _sesion_sin_proxy():
    s = requests.Session()
    s.trust_env = False  # no usar proxies del entorno para localhost
    return s


@ev(5, "Certificado TLS correcto", "Conexión aceptada.")
def test_05_tls_certificado_confiable(app, pki):
    """Servidor con certificado firmado por la CA local; el cliente confía en ca.crt -> HTTPS 200, TLS ≥ 1.2."""
    srv, puerto = _servidor(app, pki / "servidor.crt", pki / "servidor.key")
    try:
        r = _sesion_sin_proxy().get(f"https://localhost:{puerto}/", verify=str(pki / "ca.crt"), timeout=10)
        assert r.status_code == 200
        assert "Strict-Transport-Security" in r.headers
        ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
        with socket.create_connection(("127.0.0.1", puerto)) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as s:
            assert s.version() in ("TLSv1.2", "TLSv1.3")
            emisor = dict(x[0] for x in s.getpeercert()["issuer"])
            assert emisor["commonName"] == "Tienda Segura CA Raiz"
    finally:
        srv.shutdown()


@ev(6, "Certificado no confiable", "Conexión rechazada.")
def test_06_tls_certificado_no_confiable(app, pki):
    """Servidor con certificado autofirmado ajeno a la CA -> el cliente aborta el handshake (SSLError)."""
    srv, puerto = _servidor(app, pki / "no_confiable.crt", pki / "no_confiable.key")
    try:
        with pytest.raises(requests.exceptions.SSLError):
            _sesion_sin_proxy().get(f"https://localhost:{puerto}/", verify=str(pki / "ca.crt"), timeout=10)
    finally:
        srv.shutdown()


# 7 y 8: firma digital -----------------------------------------------------
def _comprobante(nav):
    n = nav()
    n.login("cliente@demo.local")
    oid = comprar(n)
    paquete = json.loads(n.get(f"/ordenes/{oid}/comprobante.json").get_data())
    return paquete


@ev(7, "Comprobante original", "Firma digital válida.")
def test_07_comprobante_original(nav, cfg):
    """Comprobante emitido tras pago aprobado: la firma RSA-PSS verifica con la clave pública."""
    paquete = _comprobante(nav)
    assert paquete["algoritmo"] == cripto.ALGORITMO_FIRMA
    for campo in ("numero_orden", "usuario", "productos", "total_centavos", "fecha", "referencia_transaccion"):
        assert campo in paquete["comprobante"]
    assert cripto.verificar_firma(cripto.canonico(paquete["comprobante"]), paquete["firma"],
                                  cfg["PUBLIC_KEY_PATH"].read_bytes())
    guardar_evidencia("comprobante_original.json", json.dumps(paquete, ensure_ascii=False, indent=2))


@ev(8, "Comprobante modificado", "Firma digital inválida.")
def test_08_comprobante_modificado(nav, cfg):
    """Se cambia el total del comprobante de 249.00 a 1.00 -> la verificación falla."""
    paquete = _comprobante(nav)
    paquete["comprobante"]["total_centavos"] = 100
    assert not cripto.verificar_firma(cripto.canonico(paquete["comprobante"]), paquete["firma"],
                                      cfg["PUBLIC_KEY_PATH"].read_bytes())
    guardar_evidencia("comprobante_modificado.json", json.dumps(paquete, ensure_ascii=False, indent=2))


# 9 ----------------------------------------------------------------------
@ev(9, "Producto descargado", "Fingerprint recuperable.")
def test_09_fingerprint_recuperable(nav, cfg):
    """Descarga -> se extrae el código del PDF (texto invisible), el HMAC valida y apunta al usuario y orden correctos;
    sobrevive a renombrar el archivo y a borrar los metadatos."""
    n = nav()
    n.login("cliente@demo.local")
    oid = comprar(n)
    r = n.get(f"/descargar/{oid}/1")
    assert r.status_code == 200 and r.mimetype == "application/pdf"
    copia = r.get_data()
    clave = cripto.leer_clave(cfg["FP_KEY_PATH"])
    codigos = huella.extraer_de_pdf(copia)
    assert len(codigos) == 1
    info = huella.validar_codigo(codigos[0], clave)
    assert info and info["user_id"] == 1 and info["order_id"] == oid
    db = conectar(cfg["DB_PATH"])
    assert tuple(db.execute("SELECT user_id, order_id FROM downloads WHERE fingerprint = ?", (codigos[0],)).fetchone()) == (1, oid)

    # Robustez: quitar metadatos (reescribir el PDF sin /Fingerprint) no elimina la huella del contenido.
    import io
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter()
    for p in PdfReader(io.BytesIO(copia)).pages:
        w.add_page(p)
    buf = io.BytesIO()
    w.write(buf)
    assert huella.extraer_de_pdf(buf.getvalue()) == codigos

    # Una huella alterada no valida (no se puede inculpar a otro usuario).
    falsa = codigos[0].replace(".u1.", ".u2.")
    assert huella.validar_codigo(falsa, clave) is None

    # Dos descargas del mismo producto -> huellas distintas.
    assert huella.extraer_de_pdf(n.get(f"/descargar/{oid}/1").get_data()) != codigos
    guardar_evidencia("copia_con_fingerprint.pdf", copia)


# 10 ---------------------------------------------------------------------
@ev(10, "CLIENTE intenta descargar producto no comprado", "Acceso rechazado.")
def test_10_descarga_no_comprada(nav, cfg):
    """cliente2 intenta descargar el producto de la orden de cliente, y un producto que nadie compró -> 403."""
    a = nav()
    a.login("cliente@demo.local")
    oid = comprar(a, producto_id=1)
    b = nav()
    b.login("cliente2@demo.local")
    assert b.get(f"/descargar/{oid}/1").status_code == 403       # orden ajena
    assert a.get(f"/descargar/{oid}/2").status_code == 403       # producto fuera de su orden
    assert b.get(f"/ordenes/{oid}").status_code == 404           # ni siquiera ve la orden ajena
    pendiente = comprar(a, producto_id=3, resultado="RECHAZADO")
    assert a.get(f"/descargar/{pendiente}/3").status_code == 403  # pago rechazado


# 11 y 12: hash de archivos -------------------------------------------------
@ev(11, "Archivo original", "Hash esperado.")
def test_11_hash_original(cfg):
    """Se descifra cada producto y su SHA-256 coincide con products.file_hash."""
    db = conectar(cfg["DB_PATH"])
    clave = cripto.leer_clave(cfg["DATA_KEY_PATH"])
    for p in db.execute("SELECT file_name, file_hash FROM products"):
        original = cripto.descifrar((cfg["PRODUCTS_DIR"] / p["file_name"]).read_bytes(), clave)
        assert cripto.sha256_bytes(original) == p["file_hash"]


@ev(12, "Archivo modificado", "Hash diferente.")
def test_12_hash_modificado(cfg, nav):
    """Un byte cambiado en el PDF da otro SHA-256; un byte cambiado en el archivo cifrado lo rechaza AES-GCM
    y la descarga se niega con evento INTEGRITY_FAILURE."""
    db = conectar(cfg["DB_PATH"])
    p = db.execute("SELECT file_name, file_hash FROM products WHERE id = 1").fetchone()
    ruta = cfg["PRODUCTS_DIR"] / p["file_name"]
    clave = cripto.leer_clave(cfg["DATA_KEY_PATH"])
    original = bytearray(cripto.descifrar(ruta.read_bytes(), clave))
    original[200] ^= 0x01
    assert cripto.sha256_bytes(bytes(original)) != p["file_hash"]

    n = nav()
    n.login("cliente@demo.local")
    oid = comprar(n)
    cifrado = bytearray(ruta.read_bytes())
    cifrado[50] ^= 0x01
    ruta.write_bytes(bytes(cifrado))
    assert n.get(f"/descargar/{oid}/1").status_code == 500
    assert db.execute("SELECT COUNT(*) FROM security_events WHERE event='INTEGRITY_FAILURE'").fetchone()[0] == 1


# 13 ---------------------------------------------------------------------
@ev(13, "Restauración de respaldo", "Información crítica recuperada.")
def test_13_respaldo_restauracion(nav, cfg, tmp_path):
    """Respaldo cifrado -> se borran la BD y los productos -> restauración -> usuarios, productos, órdenes y
    descargas recuperados; la app vuelve a operar."""
    n = nav()
    n.login("cliente@demo.local")
    oid = comprar(n)
    db = conectar(cfg["DB_PATH"])
    antes = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
             for t in ("users", "products", "orders", "order_items", "payments", "receipts", "security_events")}
    db.close()
    archivo = crear_respaldo(cfg, tmp_path / "respaldos")

    # Desastre simulado.
    cfg["DB_PATH"].unlink()
    for f in cfg["PRODUCTS_DIR"].glob("*.enc"):
        f.unlink()
    assert not cfg["DB_PATH"].exists()

    restaurar_respaldo(cfg, archivo)
    db = conectar(cfg["DB_PATH"])
    despues = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in antes}
    assert despues == antes and antes["orders"] == 1
    # Y el sistema funciona: el cliente vuelve a descargar su producto.
    n2 = nav()
    n2.login("cliente@demo.local")
    assert n2.get(f"/descargar/{oid}/1").status_code == 200
    guardar_evidencia("respaldo_conteos.json", json.dumps({"antes": antes, "despues": despues}, indent=2))
