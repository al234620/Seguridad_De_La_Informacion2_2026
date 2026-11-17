
import sqlite3

import pytest

from aplicacion.bitacora import verificar_cadena
from aplicacion.db import conectar

from .conftest import comprar

ev = pytest.mark.evidencia


@ev("A1", "Contraseñas almacenadas", "Solo hash Argon2id, nunca texto claro.")
def test_password_solo_hash(cfg):
    """Cada password_hash empieza con $argon2id$ y no contiene la contraseña; no existe columna 'password'."""
    db = conectar(cfg["DB_PATH"])
    columnas = [c[1] for c in db.execute("PRAGMA table_info(users)")]
    assert "password" not in columnas
    for (h,) in db.execute("SELECT password_hash FROM users"):
        assert h.startswith("$argon2id$") and "Seguro2026" not in h


@ev("A2", "Formulario sin token CSRF", "Solicitud rechazada (400).")
def test_csrf(nav):
    """POST de compra sin token CSRF -> 400."""
    n = nav()
    n.login("cliente@demo.local")
    r = n.c.post("/carrito/agregar/1", data={})
    assert r.status_code == 400


@ev("A3", "Fuerza bruta", "Cuenta bloqueada tras 5 intentos fallidos.")
def test_bloqueo(nav, cfg):
    """5 contraseñas erróneas -> la 6ª, aun correcta, se rechaza por bloqueo temporal."""
    n = nav()
    for _ in range(5):
        n.login("cliente@demo.local", "IncorrectaIncorrecta1")
    assert n.login("cliente@demo.local").status_code == 401
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT COUNT(*) FROM security_events WHERE event='ACCOUNT_LOCKED'").fetchone()[0] == 1


@ev("A4", "Revocación de sesión por el administrador", "La sesión del usuario deja de ser válida.")
def test_revocar_sesion(nav):
    """El cliente tiene sesión; el admin la revoca; la siguiente petición del cliente da 401."""
    c = nav()
    c.login("cliente@demo.local")
    assert c.get("/ordenes").status_code == 200
    a = nav()
    a.login("admin@demo.local")
    a.post("/admin/usuarios/1/revocar", desde="/admin/usuarios")
    assert c.get("/ordenes").status_code == 401


@ev("A5", "Cuenta desactivada", "No puede iniciar sesión.")
def test_cuenta_desactivada(nav):
    """El ADMINISTRADOR desactiva al cliente; su contraseña correcta ya no permite entrar."""
    a = nav()
    a.login("admin@demo.local")
    a.post("/admin/usuarios/1/estado", {"status": "DESACTIVADO"}, desde="/admin/usuarios")
    assert nav().login("cliente@demo.local").status_code == 401


@ev("A6", "Bitácora de seguridad", "Solo inserción y cadena de hashes íntegra.")
def test_bitacora_inmutable(nav, cfg):
    """UPDATE/DELETE sobre security_events fallan por trigger; alterar el archivo rompe la cadena."""
    n = nav()
    n.login("cliente@demo.local")
    comprar(n)
    db = conectar(cfg["DB_PATH"])
    eventos = {r[0] for r in db.execute("SELECT DISTINCT event FROM security_events")}
    assert {"LOGIN_SUCCESS", "ORDER_CREATED", "PAYMENT_APPROVED", "SIGNATURE_CREATED"} <= eventos
    assert verificar_cadena(db)[0]
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM security_events")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("UPDATE security_events SET result = 'X'")
    # Un atacante con acceso al archivo quita el trigger y altera un registro: la cadena lo delata.
    db.execute("DROP TRIGGER trg_events_no_update")
    db.execute("UPDATE security_events SET result = 'FALSO' WHERE id = 2")
    assert verificar_cadena(db) == (False, 2)


@ev("A7", "Precio manipulado / histórico", "La orden conserva el precio de compra.")
def test_precio_historico(nav, cfg):
    """El OPERADOR cambia el precio después de la compra: order_items conserva el precio original."""
    c = nav()
    c.login("cliente@demo.local")
    oid = comprar(c)
    o = nav()
    o.login("operador@demo.local")
    o.post("/operador/productos/1/editar", {"name": "Manual de Seguridad Web", "description": "x", "price": "999.00"},
           desde="/operador/productos/1/editar")
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT price FROM products WHERE id=1").fetchone()[0] == 99900
    assert db.execute("SELECT price FROM order_items WHERE order_id=?", (oid,)).fetchone()[0] == 24900


@ev("A8", "Validación de entradas", "Datos inválidos rechazados; sin inyección SQL.")
def test_validacion(nav, cfg):
    """Registro con correo inválido y contraseña débil se rechaza; login con inyección SQL no autentica;
    el OPERADOR no puede subir un archivo que no es PDF."""
    n = nav()
    n.post("/registro", {"email": "no-es-correo", "name": "X", "password": "corta", "password2": "corta"}, desde="/registro")
    assert n.login("' OR '1'='1", "' OR '1'='1").status_code == 401
    o = nav()
    o.login("operador@demo.local")
    import io
    r = o.post("/operador/productos/nuevo",
               {"name": "Malicioso", "price": "1.00", "archivo": (io.BytesIO(b"MZ\x90\x00 ejecutable"), "x.pdf")},
               desde="/operador/productos/nuevo", content_type="multipart/form-data")
    assert r.status_code == 400
    db = conectar(cfg["DB_PATH"])
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4
    assert db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 3


@ev("A9", "Recuperación de contraseña", "Token temporal de un solo uso; nunca se envía la contraseña.")
def test_recuperacion(nav, cfg):
    """El enlace del buzón simulado cambia la contraseña; el token no se reutiliza y la contraseña vieja deja de servir."""
    n = nav()
    n.post("/recuperar", {"email": "cliente@demo.local"}, desde="/recuperar")
    correo = next(cfg["OUTBOX_DIR"].glob("*.txt")).read_text(encoding="utf-8")
    assert "ClienteSeguro2026" not in correo
    ruta = "/restablecer/" + correo.split("/restablecer/")[1].split()[0]
    nueva = "NuevaClaveSegura2026"
    assert n.post(ruta, {"password": nueva, "password2": nueva}, desde=ruta).status_code == 302
    assert nav().login("cliente@demo.local", nueva).status_code == 302
    # Reutilizar el token falla.
    assert n.get(ruta).status_code == 302
    assert nav().login("cliente@demo.local").status_code == 401  # contraseña vieja ya no sirve


@ev("A10", "Cabeceras y errores", "Cabeceras de seguridad presentes; errores sin trazas internas.")
def test_cabeceras(nav):
    """Página inexistente -> 404 genérico con CSP, X-Frame-Options, nosniff y HSTS; sin Traceback."""
    r = nav().get("/producto/99999")
    assert r.status_code == 404
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"):
        assert h in r.headers
    assert "Traceback" not in r.get_data(as_text=True)
