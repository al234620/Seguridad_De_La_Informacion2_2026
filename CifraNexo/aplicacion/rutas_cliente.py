
import io
import json
import secrets

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   request, send_file, url_for)

from . import cripto, huella
from .bitacora import registrar
from .db import ahora, get_db
from .seguridad import (hash_password, requiere_rol, texto,
                        validar_password, verificar_password)

bp = Blueprint("cliente", __name__)
CLIENTE = "CLIENTE"


# ---------------------------------------------------------------- perfil
@bp.route("/perfil", methods=["GET", "POST"])
@requiere_rol(CLIENTE, "OPERADOR", "ADMINISTRADOR")  # todos pueden editar SU propio perfil
def perfil():
    db = get_db()
    if request.method == "POST":
        accion = request.form.get("accion")
        if accion == "nombre":
            nombre = texto(request.form.get("name"), 80)
            if not nombre:
                flash("Nombre inválido.", "error")
            else:
                db.execute("UPDATE users SET name = ? WHERE id = ?", (nombre, g.user["id"]))
                db.commit()
                flash("Perfil actualizado.", "ok")
        elif accion == "password":
            u = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
            nueva = request.form.get("nueva", "")
            errores = validar_password(nueva, g.user["email"])
            if not verificar_password(u["password_hash"], request.form.get("actual", "")):
                errores.insert(0, "La contraseña actual es incorrecta.")
            if errores:
                for e in errores:
                    flash(e, "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(nueva), g.user["id"]))
                db.commit()
                # Cierra las demás sesiones; la actual se mantiene.
                db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?",
                           (g.user["id"], g.sesion_id))
                db.commit()
                registrar("PASSWORD_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"])
                flash("Contraseña actualizada.", "ok")
        return redirect(url_for("cliente.perfil"))
    u = db.execute("SELECT email, name, role, created_at, last_login FROM users WHERE id = ?",
                   (g.user["id"],)).fetchone()
    return render_template("cliente/perfil.html", u=u)


# --------------------------------------------------------------- carrito
@bp.get("/carrito")
@requiere_rol(CLIENTE)
def carrito():
    items = get_db().execute(
        "SELECT p.id, p.name, p.price FROM cart_items c JOIN products p ON p.id = c.product_id"
        " WHERE c.user_id = ? AND p.status = 'ACTIVO' ORDER BY c.added_at", (g.user["id"],)).fetchall()
    return render_template("cliente/carrito.html", items=items, total=sum(i["price"] for i in items))


@bp.post("/carrito/agregar/<int:pid>")
@requiere_rol(CLIENTE)
def carrito_agregar(pid):
    db = get_db()
    if not db.execute("SELECT 1 FROM products WHERE id = ? AND status = 'ACTIVO'", (pid,)).fetchone():
        abort(404)
    ya = db.execute("SELECT 1 FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.user_id = ?"
                    " AND oi.product_id = ? AND o.status IN ('PAGADA','ENTREGADA')", (g.user["id"], pid)).fetchone()
    if ya:
        flash("Ya adquiriste este producto; puedes descargarlo desde tus órdenes.", "ok")
        return redirect(url_for("cliente.ordenes"))
    db.execute("INSERT OR IGNORE INTO cart_items(user_id, product_id, added_at) VALUES (?,?,?)",
               (g.user["id"], pid, ahora()))
    db.commit()
    flash("Producto agregado al carrito.", "ok")
    return redirect(url_for("cliente.carrito"))


@bp.post("/carrito/quitar/<int:pid>")
@requiere_rol(CLIENTE)
def carrito_quitar(pid):
    db = get_db()
    db.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (g.user["id"], pid))
    db.commit()
    return redirect(url_for("cliente.carrito"))


# ---------------------------------------------------------------- órdenes
@bp.post("/ordenes/crear")
@requiere_rol(CLIENTE)
def crear_orden():
    db = get_db()
    items = db.execute(
        "SELECT p.id, p.price FROM cart_items c JOIN products p ON p.id = c.product_id"
        " WHERE c.user_id = ? AND p.status = 'ACTIVO'", (g.user["id"],)).fetchall()
    if not items:
        flash("Tu carrito está vacío.", "error")
        return redirect(url_for("cliente.carrito"))
    # El total y los precios se toman de la BD, nunca del formulario.
    total = sum(i["price"] for i in items)
    cur = db.execute("INSERT INTO orders(user_id, total, status, created_at) VALUES (?,?, 'PENDIENTE', ?)",
                     (g.user["id"], total, ahora()))
    oid = cur.lastrowid
    db.executemany("INSERT INTO order_items(order_id, product_id, price) VALUES (?,?,?)",
                   [(oid, i["id"], i["price"]) for i in items])
    db.execute("DELETE FROM cart_items WHERE user_id = ?", (g.user["id"],))
    db.commit()
    registrar("ORDER_CREATED", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"orden": oid, "total": total})
    return redirect(url_for("cliente.pagar", oid=oid))


def _orden_propia(oid):
    o = get_db().execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (oid, g.user["id"])).fetchone()
    if not o:
        # 404 en lugar de 403: no revela si la orden de otro usuario existe.
        registrar("ACCESS_DENIED", "DENEGADO", user_id=g.user["id"], email=g.user["email"],
                  details={"orden_ajena_o_inexistente": oid})
        abort(404)
    return o


def _items(oid):
    return get_db().execute(
        "SELECT p.id, p.name, oi.price FROM order_items oi JOIN products p ON p.id = oi.product_id"
        " WHERE oi.order_id = ? ORDER BY p.name", (oid,)).fetchall()


@bp.get("/ordenes")
@requiere_rol(CLIENTE)
def ordenes():
    lista = get_db().execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)).fetchall()
    return render_template("cliente/ordenes.html", ordenes=lista)


@bp.get("/ordenes/<int:oid>")
@requiere_rol(CLIENTE)
def orden(oid):
    o = _orden_propia(oid)
    pago = get_db().execute("SELECT * FROM payments WHERE order_id = ? ORDER BY id DESC LIMIT 1", (oid,)).fetchone()
    return render_template("cliente/orden.html", o=o, items=_items(oid), pago=pago)


# ------------------------------------------------------------ pago simulado
@bp.route("/ordenes/<int:oid>/pagar", methods=["GET", "POST"])
@requiere_rol(CLIENTE)
def pagar(oid):
    o = _orden_propia(oid)
    if o["status"] != "PENDIENTE":
        flash("Esta orden ya no admite pagos.", "error")
        return redirect(url_for("cliente.orden", oid=oid))
    if request.method == "GET":
        return render_template("cliente/pagar.html", o=o, items=_items(oid))

    # SIMULACIÓN: el usuario elige el resultado. No se capturan datos de tarjeta.
    resultado = request.form.get("resultado")
    if resultado not in ("APROBADO", "RECHAZADO"):
        abort(400)
    db = get_db()
    ref = "SIM-" + secrets.token_hex(8).upper()
    # Pago, estado de orden y comprobante forman una sola transacción:
    # nunca se queda una orden PAGADA sin comprobante si falla la firma.
    try:
        db.execute("BEGIN IMMEDIATE")
        vigente = db.execute("SELECT status, total FROM orders WHERE id=? AND user_id=?",
                             (oid, g.user["id"])).fetchone()
        if not vigente or vigente["status"] != "PENDIENTE":
            db.rollback()
            flash("Esta orden ya no admite pagos.", "error")
            return redirect(url_for("cliente.orden", oid=oid))
        db.execute("INSERT INTO payments(order_id, transaction_reference, amount, status, created_at) VALUES (?,?,?,?,?)",
                   (oid, ref, vigente["total"], resultado, ahora()))
        if resultado == "RECHAZADO":
            db.execute("UPDATE orders SET status = 'RECHAZADA' WHERE id = ?", (oid,))
        else:
            db.execute("UPDATE orders SET status = 'PAGADA' WHERE id = ?", (oid,))
            comprobante_hash = emitir_comprobante(oid, db=db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    if resultado == "RECHAZADO":
        registrar("PAYMENT_REJECTED", "RECHAZADO", user_id=g.user["id"], email=g.user["email"],
                  details={"orden": oid, "referencia": ref})
        flash("Pago simulado rechazado.", "error")
    else:
        registrar("PAYMENT_APPROVED", "EXITO", user_id=g.user["id"], email=g.user["email"],
                  details={"orden": oid, "referencia": ref})
        registrar("SIGNATURE_CREATED", "EXITO", user_id=g.user["id"], email=g.user["email"],
                  details={"orden": oid, "sha256_comprobante": comprobante_hash})
        flash("Pago simulado aprobado. Tu comprobante firmado está listo.", "ok")
    return redirect(url_for("cliente.orden", oid=oid))


# ------------------------------------------------------- comprobante firmado
def emitir_comprobante(oid, db=None):
    """Inserta comprobante en la transaccion actual. NO hace commit."""
    db = db if db is not None else get_db()
    o = db.execute("SELECT o.*, u.email, u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
                   (oid,)).fetchone()
    pago = db.execute("SELECT * FROM payments WHERE order_id = ? AND status = 'APROBADO'", (oid,)).fetchone()
    pem = current_app.config["PUBLIC_KEY_PATH"].read_bytes()
    contenido = {
        "emisor": "CifraNexo (proyecto académico)",
        "numero_orden": oid,
        "usuario": {"id": o["user_id"], "email": o["email"], "nombre": o["name"]},
        "productos": [{"id": i["id"], "nombre": i["name"], "precio_centavos": i["price"]} for i in _items(oid)],
        "total_centavos": o["total"],
        "moneda": "MXN",
        "fecha": pago["created_at"],
        "referencia_transaccion": pago["transaction_reference"],
        "algoritmo": cripto.ALGORITMO_FIRMA,
        "id_clave": cripto.id_clave_publica(pem),
    }
    datos = cripto.canonico(contenido)
    firma = cripto.firmar(datos, current_app.config["SIGNING_KEY_PATH"], current_app.config["SIGNING_KEY_PASSPHRASE"])
    db.execute("INSERT INTO receipts(order_id, content, signature, algorithm, key_id, created_at) VALUES (?,?,?,?,?,?)",
               (oid, datos.decode("utf-8"), firma, cripto.ALGORITMO_FIRMA, contenido["id_clave"], ahora()))
    return cripto.sha256_bytes(datos)


def _comprobante(oid):
    _orden_propia(oid)
    r = get_db().execute("SELECT * FROM receipts WHERE order_id = ?", (oid,)).fetchone()
    if not r:
        abort(404)
    return r


@bp.get("/ordenes/<int:oid>/comprobante")
@requiere_rol(CLIENTE)
def comprobante(oid):
    r = _comprobante(oid)
    valido = cripto.verificar_firma(r["content"].encode(), r["signature"],
                                    current_app.config["PUBLIC_KEY_PATH"].read_bytes())
    return render_template("cliente/comprobante.html", r=r, c=json.loads(r["content"]), valido=valido)


@bp.get("/ordenes/<int:oid>/comprobante.json")
@requiere_rol(CLIENTE)
def comprobante_json(oid):
    r = _comprobante(oid)
    paquete = {"comprobante": json.loads(r["content"]), "firma": r["signature"], "algoritmo": r["algorithm"]}
    return send_file(io.BytesIO(json.dumps(paquete, ensure_ascii=False, indent=2).encode()),
                     mimetype="application/json", as_attachment=True, download_name=f"comprobante_orden_{oid}.json")


@bp.route("/comprobantes/verificar", methods=["GET", "POST"])
@requiere_rol(CLIENTE)
def verificar_comprobante():
    resultado = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        crudo = archivo.read(200_000) if archivo else request.form.get("json", "").encode()[:200_000]
        try:
            paquete = json.loads(crudo)
            datos = cripto.canonico(paquete["comprobante"])
            resultado = cripto.verificar_firma(datos, paquete["firma"],
                                               current_app.config["PUBLIC_KEY_PATH"].read_bytes())
        except (ValueError, KeyError, TypeError):
            resultado = False
    return render_template("cliente/verificar.html", resultado=resultado)


# ------------------------------------------------- descarga con fingerprint
@bp.get("/descargar/<int:oid>/<int:pid>")
@requiere_rol(CLIENTE)
def descargar(oid, pid):
    db = get_db()
    fila = db.execute(
        "SELECT p.* FROM orders o JOIN order_items oi ON oi.order_id = o.id JOIN products p ON p.id = oi.product_id"
        " WHERE o.id = ? AND o.user_id = ? AND p.id = ? AND o.status IN ('PAGADA','ENTREGADA')",
        (oid, g.user["id"], pid)).fetchone()
    if not fila:
        registrar("DOWNLOAD", "DENEGADO", user_id=g.user["id"], email=g.user["email"],
                  details={"orden": oid, "producto": pid, "motivo": "no adquirido"})
        abort(403)

    # 1) Descifrar el original (AES-GCM detecta alteración del archivo cifrado).
    clave = cripto.leer_clave(current_app.config["DATA_KEY_PATH"])
    try:
        original = cripto.descifrar((current_app.config["PRODUCTS_DIR"] / fila["file_name"]).read_bytes(), clave)
    except (ValueError, FileNotFoundError):
        registrar("INTEGRITY_FAILURE", "ERROR", user_id=g.user["id"], details={"producto": pid, "etapa": "descifrado"})
        abort(500)
    # 2) Verificar SHA-256 contra el valor registrado en la BD.
    if cripto.sha256_bytes(original) != fila["file_hash"]:
        registrar("INTEGRITY_FAILURE", "ERROR", user_id=g.user["id"], details={"producto": pid, "etapa": "hash"})
        abort(500)

    # 3) Fingerprint asociado a usuario + orden + descarga.
    id_desc = huella.nuevo_id_descarga()
    codigo = huella.generar_codigo(g.user["id"], oid, id_desc, cripto.leer_clave(current_app.config["FP_KEY_PATH"]))
    visible = f"Copia licenciada a {g.user['name']} <{g.user['email']}> · Orden #{oid} · {id_desc}"
    copia = huella.insertar_en_pdf(original, codigo, visible)

    db.execute("INSERT INTO downloads(user_id, order_id, product_id, fingerprint, copy_hash, ip, created_at)"
               " VALUES (?,?,?,?,?,?,?)",
               (g.user["id"], oid, pid, codigo, cripto.sha256_bytes(copia), request.remote_addr, ahora()))
    db.execute("UPDATE orders SET status = 'ENTREGADA' WHERE id = ? AND status = 'PAGADA'", (oid,))
    db.commit()
    registrar("FINGERPRINT_CREATED", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"orden": oid, "producto": pid, "id_descarga": id_desc})
    registrar("DOWNLOAD", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"orden": oid, "producto": pid, "id_descarga": id_desc})
    return send_file(io.BytesIO(copia), mimetype="application/pdf", as_attachment=True,
                     download_name=f"producto_{pid}_orden_{oid}.pdf")
