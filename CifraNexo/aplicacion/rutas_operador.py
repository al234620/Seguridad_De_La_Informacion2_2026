
import secrets
import io

from pypdf import PdfReader

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from . import cripto
from .bitacora import registrar
from .db import ahora, get_db
from .seguridad import precio_a_centavos, requiere_rol, texto

bp = Blueprint("operador", __name__)
OPERADOR = "OPERADOR"
ESTADOS_OPERADOR = ("ENTREGADA", "CANCELADA")


def _guardar_pdf(archivo):
    """Valida y guarda un PDF cifrado. Devuelve (nombre, sha256) o None."""
    if not archivo or not archivo.filename:
        return None
    datos = archivo.read()
    # Validación por contenido (firma mágica), no por extensión ni por el Content-Type del cliente.
    if not datos.startswith(b"%PDF-") or len(datos) > current_app.config["MAX_CONTENT_LENGTH"]:
        return None
    # Una cabecera %PDF- no basta: se debe poder analizar al menos una pagina.
    try:
        lector = PdfReader(io.BytesIO(datos), strict=False)
        if lector.is_encrypted or len(lector.pages) < 1:
            return None
    except Exception:
        return None
    nombre = f"{secrets.token_hex(16)}.pdf.enc"  # nombre aleatorio, no se confia en el original
    clave = cripto.leer_clave(current_app.config["DATA_KEY_PATH"])
    destino = current_app.config["PRODUCTS_DIR"] / nombre
    destino.write_bytes(cripto.cifrar(datos, clave))
    return nombre, cripto.sha256_bytes(datos)


@bp.get("/productos")
@requiere_rol(OPERADOR)
def productos():
    lista = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("operador/productos.html", productos=lista)


@bp.route("/productos/nuevo", methods=["GET", "POST"])
@requiere_rol(OPERADOR)
def producto_nuevo():
    if request.method == "POST":
        nombre = texto(request.form.get("name"), 120)
        desc = texto(request.form.get("description"), 2000, requerido=False) or ""
        precio = precio_a_centavos(request.form.get("price"))
        if not nombre or precio is None:
            flash("Datos inválidos: nombre (1-120) y precio (ej. 199.00) son obligatorios.", "error")
            return render_template("operador/producto_form.html", p=None), 400
        guardado = _guardar_pdf(request.files.get("archivo"))
        if not guardado:
            flash("Es obligatorio subir un archivo PDF válido.", "error")
            return render_template("operador/producto_form.html", p=None), 400
        db = get_db()
        cur = db.execute(
            "INSERT INTO products(name, description, price, file_name, file_hash, status, created_at)"
            " VALUES (?,?,?,?,?,'ACTIVO',?)", (nombre, desc, precio, guardado[0], guardado[1], ahora()))
        db.commit()
        registrar("PRODUCT_CREATED", "EXITO", user_id=g.user["id"], email=g.user["email"],
                  details={"producto": cur.lastrowid, "sha256": guardado[1]})
        flash("Producto registrado.", "ok")
        return redirect(url_for("operador.productos"))
    return render_template("operador/producto_form.html", p=None)


@bp.route("/productos/<int:pid>/editar", methods=["GET", "POST"])
@requiere_rol(OPERADOR)
def producto_editar(pid):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if not p:
        abort(404)
    if request.method == "POST":
        nombre = texto(request.form.get("name"), 120)
        desc = texto(request.form.get("description"), 2000, requerido=False) or ""
        precio = precio_a_centavos(request.form.get("price"))
        if not nombre or precio is None:
            flash("Datos inválidos.", "error")
            return render_template("operador/producto_form.html", p=p), 400
        archivo = request.files.get("archivo")
        nombre_archivo, sha = p["file_name"], p["file_hash"]
        if archivo and archivo.filename:
            guardado = _guardar_pdf(archivo)
            if not guardado:
                flash("El archivo debe ser un PDF válido.", "error")
                return render_template("operador/producto_form.html", p=p), 400
            nombre_archivo, sha = guardado
        db.execute("UPDATE products SET name = ?, description = ?, price = ?, file_name = ?, file_hash = ? WHERE id = ?",
                   (nombre, desc, precio, nombre_archivo, sha, pid))
        db.commit()
        registrar("PRODUCT_UPDATED", "EXITO", user_id=g.user["id"], email=g.user["email"], details={"producto": pid})
        if precio != p["price"]:
            registrar("PRICE_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"],
                      details={"producto": pid, "antes": p["price"], "despues": precio})
        flash("Producto actualizado. Las órdenes históricas conservan su precio original.", "ok")
        return redirect(url_for("operador.productos"))
    return render_template("operador/producto_form.html", p=p)


@bp.post("/productos/<int:pid>/estado")
@requiere_rol(OPERADOR)
def producto_estado(pid):
    estado = request.form.get("status")
    if estado not in ("ACTIVO", "INACTIVO"):
        abort(400)
    db = get_db()
    if db.execute("UPDATE products SET status = ? WHERE id = ?", (estado, pid)).rowcount == 0:
        abort(404)
    db.commit()
    registrar("PRODUCT_STATUS_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"producto": pid, "estado": estado})
    return redirect(url_for("operador.productos"))


@bp.get("/ordenes")
@requiere_rol(OPERADOR)
def ordenes():
    # Solo los datos necesarios para procesar pedidos (sin hashes ni sesiones).
    lista = get_db().execute(
        "SELECT o.id, o.total, o.status, o.created_at, u.email,"
        " (SELECT COUNT(*) FROM order_items WHERE order_id = o.id) AS n_items"
        " FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id DESC").fetchall()
    return render_template("operador/ordenes.html", ordenes=lista, estados=ESTADOS_OPERADOR)


@bp.post("/ordenes/<int:oid>/estado")
@requiere_rol(OPERADOR)
def orden_estado(oid):
    estado = request.form.get("status")
    if estado not in ESTADOS_OPERADOR:
        abort(400)
    db = get_db()
    o = db.execute("SELECT status FROM orders WHERE id = ?", (oid,)).fetchone()
    if not o:
        abort(404)
    # Transiciones permitidas: no resucitar CANCELADA/RECHAZADA ni
    # convertir una orden PENDIENTE en pagada manualmente.
    permitidas = {
        "PENDIENTE": ("CANCELADA",),
        "PAGADA": ("ENTREGADA", "CANCELADA"),
        "ENTREGADA": (),
        "RECHAZADA": (),
        "CANCELADA": (),
    }
    if estado not in permitidas.get(o["status"], ()):
        flash("Transición de estado no permitida.", "error")
        return redirect(url_for("operador.ordenes"))
    if estado == "ENTREGADA" and not db.execute(
        "SELECT 1 FROM payments WHERE order_id=? AND status='APROBADO'", (oid,)
    ).fetchone():
        flash("No existe pago aprobado.", "error")
        return redirect(url_for("operador.ordenes"))
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (estado, oid))
    db.commit()
    registrar("ORDER_STATUS_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"orden": oid, "antes": o["status"], "despues": estado})
    flash("Estado actualizado.", "ok")
    return redirect(url_for("operador.ordenes"))
