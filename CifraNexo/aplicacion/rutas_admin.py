
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from . import cripto, huella
from .bitacora import registrar, verificar_cadena
from .db import get_db
from .seguridad import ROLES, entero, requiere_rol, revocar_sesiones

bp = Blueprint("admin", __name__)
ADMIN = "ADMINISTRADOR"
AJUSTES = {
    "max_intentos_login": (3, 20),
    "minutos_bloqueo": (1, 1440),
    "minutos_inactividad_sesion": (5, 240),
    "horas_vida_sesion": (1, 24),
    "minutos_token_recuperacion": (5, 120),
}


def _usuario_objetivo(uid):
    u = get_db().execute("SELECT id, email, name, role, status FROM users WHERE id = ?", (uid,)).fetchone()
    if not u:
        abort(404)
    if u["id"] == g.user["id"]:
        # Evita autoescalamiento / autobloqueo: otro administrador debe hacerlo.
        flash("No puedes modificar tu propia cuenta desde aquí.", "error")
        return None
    return u


@bp.get("/usuarios")
@requiere_rol(ADMIN)
def usuarios():
    # Nunca se selecciona password_hash.
    lista = get_db().execute(
        "SELECT u.id, u.email, u.name, u.role, u.status, u.created_at, u.last_login, u.locked_until,"
        " (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.revoked = 0) AS sesiones"
        " FROM users u ORDER BY u.id").fetchall()
    return render_template("admin/usuarios.html", usuarios=lista, roles=ROLES)


@bp.post("/usuarios/<int:uid>/rol")
@requiere_rol(ADMIN)
def cambiar_rol(uid):
    rol = request.form.get("role")
    if rol not in ROLES:
        abort(400)
    u = _usuario_objetivo(uid)
    if u and u["role"] != rol:
        db = get_db()
        db.execute("UPDATE users SET role = ? WHERE id = ?", (rol, uid))
        db.commit()
        revocar_sesiones(uid)  # el nuevo rol aplica en la siguiente sesión
        registrar("ROLE_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"],
                  details={"usuario": uid, "antes": u["role"], "despues": rol})
        flash(f"Rol de {u['email']} cambiado a {rol}.", "ok")
    return redirect(url_for("admin.usuarios"))


@bp.post("/usuarios/<int:uid>/estado")
@requiere_rol(ADMIN)
def cambiar_estado(uid):
    estado = request.form.get("status")
    if estado not in ("ACTIVO", "DESACTIVADO"):
        abort(400)
    u = _usuario_objetivo(uid)
    if u and u["status"] != estado:
        db = get_db()
        db.execute("UPDATE users SET status = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?", (estado, uid))
        db.commit()
        if estado == "DESACTIVADO":
            revocar_sesiones(uid)
        registrar("ACCOUNT_DISABLED" if estado == "DESACTIVADO" else "ACCOUNT_ENABLED", "EXITO",
                  user_id=g.user["id"], email=g.user["email"], details={"usuario": uid})
        flash(f"Cuenta {u['email']}: {estado}.", "ok")
    return redirect(url_for("admin.usuarios"))


@bp.post("/usuarios/<int:uid>/revocar")
@requiere_rol(ADMIN)
def revocar(uid):
    u = get_db().execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchone()
    if not u:
        abort(404)
    n = revocar_sesiones(uid)
    registrar("SESSION_REVOKED", "EXITO", user_id=g.user["id"], email=g.user["email"],
              details={"usuario": uid, "sesiones": n})
    flash(f"{n} sesión(es) revocada(s) de {u['email']}.", "ok")
    return redirect(url_for("admin.usuarios"))


@bp.get("/sesiones")
@requiere_rol(ADMIN)
def sesiones():
    lista = get_db().execute(
        "SELECT substr(s.id, 1, 12) AS sid, u.email, s.created_at, s.last_seen, s.expires_at, s.ip, s.revoked"
        " FROM sessions s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC LIMIT 200").fetchall()
    return render_template("admin/sesiones.html", sesiones=lista)


@bp.get("/eventos")
@requiere_rol(ADMIN)
def eventos():
    tipo = (request.args.get("evento") or "").strip().upper()[:40]
    db = get_db()
    if tipo:
        lista = db.execute("SELECT * FROM security_events WHERE event = ? ORDER BY id DESC LIMIT 500", (tipo,)).fetchall()
    else:
        lista = db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 500").fetchall()
    tipos = [r["event"] for r in db.execute("SELECT DISTINCT event FROM security_events ORDER BY event")]
    integra, dato = verificar_cadena(db)
    return render_template("admin/eventos.html", eventos=lista, tipos=tipos, tipo=tipo, integra=integra, dato=dato)


@bp.get("/operaciones")
@requiere_rol(ADMIN)
def operaciones():
    db = get_db()
    resumen = {
        "usuarios": db.execute("SELECT role, COUNT(*) n FROM users GROUP BY role").fetchall(),
        "ordenes": db.execute("SELECT status, COUNT(*) n, COALESCE(SUM(total),0) total FROM orders GROUP BY status").fetchall(),
        "descargas": db.execute("SELECT COUNT(*) n FROM downloads").fetchone()["n"],
        "fallos_login_24h": db.execute(
            "SELECT COUNT(*) n FROM security_events WHERE event = 'LOGIN_FAILED'"
            " AND created_at > strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')").fetchone()["n"],
    }
    return render_template("admin/operaciones.html", r=resumen)


@bp.route("/configuracion", methods=["GET", "POST"])
@requiere_rol(ADMIN)
def configuracion():
    db = get_db()
    if request.method == "POST":
        cambios = {}
        for clave, (minimo, maximo) in AJUSTES.items():
            v = entero(request.form.get(clave))
            if v is None or not (minimo <= v <= maximo):
                flash(f"Valor inválido para {clave} (rango {minimo}-{maximo}).", "error")
                return redirect(url_for("admin.configuracion"))
            cambios[clave] = v
        for clave, v in cambios.items():
            db.execute("UPDATE settings SET value = ? WHERE key = ?", (str(v), clave))
        db.commit()
        registrar("SECURITY_CONFIG_CHANGED", "EXITO", user_id=g.user["id"], email=g.user["email"], details=cambios)
        flash("Configuración de seguridad actualizada.", "ok")
        return redirect(url_for("admin.configuracion"))
    valores = {r["key"]: r["value"] for r in db.execute("SELECT key, value FROM settings")}
    return render_template("admin/configuracion.html", valores=valores, ajustes=AJUSTES)


@bp.route("/rastrear", methods=["GET", "POST"])
@requiere_rol(ADMIN)
def rastrear():
    """Copia sospechosa -> extracción -> fingerprint -> usuario y orden."""
    resultados = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        datos = archivo.read() if archivo else b""
        if not datos.startswith(b"%PDF-"):
            flash("Sube un PDF.", "error")
            return redirect(url_for("admin.rastrear"))
        clave = cripto.leer_clave(current_app.config["FP_KEY_PATH"])
        db = get_db()
        resultados = []
        try:
            codigos_extraidos = huella.extraer_de_pdf(datos)
        except Exception:
            flash("El PDF no se puede leer o esta danado.", "error")
            return redirect(url_for("admin.rastrear"))
        for codigo in codigos_extraidos:
            info = huella.validar_codigo(codigo, clave)
            fila = db.execute(
                "SELECT d.*, u.email, u.name, p.name AS producto FROM downloads d JOIN users u ON u.id = d.user_id"
                " JOIN products p ON p.id = d.product_id WHERE d.fingerprint = ?", (codigo,)).fetchone() if info else None
            resultados.append({"codigo": codigo, "mac_valida": bool(info), "descarga": fila})
        if not resultados:
            # Respaldo: coincidencia exacta del hash de la copia entregada.
            fila = db.execute(
                "SELECT d.*, u.email, u.name, p.name AS producto FROM downloads d JOIN users u ON u.id = d.user_id"
                " JOIN products p ON p.id = d.product_id WHERE d.copy_hash = ?", (cripto.sha256_bytes(datos),)).fetchone()
            if fila:
                resultados.append({"codigo": fila["fingerprint"], "mac_valida": True, "descarga": fila})
        registrar("FINGERPRINT_TRACED", "EXITO" if resultados else "SIN_HUELLA", user_id=g.user["id"],
                  email=g.user["email"], details={"encontrados": len(resultados)})
    return render_template("admin/rastrear.html", resultados=resultados)
