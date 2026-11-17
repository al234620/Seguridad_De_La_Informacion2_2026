
import hashlib
import secrets
from datetime import timedelta

from flask import (Blueprint, abort, current_app, flash, g, make_response, redirect,
                   render_template, request, send_file, url_for)

from .bitacora import registrar
from .db import ahora, ajuste, en, get_db
from .seguridad import (borrar_cookie_sesion, cerrar_sesion_actual, crear_sesion, hash_password,
                        necesita_rehash, poner_cookie_sesion, revocar_sesiones, texto,
                        validar_email, validar_password, verificar_password)

bp = Blueprint("publico", __name__)

MSG_LOGIN = "Correo o contraseña incorrectos."  # genérico: no revela si el correo existe


@bp.get("/")
def catalogo():
    productos = get_db().execute(
        "SELECT id, name, description, price FROM products WHERE status = 'ACTIVO' ORDER BY name").fetchall()
    return render_template("catalogo.html", productos=productos)


@bp.get("/producto/<int:pid>")
def producto(pid):
    p = get_db().execute(
        "SELECT id, name, description, price, file_hash FROM products WHERE id = ? AND status = 'ACTIVO'",
        (pid,)).fetchone()
    if not p:
        abort(404)
    return render_template("producto.html", p=p)


@bp.get("/clave-publica.pem")
def clave_publica():
    return send_file(current_app.config["PUBLIC_KEY_PATH"], mimetype="application/x-pem-file",
                     as_attachment=True, download_name="firma_publica.pem")


# ------------------------------------------------------------- registro
@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        nombre = texto(request.form.get("name"), 80)
        password = request.form.get("password", "")
        errores = []
        if not email:
            errores.append("Correo inválido.")
        if not nombre:
            errores.append("Nombre inválido (1 a 80 caracteres).")
        errores += validar_password(password, email or "")
        if password != request.form.get("password2", ""):
            errores.append("Las contraseñas no coinciden.")
        if not errores:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                errores.append("No fue posible crear la cuenta con esos datos.")
            else:
                # El registro público SIEMPRE crea rol CLIENTE (no se acepta 'role' del formulario).
                cur = db.execute(
                    "INSERT INTO users(email, password_hash, name, role, status, created_at)"
                    " VALUES (?,?,?,'CLIENTE','ACTIVO',?)", (email, hash_password(password), nombre, ahora()))
                db.commit()
                registrar("USER_REGISTERED", "EXITO", user_id=cur.lastrowid, email=email)
                flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
                return redirect(url_for("publico.login"))
        for e in errores:
            flash(e, "error")
    return render_template("registro.html")


# --------------------------------------------------------------- login
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    db = get_db()
    email = validar_email(request.form.get("email")) or ""
    password = request.form.get("password", "")
    u = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone() if email else None

    if u and u["locked_until"] and u["locked_until"] > ahora():
        registrar("LOGIN_FAILED", "BLOQUEADO", user_id=u["id"], email=email, details="cuenta bloqueada temporalmente")
        flash("Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.", "error")
        return render_template("login.html"), 401

    ok = verificar_password(u["password_hash"] if u else None, password)
    if not ok or not u or u["status"] != "ACTIVO":
        if u:
            intentos = u["failed_attempts"] + 1
            bloqueo = None
            if intentos >= ajuste("max_intentos_login", 5):
                bloqueo = en(timedelta(minutes=ajuste("minutos_bloqueo", 15)))
                intentos = 0
                registrar("ACCOUNT_LOCKED", "EXITO", user_id=u["id"], email=email)
            db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                       (intentos, bloqueo, u["id"]))
            db.commit()
        motivo = "cuenta desactivada" if (u and ok) else "credenciales inválidas"
        registrar("LOGIN_FAILED", "FALLO", user_id=u["id"] if u else None, email=email or None, details=motivo)
        flash(MSG_LOGIN, "error")
        return render_template("login.html"), 401

    if necesita_rehash(u["password_hash"]):
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), u["id"]))
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
               (ahora(), u["id"]))
    db.commit()
    token = crear_sesion(u["id"])
    registrar("LOGIN_SUCCESS", "EXITO", user_id=u["id"], email=email)
    destino = {"OPERADOR": "operador.productos", "ADMINISTRADOR": "admin.usuarios"}.get(u["role"], "publico.catalogo")
    return poner_cookie_sesion(make_response(redirect(url_for(destino))), token)


@bp.post("/logout")
def logout():
    if g.user:
        registrar("LOGOUT", "EXITO", user_id=g.user["id"], email=g.user["email"])
    cerrar_sesion_actual()
    flash("Sesión cerrada.", "ok")
    return borrar_cookie_sesion(make_response(redirect(url_for("publico.catalogo"))))


# --------------------------------------------- recuperación de contraseña
def _hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        db = get_db()
        u = db.execute("SELECT id, email FROM users WHERE email = ? AND status = 'ACTIVO'",
                       (email,)).fetchone() if email else None
        if u:
            token = secrets.token_urlsafe(32)
            minutos = ajuste("minutos_token_recuperacion", 20)
            # Un token nuevo invalida los anteriores pendientes.
            db.execute("UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                       (ahora(), u["id"]))
            db.execute("INSERT INTO password_resets(user_id, token_hash, created_at, expires_at) VALUES (?,?,?,?)",
                       (u["id"], _hash_token(token), ahora(), en(timedelta(minutes=minutos))))
            db.commit()
            _enviar_correo_simulado(u["email"], url_for("publico.restablecer", token=token, _external=True), minutos)
            registrar("PASSWORD_RESET", "SOLICITADO", user_id=u["id"], email=u["email"])
        else:
            registrar("PASSWORD_RESET", "SOLICITADO_SIN_CUENTA", email=email)
        # Misma respuesta exista o no la cuenta (evita enumeración de usuarios).
        flash("Si el correo está registrado, recibirás un enlace temporal de recuperación.", "ok")
        return redirect(url_for("publico.login"))
    return render_template("recuperar.html")


def _enviar_correo_simulado(destino, enlace, minutos):
    """No hay servidor de correo: el mensaje se escribe en buzon/ (simulación)."""
    carpeta = current_app.config["OUTBOX_DIR"]
    carpeta.mkdir(parents=True, exist_ok=True)
    nombre = f"{ahora().replace(':', '')}_{destino}.txt"
    (carpeta / nombre).write_text(
        f"Para: {destino}\nAsunto: Recuperación de contraseña\n\n"
        f"Usa este enlace para definir una nueva contraseña (válido {minutos} minutos, un solo uso):\n{enlace}\n\n"
        "Nunca te enviaremos tu contraseña anterior.\n", encoding="utf-8")


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
def restablecer(token):
    db = get_db()
    r = db.execute(
        "SELECT pr.id, pr.user_id, u.email FROM password_resets pr JOIN users u ON u.id = pr.user_id"
        " WHERE pr.token_hash = ? AND pr.used_at IS NULL AND pr.expires_at > ?",
        (_hash_token(token), ahora())).fetchone()
    if not r:
        registrar("PASSWORD_RESET", "TOKEN_INVALIDO")
        flash("El enlace no es válido o ya expiró.", "error")
        return redirect(url_for("publico.recuperar"))
    if request.method == "POST":
        password = request.form.get("password", "")
        errores = validar_password(password, r["email"])
        if password != request.form.get("password2", ""):
            errores.append("Las contraseñas no coinciden.")
        if not errores:
            db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
                       (hash_password(password), r["user_id"]))
            db.execute("UPDATE password_resets SET used_at = ? WHERE id = ?", (ahora(), r["id"]))
            db.commit()
            revocar_sesiones(r["user_id"])  # cierra sesiones abiertas con la contraseña vieja
            registrar("PASSWORD_RESET", "EXITO", user_id=r["user_id"], email=r["email"])
            flash("Contraseña actualizada. Inicia sesión.", "ok")
            return redirect(url_for("publico.login"))
        for e in errores:
            flash(e, "error")
    return render_template("restablecer.html", token=token)
