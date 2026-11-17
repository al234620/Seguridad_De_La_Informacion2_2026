
import hashlib
import hmac
import re
import secrets
from datetime import timedelta
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import abort, current_app, g, request, session

from .bitacora import registrar
from .db import ahora, ajuste, en, get_db

# Argon2id con parámetros recomendados por OWASP (m=19 MiB, t=2, p=1) o
# superiores. La biblioteca genera y guarda la sal dentro del hash.
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)
# Hash ficticio para igualar tiempos cuando el correo no existe.
_HASH_FICTICIO = _ph.hash("contrasena-ficticia-para-igualar-tiempos")

ROLES = ("CLIENTE", "OPERADOR", "ADMINISTRADOR")


# ------------------------------------------------------------ contraseñas
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verificar_password(password_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(password_hash or _HASH_FICTICIO, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def necesita_rehash(password_hash: str) -> bool:
    return _ph.check_needs_rehash(password_hash)


# -------------------------------------------------------------- validación
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,24}$")


def validar_email(email: str) -> str | None:
    email = (email or "").strip().lower()
    return email if _RE_EMAIL.fullmatch(email) else None


def validar_password(password: str, email: str = "") -> list[str]:
    errores = []
    if len(password or "") < 12:
        errores.append("La contraseña debe tener al menos 12 caracteres.")
    if len(password or "") > 128:
        errores.append("La contraseña no puede exceder 128 caracteres.")
    if password and not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        errores.append("La contraseña debe combinar letras y números.")
    if email and password and email.split("@")[0].lower() in password.lower():
        errores.append("La contraseña no debe contener tu correo.")
    return errores


def texto(valor, max_len, requerido=True) -> str | None:
    valor = (valor or "").strip()
    if (requerido and not valor) or len(valor) > max_len:
        return None
    # Quita caracteres de control (excepto saltos de línea).
    return "".join(c for c in valor if c in "\n\t" or ord(c) >= 32)


def precio_a_centavos(valor: str) -> int | None:
    valor = (valor or "").strip().replace(",", "")
    if not re.fullmatch(r"\d{1,7}(\.\d{1,2})?", valor):
        return None
    entero, _, dec = valor.partition(".")
    return int(entero) * 100 + int((dec + "00")[:2])


def entero(valor) -> int | None:
    try:
        n = int(valor)
        return n if 0 < n < 2**31 else None
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ CSRF
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def verificar_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        enviado = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        esperado = session.get("csrf", "")
        if not esperado or not hmac.compare_digest(enviado, esperado):
            registrar("CSRF_FAILED", "DENEGADO", user_id=getattr(g, "user", None) and g.user["id"],
                      details={"ruta": request.path})
            abort(400)


# --------------------------------------------------------------- sesiones
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def crear_sesion(user_id: int) -> str:
    db = get_db()
    token = secrets.token_urlsafe(32)
    horas = ajuste("horas_vida_sesion", 8)
    db.execute(
        "INSERT INTO sessions(id, user_id, created_at, last_seen, expires_at, ip, user_agent)"
        " VALUES (?,?,?,?,?,?,?)",
        (_hash_token(token), user_id, ahora(), ahora(), en(timedelta(hours=horas)),
         request.remote_addr, (request.user_agent.string or "")[:200]))
    db.commit()
    # Fijación de sesión: un nuevo token CSRF tras autenticarse.
    session.clear()
    session["csrf"] = secrets.token_urlsafe(32)
    return token


def poner_cookie_sesion(resp, token):
    resp.set_cookie(current_app.config["AUTH_COOKIE"], token, httponly=True, secure=True,
                    samesite="Strict", path="/")
    return resp


def borrar_cookie_sesion(resp):
    resp.delete_cookie(current_app.config["AUTH_COOKIE"], path="/", secure=True, samesite="Strict")
    return resp


def cargar_usuario():
    g.user = None
    g.sesion_id = None
    token = request.cookies.get(current_app.config["AUTH_COOKIE"])
    if not token:
        return
    db = get_db()
    sid = _hash_token(token)
    fila = db.execute(
        "SELECT s.id AS sid, s.last_seen, s.expires_at, s.revoked, u.id, u.email, u.name, u.role, u.status"
        " FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?", (sid,)).fetchone()
    if not fila or fila["revoked"] or fila["status"] != "ACTIVO":
        return
    limite_inactividad = en(-timedelta(minutes=ajuste("minutos_inactividad_sesion", 30)))
    if fila["expires_at"] < ahora() or fila["last_seen"] < limite_inactividad:
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (sid,))
        db.commit()
        return
    db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (ahora(), sid))
    db.commit()
    g.user = {k: fila[k] for k in ("id", "email", "name", "role", "status")}
    g.sesion_id = sid


def cerrar_sesion_actual():
    if g.get("sesion_id"):
        db = get_db()
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.sesion_id,))
        db.commit()
    session.clear()


def revocar_sesiones(user_id: int) -> int:
    db = get_db()
    cur = db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,))
    db.commit()
    return cur.rowcount


# ---------------------------------------------- control de acceso (RBAC)
def requiere_login(f):
    @wraps(f)
    def envoltura(*a, **kw):
        if not g.get("user"):
            abort(401)
        return f(*a, **kw)
    return envoltura


def requiere_rol(*roles):
    """Privilegio mínimo: cada ruta declara exactamente qué roles la usan."""
    def decorador(f):
        @wraps(f)
        def envoltura(*a, **kw):
            if not g.get("user"):
                abort(401)
            if g.user["role"] not in roles:
                registrar("ACCESS_DENIED", "DENEGADO", user_id=g.user["id"], email=g.user["email"],
                          details={"ruta": request.path, "rol": g.user["role"], "requerido": list(roles)})
                abort(403)
            return f(*a, **kw)
        return envoltura
    return decorador


# ----------------------------------------------------- cabeceras seguras
def cabeceras_seguras(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if g.get("user"):
        resp.headers["Cache-Control"] = "no-store"
    resp.headers.pop("Server", None)
    return resp
