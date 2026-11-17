
import json
import logging

from flask import has_request_context, request

from .cripto import sha256_bytes
from .db import ahora, get_db

GENESIS = "0" * 64
_log = logging.getLogger("seguridad")


def _material(prev_hash, created_at, user_id, email, event, result, source, details):
    return json.dumps([prev_hash, created_at, user_id, email, event, result, source, details],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def registrar(event, result, user_id=None, email=None, details=None, db=None):
    db = db or get_db()
    source = request.remote_addr if has_request_context() else "sistema"
    if details is not None and not isinstance(details, str):
        details = json.dumps(details, ensure_ascii=False, sort_keys=True)
    created_at = ahora()
    fila = db.execute("SELECT hash FROM security_events ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = fila["hash"] if fila else GENESIS
    h = sha256_bytes(_material(prev_hash, created_at, user_id, email, event, result, source, details))
    db.execute(
        "INSERT INTO security_events(user_id, email, event, result, source, details, created_at, prev_hash, hash)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (user_id, email, event, result, source, details, created_at, prev_hash, h))
    db.commit()
    try:
        _log.info("%s %s user=%s email=%s origen=%s %s", event, result, user_id, email, source, details or "")
    except Exception:  # el log de archivo nunca debe tumbar la operación
        pass


def verificar_cadena(db=None):
    """Devuelve (True, n) si la cadena está íntegra, o (False, id_roto)."""
    db = db or get_db()
    prev = GENESIS
    n = 0
    for r in db.execute("SELECT * FROM security_events ORDER BY id"):
        esperado = sha256_bytes(_material(prev, r["created_at"], r["user_id"], r["email"], r["event"],
                                          r["result"], r["source"], r["details"]))
        if r["prev_hash"] != prev or r["hash"] != esperado:
            return False, r["id"]
        prev = r["hash"]
        n += 1
    return True, n


def configurar_log_archivo(app):
    ruta = app.config["LOG_PATH"]
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(ruta) for h in _log.handlers):
        h = logging.FileHandler(ruta, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        _log.addHandler(h)
    _log.setLevel(logging.INFO)
    _log.propagate = False
