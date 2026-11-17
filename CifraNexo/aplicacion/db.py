
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, g


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def en(delta: timedelta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def conectar(ruta):
    conn = sqlite3.connect(ruta)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = conectar(current_app.config["DB_PATH"])
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def crear_esquema(ruta_db, ruta_schema):
    conn = conectar(ruta_db)
    with open(ruta_schema, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def ajuste(clave, defecto):
    fila = get_db().execute("SELECT value FROM settings WHERE key = ?", (clave,)).fetchone()
    try:
        return int(fila["value"]) if fila else defecto
    except ValueError:
        return defecto
