
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
EVIDENCIAS = RAIZ / "evidencias"

from aplicacion import create_app  # noqa: E402
from aplicacion.config import configuracion_por_defecto  # noqa: E402
from scripts.inicializar import inicializar  # noqa: E402

PWD = {
    "cliente@demo.local": "ClienteSeguro2026",
    "cliente2@demo.local": "OtroCliente2026",
    "operador@demo.local": "OperadorSeguro2026",
    "admin@demo.local": "AdminSeguro2026x",
}


@pytest.fixture()
def cfg(tmp_path):
    c = configuracion_por_defecto()
    c.update({
        "RAIZ": tmp_path,
        "DB_PATH": tmp_path / "base_de_datos" / "tienda.db",
        "PRODUCTS_DIR": tmp_path / "productos",
        "SECRETS_DIR": tmp_path / "secretos",
        "SIGNING_KEY_PATH": tmp_path / "secretos" / "firma_privada.pem",
        "PUBLIC_KEY_PATH": tmp_path / "claves_publicas" / "firma_publica.pem",
        "DATA_KEY_PATH": tmp_path / "secretos" / "clave_datos.key",
        "FP_KEY_PATH": tmp_path / "secretos" / "clave_huella.key",
        "FLASK_KEY_PATH": tmp_path / "secretos" / "clave_flask.key",
        "OUTBOX_DIR": tmp_path / "buzon",
        "LOG_PATH": tmp_path / "logs" / "seguridad.log",
        "TESTING": True,
    })
    inicializar(c)
    return c


@pytest.fixture()
def app(cfg):
    return create_app(cfg)


class Navegador:
    """Cliente de prueba sobre HTTPS que maneja el token CSRF."""

    def __init__(self, app):
        self.c = app.test_client()
        self.c.environ_base["wsgi.url_scheme"] = "https"
        self.c.environ_base["REMOTE_ADDR"] = "192.0.2.10"

    def csrf(self, ruta="/login"):
        html = self.c.get(ruta).get_data(as_text=True)
        m = re.search(r'name="csrf_token" value="([^"]+)"', html)
        return m.group(1) if m else ""

    def get(self, ruta, **kw):
        return self.c.get(ruta, **kw)

    def post(self, ruta, datos=None, desde="/login", **kw):
        datos = dict(datos or {})
        datos.setdefault("csrf_token", self.csrf(desde))
        return self.c.post(ruta, data=datos, **kw)

    def login(self, email, password=None):
        return self.post("/login", {"email": email, "password": password or PWD[email]})


@pytest.fixture()
def nav(app):
    return lambda: Navegador(app)


def comprar(n, producto_id=1, resultado="APROBADO"):
    """Flujo completo de compra para un navegador ya autenticado como CLIENTE."""
    n.post(f"/carrito/agregar/{producto_id}", desde="/")
    r = n.post("/ordenes/crear", desde="/carrito")
    oid = int(r.headers["Location"].rstrip("/").split("/")[-2])
    n.post(f"/ordenes/{oid}/pagar", {"resultado": resultado}, desde=f"/ordenes/{oid}/pagar")
    return oid


# --------------------------------------------------- reporte de evidencias
_resultados = []


def pytest_configure(config):
    config.addinivalue_line("markers", "evidencia(num, prueba, esperado): prueba obligatoria del enunciado")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    salida = yield
    rep = salida.get_result()
    m = item.get_closest_marker("evidencia")
    if m and rep.when == "call":
        num, prueba, esperado = m.args
        _resultados.append((num, prueba, esperado, "APROBADA" if rep.passed else "FALLIDA",
                            " ".join((item.function.__doc__ or "").split()),
                            item.nodeid))


def pytest_sessionfinish(session, exitstatus):
    if not _resultados:
        return
    EVIDENCIAS.mkdir(exist_ok=True)
    filas = sorted(_resultados, key=lambda r: (isinstance(r[0], str), int(str(r[0]).lstrip("A"))))
    lineas = [
        "# Reporte de pruebas obligatorias",
        "",
        f"Generado automáticamente por `pytest` el {datetime.now():%Y-%m-%d %H:%M:%S}.",
        "",
        "| # | Prueba | Resultado esperado | Estado | Qué se verificó | Prueba automatizada |",
        "|---|---|---|---|---|---|",
    ]
    for num, prueba, esperado, estado, doc, nodo in filas:
        icono = "✅" if estado == "APROBADA" else "❌"
        lineas.append(f"| {num} | {prueba} | {esperado} | {icono} {estado} | {doc} | `{nodo}` |")
    aprobadas = sum(1 for r in filas if r[3] == "APROBADA")
    lineas += ["", f"**{aprobadas} de {len(filas)} pruebas aprobadas.**", "",
               "Los archivos de apoyo (copia con fingerprint, comprobantes original y alterado, respaldo) "
               "están en `evidencias/artefactos/`."]
    (EVIDENCIAS / "reporte_pruebas.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")


def guardar_evidencia(nombre, datos: bytes | str):
    d = EVIDENCIAS / "artefactos"
    d.mkdir(parents=True, exist_ok=True)
    (d / nombre).write_bytes(datos.encode() if isinstance(datos, str) else datos)


def copiar_evidencia(origen: Path, nombre: str):
    d = EVIDENCIAS / "artefactos"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(origen, d / nombre)
