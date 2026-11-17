
import argparse
import io
import json
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion import cripto  # noqa: E402
from aplicacion.config import configuracion_por_defecto  # noqa: E402

AAD = b"tienda-segura/respaldo/v1"


def _clave(cfg):
    ruta = cfg["SECRETS_DIR"] / "clave_respaldo.key"
    cripto.generar_clave_simetrica(ruta)
    return cripto.leer_clave(ruta)


def crear_respaldo(cfg, destino: Path | None = None) -> Path:
    destino = destino or (cfg["RAIZ"] / "respaldos")
    destino.mkdir(parents=True, exist_ok=True)
    marca = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        copia_db = tmp / "tienda.db"
        origen = sqlite3.connect(cfg["DB_PATH"])
        dest = sqlite3.connect(copia_db)
        origen.backup(dest)  # copia consistente aunque la app esté en uso
        dest.close()
        origen.close()
        manifiesto = {"creado": marca, "archivos": {"tienda.db": cripto.sha256_archivo(copia_db)}}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(copia_db, arcname="tienda.db")
            for f in sorted(cfg["PRODUCTS_DIR"].glob("*.enc")):
                tar.add(f, arcname=f"productos/{f.name}")
                manifiesto["archivos"][f"productos/{f.name}"] = cripto.sha256_archivo(f)
            datos = json.dumps(manifiesto, indent=2).encode()
            info = tarfile.TarInfo("manifiesto.json")
            info.size = len(datos)
            tar.addfile(info, io.BytesIO(datos))
    salida = destino / f"respaldo_{marca}.tar.gz.enc"
    salida.write_bytes(cripto.cifrar(buf.getvalue(), _clave(cfg), AAD))
    (destino / f"respaldo_{marca}.sha256").write_text(f"{cripto.sha256_archivo(salida)}  {salida.name}\n")
    return salida


def _abrir(cfg, archivo: Path):
    tar_bytes = cripto.descifrar(archivo.read_bytes(), _clave(cfg), AAD)
    tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz")
    manifiesto = json.loads(tar.extractfile("manifiesto.json").read())
    return tar, manifiesto


def verificar_respaldo(cfg, archivo: Path) -> dict:
    tar, manifiesto = _abrir(cfg, archivo)
    for nombre, esperado in manifiesto["archivos"].items():
        if cripto.sha256_bytes(tar.extractfile(nombre).read()) != esperado:
            raise ValueError(f"Hash incorrecto en {nombre}")
    return manifiesto


def restaurar_respaldo(cfg, archivo: Path) -> dict:
    manifiesto = verificar_respaldo(cfg, archivo)  # primero verificar, luego tocar nada
    tar, _ = _abrir(cfg, archivo)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for miembro in tar.getmembers():
            # Defensa contra path traversal en el tar.
            if miembro.name.startswith("/") or ".." in Path(miembro.name).parts:
                raise ValueError(f"Ruta peligrosa en respaldo: {miembro.name}")
        tar.extractall(tmp, filter="data")
        cfg["DB_PATH"].parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp / "tienda.db", cfg["DB_PATH"])
        cfg["PRODUCTS_DIR"].mkdir(parents=True, exist_ok=True)
        for f in (tmp / "productos").glob("*.enc"):
            shutil.copy2(f, cfg["PRODUCTS_DIR"] / f.name)
    return manifiesto


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("accion", choices=["crear", "restaurar", "verificar"])
    ap.add_argument("archivo", nargs="?")
    a = ap.parse_args()
    cfg = configuracion_por_defecto()
    if a.accion == "crear":
        print("Respaldo creado:", crear_respaldo(cfg))
    elif not a.archivo:
        ap.error("indica el archivo de respaldo")
    elif a.accion == "verificar":
        m = verificar_respaldo(cfg, Path(a.archivo))
        print(f"Respaldo íntegro ({len(m['archivos'])} archivos, creado {m['creado']}).")
    else:
        m = restaurar_respaldo(cfg, Path(a.archivo))
        print(f"Restaurados {len(m['archivos'])} archivos del respaldo {m['creado']}.")
