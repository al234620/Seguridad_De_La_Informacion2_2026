
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion import cripto  # noqa: E402
from aplicacion.bitacora import verificar_cadena  # noqa: E402
from aplicacion.config import configuracion_por_defecto  # noqa: E402
from aplicacion.db import conectar  # noqa: E402

cfg = configuracion_por_defecto()
args = sys.argv[1:]
if args == ["--productos"]:
    conn = conectar(cfg["DB_PATH"])
    clave = cripto.leer_clave(cfg["DATA_KEY_PATH"])
    ok = True
    for p in conn.execute("SELECT id, name, file_name, file_hash FROM products"):
        try:
            real = cripto.sha256_bytes(cripto.descifrar((cfg["PRODUCTS_DIR"] / p["file_name"]).read_bytes(), clave))
            estado = "OK" if real == p["file_hash"] else "HASH DIFERENTE"
        except (ValueError, FileNotFoundError) as e:
            estado = f"ERROR ({e})"
        ok &= estado == "OK"
        print(f"[{estado}] #{p['id']} {p['name']}")
    sys.exit(0 if ok else 1)
elif args == ["--bitacora"]:
    integra, dato = verificar_cadena(conectar(cfg["DB_PATH"]))
    print(f"Bitácora íntegra: {dato} registros." if integra else f"Bitácora ALTERADA en el registro #{dato}.")
    sys.exit(0 if integra else 1)
elif len(args) == 2:
    real = cripto.sha256_archivo(args[0])
    print(f"Esperado: {args[1].lower()}\nObtenido: {real}")
    print("HASH ESPERADO: archivo íntegro." if real == args[1].lower() else "HASH DIFERENTE: archivo modificado.")
    sys.exit(0 if real == args[1].lower() else 1)
else:
    raise SystemExit(__doc__)
