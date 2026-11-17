
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion import cripto, huella  # noqa: E402
from aplicacion.config import configuracion_por_defecto  # noqa: E402
from aplicacion.db import conectar  # noqa: E402

if len(sys.argv) != 2:
    raise SystemExit(__doc__)
cfg = configuracion_por_defecto()
datos = Path(sys.argv[1]).read_bytes()
clave = cripto.leer_clave(cfg["FP_KEY_PATH"])
codigos = huella.extraer_de_pdf(datos)
if not codigos:
    print("No se encontró fingerprint en el archivo.")
    sys.exit(1)
conn = conectar(cfg["DB_PATH"])
for c in codigos:
    info = huella.validar_codigo(c, clave)
    print(f"Fingerprint: {c}")
    print(f"  HMAC: {'VÁLIDO' if info else 'INVÁLIDO (falsificado o alterado)'}")
    if info:
        d = conn.execute(
            "SELECT d.*, u.email, u.name, p.name AS producto FROM downloads d JOIN users u ON u.id = d.user_id"
            " JOIN products p ON p.id = d.product_id WHERE d.fingerprint = ?", (c,)).fetchone()
        if d:
            print(f"  Usuario: {d['name']} <{d['email']}> (id {d['user_id']})")
            print(f"  Orden:   #{d['order_id']}  Producto: {d['producto']}")
            print(f"  Descarga: {d['created_at']} desde {d['ip']}")
        else:
            print(f"  Usuario id {info['user_id']}, orden #{info['order_id']} (sin registro de descarga en esta BD)")
