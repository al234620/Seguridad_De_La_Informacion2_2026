
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aplicacion.cripto import canonico, sha256_bytes, verificar_firma  # noqa: E402

if len(sys.argv) != 3:
    raise SystemExit(__doc__)
paquete = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
datos = canonico(paquete["comprobante"])
ok = verificar_firma(datos, paquete["firma"], Path(sys.argv[2]).read_bytes())
print(f"SHA-256 del comprobante: {sha256_bytes(datos)}")
print("FIRMA VÁLIDA: el comprobante es íntegro y auténtico." if ok else
      "FIRMA INVÁLIDA: el comprobante fue modificado o no fue emitido con esta clave.")
sys.exit(0 if ok else 1)
