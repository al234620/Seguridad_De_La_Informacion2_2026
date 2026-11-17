
import io
import re
import secrets

from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import Color
from reportlab.pdfgen import canvas

from .cripto import hmac_sha256

PATRON = re.compile(r"FP1\.u(\d+)\.o(\d+)\.d([0-9a-f]{12})\.([0-9a-f]{20})")


def nuevo_id_descarga() -> str:
    return secrets.token_hex(6)


def generar_codigo(user_id: int, order_id: int, id_descarga: str, clave: bytes) -> str:
    base = f"FP1.u{user_id}.o{order_id}.d{id_descarga}"
    return f"{base}.{hmac_sha256(clave, base.encode())[:20]}"


def validar_codigo(codigo: str, clave: bytes) -> dict | None:
    m = PATRON.fullmatch(codigo)
    if not m:
        return None
    u, o, d, mac = m.groups()
    esperado = generar_codigo(int(u), int(o), d, clave)
    if not secrets.compare_digest(esperado, codigo):
        return None
    return {"user_id": int(u), "order_id": int(o), "id_descarga": d, "codigo": codigo}


def _capa(ancho, alto, codigo, texto_visible) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ancho, alto))
    # Canal 1: visible, discreto.
    c.setFont("Helvetica", 7)
    c.setFillColor(Color(0.45, 0.45, 0.45))
    c.drawString(36, 18, texto_visible[:150])
    # Canal 2: invisible (Tr 3 = ni relleno ni trazo).
    for (x, y) in ((40, alto - 30), (ancho / 3, alto / 2), (40, 30)):
        t = c.beginText(x, y)
        t.setTextRenderMode(3)
        t.setFont("Helvetica", 6)
        t.textLine(codigo)
        c.drawText(t)
    c.showPage()
    c.save()
    return buf.getvalue()


def insertar_en_pdf(pdf: bytes, codigo: str, texto_visible: str) -> bytes:
    lector = PdfReader(io.BytesIO(pdf))
    escritor = PdfWriter(clone_from=lector)
    for pagina in escritor.pages:
        ancho, alto = float(pagina.mediabox.width), float(pagina.mediabox.height)
        capa = PdfReader(io.BytesIO(_capa(ancho, alto, codigo, texto_visible))).pages[0]
        pagina.merge_page(capa)
    meta = dict(lector.metadata or {})
    meta.update({"/Fingerprint": codigo, "/Licencia": texto_visible})
    escritor.add_metadata(meta)
    salida = io.BytesIO()
    escritor.write(salida)
    return salida.getvalue()


def extraer_de_pdf(pdf: bytes) -> list[str]:
    """Busca códigos en texto (incluido invisible) y metadatos."""
    encontrados = []
    lector = PdfReader(io.BytesIO(pdf))
    for pagina in lector.pages:
        try:
            encontrados += [m.group(0) for m in PATRON.finditer(pagina.extract_text() or "")]
        except Exception:
            continue
    meta = lector.metadata or {}
    if meta.get("/Fingerprint"):
        encontrados += [m.group(0) for m in PATRON.finditer(str(meta["/Fingerprint"]))]
    # Sin duplicados, conservando el orden.
    return list(dict.fromkeys(encontrados))
