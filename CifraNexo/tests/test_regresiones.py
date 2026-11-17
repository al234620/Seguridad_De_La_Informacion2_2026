import io
import ipaddress

from cryptography import x509
from aplicacion import cripto
from aplicacion.db import conectar
from scripts.crear_ca import crear
from .conftest import comprar


def test_pki_incluye_ip_tailscale(tmp_path):
    ruta = crear(tmp_path / 'certs', ['100.101.102.103'])
    cert = x509.load_pem_x509_certificate((ruta / 'servidor.crt').read_bytes())
    nombres = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address('100.101.102.103') in nombres.get_values_for_type(x509.IPAddress)
    assert 'localhost' in nombres.get_values_for_type(x509.DNSName)


def test_pdf_corrupto_con_cabecera_valida_rechazado(nav, cfg):
    o = nav()
    o.login('operador@demo.local')
    r = o.post('/operador/productos/nuevo', {
        'name': 'PDF roto', 'price': '100.00',
        'archivo': (io.BytesIO(b'%PDF-1.7\ncontenido falso'), 'documento.pdf')
    }, desde='/operador/productos/nuevo', content_type='multipart/form-data')
    assert r.status_code == 400
    db = conectar(cfg['DB_PATH'])
    assert db.execute('SELECT COUNT(*) FROM products').fetchone()[0] == 3


def test_pago_no_queda_pagado_si_firma_falla(nav, cfg, monkeypatch):
    n = nav()
    n.login('cliente@demo.local')
    n.post('/carrito/agregar/1', desde='/')
    r = n.post('/ordenes/crear', desde='/carrito')
    oid = int(r.headers['Location'].rstrip('/').split('/')[-2])

    def falla(*args, **kwargs):
        raise RuntimeError('Simulacion de fallo al firmar')

    monkeypatch.setattr(cripto, 'firmar', falla)
    r = n.post(f'/ordenes/{oid}/pagar', {'resultado':'APROBADO'}, desde=f'/ordenes/{oid}/pagar')
    assert r.status_code == 500
    db = conectar(cfg['DB_PATH'])
    assert db.execute('SELECT status FROM orders WHERE id=?', (oid,)).fetchone()[0] == 'PENDIENTE'
    assert db.execute('SELECT COUNT(*) FROM payments WHERE order_id=?', (oid,)).fetchone()[0] == 0
    assert db.execute('SELECT COUNT(*) FROM receipts WHERE order_id=?', (oid,)).fetchone()[0] == 0


def test_operador_no_reactiva_cancelada(nav, cfg):
    cliente=nav()
    cliente.login('cliente@demo.local')
    oid = comprar(cliente)
    operador=nav()
    operador.login('operador@demo.local')
    operador.post(f'/operador/ordenes/{oid}/estado', {'status':'CANCELADA'}, desde='/operador/ordenes')
    operador.post(f'/operador/ordenes/{oid}/estado', {'status':'ENTREGADA'}, desde='/operador/ordenes')
    db=conectar(cfg['DB_PATH'])
    assert db.execute('SELECT status FROM orders WHERE id=?', (oid,)).fetchone()[0] == 'CANCELADA'
