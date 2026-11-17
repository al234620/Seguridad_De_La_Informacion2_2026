
import os
import ssl

from . import create_app


def contexto_tls(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4:!3DES")
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    app = create_app()
    cfg = app.config
    if not cfg["TLS_CERT"].exists():
        raise SystemExit("Falta el certificado. Ejecuta: python scripts/crear_ca.py [--ip IP_TAILSCALE]")
    host = os.environ.get("TIENDA_HOST", "127.0.0.1")
    port = int(os.environ.get("TIENDA_PUERTO", "8443"))
    print(f"Servidor HTTPS disponible en https://{host}:{port}  (Ctrl+C para detener)")
    print("Uso academico en red privada: NO exponer el puerto al Internet publico.")
    app.run(host=host, port=port, ssl_context=contexto_tls(cfg["TLS_CERT"], cfg["TLS_KEY"]), debug=False)


if __name__ == "__main__":
    main()
