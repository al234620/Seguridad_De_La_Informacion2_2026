import argparse
import ipaddress
from pathlib import Path
from cryptography import x509

RAIZ=Path(__file__).resolve().parent.parent

def verificar(ruta, direccion):
    cert=x509.load_pem_x509_certificate(Path(ruta).read_bytes())
    san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        ip=ipaddress.ip_address(direccion)
        return ip in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        return direccion in san.get_values_for_type(x509.DNSName)

if __name__=='__main__':
    a=argparse.ArgumentParser()
    a.add_argument('--ip',default='localhost')
    a.add_argument('--cert',type=Path,default=RAIZ/'certificados'/'servidor.crt')
    args=a.parse_args()
    try:
        bien=verificar(args.cert,args.ip)
    except (OSError,ValueError,x509.ExtensionNotFound) as e:
        print('ERROR certificado:',e)
        raise SystemExit(1)
    print('OK: certificado cubre',args.ip) if bien else print('ERROR: certificado NO cubre',args.ip)
    raise SystemExit(0 if bien else 1)
