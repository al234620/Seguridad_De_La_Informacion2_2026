
set -euo pipefail
DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/certificados}"
mkdir -p "$DEST"
cd "$DEST"
umask 077

DIAS_CA=1825      # 5 años
DIAS_SERVIDOR=397 # máximo aceptado por navegadores

if [[ ! -f ca.key ]]; then
  echo "[1/3] Creando CA local (RSA 4096)…"
  openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -key ca.key -sha256 -days "$DIAS_CA" -out ca.crt \
    -subj "/C=MX/ST=Chihuahua/O=Proyecto Tienda Segura/OU=PKI Academica/CN=Tienda Segura CA Raiz" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
fi

echo "[2/3] Emitiendo certificado del servidor (RSA 2048, SAN localhost)…"
openssl genrsa -out servidor.key 2048 2>/dev/null
openssl req -new -key servidor.key -out servidor.csr \
  -subj "/C=MX/ST=Chihuahua/O=Proyecto Tienda Segura/CN=localhost"
cat > servidor.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:tienda.local,IP:127.0.0.1
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in servidor.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out servidor.crt -days "$DIAS_SERVIDOR" -sha256 -extfile servidor.ext 2>/dev/null
rm -f servidor.csr servidor.ext

echo "[3/3] Creando certificado NO confiable (autofirmado, para la prueba de rechazo)…"
openssl req -x509 -newkey rsa:2048 -nodes -keyout no_confiable.key -out no_confiable.crt \
  -days 30 -sha256 -subj "/CN=localhost/O=Atacante" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

chmod 600 ./*.key
chmod 644 ./*.crt
echo
echo "Verificación de la cadena:"
openssl verify -CAfile ca.crt servidor.crt
echo
echo "Listo. Importa $DEST/ca.crt como CA de confianza en tu navegador o sistema."
