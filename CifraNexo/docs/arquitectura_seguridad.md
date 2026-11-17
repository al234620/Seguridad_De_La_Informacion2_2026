# Arquitectura de seguridad

## 1. Arquitectura general

```
                         Internet
            ┌───────────────┴────────────────┐
            │ 443/tcp (HTTPS)                │ 51820/udp (VPN WireGuard)
            ▼                                ▼
   ┌──────────────────┐            ┌──────────────────────┐
   │ Clientes         │            │ Administrador        │
   │ (navegador)      │            │ VPN → red 10.10.0.0/24│
   └────────┬─────────┘            └──────────┬───────────┘
            │ TLS 1.2/1.3, cert. CA local      │ SSH (llaves, sin root)
            ▼                                  ▼
   ┌───────────────────────────────────────────────────────┐
   │ Servidor de aplicación (Flask)                        │
   │  ├─ Autenticación + sesiones + RBAC  (seguridad.py)    │
   │  ├─ Módulo criptográfico             (cripto.py)       │
   │  ├─ Firma digital de comprobantes    (cripto.py)       │
   │  ├─ Fingerprinting                   (huella.py)       │
   │  └─ Registro de eventos              (bitacora.py)     │
   │        │                 │                    │        │
   │  Base de datos      productos/*.enc     secretos/ (600)│
   │  (SQLite)           AES-256-GCM         fuera del repo │
   └───────────────────────────────────────────────────────┘
```

## 2. Servicios de seguridad y el mecanismo que los aporta

| Servicio | Mecanismo en el sistema | Dónde |
|---|---|---|
| **Confidencialidad** | HTTPS/TLS para todo el tráfico; productos cifrados en reposo con AES-256-GCM; contraseñas solo como hash Argon2id; tokens de sesión y de recuperación guardados como SHA-256; claves privadas fuera del repositorio con permisos 600; VPN para la administración | `servidor.py`, `cripto.py`, `seguridad.py`, `scripts/crear_ca.py` |
| **Integridad** | SHA-256 de cada producto verificado antes de cada descarga; etiqueta GCM detecta archivos cifrados alterados; firma digital del comprobante; bitácora encadenada con SHA-256 y protegida por triggers; manifiesto SHA-256 en los respaldos; precio histórico en `order_items` | `rutas_cliente.descargar`, `bitacora.py`, `scripts/respaldo.py` |
| **Disponibilidad** | Respaldo cifrado en caliente de BD + productos; restauración verificada; bloqueo temporal (no permanente) ante fuerza bruta; validación de tamaño de archivos (20 MB) | `scripts/respaldo.py`, prueba 13 |
| **Autenticación** | Argon2id + verificación con la biblioteca; sesiones aleatorias de 256 bits, del lado servidor, con expiración por inactividad y absoluta; certificado de servidor X.509 emitido por la CA local; SSH por par de claves | `seguridad.py`, `rutas_publicas.login` |
| **No repudio** | Comprobante firmado con RSA-PSS 3072/SHA-256: solo el poseedor de la clave privada pudo emitirlo y cualquiera lo verifica con la clave pública; fingerprint con HMAC que vincula cada copia a usuario + orden; bitácora con usuario, evento, fecha, resultado y origen | `rutas_cliente.emitir_comprobante`, `huella.py` |

## 3. Criptografía aplicada

| Uso | Algoritmo | Justificación |
|---|---|---|
| Contraseñas | Argon2id (t=3, m=64 MiB, p=2, sal de 16 bytes) | Ganador de la PHC y recomendación de OWASP; costoso en memoria contra GPU/ASIC. La biblioteca guarda sal y parámetros en el propio hash y permite *rehash* si se suben los parámetros. |
| Integridad de archivos | SHA-256 | Resistente a colisiones; estándar para huellas de archivos. |
| Productos en reposo | AES-256-GCM, nonce aleatorio de 96 bits, AAD fija | Cifrado autenticado: confidencialidad + integridad en una sola operación. |
| Firma de comprobantes | RSA-PSS, 3072 bits, SHA-256, MGF1 | Nivel de seguridad de 128 bits (NIST SP 800-57); PSS es el relleno probadamente seguro para firmas RSA. |
| Fingerprint | HMAC-SHA256 truncado a 80 bits | Impide fabricar un código que inculpe a otro usuario sin la clave del servidor. |
| Canonización | JSON con llaves ordenadas y sin espacios | La firma se calcula sobre bytes deterministas; el verificador reconstruye exactamente los mismos bytes. |

### Gestión de claves

| Clave | Ubicación | En el repositorio | Quién la usa |
|---|---|---|---|
| Privada de firma (RSA) | `secretos/firma_privada.pem` (600, opcionalmente cifrada con `TIENDA_FIRMA_PASSPHRASE`) | No | Solo el proceso de la aplicación |
| Pública de firma | `claves_publicas/firma_publica.pem` y `/clave-publica.pem` | Sí | Cualquiera, para verificar |
| AES de productos | `secretos/clave_datos.key` | No | Aplicación |
| HMAC de huellas | `secretos/clave_huella.key` | No | Aplicación |
| AES de respaldos | `secretos/clave_respaldo.key` | No | Script de respaldo |
| CA y servidor TLS | `certificados/*.key` (600) | No | OpenSSL / servidor |

Ningún rol de la aplicación (ni el ADMINISTRADOR) tiene una pantalla para leer
estas claves. Las claves se custodian aparte del respaldo de datos.

## 4. Fingerprinting (esteganografía)

**Técnica.** Cada descarga genera `FP1.u<usuario>.o<orden>.d<descarga>.<HMAC>` y
lo inserta en el contenido de **cada página** del PDF por tres canales:

1. Texto invisible (modo de renderizado 3 de PDF) en tres posiciones de cada página.
2. Marca visible discreta en el pie: nombre, correo, número de orden.
3. Metadato `/Fingerprint` del documento.

| Criterio | Evaluación |
|---|---|
| Imperceptibilidad | El canal 1 no cambia ni un píxel de la página renderizada (ver `evidencias/capturas`). La marca visible es intencional (disuasión) y ocupa una línea de 7 pt. |
| Robustez | Sobrevive a: renombrar el archivo, copiarlo, quitar metadatos, reescribir el PDF, extraer o reordenar páginas, unirlo con otros PDF. **No** sobrevive a imprimir/escanear, capturas de pantalla o rasterizar el PDF a imagen; para esos casos queda la marca visible (que sí es recortable). Esta limitación técnica debe explicarse en la demostración. |
| Capacidad | El identificador ocupa 45 bytes; se repite 3 veces por página. Sobra capacidad. |
| Seguridad | El HMAC impide falsificar huellas; cada descarga tiene un ID aleatorio, así que dos copias del mismo usuario se distinguen. Además se guarda el SHA-256 de cada copia entregada como respaldo de identificación exacta. |

**Recuperación.** `scripts/detectar_fingerprint.py copia.pdf` o la pantalla
*Rastrear copia* del ADMINISTRADOR: extrae el texto, valida el HMAC y busca la
descarga en la tabla `downloads` → usuario, orden, fecha e IP.

## 5. TLS, certificados y PKI (Windows)

`scripts/crear_ca.py` genera sin Bash ni OpenSSL externo:

- **CA raíz local** RSA 3072 (`CA:TRUE`, restricciones de firma de certificados).
- **Certificado del servidor** RSA 3072, `serverAuth`, SAN `localhost`, `127.0.0.1` y opcionalmente la IP Tailscale indicada con `--ip`.
- **Certificado no confiable** autofirmado, para la prueba de rechazo.

El servidor solo escucha por HTTPS con TLS ≥ 1.2, suites de cifrado moderno y cookies Secure/HttpOnly/SameSite. Para una PC Windows enlazada mediante Tailscale hay que generar el SAN correspondiente, iniciar enlazado a esa IP y confiar en `ca.crt` desde el equipo cliente. Ver `docs/DESPLIEGUE_WINDOWS_TAILSCALE.md`.

Pruebas: `test_05` valida certificado de confianza con `ca.crt` y `test_06` rechaza uno no confiable. Las claves privadas del servidor y de la CA nunca se transfieren al cliente.

## 6. Administración: SSH, VPN e IPSec

```text
PC administradora -> Tailscale (red privada) -> OpenSSH Windows servidor
PC cliente        -> Tailscale (red privada) -> HTTPS:8443 aplicación Windows
```

- **SSH**: OpenSSH Server real en la PC Windows con cuenta de mantenimiento distinta de las cuentas de la tienda, autenticación con clave pública Ed25519 y reglas de firewall restringidas a la IP privada del administrador. Ejemplo: `scripts/config/sshd_config_windows_ejemplo.txt`.
- **VPN**: Tailscale existente entre las PCs; no se requiere abrir puertos del módem. El servidor HTTPS se liga a su IP Tailscale y el certificado X.509 incluye esa IP en SAN.
- **IPSec**: alternativa arquitectónica en modo túnel (IKEv2+ESP) para proteger tráfico entre dos gateways o sedes. Se documenta y no se desarrolla desde cero, conforme a la restricción de la actividad.

Esta parte exige configuración en las PCs físicas: el ZIP documenta el despliegue, pero **no instala ni activa SSH o Tailscale automáticamente**.

## 7. Aplicación segura

| Principio | Implementación |
|---|---|
| Validación de entradas | Correo por expresión regular, longitudes máximas, precios con formato estricto, enteros acotados, PDF validado por cabecera y parseo de páginas con pypdf (no solo extensión), nombres de archivo aleatorios, consultas SQL parametrizadas. |
| Manejo de sesiones | Token de 256 bits; en BD solo su SHA-256; expiración por inactividad (30 min) y absoluta (8 h) configurables; nuevo token al iniciar sesión (anti fijación); revocación al cerrar sesión, al cambiar/restablecer contraseña, al cambiar rol o desactivar la cuenta. |
| CSRF | Token por sesión en todos los formularios POST, comparado en tiempo constante. |
| Privilegio mínimo | Cada ruta declara los roles exactos (`@requiere_rol`). El registro público siempre crea CLIENTE. Control a nivel de objeto: el cliente solo ve sus órdenes (404 para ajenas). |
| Separación de responsabilidades | OPERADOR: catálogo y pedidos. ADMINISTRADOR: usuarios, roles y seguridad, sin catálogo. Ninguno ve contraseñas ni claves. Un administrador no puede cambiar su propio rol ni desactivarse. |
| Errores | Páginas genéricas sin trazas (`debug=False`); el detalle va a la bitácora. Login con mensaje genérico; recuperación con la misma respuesta exista o no la cuenta. |
| Fuerza bruta | Bloqueo temporal tras N intentos (5 por defecto); tiempos de verificación iguales con o sin usuario. |
| Cabeceras | CSP restrictiva, HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cache-Control: no-store` en páginas privadas. |
| Registro | `security_events` con usuario, evento, fecha/hora, resultado, origen y detalle; solo inserción y encadenada. Copia en `logs/seguridad.log`. |
