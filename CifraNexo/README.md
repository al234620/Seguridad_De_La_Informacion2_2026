# CifraNexo — Plataforma segura de venta y distribución de contenido digital


**Equipo:**
Andre Pantoja  
Osiel Espinoza  
Roberto Molina  
David Molina

Aplicación académica en **Python + Flask + SQLite** para comercializar archivos PDF de forma simulada. Permite registro, login, recuperación de contraseña, catálogo, carrito, órdenes, pagos simulados, comprobantes firmados con RSA, descargas PDF personalizadas con fingerprinting, tres roles, HTTPS con una CA local, trazabilidad, respaldos y restauración.

Sin pagos reales, tarjetas bancarias reales, CVV ni datos personales reales. Pensado para una PC Windows servidor y segunda PC cliente conectadas con Tailscale, no para Internet público ni uso comercial.

## Instalación en Windows (PowerShell)

 Solo se necesitan PowerShell y Python. Se usarán dos computadoras: la primera como SERVIDOR (aplicación, base de datos y claves) y la segunda como CLIENTE (navegador). Esta guía supone Windows 10/11 y Python 3.12 en el servidor.

### 1. Preparar la computadora servidor

1. Instala Python 3.12 y Tailscale. Instala Visual Studio Code si quieres trabajar con el código.
2. Extrae el proyecto y abre la carpeta que contiene `requirements.txt` (la carpeta `proyecto/`) en Visual Studio Code.
3. Abre una terminal PowerShell dentro de esa carpeta y confirma que Python está disponible:

   ```powershell
   py -3.12 --version
   ```

4. Crea el entorno virtual, actualiza pip e instala las bibliotecas:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```



5. Inicializa la base de datos y los datos de demostración:

   ```powershell
   .\.venv\Scripts\python.exe scripts/inicializar.py
   ```

   Se crearán o prepararán la base SQLite, las claves necesarias y los usuarios y productos de prueba. Si la base ya tiene usuarios, el inicializador no vuelve a insertar los de demostración.

### 2. Generar certificados y arrancar el servidor con Tailscale (dos PCs)

1. Conecta el servidor a Tailscale e identifica su dirección IPv4:

   ```powershell
   tailscale status
   tailscale ip -4
   ```

   La IP se parecerá a `100.X.Y.Z`.

2. Desde la misma terminal PowerShell, guarda la IP actual y genera la CA local y el certificado HTTPS:

   ```powershell
   $ipServidor = (tailscale ip -4).Trim()
   .\.venv\Scripts\python.exe scripts/crear_ca.py --ip $ipServidor
   .\.venv\Scripts\python.exe scripts/verificar_certificado.py --ip $ipServidor
   ```

   La última línea debe indicar `OK: certificado cubre ...`. El certificado se guarda en `certificados/servidor.crt`, la clave privada en `certificados/servidor.key` y la CA en `certificados/ca.crt`.

3. Configura la IP y el puerto y ejecuta Flask con HTTPS:

   ```powershell
   $env:TIENDA_HOST = $ipServidor
   $env:TIENDA_PUERTO = "8443"
   .\.venv\Scripts\python.exe -m aplicacion.servidor
   ```



### 3. Permitir el acceso en el Firewall del servidor

Primero ejecuta `tailscale ip -4` en la PC cliente para obtener su IP. Luego, en el servidor, abre una ventana de PowerShell como administrador y sustituye los valores de ejemplo por las dos IP reales:

```powershell
$ipServidor = "100.X.Y.Z"
$ipCliente = "100.A.B.C"
New-NetFirewallRule -DisplayName "Tienda HTTPS Tailscale" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $ipServidor -LocalPort 8443 -RemoteAddress $ipCliente -Profile Any
```


### 4. Preparar la PC cliente

1. Instala Tailscale y conecta esta PC a la **misma tailnet** que el servidor. La cuenta o el dispositivo deben estar autorizados.
2. En PowerShell del cliente, comprueba la comunicación (sustituye la IP):

   ```powershell
   tailscale ping 100.X.Y.Z
   Test-NetConnection 100.X.Y.Z -Port 8443
   ```

   Para la segunda prueba, el resultado deseado es `TcpTestSucceeded : True`.

3. Copia solo el archivo `certificados/ca.crt` desde el servidor al cliente, por un medio seguro. No copiar `ca.key`, `servidor.key`, `secretos/` ni ninguna clave privada.

5. En Edge o Chrome, abre `https://100.X.Y.Z:8443`, utilizando la IP Tailscale del servidor. El navegador debe validar el certificado sin advertencias.



### 5. Administración remota por SSH y diseño de VPN/IPSec

El navegador cliente utiliza HTTPS para la tienda; SSH es para administración del equipo servidor, no para el inicio de sesión de los usuarios de la tienda. En el servidor, configura OpenSSH Server con un usuario estándar de mantenimiento, autenticación mediante claves y acceso al puerto 22 restringido a las IP autorizadas de Tailscale.

Tailscale facilita la VPN de laboratorio. **IPSec** se explica como una alternativa de arquitectura y no se implementa desde cero.

### 6. Si cambia la IP Tailscale del servidor

Detén la aplicación (`Ctrl+C`), obtén la nueva IP, vuelve a emitir el certificado del servidor y reinícialo:

```powershell
$ipServidor = (tailscale ip -4).Trim()
.\.venv\Scripts\python.exe scripts/crear_ca.py --ip $ipServidor
.\.venv\Scripts\python.exe scripts/verificar_certificado.py --ip $ipServidor
$env:TIENDA_HOST = $ipServidor
$env:TIENDA_PUERTO = "8443"
.\.venv\Scripts\python.exe -m aplicacion.servidor
```

El generador reutiliza la CA local si `ca.crt` y `ca.key` siguen presentes. Actualiza además las reglas del Firewall y la URL utilizada por el cliente.

## Seguridad de certificados y archivos privados

Solo se comparte `certificados/ca.crt` con los dispositivos cliente para confiar en la CA del laboratorio. Los archivos `certificados/ca.key`, `certificados/servidor.key`, `secretos/` y `firma_privada.pem` son privados: no se copian al cliente ni se publican en GitHub. Restringe su acceso en Windows y conserva copias seguras cuando corresponda. La CA local y el servidor son para fines académicos en una red privada.

## Cuentas de demostración 

| Rol | Usuario | Contraseña temporal |
|---|---|---|
| CLIENTE | `cliente@demo.local` | `ClienteSeguro2026` |
| CLIENTE 2 | `cliente2@demo.local` | `OtroCliente2026` |
| OPERADOR | `operador@demo.local` | `OperadorSeguro2026` |
| ADMINISTRADOR | `admin@demo.local` | `AdminSeguro2026x` |


Recuperación de contraseña: para la demostración no se envían correos reales, sino que se escribe un enlace temporal de un solo uso en `buzon/`. El canal de correo es simulado.

## Funcionalidades por rol

- **Público:** catálogo, detalle, registro, login y recuperación de contraseña.
- **CLIENTE:** perfil, carrito, crear órdenes, simular pagos, visualizar sus propias órdenes, exportar y verificar comprobantes RSA-PSS, descargar copias PDF con huella por usuario/orden.
- **OPERADOR:** administrar PDF, precios, activación/desactivación, órdenes y transición de estados permitidas; sin roles ni secretos.
- **ADMINISTRADOR:** administrar usuarios/roles/sesiones, consultar operaciones y eventos, configuración de seguridad y rastrear copia PDF; no ve contraseñas originales ni claves privadas.

## Seguridad

- **Argon2id:** sal aleatoria y verificación segura de contraseñas.
- **Sesiones:** tokens aleatorios con hash almacenado, revocación, expiración y CSRF.
- **AES-256-GCM:** PDF cifrados en reposo, hash SHA-256 para integridad.
- **Firma de comprobante:** RSA-PSS 3072/SHA-256 con clave privada externa y verificación con pública.
- **Fingerprint:** HMAC que asocia una descarga a usuario y orden, integrado por marcas visibles/invisibles en cada página y metadatos del PDF; recuperación desde script o pantalla Admin. No es infalible ante rasterizar PDF.
- **HTTPS:** TLS 1.2 o 1.3 mediante CA local creada con Python; pruebas de aceptación y rechazo de certificados.
- **SSH y VPN:** guía de OpenSSH sobre Tailscale (dos computadoras Windows); IPSec como arquitectura alternativa documentada.
- **Bitácora:** `security_events` encadenados con SHA-256, sin borrar/editar desde SQLite en operación normal.
- **Respaldos:** copia SQLite consistente + productos cifrados, manifiesto SHA-256, archivo cifrado AES-GCM. Guardar `secretos/` por separado.

## Pruebas (sección 19 del enunciado)

Desde la carpeta `proyecto/` en PowerShell, ejecuta directamente con Python (sin archivos de instalación adicionales):

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Hay 13 pruebas obligatorias, 10 pruebas adicionales y 4 pruebas de regresión para integridad del PDF, transacciones, estados de órdenes y SAN del certificado. Tras ejecutarlas, `evidencias/reporte_pruebas.md` muestra resultados reales de la ejecución actual (13+10 anotadas como evidencias y 4 regresiones).

## Respaldos y restauración

Desde `proyecto/`, con el entorno Python activo o llamando `python` de `.venv`:

```powershell
.\.venv\Scripts\python.exe scripts/respaldo.py crear
.\.venv\Scripts\python.exe scripts/respaldo.py verificar "respaldos\NOMBRE_DEL_ARCHIVO.tar.gz.enc"
# Para restaurar, detener primero el servidor y usar una COPIA de este proyecto:
.\.venv\Scripts\python.exe scripts/respaldo.py restaurar "respaldos\NOMBRE_DEL_ARCHIVO.tar.gz.enc"
```

No se incluyen las claves simétricas de `secretos/` en los respaldos cifrados: custódialas en un medio separado. No restaures sobre el servidor con usuarios conectados; haz la demostración sobre una copia para evitar pérdida accidental de datos. La base SQLite no se cifra por defecto, aunque las copias de productos y los archivos de respaldo sí están cifrados: limita el acceso del sistema operativo a la carpeta.


## Limitaciones del proyecto académico

- Se usa el servidor de desarrollo de Werkzeug solo en una red privada. No se debe publicar en Internet ni presentar como infraestructura de producción.
- SSH y Tailscale se configuran en las PCs reales, no automáticamente al descomprimir el ZIP. Su funcionamiento entre equipos debe mostrarse en la exposición.
- No se implementa IPSec desde cero; se describe su uso como alternativa de diseño, según el alcance autorizado.
- Solo PDFs. El fingerprint invisible no resiste convertir cada página a imágenes, y una marca visible puede recortarse.

## Subir el código a GitHub

Esta versión del repositorio **no incluye** la base de datos, las claves ni los certificados de la computadora servidor. Para ver la lista de exclusiones, instrucciones de regeneración y comandos de publicación, consulta [`PUBLICAR_EN_GITHUB.md`](PUBLICAR_EN_GITHUB.md).
