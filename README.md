# WebScan

Proyecto personal de aprendizaje en ciberseguridad aplicada: herramienta de diagnóstico de seguridad web en Python, con dos modos:

- **Pasivo** (por defecto): detecta errores de configuración y malas prácticas habituales (basado en OWASP Secure Headers / Top 10 A05) usando solo peticiones GET normales, sin enviar ningún payload.
- **Activo** (opt-in, solo CLI): además envía payloads no destructivos de XSS reflejado, inyección SQL y redirección abierta para confirmar si una debilidad es explotable de verdad.

> ⚠️ Analiza solo sistemas propios o con **autorización escrita**. El CLI exige `--i-have-authorization` y la web pide confirmarlo. El modo activo exige además `--active --i-accept-active-risk`: tu autorización debe cubrir explícitamente pruebas activas/intrusivas, no solo el diagnóstico pasivo.

## Instalación (Windows / PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Uso

```powershell
# Reporte en terminal
python -m webscan scan https://tu-sitio.cl --i-have-authorization

# Reporte HTML o JSON
python -m webscan scan https://tu-sitio.cl --i-have-authorization --format html -o reporte.html
python -m webscan scan https://tu-sitio.cl --i-have-authorization --format json -o reporte.json

# Solo algunos chequeos
python -m webscan list-checks
python -m webscan scan https://tu-sitio.cl --i-have-authorization --only headers,cookies,tls

# Sistema propio en red interna / localhost
python -m webscan scan http://localhost:8080 --i-have-authorization --allow-private

# CI/CD: falla (código 2) si hay hallazgos Alta o superior
python -m webscan scan https://staging.tu-sitio.cl --i-have-authorization --fail-on high

# Interfaz web local
python -m webscan serve        # http://127.0.0.1:5000

# Pruebas ACTIVAS (XSS, SQLi, open redirect): solo CLI, doble confirmación obligatoria
python -m webscan scan https://tu-sitio.cl --i-have-authorization --active --i-accept-active-risk
```

## Qué revisa

| Chequeo | Contenido |
|---|---|
| `headers` | HSTS, CSP (y debilidades), anti-clickjacking, nosniff, Referrer/Permissions-Policy, divulgación de versiones (Server, X-Powered-By), caché |
| `transport` | Redirección HTTP→HTTPS, sitio servido sin cifrar |
| `cookies` | Secure, HttpOnly, SameSite, prefijos `__Host-` |
| `cors` | Reflexión de Origin, comodín, origen `null`, credenciales |
| `content` | Contenido mixto, SRI en CDNs, formularios de login inseguros, comentarios sensibles, secretos en el HTML, meta generator |
| `tls` | Validez y vencimiento del certificado, TLS 1.0/1.1 aceptado, cifrados débiles |
| `dns` | SPF, DMARC, CAA |
| `exposure` | `.env`, `.git`, volcados SQL, `phpinfo`, Actuator, listado de directorios, `security.txt` |

Todos los chequeos pasivos son peticiones GET simples, handshakes TLS y consultas DNS. No hay fuerza bruta, inyección de payloads ni explotación.

## Pruebas activas (opt-in, solo CLI)

| Chequeo | Técnica | Qué hace |
|---|---|---|
| `xss_reflected` | XSS reflejado | Envía una marca aleatoria con metacaracteres de ruptura HTML (`"'><`) en cada parámetro GET descubierto; si vuelve sin codificar en la respuesta, lo reporta. No ejecuta JavaScript ni usa `<script>`/`alert()` reales. |
| `sqli` | Inyección SQL | Basada en error (comilla suelta → firma de error de MySQL/PostgreSQL/MSSQL/SQLite/Oracle) y basada en booleano (`OR '1'='1'` vs `AND '1'='2'`, comparando con la respuesta original). Sin payloads destructivos (sin DROP/DELETE/UPDATE) ni basados en tiempo (sin SLEEP), para no cargar ni ralentizar el objetivo. |
| `open_redirect` | Redirección abierta | En parámetros con nombre típico de redirección (`url`, `next`, `redirect`, `return`, `continue`...), comprueba si el servidor redirige a un dominio externo arbitrario (`webscan-probe.invalid`, que no existe). |
| `cmd_injection` | Inyección de comandos (OS) | Añade un separador de shell + `sleep`/`ping` (p. ej. `$(sleep 3)`) y mide si la respuesta se demora lo esperado; confirma con un segundo sondeo de retardo distinto (+2s) para descartar que sea solo un sitio lento. Sin comandos destructivos. |
| `ssti` | Server-Side Template Injection | Envía una multiplicación en sintaxis de motor de plantillas (`{{a*b}}` Jinja2/Twig, `<%= a*b %>` ERB, `${a*b}` Freemarker/EL); si el **resultado** aparece calculado en la respuesta (no la expresión literal), el motor la evaluó en servidor. Sin acceso a `__class__`, sin ejecutar comandos vía plantilla. |

Diseño de seguridad del propio modo activo:

- **Opt-in explícito y doble**: hay que pasar `--active` **y** `--i-accept-active-risk`; ninguno de los dos solo basta. Sin ambos, el CLI rechaza el escaneo con el código de salida 1.
- **Nunca por la interfaz web**: un checkbox marcado por un visitante anónimo no es autorización real para lanzar payloads contra un tercero, así que `webscan serve` siempre llama a `scan(..., active=False)` sin excepción.
- **Solo parámetros GET de la propia página**: los parámetros se descubren únicamente en la página principal ya descargada (su query string, sus enlaces `<a>` y sus formularios `method="get"`). Los formularios `POST` se ignoran a propósito: enviarlos podría tener efectos reales (login, compra, borrado, envío de correo) y esta herramienta nunca debe causarlos. No hay rastreo (crawling) a otras páginas ni fuerza bruta de rutas.
- **Presupuesto acotado**: como máximo 6 parámetros por chequeo, cada uno con 2-3 peticiones adicionales; todas pasan por el mismo `HttpClient` con el límite de 2 MB/5 redirecciones y la revalidación anti-SSRF en cada salto.
- **Sin confirmación de ejecución real**: para XSS solo se comprueba que el texto vuelve sin escapar (condición necesaria para que un payload real funcione), nunca se intenta ejecutar JavaScript de verdad; para SQLi no hay técnicas basadas en tiempo ni se intenta leer datos reales de la base; para SSTI solo se evalúa una multiplicación, nunca se intenta escapar el sandbox de la plantilla ni ejecutar comandos a través de ella.
- **`cmd_injection` es el único chequeo con retardo deliberado** (necesario para detectar inyección ciega de forma no destructiva): solo tarda varios segundos cuando el parámetro SÍ es vulnerable (el comando se ejecuta de verdad en el servidor) — en un sitio no vulnerable el `sleep`/`ping` nunca se ejecuta y la respuesta vuelve rápido, así que el costo en tiempo no se paga en el caso normal. Usa `--skip cmd_injection` si quieres evitarlo por completo.

## Seguridad de la propia herramienta

- **Anti-SSRF**: se resuelve el host y se bloquean IPs privadas, loopback, link-local (p. ej. metadatos cloud `169.254.169.254`) y reservadas. Se revalida en **cada redirección**. La web nunca permite redes privadas; el CLI solo con `--allow-private`.
- Límite de 2 MB por respuesta, 5 redirecciones y timeouts.
- Web: token CSRF, confirmación de autorización, límite de 5 análisis / 5 min por IP, cabeceras de seguridad y CSP propia.
- Reportes HTML escapan todo el contenido (evidencia incluida). Los archivos sensibles hallados **nunca se vuelcan** al reporte.
- Si publicas la web, pon un proxy inverso con HTTPS y define `WEBSCAN_SECRET_KEY`.

## Agregar un chequeo

```python
# webscan/checks/mi_chequeo.py
from ..models import Finding, Severity
from . import Context, register

@register("mi_chequeo")
def run(ctx: Context) -> list[Finding]:
    ...  # ctx.main = respuesta principal, ctx.client.get_quiet(url) para más peticiones
    return []
```
Y añade el import en `load_all()` de `webscan/checks/__init__.py`.

## Pruebas

```powershell
python -m pytest -q
```
Incluye un servidor local mal configurado a propósito para validar los hallazgos.

## Ideas para siguientes versiones

- Rastreo ligero (crawler) respetando `robots.txt` para analizar más de una página (hoy el modo activo solo mira la página de inicio).
- Detección de versiones de librerías JS con CVE conocidos (integrar OSV.dev).
- Integración con GitHub Actions (`--fail-on`) y salida SARIF.
- SQLi ciega basada en tiempo (SLEEP/pg_sleep) con límites muy estrictos, si hace falta cubrir casos que el booleano no detecta.
- Más variantes de separador de shell en `cmd_injection` (pipe `|`, backticks) y de sintaxis en `ssti` (Thymeleaf, Smarty, Vue/Angular del lado del servidor).

## Autor

Mauricio Maluenda ([MauExpl01t](https://github.com/MauExpl01t)), estudiante de Ingeniería en Ciberseguridad (INACAP).

## Nota importante

Los reportes que genera esta herramienta (`--format html`/`json` o `-o archivo`) pueden contener hallazgos
reales de un sitio y **nunca deben publicarse en un repositorio público**. El `.gitignore` de este proyecto
ya excluye los nombres de archivo habituales (`informe*`, `reporte*`), pero revisa siempre `git status`
antes de hacer commit.

## Licencia

MIT. Úsala solo contra sistemas propios o con autorización escrita; el autor no se hace responsable del
mal uso de esta herramienta.
