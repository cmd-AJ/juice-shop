# Hito 3 — Detección y respuesta (Blue Team)

**Proyecto Final Integrador: OWASP Juice Shop y Secure SDLC**  
**Rama de trabajo:** `h3-blue-team`

## 1. Objetivo y alcance

Implementar un WAF con **ModSecurity y OWASP Core Rule Set (CRS)** delante de Juice Shop, centralizar los registros con **Filebeat → Elasticsearch → Kibana**, comprobar detección y bloqueo, analizar posibles falsos positivos y documentar la repetición de las pruebas del Red Team.

> **Alcance y limitación de versión:** Las pruebas aquí descritas se efectuaron sobre la imagen `bkimminich/juice-shop:v20.3.0`, desplegada en Docker. El repositorio del equipo declara `20.4.0-SNAPSHOT`. Los resultados no se deben atribuir automáticamente al código de la rama del equipo sin repetir la validación sobre esa versión. El WAF se expone solo por `127.0.0.1:8080`, y la imagen de Juice Shop no publica el puerto 3000 en el host.

## 2. Arquitectura y configuración

```text
Cliente local (127.0.0.1:8080)
          |
          v
Nginx + ModSecurity + OWASP CRS 4.30.0
          |                     \
          v                      -> logs (access + audit)
Juice Shop v20.3.0                       |
puerto 3000 interno                      v
                                      Filebeat 9.3.3
                                          |
                                          v
                                    Elasticsearch 9.3.3
                                          |
                                          v
                                       Kibana 9.3.3
```

Los archivos de despliegue se encuentran en `waf-siem/docker-compose.yml`, `waf-siem/filebeat.yml` y `waf-siem/waf/`. El archivo `waf-siem/.env` contiene **configuración local** y no debe publicarse. Se agregó `/waf-siem/.env` al `.gitignore` y se ejecutó `git rm --cached waf-siem/.env` para dejar de rastrearlo **sin borrar la copia local**; ese cambio queda pendiente de commit/push. Para compartir parámetros de ejemplo se conserva `waf-siem/.env.example`. No se deben subir secretos ni configuraciones específicas de una máquina.

Variables relevantes **del laboratorio**, no un archivo `.env` para publicar:

```dotenv
APP_BACKEND=http://juice-shop-h3:3000
WAF_BIND=127.0.0.1
WAF_PORT=8080
MODSEC_RULE_ENGINE=On
ALLOWED_METHODS=GET HEAD POST OPTIONS PUT
BLOCKING_PARANOIA=1
ELASTIC_VERSION=9.3.3
```

La activación de `PUT` permite evaluar la PoC de reseñas sin confundir un rechazo genérico del método con un control real de autorización. Debe revisarse en cualquier despliegue distinto del laboratorio.

## 3. Flujo de evidencias: ingesta y dashboard

Se verificó el estado de los servicios con `docker compose -f waf-siem/docker-compose.yml ps` y la aplicación a través del WAF con `curl.exe -I http://localhost:8080` (HTTP 200). Los registros de Nginx se almacenaron en `/var/log/waf/access.log` y los eventos de auditoría de ModSecurity en `/var/log/waf/modsec_audit.json`.

Filebeat ingestó los registros al data stream `filebeat-9.3.3`. Se creó el Data View `filebeat-*` en Kibana y se verificaron inicialmente **21 solicitudes de acceso**; después se observaron **tres eventos de auditoría** correspondientes a las pruebas controladas de XSS, SQLi y firma de escáner. El dashboard **`Hito 3 - WAF Security Monitoring`** contiene:

- **Eventos por origen** (`waf-access` / `waf-audit`). En la captura de referencia: 24 accesos y 3 auditorías.
- **Reglas OWASP CRS activadas** (recuento por identificador de regla, no número de ataques independientes).
- **Detecciones a lo largo del tiempo** (recuento temporal de eventos `waf-audit`).

**Exportación e importación del dashboard.** Se exportaron los *Saved Objects* a [`kibana-dashboard.ndjson`](kibana-dashboard.ndjson) desde Kibana, con la opción de incluir objetos relacionados. El archivo contiene **2 objetos** —el dashboard y el Data View `filebeat-*`—, **0 referencias faltantes** y sus tres paneles incrustados. Para reutilizarlo en otra instalación de Kibana compatible:

1. Levantar Elasticsearch, Kibana y Filebeat y comprobar que exista el flujo de logs del WAF.
2. Abrir **Stack Management → Saved Objects → Import** y seleccionar `docs/hito-3/kibana-dashboard.ndjson`.
3. Comprobar que aparezcan el Data View `filebeat-*` y el dashboard **Hito 3 - WAF Security Monitoring**; seleccionar un intervalo de tiempo con registros.

La exportación **no incluye los logs ni los contenedores**: cada integrante debe iniciar su propia infraestructura y generar eventos. Los paneles esperan los campos `fields.fuente` y `modsec.transaction.messages.details.ruleId` según la ingesta configurada.

**Nota de tiempo:** en esta configuración `@timestamp` refleja la marca temporal atribuida por Filebeat al documento; la hora exacta de la solicitud también está en el mensaje Nginx o en el JSON de auditoría. Guardar ambos valores cuando se correlacionen PoC y eventos.

## 4. Tres familias de detección comprobadas

| Prueba controlada | Payload / indicador | Reglas observadas | `DetectionOnly` | `On` |
|---|---|---|---|---|
| XSS en `GET /rest/products/search?q=...` | `<script>alert(1)</script>` | `941100`, `941110`, `941160`, `941390`, `949110` | HTTP 200; anomaly score 20 | HTTP 403 |
| SQL Injection en búsqueda | `' OR '1'='1` | `942100`, `949110` | HTTP 200; anomaly score 5 | HTTP 403 |
| Identificación de herramienta de escaneo | `User-Agent: Nikto/2.5.0` | `913100`, `949110` | HTTP 200; anomaly score 5 | No se documentó prueba de bloqueo en `On` |

**Detección de ráfagas por IP mediante ES|QL:** además de la firma Nikto (`913100`), se guardó la consulta reproducible [`deteccion-rafagas.esql`](deteccion-rafagas.esql), que agrupa eventos `waf-access` por IP y minuto con un umbral de **10 o más solicitudes/minuto**. En una prueba controlada de 20 solicitudes GET legítimas (todas HTTP 200), Elasticsearch devolvió **20 eventos para `172.19.0.1` en `2026-11-17T19:20:00Z`**, documentados en la evidencia 18. Esta es una **consulta de detección ejecutada manualmente**, no una alerta automática ni una regla de bloqueo del WAF. Es un umbral de laboratorio que también podría activarse con tráfico legítimo. La IP `172.19.0.1` corresponde al entorno Docker local, por lo que no identifica necesariamente al cliente externo real. Además, el agrupamiento usa `@timestamp` de Filebeat (ingesta), no la hora original de Nginx; esto limita la precisión temporal.

Las pruebas controladas de XSS y SQLi verifican la detección de patrones y su bloqueo, **no** la explotación de esas vulnerabilidades en la aplicación.

## 5. Validación de las PoC compartidas por Red Team

El WAF estaba en modo `On` al ejecutar estas pruebas. La PoC-04 fue actualizada por el Red Team: actualmente corresponde a **XXE**, no al antiguo hallazgo de bypass por puerto 3000.

| PoC | Petición | Respuesta observada | ¿El WAF bloqueó? | Interpretación y acción pendiente |
|---|---|---|---|---|
| **01 — Open Redirect** | `GET /redirect?to=http://sitio-falso.example/?x=https://github.com/juice-shop/juice-shop` | **302 Found**; `Location` al dominio externo de prueba | **No** | La redirección se emitió; validar destinos permitidos en código (H4). No se siguió el enlace externo. |
| **02 — Falta de anti-CSRF** | Con cuenta de laboratorio, `POST /dataerasure` con cookie `token`, sin token anti-CSRF independiente | **200 OK**; `Set-Cookie` borra la cookie | **No** | La solicitud se procesó, pero no se demostró el ataque entre orígenes desde navegador ni se verificó eliminación efectiva. Requiere validación adicional del Red Team y protección en código. |
| **03 — Reseñas sin autenticación** | `PUT /rest/products/24/reviews` con JSON `message`, `author`; sin token explícito | **201 Created**; `{"status":"success"}` | **No** | Petición aceptada sin credenciales explícitas. Revisar control de identidad/autorización en el backend (H4). |
| **04 — XXE en carga XML** | `POST /file-upload` con archivo `poc-h3.xml`, entidad externa apuntando a `/tmp/xxe-h3.txt` | **410 Gone**; carga XML descontinuada | **No: 410 de aplicación** | No apareció la cadena inocua `XXE_H3_CANARY`; **XXE no confirmada** en v20.3.0. Repetir con versión/código Red Team antes de concluir. |

Las solicitudes se registraron en `access.log`. Se debe distinguir entre **una solicitud registrada** y **una alerta de auditoría de ModSecurity**: una petición permitida no equivale a una regla de detección activada. Las cuatro PoC necesitan correlación explícita (hora, ruta, payload, estado, identificador de auditoría si existe) en la demostración definitiva. Las pruebas son locales; no se atacaron sistemas de terceros.

### 5.2 Revalidación del Red Team sobre la versión integrada (`20.4.0-SNAPSHOT`)

El Red Team repitió las cuatro PoC sobre la **versión integrada del repositorio**, a través del mismo WAF (`http://localhost:8080`, ModSecurity + CRS en modo `On`). La versión se confirmó con `GET /rest/admin/application-version` → `{"version":"20.4.0-SNAPSHOT"}`. Las evidencias crudas (headers, body y código HTTP por PoC) están en `waf-siem/evidencias/poc_20261117_161550/`.

Ninguna de las cuatro PoC es un payload de inyección (XSS/SQLi), por lo que el CRS las deja pasar; su mitigación corresponde a la capa de aplicación (Hito 4).

| PoC | Vulnerabilidad | Endpoint | Código HTTP | Resultado | WAF | CVSS v3.1 (propuesto) |
|---|---|---|---|---|---|---|
| 01 | Open Redirect (CWE-601) | `GET /redirect` | 302 | Confirmada | Permitió | 6.1 (Media) |
| 02 | CSRF (CWE-352) | `POST /dataerasure` | 200 | Confirmada a nivel app (ver caveat) | Permitió | 6.5 (Media) |
| 03 | Falta de autorización en reseñas (CWE-862) | `PUT /rest/products/1/reviews` | 201 | Confirmada | Permitió | 5.3 (Media) |
| 04 | XXE (CWE-611) | `POST /file-upload` | 410 | No demostrada | N/A | — |

> Los valores CVSS son **propuestos** por el Red Team; ajústense según la rúbrica del curso.

#### PoC 01 — Open Redirect

- **Endpoint:** `GET /redirect?to=<url>`
- **Descripción.** El endpoint valida la allowlist por *contenido/substring* en vez de por destino real. Incluyendo una URL permitida como parámetro de una URL atacante, la validación pasa y el usuario es redirigido a un dominio arbitrario.
- **Reproducción.**

```bash
# Control: destino allowlisted (comportamiento legítimo) -> 302
curl -i "http://localhost:8080/redirect?to=https://github.com/juice-shop/juice-shop"
# Bypass: URL atacante con la allowlisted embebida como parámetro
curl -i "http://localhost:8080/redirect?to=https://attacker.example/?x=https://github.com/juice-shop/juice-shop"
```

- **Resultado observado.** `HTTP/1.1 302` con `Location: https://attacker.example/?x=https://github.com/juice-shop/juice-shop`. La redirección apunta al dominio atacante, confirmando el open redirect. El WAF no bloqueó.
- **Impacto.** Phishing / robo de credenciales: un enlace a un dominio confiable redirige a un sitio del atacante. Requiere interacción de la víctima (clic).
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → **6.1 (Media)**. *Scope: Changed* porque el efecto cruza a un dominio distinto.
- **Recomendación (H4).** Validar `to` contra allowlist por *igualdad exacta* de origen (esquema + host), no por substring.

#### PoC 02 — CSRF en `/dataerasure`

- **Endpoint:** `POST /dataerasure`
- **Descripción.** La acción de borrado de datos se procesa basándose únicamente en la cookie de sesión `token`, sin exigir un token anti-CSRF impredecible. El navegador adjunta la cookie automáticamente.
- **Reproducción.**

```bash
# 1) Crear usuario
curl -X POST http://localhost:8080/api/Users -H 'Content-Type: application/json' \
  -d '{"email":"csrf@test.op","password":"Passw0rd!","securityQuestion":{"id":1},"securityAnswer":"test"}'
# 2) Login y copiar authentication.token
curl -X POST http://localhost:8080/rest/user/login -H 'Content-Type: application/json' \
  -d '{"email":"csrf@test.op","password":"Passw0rd!"}'
# 3) POST sin token anti-CSRF, solo con la cookie de sesión
curl -i -X POST http://localhost:8080/dataerasure \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: token=<TOKEN>' \
  --data-urlencode 'email=csrf@test.op' --data-urlencode 'securityAnswer=test'
```

- **Resultado observado.** `HTTP/1.1 200`. La acción se procesa sin exigir token anti-CSRF. El WAF no bloqueó. (Coincide con lo observado por Blue Team en v20.3.0, incluida la respuesta que limpia la cookie.)
- **Caveat — escenario cross-site pendiente de cierre.** El `curl` demuestra una sola mitad: que el endpoint **no exige token anti-CSRF**. La explotabilidad real desde otro sitio depende del atributo `SameSite` de la cookie `token`:
  - `SameSite=Lax`/`Strict` → el navegador **no** envía la cookie en un POST cross-site; el ataque queda mitigado por el navegador, aunque la falla de diseño persiste.
  - `SameSite=None` (o ausente, según el navegador) → el POST cross-site sí envía la cookie; explotable de extremo a extremo.
  - **Pendiente:** confirmar `SameSite` de `token` (DevTools → Application → Cookies) y reproducir la página desde un **host distinto** (p. ej. `127.0.0.1` vs `localhost`), ya que dos puertos de `localhost` se consideran *same-site* y no prueban el escenario cross-site.
- **Precondición.** El atacante debe conocer `email` y `securityAnswer` de la víctima. En Juice Shop las preguntas de seguridad son débiles y recuperables, lo que mantiene la viabilidad.
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` → **6.5 (Media)**. Si se confirma `SameSite=Lax`, considerar `AC:H` o reclasificar como hallazgo de diseño sin explotación directa.
- **Recomendación (H4).** Token anti-CSRF por sesión/petición en acciones de estado + `SameSite=Strict`/`Lax` y `Secure` en la cookie de sesión.

#### PoC 03 — Reseñas sin autenticación

- **Endpoint:** `PUT /rest/products/1/reviews`
- **Descripción.** El endpoint acepta la petición sin credenciales. Un usuario no autenticado puede publicar reseñas (incluyendo autoría arbitraria en `author`).
- **Reproducción.**

```bash
curl -i -X PUT http://localhost:8080/rest/products/1/reviews \
  -H 'Content-Type: application/json' \
  -d '{"message":"PoC sin autenticacion","author":"anon@poc"}'
```

- **Resultado observado.** `HTTP/1.1 201`. La reseña se crea sin cabecera `Authorization` ni sesión. El WAF no bloqueó. (Blue Team observó lo mismo en v20.3.0 sobre el producto 24; aquí sobre el producto 1.)
- **Impacto.** Inyección de contenido y suplantación de autoría (spam, reseñas falsas, abuso de reputación).
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` → **5.3 (Media)**.
- **Recomendación (H4).** Exigir autenticación y derivar `author` del usuario autenticado del token, no del cuerpo de la petición.

#### PoC 04 — XXE (no demostrada en esta versión)

- **Endpoint:** `POST /file-upload`
- **Descripción.** Se intentó el vector clásico de XXE subiendo un XML con una entidad externa que referencia un archivo local del servidor.
- **Reproducción.**

```bash
cat > xxe.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
XML
curl -i -X POST http://localhost:8080/file-upload -F "file=@xxe.xml"
```

- **Resultado observado.** `HTTP/1.1 410 Gone` generado por la aplicación. No se obtuvo contenido del archivo ni evidencia de procesamiento de la entidad externa. (Coincide con v20.3.0.)
- **Interpretación.** El `410` sugiere que el endpoint/flujo de parseo XML fue deshabilitado o retirado. **XXE no confirmada** en `20.4.0-SNAPSHOT`.
- **Decisión recomendada.** Documentar como **no explotable en la versión integrada** (con la evidencia del 410), o sustituir por otra vulnerabilidad real presente en esta versión. No reportarla como confirmada.

### 5.3 Consistencia entre versiones

Los resultados coinciden en ambas versiones, lo que respalda que los hallazgos no dependen de la imagen de laboratorio y aplican a la versión integrada del equipo:

| PoC | `v20.3.0` (Blue, WAF) | `20.4.0-SNAPSHOT` (Red, WAF) | Consistencia |
|---|---|---|---|
| 01 — Open Redirect | 302, no bloqueó | 302, no bloqueó | ✔ igual |
| 02 — CSRF `/dataerasure` | 200, no bloqueó | 200, no bloqueó | ✔ igual |
| 03 — Reseñas sin auth | 201, no bloqueó | 201, no bloqueó | ✔ igual |
| 04 — XXE | 410, no confirmada | 410, no confirmada | ✔ igual |

**Correlación con SIEM (pendiente).** Las cuatro PoC de la revalidación (5.2) necesitan su correlación explícita en Kibana (hora, ruta, payload, estado, identificador de auditoría si existe). La corrida quedó registrada bajo el timestamp `20261117_161550` (local, UTC-6). Consulta de referencia en Discover:

```
url.path: ("/redirect" or "/dataerasure" or "/rest/products/1/reviews" or "/file-upload")
```

## 6. Análisis de falsos positivos y ajustes

Se revisó `waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`. Este archivo **ya contenía** la regla local `10001`, limitada al encabezado `Host` con IP `127.0.0.1`, que excluye **solo ese objetivo** de la evaluación de la regla CRS `920350` (encabezado `Host` con dirección IP numérica). No se desactivó el conjunto de reglas de OWASP CRS.

**Prueba de alcance con `MODSEC_RULE_ENGINE=On`:**

| Solicitud legítima | Respuesta | Auditoría de ModSecurity |
|---|---|---|
| `GET /` con `Host: 127.0.0.1:8080` | HTTP 200 | No se observó coincidencia `920350` para esta prueba |
| `GET /` con `Host: 127.0.0.2:8080` | HTTP 200 | Sí se registró `920350`: `Host header is a numeric IP address` |

Para la segunda prueba, el registro mostró `Host: 127.0.0.2:8080`, respuesta `200` y la regla `920350`, el **17/11/2026 a las 19:44:19** (marca temporal del evento). La [evidencia 19](evidencias/19-regla-920350-host-alternativo.png) presenta la coincidencia y el estado HTTP. También se verificó una búsqueda legítima `GET /rest/products/search?q=apple` → HTTP 200.

**Interpretación y limitaciones:** la comparación muestra que la detección `920350` sigue activa para un encabezado *Host* alternativo fuera de la exclusión. **No se observó bloqueo de tráfico legítimo**, por lo que no se afirma haber corregido un falso positivo que devolviera HTTP 403. La excepción `10001` **ya existía** antes de esta sesión; no se realizó una prueba antes/después de habilitarla ni se demostró que fuera indispensable. El HTTP 200 por sí solo tampoco demuestra la necesidad de la exclusión. El objetivo de esta prueba fue comprobar su alcance limitado y documentar el riesgo de detecciones sobre tráfico legítimo.

En `ALLOWED_METHODS` se incorporó `PUT` para que la PoC-03 no fuera rechazada por método HTTP (`911100`). Esto es un **ajuste de política para el laboratorio**, no una corrección de la vulnerabilidad de reseñas sin autenticación.

## 7. Evidencias (capturas)

| N.º | Archivo | Contenido |
|---|---|---|
| 01 | [Infraestructura](evidencias/01-infraestructura.png) | Contenedores y Juice Shop en Docker |
| 02 | [Ingesta Elasticsearch](evidencias/02-ingesta-elasticsearch.png) | Índice/data stream de Filebeat con documentos |
| 03 | [Discover / accesos](evidencias/03-kibana-discover.png) | Logs de Nginx accesibles en Kibana |
| 04 | [XSS en ModSecurity](evidencias/04-deteccion-xss-modsecurity.png) | Payload y reglas de XSS |
| 05 | [XSS en Kibana](evidencias/05-deteccion-xss-kibana.png) | Reglas XSS recibidas por SIEM |
| 06 | [SQLi en ModSecurity](evidencias/06-deteccion-sqli-modsecurity.png) | Regla 942100, score 5 |
| 07 | [SQLi en Kibana](evidencias/07-deteccion-sqli-kibana.png) | Alerta SQLi ingerida |
| 08 | [Escáner en ModSecurity](evidencias/08-deteccion-escaner-modsecurity.png) | User-Agent Nikto, regla 913100 |
| 09 | [Escáner en Kibana](evidencias/09-deteccion-escaner-kibana.png) | Firma de escáner visible en Discover |
| 10 | [Dashboard WAF + SIEM](evidencias/10-dashboard-waf-siem.png) | Tres paneles y rango temporal |
| 11 | [Bloqueo XSS](evidencias/11-bloqueo-xss.png) | HTTP 403, modo Enabled, score 20 |
| 12 | [Bloqueo SQLi](evidencias/12-bloqueo-sqli.png) | HTTP 403, modo Enabled, score 5 |
| 13 | [Puerto 3000 no publicado](evidencias/13-puerto-3000-no-publicado.png) | Conexión desde Windows al loopback 3000 falla; no demuestra aislamiento frente a otras redes Docker |
| 14 | [PoC-01 Open Redirect](evidencias/14-poc01-open-redirect.png) | HTTP 302 y Location externa |
| 15 | [PoC-03 reseñas](evidencias/15-poc03-resena-sin-autenticacion.png) | HTTP 201 sin token explícito |
| 16 | [PoC-02 CSRF](evidencias/16-poc02-csrf-dataerasure.png) | HTTP 200 y limpieza de cookie |
| 17 | [PoC-04 XXE no confirmada](evidencias/17-poc04-xxe-no-confirmada.png) | HTTP 410 del backend |
| 18 | [Ráfaga de solicitudes por IP](evidencias/18-deteccion-rafaga-ip.png) | 20 solicitudes de `172.19.0.1` agrupadas en un minuto por consulta ES|QL |
| 19 | [Regla 920350 y Host alternativo](evidencias/19-regla-920350-host-alternativo.png) | `Host: 127.0.0.2:8080` activó `920350` y recibió HTTP 200; detección sin bloqueo |

## 8. Cierre del Blue Team y pendientes de integración

**Evidencias ya preparadas:** infraestructura WAF/SIEM, dashboard exportado con su Data View, detecciones de SQLi y XSS, consulta de ráfagas por IP, respuestas HTTP 403 a pruebas controladas, resultados de las cuatro PoC ejecutadas y revisión del alcance de la exclusión `10001`. Los datos históricos no se incluyen en el export de Kibana. No se configuraron alertas automáticas: la tercera detección se realiza mediante consulta ES|QL manual.

**Pendientes para la entrega e integración:**

1. **GitHub:** comprobar los archivos referenciados, confirmar que `.env` no se vuelve a rastrear, excluir los ZIP locales y realizar commit/push de esta rama.
2. **PoC y versión del equipo:** repetir las pruebas sobre el código real del repositorio `20.4.0-SNAPSHOT` o dejar acordado el alcance del laboratorio `v20.3.0`; no extrapolar resultados entre versiones. La PoC-04 (XXE) no se confirmó y las PoC 01–03 no fueron bloqueadas por el WAF en las pruebas documentadas.
3. **Demostración final con Red Team / H4:** correlacionar en vivo petición, hora, payload, respuesta HTTP y registro del WAF/SIEM. Distinguir una detección de ModSecurity de una solicitud solo registrada en `access.log` y comprobar las correcciones H4 por separado.
4. **Falsos positivos:** la revisión documenta una excepción preexistente y una detección sin bloqueo, **no** una corrección de falso bloqueo demostrada mediante comparación antes/después. Si el docente exige esa evidencia específicamente, realizar una prueba adicional controlada.
5. **Informe final H1–H4:** integrar la matriz de trazabilidad, riesgos residuales, correcciones de código y repetición posterior de las PoC.

## 9. Uso de IA

Se utilizó ChatGPT para estructurar pruebas controladas, interpretar evidencias y preparar la documentación. Se utilizó Claude en el navegador para crear el Data View `filebeat-*` y el dashboard de Kibana. Toda configuración y conclusión debe ser revisada y validada por los integrantes del equipo, conforme a las reglas de uso de IA del curso.
