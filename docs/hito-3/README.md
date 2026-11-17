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

El Red Team repitió las cuatro PoC sobre la **versión integrada del repositorio** (`20.4.0-SNAPSHOT`, confirmada con `GET /rest/admin/application-version`), a través del mismo WAF (`http://localhost:8080`). Para separar **detección** de **bloqueo**, se ejecutaron en tres escenarios controlados:

| Escenario | `MODSEC_RULE_ENGINE` | `ALLOWED_METHODS` | Evidencias |
|---|---|---|---|
| **A** — Detección | `DetectionOnly` | sin `PUT` | `waf-siem/evidencias/poc_20261117_161550/` |
| **B** — Bloqueo, método restrictivo | `On` | sin `PUT` | `waf-siem/evidencias/poc_20261117_170506/` |
| **C** — Bloqueo, config realista | `On` | con `PUT` | `waf-siem/evidencias/poc_20261117_170752/` |

> El escenario **C** es el comparable con el Blue Team (modo `On` + `PUT` permitido), porque el endpoint de reseñas de Juice Shop *es* un `PUT`: una política que prohíba `PUT` también rompe la funcionalidad legítima de la aplicación.

**Resultados por escenario (código HTTP a través del WAF):**

| PoC | Endpoint | A (Detect.) | B (On, sin PUT) | C (On, con PUT) | ¿WAF bloquea la vuln.? | CVSS (propuesto) |
|---|---|---|---|---|---|---|
| 01 — Open Redirect (CWE-601) | `GET /redirect` | 302 | 302 | 302 | **No** | 6.1 (Media) |
| 02 — CSRF (CWE-352) | `POST /dataerasure` | 200 | 200 | 200 | **No** | 6.5 (Media) |
| 03 — Reseñas sin auth (CWE-862) | `PUT /rest/products/1/reviews` | 201 | 403\* | 201 | **No** (\*403 por método) | 5.3 (Media) |
| 04 — XXE (CWE-611) | `POST /file-upload` | 410 | 410 | 410 | N/A (no demostrada) | — |

> \* El 403 del escenario B lo produce la regla `911100` (método `PUT` no permitido), **no** una detección de la falta de autorización. Con `PUT` permitido (escenario C, el realista) la petición pasa (201). Los valores CVSS son **propuestos**; ajústense a la rúbrica del curso.

**Evidencia de detección (escenario A, `DetectionOnly`).** En modo detección, Kibana (`fields.fuente: "waf-audit"`) registró eventos de auditoría de ModSecurity para dos PoC, confirmando que el WAF **ve** parte del tráfico aunque no lo bloquee en la configuración realista:

| PoC | URI auditada | Reglas CRS (`ruleId`) | Interpretación |
|---|---|---|---|
| 03 — Reseñas | `/rest/products/1/reviews` | `911100`, `949110` | `911100` marca el **método** `PUT`; `949110` es la evaluación de anomalía. No detecta la falla de autorización. |
| 04 — XXE | `/file-upload` | (sin `ruleId` específico) | Evento de auditoría sin regla concreta; la app responde `410`. |

Las PoC 01 (`/redirect`) y 02 (`/dataerasure`) **no** generaron evento de auditoría: solo quedaron en el log de acceso (`fields.fuente: "waf-access"`). El WAF no las detecta en absoluto.

**Conclusión de la revalidación.** En la configuración realista (escenario C), el WAF **no bloquea ninguna de las cuatro PoC**. El único bloqueo observado (PoC-03 en escenario B) fue un artefacto de una política de métodos sobre-restrictiva que además rompería la funcionalidad legítima de reseñas. Esto confirma que el OWASP CRS no mitiga vulnerabilidades de lógica de negocio, control de acceso, CSRF ni open redirect — su fuerte es la inyección (XSS/SQLi, bloqueadas en la sección 4). La remediación corresponde al código (Hito 4).

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

- **Resultado observado.** En la configuración realista (escenario C, `On` + `PUT` permitido) → `HTTP/1.1 201`: la reseña se crea sin `Authorization` ni sesión y el WAF no la bloquea. En el escenario B (`On` sin `PUT`) → `403`, pero por la regla `911100` (método no permitido), **no** por la falla de autorización — y esa política también rompería las reseñas legítimas. Blue Team observó 201 en v20.3.0 (producto 24) con `PUT` permitido; aquí producto 1.
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

- **Resultado observado.** `HTTP/1.1 410 Gone` generado por la aplicación en los tres escenarios. En `DetectionOnly` generó un evento de auditoría (sin `ruleId` específico), pero el WAF no bloquea y la app responde 410. No se obtuvo contenido del archivo ni evidencia de procesamiento de la entidad externa. (Coincide con v20.3.0.)
- **Interpretación.** El `410` sugiere que el endpoint/flujo de parseo XML fue deshabilitado o retirado. **XXE no confirmada** en `20.4.0-SNAPSHOT`.
- **Decisión recomendada.** Documentar como **no explotable en la versión integrada** (con la evidencia del 410), o sustituir por otra vulnerabilidad real presente en esta versión. No reportarla como confirmada.

### 5.3 Consistencia entre versiones

Comparando la **configuración equivalente** (modo `On` + `PUT` permitido): escenario C del Red Team sobre `20.4.0-SNAPSHOT` vs las pruebas del Blue Team sobre `v20.3.0`. Los resultados coinciden, lo que respalda que los hallazgos no dependen de la imagen de laboratorio y aplican a la versión integrada del equipo:

| PoC | `v20.3.0` (Blue, `On`+PUT) | `20.4.0-SNAPSHOT` (Red, escenario C) | Consistencia |
|---|---|---|---|
| 01 — Open Redirect | 302, no bloqueó | 302, no bloqueó | ✔ igual |
| 02 — CSRF `/dataerasure` | 200, no bloqueó | 200, no bloqueó | ✔ igual |
| 03 — Reseñas sin auth | 201, no bloqueó | 201, no bloqueó | ✔ igual |
| 04 — XXE | 410, no confirmada | 410, no confirmada | ✔ igual |

**Correlación con SIEM.** Los eventos de la corrida en `DetectionOnly` (escenario A, timestamp `20261117_161550`, local UTC-6) se ubican en Kibana con el Data View `filebeat-*`. El campo de la ruta es `modsec.transaction.request.uri` (presente solo en los docs `waf-audit`); los de acceso usan `fields.fuente: "waf-access"`. Para aislar las detecciones de ModSecurity:

```
fields.fuente: "waf-audit"
```

Esto devuelve los dos eventos auditados (`/rest/products/1/reviews` con `911100`+`949110`, y `/file-upload`), que son la evidencia de "detección sin bloqueo".

### 5.4 Nota de interpretación conjunta (WAF vs código)

Que el WAF no bloquee las cuatro PoC en la configuración realista **no es una deficiencia de la implementación del Blue Team**, sino una característica esperada de los WAF basados en firmas:

- El WAF (ModSecurity + OWASP CRS) **detecta y bloquea ataques de inyección** —XSS, SQLi, escaneo— que es exactamente lo que demuestra la sección 4 (HTTP 403, evidencias 11 y 12). Ese es el entregable del WAF y está cumplido.
- Las cuatro PoC del Red Team (open redirect, CSRF, falta de autorización, XXE) pertenecen a **clases de vulnerabilidad de lógica de negocio y control de acceso**, sin firma reconocible en la petición. Ningún WAF las bloquea de forma genérica; su remediación corresponde al **código (Hito 4)**.
- Aun así, en modo `DetectionOnly` el WAF **detectó** dos de ellas (reseñas y XXE, con sus reglas en Kibana), lo que muestra valor como capa de monitoreo incluso donde no bloquea.

En otras palabras, ambos equipos coinciden en la misma conclusión (el propio cuadro del Blue Team en la sección 5.1 ya marca "¿bloqueó? No" para las cuatro PoC). El resultado ilustra **defensa en profundidad**: el WAF es una capa (inyección) y el código es otra (lógica, acceso, CSRF). No se contrapone al trabajo del Blue Team; lo complementa y motiva el Hito 4.

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

Se utilizó ChatGPT para estructurar pruebas controladas, interpretar evidencias y preparar la documentación. Se utilizó Claude en el navegador para crear el Data View `filebeat-*` y el dashboard de Kibana. 
