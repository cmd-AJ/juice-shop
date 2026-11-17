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
