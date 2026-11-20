# Hito 4 – Remediación de vulnerabilidades

## 1. Objetivo

Corregir dos vulnerabilidades identificadas durante el Hito 3 en OWASP Juice Shop:

1. Open Redirect: posibilidad de redirigir a usuarios hacia dominios externos no autorizados.
2. Creación de reseñas sin autenticación y posibilidad de falsificar la identidad del autor.

Las modificaciones se realizan sobre la rama `h4-blue-team`, conservando el trabajo de los hitos anteriores.

## 2. Vulnerabilidad 1: Open Redirect

### 2.1. Comportamiento vulnerable

La validación original utilizaba `url.includes(allowedUrl)`. Esto permitía que una URL externa que contuviera una dirección autorizada fuera aceptada.

Pruebas realizadas antes de la corrección:

- Una dirección legítima de GitHub incluida en la lista permitida respondía con HTTP 302.
- Una dirección externa maliciosa que incorporaba una URL permitida también respondía con HTTP 302.

Evidencias:

- `evidencias/01_redirect_legitimo.txt`
- `evidencias/02_redirect_externo.txt`

### 2.2. Corrección implementada

Archivo: `lib/insecurity.ts`

Se sustituyó la validación por una comparación exacta mediante `redirectAllowlist.has(url)`.

La función también rechaza valores vacíos o que no sean cadenas.

Con este cambio, únicamente se aceptan destinos que coinciden exactamente con una entrada de la lista permitida.

### 2.3. Cambios relacionados

- Se actualizó `test/server/insecurity.unit.test.ts` para comprobar el rechazo de URLs manipuladas.
- Se actualizó `test/server/redirect.unit.test.ts` para verificar que las redirecciones no autorizadas sean rechazadas.
- Se actualizó `test/api/redirect.test.ts` para validar el comportamiento HTTP.
- Se actualizó `test/cypress/e2e/redirect.spec.ts` para comprobar el rechazo de la URL maliciosa.
- Se retiró la dependencia del parámetro `testDecal` y del evento `verifySvgInjectionChallenge`, que utilizaban el flujo de redirección vulnerable.
- Se actualizaron `frontend/src/app/deluxe-user/deluxe-user.component.ts`, `lib/startup/registerWebsocketEvents.ts` y `test/cypress/e2e/deluxe.spec.ts` para eliminar ese flujo de explotación, conservando la funcionalidad de membresía Deluxe.

### 2.4. Evidencias posteriores

- `evidencias/03_redirect_legitimo_postfix.txt`: destino autorizado.
- `evidencias/04_redirect_malicioso_postfix.txt`: URL externa rechazada.
- `evidencias/05_redirect_subdominio_postfix.txt`: dominio engañoso rechazado.

Resultados observados:

- Destino legítimo: HTTP 302.
- Destino externo malicioso: HTTP 406, sin cabecera `Location`.
- Dominio engañoso: HTTP 406, sin cabecera `Location`.

## 3. Vulnerabilidad 2: creación de reseñas sin autenticación

### 3.1. Comportamiento vulnerable

La ruta `PUT /rest/products/:id/reviews` permitía crear reseñas sin exigir autenticación.

La prueba inicial reprodujo el problema:

- Método: PUT.
- Ruta: `/rest/products/1/reviews`.
- Cabecera Authorization: no enviada.
- Resultado: HTTP 201.

Evidencia: `evidencias/06_review_sin_autenticacion_baseline.txt`.

### 3.2. Corrección implementada

Archivos modificados:

- `server.ts`
- `routes/createProductReviews.ts`

Se incorporó el middleware `security.isAuthorized()` a la ruta de creación de reseñas.

Además, el controlador:

- Comprueba que exista un usuario autenticado.
- Rechaza solicitudes sin identidad válida con HTTP 401.
- Obtiene el correo del autor desde el usuario autenticado.
- No utiliza el campo `author` enviado por el cliente.
- Conserva la respuesta HTTP 201 cuando la creación es válida.

### 3.3. Pruebas posteriores

La petición anónima fue repetida después de la corrección:

- Método: PUT.
- Ruta: `/rest/products/1/reviews`.
- Authorization: no enviada.
- Resultado: HTTP 401.

Evidencia: `evidencias/07_review_sin_autenticacion_postfix.txt`.

También se actualizaron las pruebas de `test/api/product-review.test.ts` para comprobar que:

1. Una solicitud anónima recibe HTTP 401.
2. Un usuario autenticado puede crear una reseña.
3. Aunque el cliente envíe `author: H4-ATTACKER`, el autor almacenado corresponde al correo de la cuenta autenticada.

## 4. Resultados de las pruebas

Validación final ejecutada el 20/11/2026 sobre la rama `h4-blue-team` (Node 22, npm 11).

### 4.1. Pruebas unitarias

| Prueba | Resultado |
|---|---:|
| `insecurity.unit.test.ts` + `redirect.unit.test.ts` | 46/46 aprobadas |
| Suite completa `npm run test:server` | 404 aprobadas, 0 fallidas, 2 omitidas (preexistentes) |

### 4.2. Pruebas API

| Prueba | Resultado |
|---|---:|
| `redirect.test.ts` + `product-review.test.ts` | 24 aprobadas, 0 fallidas, 1 omitida |
| Suite completa `npm run test:api` | 581 aprobadas, 0 fallidas, 6 omitidas (preexistentes) |

La prueba omitida de reseñas corresponde a una prueba preexistente marcada con `it.skip`, relacionada con el issue #1960.

### 4.3. Pruebas Cypress

Ejecución inicial de:

`test/cypress/e2e/redirect.spec.ts` y `test/cypress/e2e/deluxe.spec.ts`

Resultado inicial: 4 pruebas aprobadas.

Una segunda ejecución detectó un fallo en `Deluxe Fraud` debido al estado persistente de la cuenta de prueba Deluxe, después de que la primera ejecución modificara esa cuenta. No se considera una regresión demostrada de Open Redirect; debe tenerse en cuenta al repetir la prueba (reiniciar la aplicación antes de repetir).

### 4.4. Compilación y lint

- `npm run build:frontend` y `npm run build:server` (tsc): sin errores.
- ESLint sobre todos los archivos modificados (backend, pruebas y componente Angular): sin errores.
- Se eliminaron los caracteres BOM (UTF-8) que el editor de Windows había agregado a cinco archivos `.ts`, se corrigió la indentación de `insecurity.unit.test.ts` y una aserción de Cypress (`to.be.undefined` → `to.equal(undefined)`) que el lint rechazaba.
- Las evidencias `03`–`07` se convirtieron de UTF-16 a UTF-8 para que GitHub las muestre como texto.

## 5. Re-test del Red Team

**Responsables:** Red Team (Andre Jo, Pedro Guzmán).

El Red Team repitió las PoC-01 y PoC-03 del Hito 2 contra la versión corregida. Para que la verificación sea reproducible se automatizó en `docs/hito-4/retest-red-team.sh`, que lanza los mismos payloads y **falla (exit 1) si alguna PoC corregida sigue siendo explotable**.

```bash
bash docs/hito-4/retest-red-team.sh http://localhost:3000 resultado.txt
```

Para demostrar que el script detecta realmente la vulnerabilidad (falla antes y pasa después), se ejecutó contra dos objetivos locales:

| Caso | Payload | Antes: `bkimminich/juice-shop:v20.3.0` (versión del H3) | Después: rama `h4-blue-team` |
|---|---|---|---|
| PoC-01a | `to=https://github.com/juice-shop/juice-shop` (destino permitido) | 302 | 302 (funcionalidad legítima conservada) |
| PoC-01b | `to=http://sitio-falso.example/?x=https://github.com/juice-shop/juice-shop` | **302**, `Location` al dominio del atacante | **406**, sin `Location` |
| PoC-01c | `to=https://github.com.evil.example/juice-shop/juice-shop` | 406 | 406 |
| PoC-01d | `to=/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop` | **302** | **406** |
| PoC-03a | `PUT /rest/products/1/reviews` sin token, `author: admin@juice-sh.op` | **201** | **401** |
| PoC-03b | Mismo PUT con token de `jim@juice-sh.op` | 201 | 201 |
| PoC-03c | Autor almacenado de la reseña de PoC-03b | **`admin@juice-sh.op`** (suplantado) | `jim@juice-sh.op` (del token) |
| PoC-03d | ¿La reseña anónima quedó publicada? | **Sí** | No |
| **Resultado** | | **FAIL** (5 casos explotables) | **PASS** (8/8) |

Evidencias:

- `evidencias/09_retest_red_team_baseline_v20.3.0.txt`: salida completa contra la versión vulnerable.
- `evidencias/08_retest_red_team_postfix.txt`: salida completa contra la versión corregida.

Todas las pruebas se realizaron sobre instancias locales (`localhost`); no se siguió ningún enlace externo ni se atacaron sistemas de terceros.

## 6. Integración en el pipeline (GitHub Actions)

Se actualizó `.github/workflows/devsecops.yml` (ahora `DevSecOps (H2-H4)`):

| Job | Cambio en H4 | Propósito |
|---|---|---|
| `h4-regression-tests` | **Nuevo** | Ejecuta las pruebas unitarias y API de las dos correcciones. Si alguien reintroduce `includes()` o quita `isAuthorized()`, el pipeline falla. |
| `dast-zap` | Antes escaneaba la imagen pública `bkimminich/juice-shop:latest`; **ahora construye la imagen desde el código de la rama** (`docker build .`) | El DAST y el re-test evalúan el código del equipo con las correcciones, no la versión original. |
| `dast-zap` → paso `Red Team retest` | **Nuevo** | Ejecuta `retest-red-team.sh` contra la imagen construida y publica el artefacto `red-team-retest`. |
| `security-gate` | Sin cambios | Sigue bloqueando alertas High de ZAP y advirtiendo las Medium. |

Artefactos de cada ejecución: `semgrep-report`, `npm-audit-reports`, `sbom-cyclonedx`, `zap-reports`, `red-team-retest`, `security-gate-summary`.

## 7. Riesgo residual

| PoC | Estado en H4 | Justificación |
|---|---|---|
| PoC-01 Open Redirect (CWE-601) | **Corregida** | Comparación exacta contra la allowlist. |
| PoC-03 Reseña sin autenticación (CWE-862) | **Corregida** | `isAuthorized()` + autor tomado del token. |
| PoC-02 Falta de anti-CSRF en `/dataerasure` (CWE-352) | Pendiente / riesgo aceptado | No forma parte de las dos correcciones seleccionadas. Mitigación propuesta: token anti-CSRF por sesión y cookie `token` con `SameSite=Strict`. |
| PoC-04 XXE en `/file-upload` (CWE-611) | Pendiente / no confirmada en v20.3.0 | En el H3 la carga XML respondió 410 y no se observó el canario. Mitigación propuesta: parser sin entidades externas (`noent: false`) y autenticación en la ruta. |

## 8. Archivos de evidencia

La carpeta `evidencias/` contiene:

| Archivo | Descripción |
|---|---|
| `01_redirect_legitimo.txt` | Redirección legítima antes de la corrección |
| `02_redirect_externo.txt` | Redirección externa vulnerable |
| `03_redirect_legitimo_postfix.txt` | Redirección legítima después de la corrección |
| `04_redirect_malicioso_postfix.txt` | Rechazo de URL externa |
| `05_redirect_subdominio_postfix.txt` | Rechazo de dominio engañoso |
| `06_review_sin_autenticacion_baseline.txt` | Creación anónima antes de la corrección |
| `07_review_sin_autenticacion_postfix.txt` | Rechazo de creación anónima después de la corrección |
| `08_retest_red_team_postfix.txt` | Re-test del Red Team sobre la versión corregida (PASS 8/8) |
| `09_retest_red_team_baseline_v20.3.0.txt` | Mismo re-test sobre la versión vulnerable v20.3.0 (FAIL) |

La carpeta `respaldo/` conserva las versiones originales de los archivos principales modificados para la corrección de Open Redirect.

## 9. Archivos principales modificados

- `lib/insecurity.ts`
- `lib/startup/registerWebsocketEvents.ts`
- `routes/createProductReviews.ts`
- `server.ts`
- `frontend/src/app/deluxe-user/deluxe-user.component.ts`
- `test/server/insecurity.unit.test.ts`
- `test/server/redirect.unit.test.ts`
- `test/api/redirect.test.ts`
- `test/api/product-review.test.ts`
- `test/cypress/e2e/redirect.spec.ts`
- `test/cypress/e2e/deluxe.spec.ts`
- `.github/workflows/devsecops.yml`
- `docs/hito-4/retest-red-team.sh`

## 10. Estado del hito

Las dos vulnerabilidades seleccionadas fueron reproducidas antes de la corrección, corregidas en el código y verificadas después por el Blue Team (pruebas automatizadas) y por el Red Team (re-test de las PoC contra la versión vulnerable y la corregida).

Compilación, lint y suites completas de pruebas unitarias y API validadas el 20/11/2026. Queda pendiente confirmar la ejecución en verde del workflow en GitHub Actions tras publicar la rama.
