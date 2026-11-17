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

### 4.1. Pruebas unitarias

| Prueba | Resultado |
|---|---:|
| `insecurity.unit.test.ts` | 54/54 aprobadas |
| `redirect.unit.test.ts` | 13/13 aprobadas |

### 4.2. Pruebas API

| Prueba | Resultado |
|---|---:|
| `redirect.test.ts` | 11/11 aprobadas |
| `product-review.test.ts` | 13 aprobadas, 0 fallidas, 1 omitida |

La prueba omitida de reseñas corresponde a una prueba preexistente marcada con `it.skip`, relacionada con el issue #1960.

### 4.3. Pruebas Cypress

Ejecución inicial de:

`test/cypress/e2e/redirect.spec.ts` y `test/cypress/e2e/deluxe.spec.ts`

Resultado inicial: 4 pruebas aprobadas.

Una segunda ejecución detectó un fallo en `Deluxe Fraud` debido al estado persistente de la cuenta de prueba Deluxe, después de que la primera ejecución modificara esa cuenta. No se considera una regresión demostrada de Open Redirect; debe tenerse en cuenta al repetir la prueba.

### 4.4. Compilación

`npm run build` había finalizado correctamente después de los cambios de frontend, sin errores de compilación de Angular ni TypeScript.

Se realizará una validación final de compilación antes de cerrar el hito.

## 5. Archivos de evidencia

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

La carpeta `respaldo/` conserva las versiones originales de los archivos principales modificados para la corrección de Open Redirect.

## 6. Archivos principales modificados

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

## 7. Estado del hito

Las dos vulnerabilidades seleccionadas fueron reproducidas antes de la corrección y verificadas después de aplicar los cambios.

La validación final de compilación, revisión del diff y publicación de la rama `h4-blue-team` quedan pendientes de cierre.
