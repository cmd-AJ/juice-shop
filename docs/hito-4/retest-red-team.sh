#!/usr/bin/env bash
# Hito 4 - Re-test del Red Team sobre la versión corregida.
# Repite las PoC-01 (Open Redirect) y PoC-03 (reseña sin autenticación)
# contra una instancia LOCAL de Juice Shop y falla si alguna sigue siendo explotable.
#
# Uso: bash docs/hito-4/retest-red-team.sh [URL_BASE] [ARCHIVO_SALIDA]
#   URL_BASE        por defecto http://localhost:3000 (usar http://localhost:8080 si se pasa por el WAF)
#   ARCHIVO_SALIDA  por defecto retest-red-team.txt

set -u

BASE="${1:-http://localhost:3000}"
OUT="${2:-retest-red-team.txt}"
FAILED=0

log () { echo "$*" | tee -a "$OUT"; }

: > "$OUT"
log "=== H4 - RE-TEST RED TEAM ==="
log "Fecha (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
log "Objetivo:    $BASE"
log ""

check () {
  # $1 = id, $2 = descripción, $3 = estado obtenido, $4 = estado esperado, $5 = detalle
  if [ "$3" = "$4" ]; then
    log "[PASS] $1 - $2 -> HTTP $3 (esperado $4) $5"
  else
    log "[FAIL] $1 - $2 -> HTTP $3 (esperado $4) $5"
    FAILED=1
  fi
}

# ---------- PoC-01: Open Redirect (CWE-601) ----------
redirect_case () {
  local id="$1" desc="$2" target="$3" expected="$4"
  local headers status location
  headers=$(curl -s -o /dev/null -D - --max-redirs 0 -G "$BASE/redirect" --data-urlencode "to=$target")
  status=$(echo "$headers" | awk 'NR==1{print $2}')
  location=$(echo "$headers" | grep -i '^location:' | tr -d '\r' | cut -d' ' -f2-)
  check "$id" "$desc" "$status" "$expected" "Location='${location:-ninguna}'"
}

log "--- PoC-01 Open Redirect: GET /redirect?to=... ---"
redirect_case "PoC-01a" "Destino permitido exacto" "https://github.com/juice-shop/juice-shop" 302
redirect_case "PoC-01b" "Payload original (dominio externo + URL permitida en query)" "http://sitio-falso.example/?x=https://github.com/juice-shop/juice-shop" 406
redirect_case "PoC-01c" "Dominio engañoso (github.com.evil.example)" "https://github.com.evil.example/juice-shop/juice-shop" 406
redirect_case "PoC-01d" "Ruta interna con URL permitida en query" "/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop" 406
log ""

# ---------- PoC-03: reseña sin autenticación (CWE-862) ----------
log "--- PoC-03 Reseñas: PUT /rest/products/1/reviews ---"
MSG="H4_RETEST_$(date +%s)"
status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/rest/products/1/reviews" \
  -H 'Content-Type: application/json' \
  -d "{\"message\":\"$MSG-anon\",\"author\":\"admin@juice-sh.op\"}")
check "PoC-03a" "PUT anónimo con author falsificado" "$status" 401 ""

TOKEN=$(curl -s -X POST "$BASE/rest/user/login" -H 'Content-Type: application/json' \
  -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then
  log "[FAIL] PoC-03b - No se pudo iniciar sesión como jim@juice-sh.op"
  FAILED=1
else
  status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/rest/products/1/reviews" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
    -d "{\"message\":\"$MSG-auth\",\"author\":\"admin@juice-sh.op\"}")
  check "PoC-03b" "PUT autenticado (jim) intentando firmar como admin" "$status" 201 ""

  author=$(curl -s "$BASE/rest/products/1/reviews" | tr '}' '\n' | grep "$MSG-auth" | sed -n 's/.*"author":"\([^"]*\)".*/\1/p')
  if [ "$author" = "jim@juice-sh.op" ]; then
    log "[PASS] PoC-03c - Autor almacenado = '$author' (se ignora el author del cliente)"
  else
    log "[FAIL] PoC-03c - Autor almacenado = '${author:-no encontrado}' (esperado jim@juice-sh.op)"
    FAILED=1
  fi

  anon=$(curl -s "$BASE/rest/products/1/reviews" | grep -c "$MSG-anon")
  if [ "$anon" = "0" ]; then
    log "[PASS] PoC-03d - La reseña anónima no fue almacenada"
  else
    log "[FAIL] PoC-03d - La reseña anónima sí aparece publicada"
    FAILED=1
  fi
fi
log ""

if [ "$FAILED" = "0" ]; then
  log "RESULTADO: PASS - Las PoC corregidas ya no son explotables"
else
  log "RESULTADO: FAIL - Al menos una PoC corregida sigue siendo explotable"
fi
exit "$FAILED"
