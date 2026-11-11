param(
    [string]$ReportPath = (Join-Path $PSScriptRoot "zap-report.json")
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "       SECURITY GATE - ZAP" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Comprobar que existe el reporte
if (-not (Test-Path $ReportPath)) {
    Write-Host "[ERROR] No se encontro el reporte: $ReportPath" -ForegroundColor Red
    exit 1
}

# 2. Leer y validar el JSON
try {
    $data = Get-Content $ReportPath -Raw | ConvertFrom-Json
}
catch {
    Write-Host "[ERROR] No se pudo leer el JSON de ZAP." -ForegroundColor Red
    exit 1
}

if ($null -eq $data.site) {
    Write-Host "[ERROR] El reporte no contiene sitios para analizar." -ForegroundColor Red
    exit 1
}

# 3. Obtener las alertas
$alerts = @(
    foreach ($site in @($data.site)) {
        foreach ($alert in @($site.alerts)) {
            if ($null -ne $alert) {
                if ($null -eq $alert.riskcode) {
                    Write-Host "[ERROR] Una alerta no contiene riskcode." -ForegroundColor Red
                    exit 1
                }

                [PSCustomObject]@{
                    Alert    = $alert.alert
                    RiskCode = [int]$alert.riskcode
                    Count    = [int]$alert.count
                }
            }
        }
    }
)

# 4. Clasificar por severidad
$high = @($alerts | Where-Object { $_.RiskCode -eq 3 })
$medium = @($alerts | Where-Object { $_.RiskCode -eq 2 })
$low = @($alerts | Where-Object { $_.RiskCode -eq 1 })
$info = @($alerts | Where-Object { $_.RiskCode -eq 0 })

# 5. Mostrar resumen
Write-Host "RESUMEN DE ALERTAS" -ForegroundColor Cyan
Write-Host "----------------------------------------"
Write-Host "High:          $($high.Count) tipos / $(($high | Measure-Object Count -Sum).Sum) instancias"
Write-Host "Medium:        $($medium.Count) tipos / $(($medium | Measure-Object Count -Sum).Sum) instancias"
Write-Host "Low:           $($low.Count) tipos / $(($low | Measure-Object Count -Sum).Sum) instancias"
Write-Host "Informational: $($info.Count) tipos / $(($info | Measure-Object Count -Sum).Sum) instancias"

# 6. Mostrar política aplicada
Write-Host "`nPOLITICA DEL SECURITY GATE" -ForegroundColor Cyan
Write-Host "High          -> FAIL (bloquear)"
Write-Host "Medium        -> WARN (permitir con advertencia)"
Write-Host "Low           -> PASS (registrar)"
Write-Host "Informational -> PASS (registrar)"

# 7. Tomar decisión
Write-Host "`n========================================"

if ($high.Count -gt 0) {
    Write-Host "SECURITY GATE: FAIL" -ForegroundColor Red
    Write-Host "Se encontraron alertas High. Proceso bloqueado."
    exit 1
}
elseif ($medium.Count -gt 0) {
    Write-Host "SECURITY GATE: WARN" -ForegroundColor Yellow
    Write-Host "Hay alertas Medium que requieren revision."
    Write-Host "No se encontraron alertas High."
    exit 0
}
else {
    Write-Host "SECURITY GATE: PASS" -ForegroundColor Green
    Write-Host "No se encontraron alertas High ni Medium."
    exit 0
}
