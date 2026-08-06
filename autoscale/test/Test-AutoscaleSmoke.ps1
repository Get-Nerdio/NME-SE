# Dev fixture: offline smoke test for Get-NerdioAutoscaleSheet.ps1. NOT for customers.
# Zero-plan tenant: proves the empty path + the zip packaging (HTML + log, CSV absent).
# Core translation logic was validated by a fuller 27-assertion harness pre-v0.3 and
# live on 2026-08-04; this smoke guards the run/package skeleton across changes.
# Run on any pwsh 7+: pwsh -File Test-AutoscaleSmoke.ps1
function Get-AzContext { [pscustomobject]@{ Name = 'mock' } }
function Invoke-AzRestMethod {
    param([string]$Method, [string]$Path, [string]$Payload)
    if ($Method -eq 'POST' -and $Path -like '*Microsoft.ResourceGraph*') {
        return [pscustomobject]@{ StatusCode = 200; Content = '{"data":[]}' }
    }
    return [pscustomobject]@{ StatusCode = 404; Content = '{}' }
}
function Invoke-AzOperationalInsightsQuery { param([string]$WorkspaceId, [string]$Query) [pscustomobject]@{ Results = @() } }

Remove-Item /tmp/smoke-autoscale*.* -Force -ErrorAction SilentlyContinue
& "$PSScriptRoot/../Get-NerdioAutoscaleSheet.ps1" -SkipDownload -OutFile /tmp/smoke-autoscale.html

Write-Host "`n--- VALIDATION ---"
Remove-Item /tmp/smokecheck -Recurse -Force -ErrorAction SilentlyContinue
$zipOk = Test-Path /tmp/smoke-autoscale.zip
if ($zipOk) { Expand-Archive /tmp/smoke-autoscale.zip -DestinationPath /tmp/smokecheck -Force }
$log = if (Test-Path /tmp/smokecheck/smoke-autoscale-console.log) { Get-Content /tmp/smokecheck/smoke-autoscale-console.log -Raw } else { '' }
$html = if (Test-Path /tmp/smokecheck/smoke-autoscale.html) { Get-Content /tmp/smokecheck/smoke-autoscale.html -Raw } else { '' }

$checks = [ordered]@{
    'html written'              = (Test-Path /tmp/smoke-autoscale.html)
    'zip packaged'              = $zipOk
    'zip holds html + log'      = (($html -ne '') -and ($log -ne ''))
    'no csv in zip (0 plans)'   = (-not (Test-Path /tmp/smokecheck/smoke-autoscale-review.csv))
    'html is the profiles page' = ($html -match 'NME Auto-Scale Profiles')
    'log captured + clean'      = ($log -match 'No scaling plans found' -and $log -notmatch [char]27)
}
$fail = 0
foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host "PASS  $k" -ForegroundColor Green }
    else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
if ($fail -eq 0) { Write-Host "`nALL CHECKS PASSED" -ForegroundColor Green } else { Write-Host "`n$fail CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
