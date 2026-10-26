param([switch]$AcceptSplunkTerms)
$ErrorActionPreference = 'Stop'

if (-not $AcceptSplunkTerms) {
    throw 'Review the Splunk terms linked in docs/dung_splunk_cuc_bo_28-9.md, then explicitly pass -AcceptSplunkTerms. No container was started.'
}
$taskRoot = Split-Path -Parent $PSScriptRoot
$composePath = Join-Path $taskRoot 'dev/splunk/compose.yaml'
& docker info --format '{{.OSType}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Open Docker Desktop and wait for its Linux engine to be ready.' }
if (-not $env:SPLUNK_PASS) {
    $secure = Read-Host 'Choose a Splunk admin password (not an API key)' -AsSecureString
    $env:SPLUNK_PASS = [System.Net.NetworkCredential]::new('', $secure).Password
}
if ([string]::IsNullOrWhiteSpace($env:SPLUNK_PASS)) { throw 'Empty password' }
$env:SPLUNK_USER = 'admin'
$savedPassword = $env:SPLUNK_PASSWORD
$savedStartArgs = $env:SPLUNK_START_ARGS
$savedTerms = $env:SPLUNK_GENERAL_TERMS
try {
    $env:SPLUNK_PASSWORD = $env:SPLUNK_PASS
    $env:SPLUNK_START_ARGS = '--accept-license'
    $env:SPLUNK_GENERAL_TERMS = '--accept-sgt-current-at-splunk-com'
    & docker compose -f $composePath config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose validation failed' }
    & docker compose -f $composePath up -d
    if ($LASTEXITCODE -ne 0) { throw 'Splunk startup failed; inspect Docker Desktop' }
    Write-Host 'Starting Splunk at http://127.0.0.1:8000. Check license and available ingest capacity before importing. No CTI events were imported.'
} finally {
    $env:SPLUNK_PASSWORD = $savedPassword
    $env:SPLUNK_START_ARGS = $savedStartArgs
    $env:SPLUNK_GENERAL_TERMS = $savedTerms
}
