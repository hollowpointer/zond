<#
.SYNOPSIS
    Run Zond Integration Tests on Windows.

.DESCRIPTION
    This script automates the execution of the Zond integration test suite on Windows.
    It ensures the environment is suitable for testing (Administrator check) and 
    executes the platform-specific integration tests.

.EXAMPLE
    .\run_integration_windows.ps1
#>

# 1. Require Administrator Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Zond integration tests require Administrator privileges to perform hardware heuristics and raw socket discovery."
    Write-Host "Please restart your PowerShell session as Administrator and try again." -ForegroundColor Red
    exit 1
}

Write-Host ">>> Zond Windows Integration Test Suite" -ForegroundColor Cyan

# 2. Workspace Check
if (-not (Test-Path "Cargo.toml")) {
    Write-Error "Script must be run from the repository root."
    exit 1
}

# 3. Execution
Write-Host ">>> Compiling and running platform tests..." -ForegroundColor Gray
# We target use 'zond-integration-tests' specifically to isolate from Linux-bound tests
cargo test -p zond-integration-tests -- --nocapture

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n>>> Integration tests FAILED." -ForegroundColor Red
    exit $LASTEXITCODE
} else {
    Write-Host "`n>>> Integration tests PASSED." -ForegroundColor Green
    exit 0
}
