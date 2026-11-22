$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    Write-Host '[1/3] Creating the Python environment...'
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        & py.exe -3 -m venv .venv
    } elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
        & python.exe -m venv .venv
    } else {
        throw 'Python 3.11+ is required. Install Python, enable Add python.exe to PATH, then reopen this window.'
    }
    if ($LASTEXITCODE -ne 0) { throw 'Unable to create Python environment' }
}
& $taskPython -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required. The Python environment in .venv is not usable.' }
Write-Host '[2/3] Installing or checking runtime dependencies. The first run can take a few minutes...'
& $taskPython -m pip install -e .
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
if (-not $env:QUICKPOOL_HOST) { $env:QUICKPOOL_HOST = '127.0.0.1' }
if (-not $env:QUICKPOOL_PORT) { $env:QUICKPOOL_PORT = '8045' }
if (-not $env:QUICKPOOL_DATA_DIR) { $env:QUICKPOOL_DATA_DIR = Join-Path $PSScriptRoot 'data' }
$taskData = [System.IO.Path]::GetFullPath($env:QUICKPOOL_DATA_DIR)
Write-Host '[3/3] Starting QuickPool. Keep this window open; press Ctrl+C to stop.'
Write-Host "Console: http://127.0.0.1:$($env:QUICKPOOL_PORT)/"
Write-Host "Data: $taskData"
Write-Host "Console admin key file: $(Join-Path $taskData 'admin.key')"
& $taskPython -m quickpool
exit $LASTEXITCODE

