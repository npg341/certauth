param([string]$What = "demo")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"
$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPy)) {
    Write-Host "== First run: creating virtual environment ==" -ForegroundColor Cyan
    $candidates = @(
        @("py", "-3"), @("python"), @("python3"),
        @("$env:USERPROFILE\anaconda3\python.exe"), @("$env:USERPROFILE\miniconda3\python.exe"),
        @("$env:LOCALAPPDATA\anaconda3\python.exe"), @("$env:ProgramData\anaconda3\python.exe")
    )
    $base = $null
    foreach ($c in $candidates) {
        try {
            $exe = $c[0]; $rest = @($c | Select-Object -Skip 1)
            $v = & $exe @rest -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -eq 0 -and [version]$v -ge [version]"3.10") { $base = $c; break }
        } catch { }
    }
    if (-not $base) {
        Write-Host "Python 3.10+ not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')." -ForegroundColor Red
        exit 1
    }
    Write-Host "Using: $($base -join ' ') (Python $v)"
    $exe = $base[0]; $rest = @($base | Select-Object -Skip 1)
    & $exe @rest -m venv .venv
    & $venvPy -m pip install --disable-pip-version-check -q -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed" -ForegroundColor Red; exit 1 }
}

switch ($What) {
    "demo"  { & $venvPy demo.py }
    "test"  {
        $ErrorActionPreference = "Continue"
        & $venvPy -m pytest -v --durations=10 --junitxml=test-report.xml
    }
    "diag"  { & $venvPy diag.py }
    "setup" { & $venvPy -c "import cryptography, sys; print('Ready: Python', sys.version.split()[0], '| cryptography', cryptography.__version__)" }
}
exit $LASTEXITCODE
