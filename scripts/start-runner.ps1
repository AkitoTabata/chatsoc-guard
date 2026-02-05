# scripts/start-runner.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# このスクリプトの1個上（=プロジェクト直下）へ移動
Set-Location (Split-Path $PSScriptRoot -Parent)

# venv 有効化
if (!(Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "[ERROR] .venv not found. Please create venv first." -ForegroundColor Red
    exit 1
}

.\.venv\Scripts\Activate.ps1

# runner 起動
python .\detection\runner.py
