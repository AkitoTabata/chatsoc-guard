# scripts/start.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# このスクリプトの1個上（=プロジェクト直下）へ移動
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "[INFO] starting redis (docker compose)..." -ForegroundColor Cyan
docker compose up -d

# venv 有効化
if (!(Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "[ERROR] .venv not found. Please create venv first." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] activating venv..." -ForegroundColor Cyan
.\.venv\Scripts\Activate.ps1

Write-Host "[INFO] starting fastapi (uvicorn)..." -ForegroundColor Cyan
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
