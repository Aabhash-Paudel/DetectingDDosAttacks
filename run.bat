@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   DDoS Shield - Setup and Run (Windows)
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

set "VENV_DIR=.venv"
set "PY=%VENV_DIR%\Scripts\python.exe"

:: Create venv if missing (local, repo-scoped)
echo [1/4] Creating virtual environment (local)...
if not exist "%PY%" (
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Install dependencies (inside venv)
echo [2/4] Installing dependencies...
"%PY%" -m pip install --upgrade pip >nul
"%PY%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

:: Train model if not exists
if not exist "backend\model.pkl" (
    echo [3/4] Training model (first run only, may take ~30 seconds)...
    "%PY%" backend\train_model.py
    if errorlevel 1 (
        echo ERROR: Model training failed.
        pause
        exit /b 1
    )
) else (
    echo [3/4] Model already trained, skipping.
)

:: Start server
echo [4/4] Starting DDoS Shield server...
echo.
echo  -----------------------------------------------
echo   Open your browser at: http://localhost:5000
echo  -----------------------------------------------
echo.
"%PY%" backend\app.py
pause
