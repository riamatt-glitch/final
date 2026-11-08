@echo off
rem One-time setup for the Risk-Based Vulnerability Management System (RBVMS).
rem Safe to run again: it only creates what is missing.
cd /d "%~dp0"

where python >nul 2>nul || (
  echo Python was not found. Install it with:  winget install -e --id Python.Python.3.12
  echo then open a NEW terminal and run setup.bat again.
  pause & exit /b 1
)

if not exist venv\Scripts\python.exe (
  echo [1/5] Creating the Python virtual environment...
  python -m venv venv || (pause & exit /b 1)
) else (
  echo [1/5] Virtual environment already exists.
)

echo [2/5] Installing the Python packages from requirements.txt...
venv\Scripts\python.exe -m pip install --quiet --upgrade pip
venv\Scripts\python.exe -m pip install --quiet -r requirements.txt || (pause & exit /b 1)

if not exist .env (
  copy .env.example .env >nul
  echo [3/5] Created .env from .env.example. It uses SQLite until you set DB_ENGINE=mysql and DB_PASSWORD in .env.
) else (
  echo [3/5] .env already exists.
)

echo [4/5] Creating or updating the database tables...
venv\Scripts\python.exe manage.py migrate || (pause & exit /b 1)

venv\Scripts\python.exe manage.py shell -c "import sys; from vulnmgmt.models import Asset; sys.exit(0 if Asset.objects.exists() else 1)" >nul 2>nul
if errorlevel 1 (
  echo [5/5] Loading the demo organisation...
  venv\Scripts\python.exe manage.py seed_demo
) else (
  echo [5/5] Data already present - demo data not reloaded.
)

echo.
echo Setup complete. Double-click start.bat to run the system.
pause
