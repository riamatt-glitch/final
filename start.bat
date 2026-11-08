@echo off
rem Starts the RBVMS web application and opens it in your browser. Press Ctrl+C in this window to stop it.
cd /d "%~dp0"

if not exist venv\Scripts\python.exe (
  echo The virtual environment is missing. Run setup.bat first.
  pause & exit /b 1
)

findstr /b /i "DB_ENGINE=mysql" .env >nul 2>nul && (
  sc query MySQL80 | find "RUNNING" >nul || (
    echo The MySQL80 service is not running.
    echo Start it from the Services app, or in an administrator terminal run:  net start MySQL80
    pause & exit /b 1
  )
)

echo Starting RBVMS at http://127.0.0.1:8000/  (press Ctrl+C to stop)
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:8000/"
venv\Scripts\python.exe manage.py runserver 8000
