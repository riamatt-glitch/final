@echo off
rem Runs the automated test suite (pytest-django). Expect "61 passed".
cd /d "%~dp0"
venv\Scripts\python.exe -m pytest -v -o addopts=""
pause
