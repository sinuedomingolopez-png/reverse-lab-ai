@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m reverse_lab.gui
) else (
  where py >nul 2>nul
  if errorlevel 1 (
    echo Python no esta instalado. Descargalo desde https://www.python.org/downloads/windows/
    pause
    exit /b 1
  )
  py -m reverse_lab.gui
)
if errorlevel 1 (
  echo No se pudo iniciar Reverse Lab AI. Comprueba Python y Tkinter.
  pause
  exit /b 1
)
