@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python is not installed. Download Python from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
py -m reverse_lab.gui
if errorlevel 1 (
  echo Could not start Reverse Lab AI. Check that Python includes Tkinter.
  pause
  exit /b 1
)
