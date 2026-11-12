@echo off
title Alpha Miner
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
  echo.
  echo  Python is not installed.
  echo  Install it from https://python.org
  echo  IMPORTANT: tick "Add python.exe to PATH" during install.
  echo.
  pause
  exit /b 1
)
set /p ADDR=Mining reward address (alpha1...):
echo  Mining to %ADDR% ... leave this window open.
python mine_alpha.py --address %ADDR%
pause
