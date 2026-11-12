@echo off
title Alpha Blockchain Node
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
echo  Starting Alpha node (mainnet)... leave this window open.
python alphad.py --chain main
pause
