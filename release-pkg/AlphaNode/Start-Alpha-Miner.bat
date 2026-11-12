@echo off
title Alpha Miner
echo ============================================
echo   ALPHA MINER — keep Start-Alpha-Node.bat
echo   running in another window too.
echo ============================================
set /p ADDR=Enter your ALPHA address (alpha1... or 1...):
if "%ADDR%"=="" (echo No address entered. & pause & exit)
:loop
alpha_cli.exe generatetoaddress 1 %ADDR% --datadir "%~dp0data"
goto loop
