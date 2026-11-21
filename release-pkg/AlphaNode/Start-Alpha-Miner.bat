@echo off
title Alpha Miner
echo ============================================
echo   ALPHA MINER - keep Start-Alpha-Node.bat
echo   running in another window too.
echo ============================================
set /p ADDR=Enter your ALPHA address (alpha1... or 1...):
if "%ADDR%"=="" (echo No address entered. & pause & exit)
if exist "%~dp0mine_alpha.exe" (
  echo Starting hardware-aware miner (auto CPU threads, Ctrl+C to stop)...
  "%~dp0mine_alpha.exe" --datadir "%~dp0data" --address %ADDR%
) else (
  echo mine_alpha.exe not found - using basic miner.
  :loop
  alpha_cli.exe --chain main generatetoaddress 1 %ADDR% --datadir "%~dp0data"
  goto loop
)
pause
