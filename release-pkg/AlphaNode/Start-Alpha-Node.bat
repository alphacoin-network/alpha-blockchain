@echo off
title Alpha Blockchain Node
echo ============================================
echo   ALPHA BLOCKCHAIN NODE
echo   Leave this window open to keep the node
echo   running. Closing it stops the node.
echo ============================================
echo.
alphad.exe --chain main --datadir "%~dp0data"
pause
