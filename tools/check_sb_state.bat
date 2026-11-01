@echo off
setlocal
title Secure Boot state check

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo Running secure boot self-check (admin)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0check_sb_state.ps1"

echo.
echo Done. Report: %~dp0sb_report.txt
echo.
pause
