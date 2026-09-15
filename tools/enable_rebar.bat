@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [*] Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ==================================================
echo   NvStrapsReBar restore - STEP 1 or STEP 2
echo ==================================================
echo.
echo   ReBAR is lost after every BIOS flash / CMOS clear.
echo   Run this tool twice, with a REBOOT in between.
echo.
echo   --- STEP 1 (first run) ---
echo       E   enable Turing auto settings
echo       S   save to UEFI variable
echo       Q   quit, then REBOOT
echo.
echo   --- STEP 2 (after reboot) ---
echo       status line should read "GPU-side ReBAR Configured..."
echo       P   configure PCI side for the GPU
echo       64  set 64 GB request (board caps it to 32 GiB)
echo       S   save
echo       Q   quit, then REBOOT
echo.
echo   Then run check_rebar.bat - expect BAR1 Total = 32768 MiB
echo.
echo ==================================================
echo   Press any key to launch NvStrapsReBar.exe ...
pause >nul

NvStrapsReBar.exe

echo.
echo [*] Tool closed. Remember: REBOOT before verifying.
pause
