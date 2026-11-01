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
echo   NvStrapsReBar configure  (Z690M + 22GB TU102)
echo ==================================================
echo.
echo   Goal: Target BAR = 32 GiB, save, reboot.
echo.
echo   Inside the tool:
echo     1) SELECT YOUR GPU FIRST  -  do NOT just press E
echo        (E = Turing auto = 16 GiB, too small for 22GB VRAM)
echo     2) open the MANUAL ReBAR size setting
echo     3) choose 32G
echo     4) check the status line shows Target 32 GiB
echo     5) S   save to UEFI variable
echo     6) Q   quit, then REBOOT
echo.
echo   Then run check_rebar.bat - expect BAR1 Total = 32768 MiB
echo.
echo   If there is no "UEFI DXE driver" line at all, the injected
echo   driver is missing - re-flash JYZ6PA08_ReBAR_v3.bin.
echo ==================================================
echo.
echo   Press any key to launch NvStrapsReBar.exe ...
pause >nul

NvStrapsReBar.exe

echo.
echo [*] Tool closed. REBOOT first, then run check_rebar.bat.
pause
