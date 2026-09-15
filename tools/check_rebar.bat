@echo off
setlocal
cd /d "%~dp0"
echo ==================================================
echo   ReBAR / Secure Boot status check
echo ==================================================
echo.
echo --- GPU ---
nvidia-smi --query-gpu=name,pci.bus_id,memory.total --format=csv
echo.
echo --- BAR1 window (Resizable BAR) ---
powershell -NoProfile -Command "$o = @(& nvidia-smi -q -d memory); $i = [array]::IndexOf($o, '    BAR1 Memory Usage'); if ($i -ge 0) { $o[$i..([Math]::Min($i+2,$o.Count-1))] } else { 'BAR1 section not found' }"
echo.
echo --- Secure Boot ---
powershell -NoProfile -Command "try { $sb = Confirm-SecureBootUEFI; Write-Output ('SecureBootUEFI : ' + $sb) } catch { Write-Output 'SecureBootUEFI : not supported / legacy' }"
echo.
echo ==================================================
echo   EXPECT : BAR1 Total = 32768 MiB   -^> ReBAR ON
echo   IF 256 MiB                     -^> run enable_rebar.bat
echo ==================================================
pause
