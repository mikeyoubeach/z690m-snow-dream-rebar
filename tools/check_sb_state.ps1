# Secure Boot 状态自检（需要管理员权限，由 check_sb_state.bat 调用）
$ErrorActionPreference = 'Continue'
$report = Join-Path $PSScriptRoot 'sb_report.txt'
$lines = New-Object System.Collections.Generic.List[string]
function Add($s) { $lines.Add([string]$s); Write-Host $s }

Add "================================================================"
Add ("Secure Boot Check  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add "================================================================"

Add "--- 基本状态 ---"
try { Add ("SecureBootEnabled : " + (Confirm-SecureBootUEFI)) }
catch { Add ("SecureBootEnabled : ERROR - " + $_.Exception.Message) }
try {
    $sm = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
    Add ("SetupMode         : " + $sm.Bytes[0] + "   (0=User Mode 正常, 1=Setup Mode 无 PK)")
} catch { Add ("SetupMode         : READ FAIL - " + $_.Exception.Message) }

Add ""
Add "--- 变量内容（在 db/KEK 里检索证书 CN）---"
$cns = @(
    'Windows UEFI CA 2023',
    'Microsoft UEFI CA 2023',
    'Option ROM UEFI CA 2023',
    'KEK 2K CA 2023',
    'Windows Production PCA 2011',
    'Microsoft Corporation UEFI CA 2011',
    'Microsoft Corporation KEK CA 2011'
)
foreach ($n in @('PK', 'KEK', 'db', 'dbx')) {
    try {
        $v = Get-SecureBootUEFI -Name $n -ErrorAction Stop
        $bytes = $v.Bytes
        Add ("[$n] " + $bytes.Length + " bytes")
        $s = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
        foreach ($cn in $cns) { if ($s.Contains($cn)) { Add ("    [HIT] " + $cn) } }
    }
    catch { Add ("[$n] READ FAIL - " + $_.Exception.Message) }
}

Add ""
Add "--- Windows 证书服务化状态 ---"
foreach ($k in @('UEFICA2023Status', 'WindowsUEFICA2023Capable', 'ConfidenceLevel')) {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name $k -ErrorAction SilentlyContinue).$k
    Add ("$k = " + $val)
}
$sbState = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue).UEFISecureBootEnabled
Add ("UEFISecureBootEnabled = " + $sbState)

Add ""
Add "--- GPU / ReBAR ---"
try {
    $gpu = & "$env:SystemRoot\System32\nvidia-smi.exe" --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>$null
    Add ("GPU : " + $gpu)
    $bar = & "$env:SystemRoot\System32\nvidia-smi.exe" -q -d memory 2>$null | Select-String -Pattern 'BAR1' -Context 0,3
    if ($bar) { $bar | ForEach-Object { Add ("  " + $_.ToString()) } } else { Add "  BAR1: 读取不到" }
} catch { Add ("nvidia-smi 失败: " + $_.Exception.Message) }

Add ""
Add "--- 启动时间 ---"
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Add ("LastBootUpTime : " + $os.LastBootUpTime)
} catch { Add "LastBootUpTime : 读取失败" }

Add ""
Add "================================================================"

$lines | Out-File -FilePath $report -Encoding UTF8
Write-Host ""
Write-Host ("报告已写入: " + $report)
