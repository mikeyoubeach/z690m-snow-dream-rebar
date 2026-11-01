ReBAR 一键恢复包（精粤 Z690M Snow Dream D4 + RTX 2080 Ti 22GB）
================================================================

背景（一句话）
----------------------------------------------------------------
ReBAR 配置存在 UEFI 的【普通第三方变量 NvStrapsReBar】里。
每次【刷 BIOS / 清 CMOS / 载入 BIOS 默认值】这个变量都会被清掉，
所以 ReBAR 一定会掉回 256 MiB —— 这是必然现象，不是刷坏了。
解决办法就是：重跑一次下面的配置，2 分钟。

Secure Boot 证书（PK/KEK/db）属于认证变量，固件删不掉，
所以刷 BIOS 之后它【不会丢】，不需要重做。这个包里也不含刷写程序。


文件
----------------------------------------------------------------
enable_rebar.bat    管理员启动配置工具（会自动弹 UAC）
check_rebar.bat     一键自检：BAR1 窗口 + Secure Boot 状态
NvStrapsReBar.exe   配置工具本体（v0.3）


操作（1 次重启 + 1 次配置）
----------------------------------------------------------------
双击 enable_rebar.bat（管理员），然后：

第 1 步  先【选中你要配的那块显卡】—— 别直接点 E 跳过这一步

第 2 步  进「手动设置 ReBAR 尺寸」

第 3 步  选 32G（22GB 显存的卡必须 32G，16G 盖不住显存）

第 4 步  按 S 保存 → Q 退出 →【重启】

第 5 步  双击 check_rebar.bat
         期望：BAR1 Total = 32768 MiB  → ReBAR 已开启
         或 GPU-Z → Resizable BAR = Enabled

⚠️ 不要用 E（Turing 自动设置）：它按 2080 Ti 标准档给 16GiB，
   原厂 11GB 的卡够用，20 系改装 22GB 的卡最多只能开到 16G。


如果第 2 步状态行还是 Unconfigured
----------------------------------------------------------------
说明注入进 BIOS 的 NvStrapsReBar 驱动没有被 DXE 调度。
先试：进 BIOS 把 Secure Boot 临时关掉（只看不改其它项），
再跑一遍第 1、2 步，看状态行是否变化 —— 用来判断是不是
Secure Boot 把注入的第三方驱动拦住了。
（这条目前【尚未实测】，是已知的唯一未验证点。）


注意事项
----------------------------------------------------------------
* 进 BIOS 改任何设置 / 载入默认值，都会让 ReBAR 又被自动关掉
  （官方原文：if you make changes in UEFI Setup, NvStrapsReBar will be
   disabled automatically and you need to re-enable it）。
  只需要顺眼确认 Above 4G Decoding = Enabled、CSM = Disabled，别动别的。
* 想临时关掉 ReBAR：工具里 D → S → 重启（改硬件前建议先关）。
* 兜底回退：编程器写回 jgyu_bios/JYZ6PA08_ORIG.bin。
* 别再刷 v4 那个镜像了 —— 它的"移植 NVRAM"思路经查是多余的
  （证书本来就不会丢），实测收益为零。


为什么必须重跑（取证结论）
----------------------------------------------------------------
* 刷完后芯片 BIOS 区与 v3 镜像【逐字节一致】，注入驱动在位
  （0x80CA40，GUID 90d10790-bbfa-404b-873b-5bdb3ada3c56，13366 字节）
  → 刷写本身没问题。
* 枚举固件 73 个变量：有驱动每次开机写的 NvStrapsReBarStatus，
  但没有配置变量 NvStrapsReBar → 这就是 Unconfigured 的直接原因。
* 原厂镜像全盘没有任何证书，刷完却仍有 4 张 2023 证书；
  固件的 dbDefault/KEKDefault 默认库里也只有 2011 证书
  → 证明认证变量是"被保留"，不是"从默认值恢复"。

注意：NvStrapsReBar.exe 未随本仓库分发，请到上游下载后放进本目录：
https://github.com/terminatorul/NvStrapsReBar/releases  （必须用 v0.3）
