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


操作（2 次重启）
----------------------------------------------------------------
第 1 步  双击 enable_rebar.bat
         在工具里按：  E   （启用 Turing 自动设置）
                      S   （保存到固件变量）
                      Q   （退出）
         然后【重启】。

第 2 步  重启后再次双击 enable_rebar.bat
         先看状态行：应该已经从 Unconfigured 变成
                     "GPU-side ReBAR Configured ..."
         按：  P
               64   （给这块 GPU 单独配 PCI 侧 BAR，输入 64 回车）
               S
               Q
         然后【重启】。

第 3 步  双击 check_rebar.bat
         期望：BAR1 Total = 32768 MiB  → ReBAR 已开启
         或 GPU-Z → Resizable BAR = Enabled


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
