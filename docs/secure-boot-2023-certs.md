# Secure Boot 2023 证书换代：踩坑记录与排查手册

> 环境：精粤 Z690M Snow Dream D4 + i7-14700KF + 改装 22GB RTX 2080 Ti
> 记录时间：2026-11-01（这次是用**两次黑屏、一次编程器整片擦除**换来的）

---

## 一、先记住这三条（TL;DR）

1. **两类"黑屏"病因相反，处置也相反** —— 搞反了会在两种坏状态之间来回跳。
2. **这块板 BIOS 里的 `Enroll Cert Using File` 是"替换 db"，不是"追加"** —— 一张一张接着装，最后只会剩最后那张。
3. **FPT 刷写不会重置 Secure Boot 开关** —— 刷原厂 BIOS 治不了 Secure Boot 黑屏；只有**编程器整片擦除**能回到干净状态。

---

## 二、症状 → 病因对照

| 现象 | 病因 | 辅助判据 |
|---|---|---|
| 开 Secure Boot 后**黑屏 + 无限重启**，关掉就能进系统 | db 缺 `Windows UEFI CA 2023` → 启动管理器 `bootmgfw.efi` 验签失败 | `UEFICA2023Status=NotStarted`；db 里搜不到 2023 |
| 开 Secure Boot 后**能进系统，但 POST 阶段没有画面**（无 logo、按 Del 进不去 BIOS，Windows 驱动起来才亮） | db 缺 2011 CA → **显卡的 Option ROM（GOP）不被执行** | db 只剩 2023（≈1498 B） |
| 已经"关了"Secure Boot，**仍然没有 POST 画面** | Secure Boot 其实没关掉（FPT 刷写保留了该开关） | `UEFISecureBootEnabled` 仍为 1 |

> 第二条特别容易被误判成"显卡坏了"或"BIOS 坏了"。其实系统完全正常，只是固件不愿意执行显卡的显示 ROM。

---

## 三、db 字节数速查（比读变量还快）

| `db` 字节数 | 内容 |
|---|---|
| 变量不存在（`0xC0000100`） | Setup Mode，密钥库全空 |
| ≈1498 | 仅 `Windows UEFI CA 2023` |
| ≈3143 | 仅两张 2011 默认（Windows Production PCA 2011 + Microsoft Corporation UEFI CA 2011） |
| ≈4641 | 两张 2011 + `Windows UEFI CA 2023` |
| ≈7636 | 两张 2011 + 三张 2023（完整态） |

已知单张 ESL 大小：`Windows UEFI CA 2023` ≈1498、`Microsoft UEFI CA 2023` ≈1492、`Option ROM UEFI CA 2023` ≈1503。

---

## 四、为什么会这样

- 2026 年 Secure Boot 证书换代：2011 那批 CA 陆续过期（`Windows Production PCA 2011` 到 2026-10-20，`Microsoft Corporation UEFI CA 2011` 已于 2026-06-28 过期），Windows 启动管理器 `bootmgfw.efi` 更新后变成**只由 `Windows UEFI CA 2023` 签名**，不再带回退签名。
- `db` 是**固件的信任列表**，存在 BIOS 芯片的 NVRAM 变量区里 —— 跟主板型号、Windows、硬件 ID 都没有绑定关系。
- 开 Secure Boot 后，**Option ROM 也要过验签**。显卡的 GOP 由 `Microsoft Corporation UEFI CA 2011` 签发 → db 里没有它，固件就跳过执行 → POST 无画面，但系统照常启动（Windows 的 NVIDIA 驱动不需要 GOP）。

---

## 五、刷写方式对 NVRAM 的影响（关键）

| 方式 | 认证变量（PK/KEK/db/dbx） | Setup（含 Secure Boot 开关） | 第三方变量（如 ReBAR 配置） |
|---|---|---|---|
| `fptw64 -f x.bin -rewrite` | 保留 | **保留** | 清 |
| 编程器**整片擦除** + 写 | **全清** | 全清 → 重建默认 | 清 |
| BIOS 内 `Restore Factory Keys` | 覆盖为固件默认（两张 2011） | — | — |

**实测**：用 FPT 刷了字节级一致的原厂镜像之后，`UEFISecureBootEnabled` **仍然是 1**，黑屏照旧。换用编程器整片擦除 + 写同一个镜像，才变成 `SetupMode=1`、`SB=0`、画面恢复。

---

## 六、恢复路径（实测有效）

1. **编程器整片擦除**（Erase Chip，不是直接覆盖写）+ 写原厂镜像
   → `SetupMode=1`、Secure Boot 关闭、POST 画面恢复
2. 进 BIOS → Key Management → **Restore Factory Keys**
   （重建 PK/KEK/db/dbx，db = 两张 2011）
3. 用 U 盘跑微软官方 `SecureBootRecovery.efi`（**追加**语义）
   → db 变成 4641（2011 + 2023）
4. 进 BIOS → Secure Boot = Enabled（Standard 模式）→ 保存
5. 验收：**开机有 logo、能进 BIOS、能进 Windows**
6. **最后**再配 ReBAR —— 改任何 BIOS 设置都会清掉它的配置变量

> 顺序不能颠倒。第 6 步放最后，是为了让 ReBAR 只配一次。

---

## 七、诊断工具

```
tools\check_sb_state.bat    双击即可（自动提权）
  └─ check_sb_state.ps1
  └─ 输出 sb_report.txt
```

它会读：`SecureBootEnabled`、`SetupMode`、`PK/KEK/db/dbx` 的字节数和证书 CN、Windows 服务化状态、GPU BAR1。

**读数的坑：**

| 返回值 | 含义 |
|---|---|
| `0xC0000061`（ntdll）/ `err=1314`（kernel32） | **没管理员权限**，不是变量不存在 |
| `0xC0000100` | **变量真的不存在**（Setup Mode 下 PK/KEK/db/dbx 全都没有） |
| `UEFICA2023Status=NotStarted` 但开机有 logo | 只是 Windows 的证书服务化任务没重跑，**不影响功能** |

另外：`.ps1` 必须存成 **UTF-8 带 BOM**，否则 5.1 会按 ANSI 解释，中文全乱码（报告里会出现 `鍩烘湰鐘舵€` 这种）。

---

## 八、坑（照着别踩）

1. **不要**在 BIOS 里"一张一张 Enroll 证书"。本板是替换语义：装第 2 张会把第 1 张冲掉；如果最后只剩 `Option ROM CA`，bootmgr 反而验不过 → 黑屏死循环。
2. **不要**指望 FPT 刷原厂 BIOS 解决 Secure Boot 问题（开关不会回默认）。
3. **不要**一上来就 `Restore Factory Keys` —— 在 User Mode 下它会把已装好的 2023 冲回 2011，bootmgr 直接被拦。
4. **不要**在"没有 POST 画面"的时候盲操作 BIOS，很容易把别的设置改错。
5. 无核显平台（i7-14700**KF**）**没有**"拔显卡用核显"这条退路，别照搬通用建议。
6. 换一张亮机卡通常也没用 —— db 里缺 2011 时，任何 2011 签名的 Option ROM 都会被拦。

---

## 九、本次时间线（供对照）

1. 为跑 GPU 解锁工具把 Secure Boot 关掉 → 再打开 → **黑屏 + 无限重启**
2. 用 BIOS Enroll 只装 2023 → 能进系统，但 db 从 3143 掉到 1498 → **POST 无画面**
3. 清 CMOS（按按钮）→ 无效（RTC 时间没变 = 没清掉），只清了 ReBAR 变量
4. FPT 刷原厂镜像 → 无效（Secure Boot 开关被保留）
5. **编程器整片擦除 + 写原厂镜像** → 画面恢复，`SetupMode=1`
6. 刷回 ReBAR 版 v3 → 配 ReBAR（选显卡 → 手动 → 32G）→ BAR1 = 32768 MiB
7. 开 Secure Boot + 补齐证书 → **SB 开 + 有画面 + ReBAR 32G + 能进系统**
