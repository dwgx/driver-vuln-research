# 深度研究：新发现可利用驱动程序 (2026-07-15)

> 基于全网搜索，以下为我们尚未收录但具有物理内存 R/W 能力的签名驱动程序候选。
> 按优先级排序：P0 = 立即可用，P1 = 需要验证，P2 = 备选/受限。

---

## P0 — 高价值新目标

### 1. KernCoreLib64.sys (MSI Feature Manager)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-57851 |
| **厂商** | MSI (微星) |
| **驱动来源** | MSI Feature Manager (性能模式/键盘灯光) |
| **内核代码基** | WinIo 变体 |
| **设备路径** | `\\.\WinIo` |
| **签名** | Cross-signed (WinIo 变体), 时间戳 2018+ |
| **文件大小** | 25,656 bytes |
| **物理内存** | 部分 R/W — 仅 0xFC000800 以上 (≈3.94GB+) |
| **I/O 端口** | 完整 R/W，零验证 (IOCTL 0x80102050 读, 0x80102054 写) |
| **映射 IOCTL** | `0x80102040` (map), `0x80102044` (unmap) |
| **访问控制** | 地址范围检查可绕过 (ViewSize 覆盖) |
| **绕过方法** | 请求基址 0xFC000800 + ViewSize = (total_ram - 0xFC000800) |
| **限制** | **低于 3.94GB 的物理地址不可达** — 内核结构可能不可访问 |
| **Win11 25H2** | **被阻止** — cross-signed, 受 April 2026 CI 策略影响 |
| **PoC** | https://github.com/readmsr/MSI_FeatureManager_CVE |
| **利用方式** | Token stealing via DKOM (EPROCESS walk) |
| **披露日期** | 2026-07-07 |
| **补丁状态** | 厂商已移除驱动，旧版仍可用于 BYOVD |

**评估**: 中等价值。WinIo 代码基成熟，但有两个硬限制：(1) 仅映射 3.94GB 以上物理地址，内核结构可能不在范围内；(2) cross-signed 在 Win11 25H2 上被阻止。适合 Win10 或未更新系统。PoC 仓库含驱动二进制可直接下载。

**EPROCESS 偏移 (Win11 25H2 Build 26200)**:
```
UniqueProcessId:    +0x1D0
ActiveProcessLinks: +0x1D8
Token:              +0x248
ImageFileName:      +0x338
DirectoryTableBase: +0x028
```

---

### 2. IOMap64.sys (ASUS IOMap V3)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2024-41498, CVE-2024-33223 |
| **厂商** | ASUS (ASUSTeK) |
| **驱动版本** | IOMap-V3.0_20231124_vs2019 |
| **设备路径** | `\\.\IOMap` |
| **SHA-256** | `d78d7516dbb8cad08f355a070790d6dd629dcf58d816855b958669fecb8b68b5` (2023版) |
| **签名** | ASUS DigiCert (Serial: 04:14:dc:f7:ac:18:be:7b:0e:5d:1d:b9:a3:fe:e4:69), 有效期 2022-04-08 ~ 2025-03-27 |
| **物理内存** | 完整 R/W (滑动窗口) |
| **映射机制** | HalTranslateBusAddress → 失败则 MmMapIoSpace |
| **映射 IOCTL** | `0x83002138` — input: {index:u16 (<0x10), phys_addr:u32 (offset 4), selector:u16 (offset 20, 0=16MB/1=256KB)} |
| **读 IOCTL** | `0x83002104` — input: offset into mapped region, 无边界检查 |
| **写 IOCTL** | `0x83002108` — input: offset + value, 无边界检查 |
| **映射大小** | 256KB (0x40000) 可靠 / 16MB (0x1000000) 存在 |
| **滑动窗口** | 是 — 重映射后可遍历全部物理 RAM |
| **限制** | 物理地址 0x0~0x1000 排除; 挂载内核调试器会触发 MiShowBadMapper BSoD |
| **访问控制** | IoCreateDeviceSecure (可能需 Admin 打开 handle), 无 per-IOCTL 检查 |
| **分发** | ASUS GPU Tweak II, AI Suite 3, GameFirst |
| **安装路径** | `C:\Windows\System32\drivers\IOMap64.sys`, `C:\Program Files (x86)\ASUS\GPU TweakII\IOMap64.sys` |
| **加载命令** | `sc.exe create IOMap64 binPath=C:\windows\temp\IOMap64.sys type=kernel && sc.exe start IOMap64` |
| **YARA 规则** | 已有 (版本串 + IOCTL 常量 `{04 21 00 83}` / `{08 21 00 83}` + ASUS 签名序列号) |
| **LOLDrivers** | UUID: f4990bdd-8821-4a3c-a11a-4651e645810c (2023-01-09 added) |
| **MSFT VDB** | 可能未收录 (LOLDrivers ≠ MSFT blocklist) |
| **EAC** | 与 AsIO3 独立，低关注度，可能兼容 |

**评估**: 高价值。2023 年 ASUS 签名非常新。256KB 滑动窗口足够扫描 EPROCESS。
无 firmware range 限制 (vs AsIO3)，无 PID 验证，无 pipe 协议。需 Admin 打开 handle 但之后无任何 IOCTL 级别检查。
相关 PoC: RevEng.AI exp.c + DriverHunter CVE-2024-33223 伪代码分析。
GitHub: `github.com/DriverHunter/Win-Driver-EXP/tree/main/CVE-2024-33223` (含驱动二进制)。

---

### 3. TVicPort64.sys

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-30769 |
| **厂商** | EnTech Taiwan |
| **驱动** | TVicPort Generic Device Driver for direct hardware I/O |
| **设备路径** | `\\.\TVicPortDevice0` |
| **MD5** | A65643ED30A30E46317C0B25818BC9B7 |
| **SHA-256** | 9C9AB56C8BCF5EC958E7C2346F23A3027F69ABDF8AF923B591518EEE64AD98AD |
| **SHA-1** | 3740F2BC7E81D75604E47A3119FAA887D4A92A44 |
| **编译时间** | 2006-10-13 |
| **签名** | EnTech Taiwan (GlobalSign ObjectSign CA), Serial: 0100000000010de51c0971 |
| **物理内存** | 完整 R/W (ZwMapViewOfSection on `\Device\PhysicalMemory`) |
| **映射 IOCTL** | `0x80002008` |
| **访问控制** | NULL DACL — 任何用户 (含 Low Integrity/AppContainer) 可打开 |
| **补丁状态** | 厂商无响应，无补丁 |
| **下载** | https://www.entechtaiwan.com/dev/port/index.shtm (免费), LOLDrivers 有样本 |
| **LOLDrivers** | UUID: b4f3a1c2-e8d7-4f92-a301-5c6d9e0b1a2f |
| **MSFT VDB** | **未收录** |
| **Win11 25H2** | **被阻止** — cross-signed |
| **加载命令** | `sc.exe create TVicPort64 binPath=C:\windows\temp\TVicPort64.sys type=kernel && sc.exe start TVicPort64` |
| **文件版本** | 5.2.1.0, 产品版本 4.0 |

**评估**: EnTech Taiwan 出品（与我们的 ASTRA64 同一厂商）。NULL DACL 零门槛。
2006 年编译但签名仍有效。需要验证是否在 WDAC 黑名单和 2026 年 4 月跨签名废止影响范围内。

---

### 4. Realtek rtkio64.sys

| 属性 | 值 |
|------|-----|
| **CVE** | 无正式 CVE (DEF CON 27 Eclypsium 披露) |
| **厂商** | Realtek |
| **驱动** | Realtek Ethernet Controller Diagnostics |
| **版本** | 10.23.1003.2017 |
| **SHA-256** | `7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129` |
| **映射机制** | MmMapIoSpace (无验证) |
| **访问控制** | 无 (任何非特权用户可通信) |
| **PoC** | https://github.com/blogresponder/Realtek-rtkio64-Windows-driver-privilege-escalation |
| **KDU Provider** | #10 |
| **利用方式** | EPROCESS scan → token stealing |

**评估**: KDU 已集成 (Provider #10)。Realtek 签名极其普遍。无地址限制。
但是 KDU Provider #10 可能在 MSFT 黑名单 (Name-based block)。需验证。

---

### 5. Portwell Engineering Toolkits Driver

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-3437 |
| **厂商** | Portwell Inc. (博文科技) |
| **文件名** | portwell.sys |
| **文件大小** | 16,848 bytes |
| **设备路径** | `\\Device\\PORTWELL_0_1` (symlink: `\\DosDevices\\PORTWELL_0_1`) |
| **CVSS** | 8.8 (High) |
| **漏洞类型** | CWE-119 (内存缓冲区操作限制不当) |
| **物理内存读** | IOCTL `0xEA606450` |
| **物理内存写** | IOCTL `0xEA60A454` |
| **MSR 读** | IOCTL `0xEA602408` |
| **MSR 写** | IOCTL `0xEA60240C` |
| **Port I/O** | `0xEA60A440`(byte-r), `0xEA60A444`(word-r), `0xEA60A460`(dword-r), `0xEA60A464`(byte-w), `0xEA60A468`(word-w), `0xEA60A470`(dword-w) |
| **PCI 读** | IOCTL `0xEA606458` (HalGetBusDataByOffset) |
| **PCI 写** | IOCTL `0xEA60A45C` (HalSetBusDataByOffset) |
| **映射方式** | MmMapIoSpace / MmUnmapIoSpace |
| **SHA-256** | `2F0B16ED90B8C15BF52A7C32699DBE0DBCD38FC02ED2DDB4E1BA35487177B6C5` |
| **签名** | Portwell Inc. |
| **CISA 通告** | ICSA-26-062-04 (2026-03-03) |
| **访问要求** | 本地认证用户 |
| **MSFT VDB** | **未收录** |
| **LOLDrivers** | PR #327 merged, issue #314 |
| **下载** | https://github.com/KeServiceDescriptorTable/vulnerable-drivers (含二进制) |
| **厂商状态** | 未配合 CISA 修复，无补丁 |

**评估**: 极高价值。单个 16KB 驱动提供完整 7 类原语 (物理内存 R/W + MSR R/W + Port I/O + PCI bus)。
功能覆盖面超过 LnvMSRIO。CISA 已发通告说明严重性。未在 MSFT VDB 上。签名需验证是否 WHCP。
ICS/嵌入式领域驱动，关注度低于消费级驱动。二进制已在 GitHub 可下载。

---

## P1 — 需要进一步验证

### 6. ASUS Armoury Crate 驱动 (CVE-2026-8070)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-8070 |
| **厂商** | ASUS |
| **漏洞** | 绕过驱动验证机制获取物理内存访问 |
| **能力** | 物理内存 R/W + I/O 端口 + MSR |
| **CVSS** | 7.3 |
| **利用条件** | 本地 admin |
| **与 AsIO3 关系** | 这是绕过 AsIO3 验证机制的 CVE！ |

**评估**: **这可能是我们 AsIO3 死胡同的解法！** CVE 描述为 "bypass driver validation mechanism, resulting in unauthorized read and write access to physical memory"。
我们之前被 AsIO3 的 firmware whitelist 卡住，这个 CVE 可能就是绕过方法。**最高优先级验证。**

---

### 7. ASUS ROG Peripheral Driver (CVE-2026-1878)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-1878 |
| **厂商** | ASUS |
| **驱动** | ROG 外设驱动 |
| **能力** | SYSTEM 级提权 |
| **详细信息** | 待确认是否包含物理内存原语 |

---

### 8. QIOMEM.SYS (Toshiba/Dynabook)

| 属性 | 值 |
|------|-----|
| **CVE** | 无 (厂商通告但未申请 CVE) |
| **厂商** | Toshiba / Dynabook / Sharp |
| **驱动** | Generic IO & Memory Access Driver |
| **软件** | Password Utility (BIOS 密码配置) |
| **能力** | 任意物理内存访问 (驱动名暗示) |
| **签名** | Toshiba/Dynabook 签名 |
| **受影响系统** | 2009-2016 年产 Toshiba 笔记本 |
| **KDU Provider** | #56 (TPwSav) 可能相关 |

**评估**: 厂商确认漏洞存在但未公开技术细节。需获取二进制进行逆向。

---

### 9. NeacSafe64.sys (NetEase)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2025-45737 |
| **厂商** | NetEase (网易) |
| **驱动** | NeacSafe64 mini-filter driver |
| **KDU Provider** | #54 |
| **能力** | 内核 shellcode 执行 (非直接物理内存) |
| **机制** | NonPagedPool 函数指针覆写 |
| **PoC** | https://github.com/smallzhong/NeacController |

**评估**: 不是直接物理内存 R/W，而是内核代码执行。可用于映射自定义驱动或直接 shellcode。
功能更强但复杂度也更高。

---

### 10. EneIo64.sys (多个 RGB/散热品牌)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2020-12446 |
| **厂商** | ENE Technology (多品牌 OEM) |
| **使用者** | G.SKILL, MSI, Thermaltake, ASRock 等 RGB 软件 |
| **KDU Provider** | #5 (GLCKIO2), #6 (EneIo64), #8 (EneTechIo), #11 (MSI 变体) |
| **能力** | 物理内存 R/W + MSR + Port I/O |
| **PoC** | https://github.com/Xacone/Eneio64-Driver-Exploits |
| **PoC** | https://github.com/ValvojaX/EneIoExploit |
| **KASLR 绕过** | Windows 11 24H2 confirmed |
| **HVCI 兼容** | 是 (HVCI-compatible exploitation) |

**评估**: 高价值。多品牌签名版本存在。有完整 PoC（内存 R/W + MSR + Port I/O + KASLR bypass）。
某些变体在 MSFT 黑名单 (cert block)，但 MSI/Thermaltake 变体可能未被覆盖。

---

## P2 — 备选/参考

### 11. Mhyprot2.sys (miHoYo / 原神)

| 属性 | 值 |
|------|-----|
| **CVE** | 无正式 CVE |
| **厂商** | miHoYo (米哈游) |
| **驱动** | 原神反作弊内核驱动 |
| **能力** | 进程内存 R/W + 进程终止 |
| **签名** | miHoYo 有效签名 |
| **逆向** | https://github.com/keowu/mhyprot2 |
| **利用** | https://github.com/leeza007/evil-mhyprot-cli |
| **状态** | 广泛用于勒索软件 EDR 杀手，可能在检测名单上 |

**评估**: 功能强大但不是物理内存原语（是虚拟内存 R/W），且检测率高。
勒索软件组织大量使用导致检测签名丰富。**不推荐用于 anti-cheat 环境。**

---

### 12. Safetica ProcessMonitorDriver.sys

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-0828, CVE-2025-70795 |
| **厂商** | Safetica |
| **能力** | 任意进程终止 (通过 IOCTL) |
| **不适合** | 无物理内存 R/W，仅进程终止 |

---

### 13. Motorola SM56 Modem WDM (SmSerl64.sys)

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2024-55414 |
| **厂商** | Motorola |
| **能力** | 物理内存映射到用户空间 |
| **状态** | Microsoft 已通过 KB5074109 移除驱动 |
| **不适合** | 已被系统级移除，无法加载 |

---

## 重要环境变化：2026年4月 Windows 更新

**微软已在 2026 年 4 月更新中默认废止跨签名 (cross-signed) 内核驱动信任。**

影响范围：
- Windows 11 24H2, 25H2, 26H1
- Windows Server 2025
- 所有仅依赖旧跨签名证书的驱动**默认不再受信任**

对我们的影响：
| 驱动 | 签名类型 | 是否受影响 |
|------|----------|-----------|
| LnvMSRIO | WHCP (Microsoft签名) | **不受影响** |
| ThrottleStop | EV DigiCert | 需验证 |
| SIVX64 | WHCP | **不受影响** (但证书今天到期) |
| ASTRA64 | GlobalSign 2006 cross-sign | **可能受影响** |
| ArgusMonitor | EV 签名 | 需验证 |
| KernCoreLib64 | 时间戳 2018+ | 需验证 |
| IOMap64 | ASUS 签名 2023 | **不受影响** (新签名) |
| TVicPort64 | EnTech 旧签名 | **可能受影响** |

**结论**: LnvMSRIO 和 IOMap64 是两个最不受签名策略变化影响的选择。

---

## KDU 完整 Provider 列表参考 (v1.4.9, 65 个 Provider)

最新版本 v1.4.9 包含以下我们尚未研究的 Provider（有物理内存能力）：

| ID | 驱动 | 厂商 | 状态 |
|----|------|------|------|
| 52 | PmxDrv (Intel ME Tools) | Intel | 未研究 |
| 53 | HwRwDrv | Jun Liu / Shuttle | 未研究 |
| 56 | TPwSav | Toshiba | 未研究 (可能=QIOMEM) |
| 58 | CorMem (Sapera) | Teledyne | 未研究 |
| 59 | Ipctype | Digital Elect. Corp | 未研究 |
| 60 | WinHwDrv | Shangke | 未研究 |
| 61 | affdriver | AMD | 未研究 |
| 62 | mtxC9CB | Matrox | 未研究 |
| 63 | PGRHostControl | Point Grey Research | 未研究 |
| 64 | LECOMA | LECO | 未研究 |

---

## namazso/physmem_drivers 仓库 — 130+ 驱动二进制

完整收集 30 个驱动家族、130+ 个带不同签名的二进制文件：
- **GitHub**: https://github.com/namazso/physmem_drivers
- 覆盖 ASUS, ASRock, MSI, GIGABYTE, Dell, IBM, CPUID, miHoYo 等
- 无 PoC 但有所有二进制文件可直接下载

---

## 操作建议 (Action Items)

### 立即执行 (P0)
1. **CVE-2026-8070 (Armoury Crate 验证绕过)** — 这可能解锁我们的 AsIO3 死胡同
2. **KernCoreLib64.sys** — 下载 MSI Feature Manager 旧版，提取驱动，逆向验证
3. **IOMap64.sys** — ASUS 2023 签名，无访问控制，reveng.ai 有完整分析

### 短期验证 (P1)
4. **EneIo64** MSI/Thermaltake 变体 — 检查哪些签名未被黑名单覆盖
5. **TVicPort64** — 同 EnTech Taiwan 出品，验证签名有效性
6. **rtkio64** — Realtek 签名验证 + MSFT 黑名单检查

### 环境适配
7. 验证所有现有驱动在 2026-04 更新后的加载状态
8. 重点关注 WHCP 签名驱动（不受跨签名废止影响）

---

## 参考源

- [CVE-2026-57851 MSI Feature Manager](https://medium.com/@dorukcerit/cve-2026-57851-exploiting-msi-feature-manager-driver-physical-memory-abuse-for-privilege-86a86cdb979c)
- [CVE-2024-41498 IOMap64 (reveng.ai)](https://reveng.ai/blog/physmem-e-when-kernel-drivers-peek-into-memory)
- [Realtek rtkio64 PoC](https://github.com/blogresponder/Realtek-rtkio64-Windows-driver-privilege-escalation)
- [KDU Releases](https://github.com/hfiref0x/KDU/releases)
- [KDU Providers](https://github.com/hfiref0x/KDU/blob/master/Help/providers.md)
- [namazso/physmem_drivers](https://github.com/namazso/physmem_drivers)
- [EneIo64 Exploits](https://github.com/Xacone/Eneio64-Driver-Exploits)
- [EneIo Exploit (memory + MSR + port)](https://github.com/ValvojaX/EneIoExploit)
- [CVE-2026-30769 TVicPort64](https://gist.github.com/lleekkoo/6c73fa4e137aca6f5dfe6aec4f6a7b29)
- [Vulnerable Monitors (SIVX64/ASTRA64/ArgusMonitor)](https://github.com/sai2fast/Vulnerable-Monitors)
- [KeServiceDescriptorTable 80+ drivers](https://github.com/KeServiceDescriptorTable/vulnerable-drivers)
- [54 EDR Killers / 35 Drivers](https://bellatorcyber.com/blog/edr-killers-byovd-signed-vulnerable-drivers-2026)
- [CVE-2026-8070 Armoury Crate](https://www.securityweek.com/asus-armoury-crate-vulnerability-leads-to-full-system-compromise/)
- [CISA ICSA-26-062-04 Portwell](https://www.cisa.gov/news-events/ics-advisories/icsa-26-062-04)
- [April 2026 跨签名废止](https://windowsforum.com/threads/april-2026-windows-update-ends-default-trust-for-cross-signed-kernel-drivers.408485/)
- [Microsoft Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [QIOMEM.SYS Advisory](http://support.dynabook.com/support/viewContentDetail?contentId=4019186)
- [NeacController PoC](https://github.com/smallzhong/NeacController)
- [MSI Feature Manager PoC](https://github.com/readmsr/MSI_FeatureManager_CVE)
