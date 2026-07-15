# Vulnerability Arsenal — Capability Matrix
# 漏洞武器库 — 能力矩阵

> What we CAN do with these vulnerabilities, organized by capability tier.
> 用这些漏洞能做什么，按能力层级组织。

---

## Tier Overview / 层级概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TIER 0: GOD MODE (完全控制)                        │
│  Arbitrary kernel R/W + code execution + undetectable               │
│  任意内核读写 + 代码执行 + 不可检测                                    │
│  Drivers: LnvMSRIO, CorsairLLAccess64                              │
├─────────────────────────────────────────────────────────────────────┤
│                    TIER 1: FULL PHYSICAL (完整物理内存)                │
│  Read + Write any physical address, MSR access                      │
│  读写任意物理地址 + MSR 访问                                          │
│  Drivers: LnvMSRIO, Corsair, Portwell, SIVX64                      │
├─────────────────────────────────────────────────────────────────────┤
│                    TIER 2: PARTIAL PHYSICAL (部分物理内存)             │
│  Read-only or address-limited physical access                       │
│  只读或地址受限的物理访问                                              │
│  Drivers: SparkIO (R, 4GB), IOMap64 (R/W sliding), KernCoreLib64    │
├─────────────────────────────────────────────────────────────────────┤
│                    TIER 3: PRIVILEGE ESCALATION (权限提升)             │
│  Admin → SYSTEM, or bypass specific protections                     │
│  管理员提权到 SYSTEM，或绕过特定保护                                   │
│  Drivers: AsIO3 (CVE-2025-3464/2026-8070/2026-8918)                │
├─────────────────────────────────────────────────────────────────────┤
│                    TIER 4: INFORMATION LEAK (信息泄露)                 │
│  Read kernel addresses, MSR values, hardware state                  │
│  读取内核地址、MSR值、硬件状态                                         │
│  Drivers: SparkIO, HWiNFO64A, Intel EnergyDriver                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What Each Driver Can Do / 每个驱动能做什么

### LnvMSRIO.sys — The King / 王者

| Capability / 能力 | Status / 状态 | Evidence / 证据 |
|---|---|---|
| Read any physical memory / 读任意物理内存 | ✅ PROVEN | Live test Build 26200 |
| Write any physical memory / 写任意物理内存 | ✅ PROVEN | PPL byte modification confirmed |
| Read/Write MSR registers / 读写MSR寄存器 | ✅ PROVEN | IA32_GS_BASE read confirmed |
| Read/Write I/O ports / 读写IO端口 | ✅ Documented | Integration guide |
| Read/Write PCI config / 读写PCI配置空间 | ✅ Documented | Integration guide |
| EAC coexistence / EAC共存 | ✅ PROVEN | 72h no ban |
| Loads on Win11 25H2 / 在25H2上加载 | ✅ PROVEN | WHCP signed |
| No access control / 无访问控制 | ✅ PROVEN | Direct CreateFile |

**What you can achieve / 你能实现什么:**
```
✅ Read any process memory (via physical) / 读取任何进程内存
✅ Modify kernel structures (EPROCESS, tokens) / 修改内核结构
✅ Disable PPL protection on any process / 禁用任何进程的PPL保护
✅ Steal SYSTEM token → become SYSTEM / 窃取SYSTEM令牌
✅ Bypass all usermode security (EDR, AV) / 绕过所有用户态安全
✅ Read encryption keys from protected processes / 从受保护进程读取加密密钥
✅ Disable ETW logging / 禁用ETW日志
✅ Hide processes (DKOM) / 隐藏进程
✅ Load unsigned drivers (DSE bypass) / 加载未签名驱动
```

---

### CorsairLLAccess64.sys — WHQL + HVCI Survivor / WHQL + HVCI幸存者

| Capability / 能力 | Status / 状态 | Evidence / 证据 |
|---|---|---|
| Map physical memory R/W / 映射物理内存读写 | ✅ Confirmed | CVE-2020-8808 + binary RE |
| Direct MMIO read (single IOCTL) / 直接MMIO读 | ✅ Confirmed | IOCTL 0x22934C reversed |
| Direct MMIO write (single IOCTL) / 直接MMIO写 | ✅ Confirmed | IOCTL 0x229350 reversed |
| Read any MSR / 读取任意MSR | ✅ Confirmed | IOCTL 0x225388 |
| Write any MSR / 写入任意MSR | ✅ Confirmed | IOCTL 0x229384 (SEH wrapped) |
| Port I/O R/W / 端口IO读写 | ✅ Confirmed | IOCTL 0x225358/0x229354 |
| PCI config R/W / PCI配置读写 | ✅ Confirmed | IOCTL 0x225348/0x229380 |
| Loads with HVCI ON / HVCI开启时仍加载 | ✅ Confirmed | LOLDrivers: LoadsDespiteHVCI=TRUE |
| WHQL signed / WHQL签名 | ✅ Confirmed | Microsoft HW Compat Publisher |

**Unique advantage / 独特优势:**
```
🔥 Works even when Memory Integrity is ON / 即使内存完整性开启也能工作
🔥 Not on Microsoft Vulnerable Driver Blocklist / 不在微软易受攻击驱动黑名单上
🔥 Corsair iCUE installed on millions of gaming PCs / Corsair iCUE安装在数百万游戏PC上
🔥 11 IOCTLs = complete hardware control / 11个IOCTL = 完整硬件控制
```

---

### Portwell.sys — The Silent Swiss Army Knife / 沉默的瑞士军刀

| Capability / 能力 | IOCTL | Status |
|---|---|---|
| Physical memory read / 物理内存读 | `0xEA606450` | ✅ CISA confirmed |
| Physical memory write / 物理内存写 | `0xEA60A454` | ✅ CISA confirmed |
| MSR read / MSR读 | `0xEA602408` | ✅ Documented |
| MSR write / MSR写 | `0xEA60240C` | ✅ Documented |
| Port I/O read (byte/word/dword) / 端口读 | `0xEA60A440/A444/A460` | ✅ |
| Port I/O write / 端口写 | `0xEA60A464/A468/A470` | ✅ |
| PCI config read / PCI读 | `0xEA606458` | ✅ |
| PCI config write / PCI写 | `0xEA60A45C` | ✅ |
| PMC read / 性能计数器 | `0xEA602410` | ✅ |

**Why it matters / 为什么重要:**
```
📌 16KB driver — smallest in our arsenal / 最小的驱动 (16KB)
📌 12 IOCTLs covering ALL hardware primitives / 12个IOCTL覆盖所有硬件原语
📌 NOT on any blocklist / 不在任何黑名单上
📌 Zero detection on VirusTotal (0/73) / VirusTotal零检测
📌 CISA advisory = confirmed dangerous by US government / CISA通告 = 美国政府确认危险
```

---

### SparkIO.sys — Read-Only Scout / 只读侦察兵

| Capability / 能力 | Status | Limitation / 限制 |
|---|---|---|
| Physical memory read / 物理内存读 | ✅ WHQL | **32-bit addresses only (≤4GB)** |
| Port I/O R/W / 端口IO | ✅ | Full access |
| PCI config R/W / PCI配置 | ✅ | Via HalGet/SetBusData |
| Write physical memory / 物理内存写 | ❌ NOT AVAILABLE | Confirmed read-only |
| Zero access control / 零访问控制 | ✅ | IRP_MJ_CREATE = STATUS_SUCCESS |

**Use case / 使用场景:**
```
🔍 KASLR defeat: read Low Stub to leak kernel base / 读Low Stub泄露内核基址
🔍 Read BIOS/firmware structures below 4GB / 读取4GB以下的BIOS/固件结构
🔍 Enumerate PCI devices for hardware fingerprinting / 枚举PCI设备
⚠️  CANNOT write — cannot do token steal or PPL bypass alone / 不能写 — 单独不能提权
```

---

### IOMap64.sys — Sliding Window Scanner / 滑动窗口扫描器

| Capability / 能力 | Status | Detail |
|---|---|---|
| Map 256KB physical window / 映射256KB窗口 | ✅ | IOCTL 0x83002138 (selector=1) |
| Map 16MB physical window / 映射16MB窗口 | ✅ | IOCTL 0x83002138 (selector=0) |
| Read at offset in window / 窗口内偏移读 | ✅ | IOCTL 0x83002104 (BYTE/WORD/DWORD) |
| Write at offset in window / 窗口内偏移写 | ✅ | IOCTL 0x83002108 |
| Slide window to any address / 滑动窗口到任意地址 | ✅ | Remap IOCTL |
| Full address space coverage / 全地址空间覆盖 | ✅ | Sequential remapping |

**Use case / 使用场景:**
```
📖 Scan large memory regions efficiently / 高效扫描大内存区域
📖 16MB windows = fast bulk reads / 16MB窗口 = 快速批量读取
📖 Requires fewer IOCTLs than LnvMSRIO for large scans / 大扫描比LnvMSRIO需要更少IOCTL
⚠️  Needs admin to open handle / 需要管理员打开handle
```

---

### AsIO3 (CVE-2026-8070) — Zero-Load Attack / 零加载攻击

| Capability / 能力 | Status | Condition / 条件 |
|---|---|---|
| Physical memory R/W / 物理内存读写 | ✅ | Armoury Crate ≤6.4.12 installed |
| MSR access / MSR访问 | ✅ | Allowlisted subset |
| I/O port access / IO端口 | ✅ | Full |
| No driver loading needed / 无需加载驱动 | ✅ | Already running on ASUS systems |
| Low-privilege access / 低权限访问 | ✅ | CVE-2026-8070 (CWE-732) |

**Why this is special / 为什么特殊:**
```
🎯 ALREADY RUNNING on our target system / 已经在目标系统上运行
🎯 No new driver load = no PiDDBCacheTable entry / 无需加载 = 无PiDDB记录
🎯 No forensic artifact from driver installation / 无驱动安装取证痕迹
🎯 Three separate CVEs = three attack paths / 三个CVE = 三条攻击路径
⚠️  Current version (1.03.02) requires pipe auth bypass / 当前版本需要pipe认证绕过
```

---

## Attack Chains / 攻击链

### Chain A: Stealth Key Extraction / 隐秘密钥提取

```
                          NO DRIVER LOADING NEEDED
                              无需加载驱动

┌──────────┐     ┌──────────────┐     ┌────────────┐     ┌──────────┐
│ LnvMSRIO │ ──→ │ Find Process │ ──→ │ PPL Bypass │ ──→ │ Read Key │
│ (已证明)  │     │  EPROCESS    │     │ +0x5FA→0x00│     │ AES Scan │
└──────────┘     └──────────────┘     └────────────┘     └──────────┘
   Load driver      KPCR → walk         Write 1 byte      ReadProcessMemory
   加载驱动          链遍历               写入1字节          + heap scan
   
   IOCTLs: 1        IOCTLs: ~50          IOCTLs: 1         IOCTLs: 0
   Time: 0.5s       Time: 0.3s           Time: 0.01s       Time: 2-5s
```

### Chain B: HVCI-Hardened System / HVCI加固系统

```
┌────────────────┐     ┌──────────────┐     ┌────────────────┐
│ CorsairLLAccess│ ──→ │ MSR Read     │ ──→ │ Physical Write │
│ (WHQL+HVCI)   │     │ KPCR locate  │     │ Token Steal    │
└────────────────┘     └──────────────┘     └────────────────┘
   IOCTL 0x225388        Get GS_BASE           Map + overwrite
   Works on ANY Win11    定位内核               映射 + 覆写 token
```

### Chain C: Zero-Footprint via AsIO3 / 零痕迹 (通过AsIO3)

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ AsIO3 already │ ──→ │ CVE-2026-8070 │ ──→ │ Direct phys   │
│ loaded (ASUS) │     │ Permission    │     │ memory R/W    │
│ 已加载 (华硕)  │     │ bypass        │     │ 直接物理读写    │
└───────────────┘     └───────────────┘     └───────────────┘
   No load needed       No auth needed        Full capability
   无需加载              无需认证               完整能力
```

---

## Capability Comparison Matrix / 能力对比矩阵

| Driver | PhysMem R | PhysMem W | MSR R | MSR W | Port IO | PCI | WHQL | HVCI-safe | EAC-safe | On Target |
|--------|:---------:|:---------:|:-----:|:-----:|:-------:|:---:|:----:|:---------:|:--------:|:---------:|
| **LnvMSRIO** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ 72h | Needs load |
| **Corsair** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ? | Needs load |
| **Portwell** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ? | — | ? | Needs load |
| **SIVX64** | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | — | ❌ | Registered |
| **IOMap64** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ? | — | ? | Needs load |
| **SparkIO** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ? | Needs load |
| **AsIO3** | ✅* | ✅* | ⚠️ | ⚠️ | ✅ | ❌ | ✅ | — | ? | **Running** |
| **KernCoreLib64** | ⚠️ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ? | Needs load |

```
✅ = Full capability, confirmed / 完整能力，已确认
⚠️ = Partial or restricted / 部分或受限
❌ = Not available / 不可用
*  = Requires CVE exploitation first / 需要先利用CVE
```

---

## Target System Status / 目标系统状态

```
┌─────────────────────────────────────────────────────┐
│ SYSTEM: Generic Research Workstation                   │
│ OS: Windows 11 25H2 (Build 26200)                   │
│                                                     │
│ ┌─── Security Status ───────────────────────┐       │
│ │ HVCI (Memory Integrity): OFF ✅           │       │
│ │ VDB (Driver Blocklist):  DISABLED ✅      │       │
│ │ Secure Boot:             ON               │       │
│ │ VBS:                     Running          │       │
│ │ CI Policies:             Present (8 files)│       │
│ └───────────────────────────────────────────┘       │
│                                                     │
│ ┌─── Loaded Vulnerable Drivers ─────────────┐       │
│ │ AsIO3.sys v1.03.02  [RUNNING] Boot-start  │       │
│ │   → CVE-2025-3464 / CVE-2026-8070        │       │
│ │   → Device: \Device\Asusgio3              │       │
│ │   → Pipe auth required (AsusCertService)  │       │
│ └───────────────────────────────────────────┘       │
│                                                     │
│ ┌─── Available Services ────────────────────┐       │
│ │ SysMain (Superfetch): RUNNING             │       │
│ │   → VtoP translation available            │       │
│ │ AsusCertService: RUNNING (v1.03.02)       │       │
│ │   → Pipe: \\.\pipe\asuscert              │       │
│ └───────────────────────────────────────────┘       │
│                                                     │
│ ┌─── Attack Surface Summary ────────────────┐       │
│ │ Can load ANY signed driver (VDB disabled)  │       │
│ │ Can load cross-signed drivers (CI policy   │       │
│ │   in evaluation mode — not enforcing)      │       │
│ │ AsIO3 already present — zero-load option   │       │
│ └───────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────┘
```

---

## Exploitation Outcomes / 利用结果

### What becomes possible with Tier 0/1 drivers:
### 使用 Tier 0/1 驱动后可以实现什么:

| Outcome / 结果 | Method / 方法 | Risk / 风险 |
|---|---|---|
| **Read any process memory** / 读取任何进程内存 | PPL clear → ReadProcessMemory | Low |
| **Extract encryption keys** / 提取加密密钥 | Heap scan for AES key schedule | Low |
| **Become SYSTEM** / 获得SYSTEM权限 | Token steal via EPROCESS write | Low |
| **Disable all security software** / 禁用所有安全软件 | Kernel callback removal | Medium |
| **Hide from task manager** / 从任务管理器隐藏 | DKOM (unlink EPROCESS) | Medium |
| **Bypass driver signing** / 绕过驱动签名 | DSE flag modification | Medium |
| **Persist across reboots** / 跨重启持久化 | Bootkit via physical write | High |
| **Read LSASS credentials** / 读取凭据 | PPL bypass → MiniDump | Low |
| **Intercept network traffic** / 拦截网络流量 | NDIS hook via kernel write | High |
| **Modify running code** / 修改运行中的代码 | Physical write to .text | High |

---

## Risk Assessment / 风险评估

| Action / 操作 | Detection Risk / 检测风险 | BSoD Risk / 蓝屏风险 | Reversible / 可逆 |
|---|:---:|:---:|:---:|
| Load LnvMSRIO | 🟡 Low (PiDDB entry) | 🟢 None | ✅ sc delete |
| Read physical memory | 🟢 Zero (no hooks) | 🟡 Low (bad addr) | ✅ |
| Write EPROCESS Protection | 🟡 Low | 🟡 Low (wrong offset) | ✅ write back |
| Token steal | 🟡 Low | 🟡 Medium | ⚠️ Partial |
| ReadProcessMemory (after PPL) | 🟡 EAC may hook | 🟢 None | ✅ |
| Heap scan for AES keys | 🟢 Zero | 🟢 None | ✅ |
| Driver unload + cleanup | 🟢 Artifacts remain in logs | 🟢 None | ✅ |

```
🟢 = Safe / 安全
🟡 = Caution needed / 需要谨慎
🔴 = High risk / 高风险
```

---

## Current Project Score / 当前项目评分

```
Research Completeness / 研究完整度:        ████████████████████ 95%
Code Implementation / 代码实现:           ████████████████░░░░ 80%
Live Verification / 实际验证:             ████████░░░░░░░░░░░░ 40%
End-to-End Success / 端到端成功:          ████░░░░░░░░░░░░░░░░ 20%

Overall / 总体:                          5.5/10

Blocking items / 阻塞项:
  ① KTHREAD+0x220 offset live verification / 内核偏移实际验证
  ② AES key presence in VRChat heap / AES密钥在VRChat堆中的存在性
  ③ First successful key extraction / 首次成功提取密钥
```
