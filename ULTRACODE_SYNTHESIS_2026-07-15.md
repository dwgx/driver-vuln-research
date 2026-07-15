# 深度研究综合报告 — 2026-07-15

> Workflow 调度 10 个 agent 并行研究，以下为整合后的可操作情报。

---

## 一、CVE-2026-8070 最终判定

### 结论：可在 23H2 上工作，但有条件

| 属性 | 详情 |
|------|------|
| **CVE** | CVE-2026-8070 |
| **驱动** | AsIO3.sys (`\\Device\\Asusgio3`) |
| **受影响版本** | Armoury Crate 0 ~ 6.4.12 |
| **机制** | CWE-732 (设备对象权限错误) — **不同于** CVE-2025-3464 的 hardlink 绕过 |
| **核心区别** | 无需竞态条件！设备对象本身权限设置过宽，低权限用户可直接打开 handle |
| **物理内存** | 直接获取 R/W 原语 (无需 PreviousMode 修改) |
| **PoC 状态** | 无公开 PoC (EPSS 0.01%) |
| **适用 OS** | **所有安装了受影响版本的 Windows (含 23H2/24H2/25H2)** |

### 为什么 CVE-2026-8070 比 CVE-2025-3464 更好

| | CVE-2025-3464 | CVE-2026-8070 |
|---|---|---|
| 绕过机制 | NTFS hardlink 竞态 | 设备权限直接开放 |
| 需要 PreviousMode | 是 (23H2+ 蓝屏) | **否** (直接物理内存) |
| OS 兼容性 | ≤22H2 only | **所有版本** |
| 复杂度 | AC:H | AC:H (因需绕过部分验证) |
| 前提条件 | AsusCertService.exe 存在 | AsIO3 ≤6.4.12 已加载 |

### CVE-2026-8918 (补充)

| 属性 | 详情 |
|------|------|
| **CVE** | CVE-2026-8918 |
| **机制** | CWE-183 (Allowlist 过于宽松) |
| **能力** | g_goodRanges allowlist 可被绕过 → 任意物理内存 R/W |
| **要求** | **需要 Admin** (PR:H) |
| **适用 OS** | 所有版本 |
| **评估** | 如果我们本身有 Admin，这个 allowlist 绕过就是 g_goodRanges 的答案 |

### AsIO3 三步演进

```
CVE-2025-3464 (hardlink+decrement) → 仅≤22H2
      ↓ ASUS 修补
CVE-2026-8070 (权限错误) → 所有OS，低权限，无PoC
      ↓ 
CVE-2026-8918 (allowlist bypass) → 所有OS，需Admin，绕过 g_goodRanges
```

**Action**: 获取 Armoury Crate 6.0~6.4.12 版本的 AsIO3.sys，逆向 CVE-2026-8070 的具体权限缺陷。

---

## 二、Windows 11 23H2+ 缓解措施与替代路径

### PreviousMode 检查

| 构建版本 | PreviousMode 状态 |
|----------|------------------|
| 22H2 (22621) | 可修改，exploit 正常工作 |
| 23H2 (22631+) | **PREVIOUS_MODE_MISMATCH (0x1F9) bugcheck** |
| 24H2 (26100+) | 同上 + NtQuerySystemInfo 不再泄露内核地址 |

### 24H2+ 内核地址泄露替代

| 方法 | 泄露什么 | 适用版本 |
|------|---------|---------|
| NtQuerySystemInformation(HandleInfoEx) | KTHREAD 地址 | ≤23H2 |
| CVE-2025-53136 (Token TOCTOU race) | TOKEN 地址 | 24H2 (已修补) |
| Prefetch side-channel | 内核基地址 | 24H2+ (Intel) |
| 物理内存 Low Stub 读取 | 内核基地址 + CR3 | 任何版本 (需驱动) |

### 不需要 PreviousMode 的提权路径

如果有物理内存 R/W:
```
物理内存读 Low Stub → 获取 CR3
→ 页表遍历 (内核地址安全) → 找到 EPROCESS
→ 直接覆写 Token 字段 → SYSTEM
```

**结论**: CVE-2026-8070 如果直接提供物理内存原语而非 decrement，则完全不需要 PreviousMode 修改，在任何 Windows 版本上都可用。

---

## 三、新驱动详细情报

### IOMap64.sys (ASUS) — 推荐加入

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2024-41498, CVE-2024-33223 |
| **设备** | `\\.\IOMap` |
| **映射 IOCTL** | `0x83002138` |
| **读 IOCTL** | `0x83002104` |
| **写 IOCTL** | `0x83002108` |
| **映射大小** | 256KB (`0x40000`) 或 16MB (`0x1000000`) |
| **映射方式** | MmMapIoSpace (HalTranslateBusAddress fallback) |
| **滑动窗口** | 是 — 重复映射可遍历全部物理内存 |
| **访问控制** | IoCreateDeviceSecure (可能需 Admin 打开 handle)，无 per-IOCTL 检查 |
| **分发** | ASUS GPU Tweak II, AI Suite 3 |
| **安装路径** | `C:\Windows\System32\drivers\IOMap64.sys` |
| **签名** | ASUS DigiCert 2023 |
| **黑名单** | LOLDrivers 有收录，**MSFT VDB 可能未收录** |
| **EAC 兼容** | 与 AsIO3 独立，可能兼容 |

**Input 结构 (映射 IOCTL 0x83002138)**:
```c
struct map_request {
    USHORT index;       // offset 0, must < 0x10 (slot selector)
    DWORD  phys_addr;   // offset 4, physical address to map
    USHORT selector;    // offset 20, 0=16MB, 1=256KB
};
```

---

### KernCoreLib64.sys (MSI) — 有限制

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-57851 |
| **设备** | `\\.\WinIo` |
| **映射 IOCTL** | `0x80102040` |
| **绕过** | ViewSize 参数未验证，传入全部物理 RAM 大小 |
| **限制** | 仅映射 0xFC000800 以上 (≈3.94GB+)，低地址不可达 |
| **签名** | Cross-signed (WinIo 变体)，时间戳 2018 |
| **黑名单** | WinIo64 在 VDB 上，此变体可能因 hash 不同未被覆盖 |
| **25H2 加载** | **不行** — cross-signed 被 April 2026 政策阻止 |
| **PoC 仓库** | https://github.com/readmsr/MSI_FeatureManager_CVE (含驱动二进制) |

**EPROCESS 偏移 (Win11 25H2)**:
```
UniqueProcessId:    +0x1D0
ActiveProcessLinks: +0x1D8
Token:              +0x248
ImageFileName:      +0x338
DirectoryTableBase: +0x028
```

---

### Portwell.sys — 全能但需获取

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-3437 |
| **文件大小** | 16,848 bytes |
| **设备** | `\\Device\\PORTWELL_0_1` |
| **物理内存读** | `0xEA606450` |
| **物理内存写** | `0xEA60A454` |
| **MSR 读** | `0xEA602408` |
| **MSR 写** | `0xEA60240C` |
| **Port I/O** | `0xEA60A440` (byte), `0xEA60A444` (word), `0xEA60A460` (dword) |
| **PCI 读** | `0xEA606458` |
| **映射方式** | MmMapIoSpace/MmUnmapIoSpace |
| **SHA-256** | `2F0B16ED90B8C15BF52A7C32699DBE0DBCD38FC02ED2DDB4E1BA35487177B6C5` |
| **签名** | Portwell Inc. |
| **黑名单** | **未在 MSFT VDB 上** |
| **下载** | https://github.com/KeServiceDescriptorTable/vulnerable-drivers |
| **CISA** | ICSA-26-062-04 |

---

### TVicPort64.sys — NULL DACL 无门槛

| 属性 | 值 |
|------|-----|
| **CVE** | CVE-2026-30769 |
| **设备** | `\\.\TVicPortDevice0` |
| **映射 IOCTL** | `0x80002008` |
| **映射方式** | ZwMapViewOfSection (`\Device\PhysicalMemory`) |
| **访问控制** | **NULL DACL** — 任何用户/任何完整性级别 |
| **签名** | EnTech Taiwan, GlobalSign (2006) |
| **黑名单** | **未在 MSFT VDB 上** |
| **下载** | https://www.entechtaiwan.com/dev/port/index.shtm (免费) |
| **25H2 加载** | **不行** — cross-signed |

---

### QIOMEM/TPwSav — KDU Provider #56

| 属性 | 值 |
|------|-----|
| **设备** | `\\Device\\EBIoDispatch` |
| **KDU 能力** | shellcode mask 0x7 (read + write + execute) |
| **签名** | Compal electronic (Toshiba ODM) |
| **黑名单** | **未在 MSFT VDB 上** |
| **下载** | Toshiba Password Utility 包，KDU 内嵌 |
| **适用** | Windows 7-10 (MinNTBuild 7601) |

---

## 四、签名策略生存指南

### April 2026 Windows Update 影响

**机制**: 部署到 EFI 分区的 CI 签名策略文件 (.cip)，不是注册表或 WDAC 用户策略。

**两阶段部署**:
1. **评估模式** — 记录日志 (Event 3076) 但允许加载。需 100h 活跃 + 3 次重启无违规才毕业。
2. **强制模式** — 阻止加载 (Event 3077)。

**关键发现**: 如果系统在评估期间加载了 cross-signed 驱动，计数器**重置为零**。系统**永远不会自动进入强制模式**只要旧驱动持续加载。

### 绕过方法

| 方法 | 可行性 | 备注 |
|------|--------|------|
| 关闭 Secure Boot + 删除 .cip 文件 | **可行** | 需 UEFI 访问 |
| App Control 补充策略 | 可行 | 需 Pro/Enterprise |
| bcdedit /set testsigning | **无效** | 不影响 cross-sign 信任决策 |
| 注册表修改 | **无效** | 策略在 EFI 层面 |
| 保持评估模式 (持续加载旧驱动) | **可行** | 被动绕过 |

### 最终驱动分类

| 驱动 | 签名类型 | April 2026 后状态 | VDB 状态 |
|------|----------|-------------------|----------|
| **LnvMSRIO** | WHCP | **安全** | 可能被加入 (高关注度) |
| **SIVX64** | WHCP | **安全** (证书到期不影响已签名二进制) | 未收录 |
| **IOMap64** (2023) | ASUS Authenticode | 需验证是否 attestation-signed | 可能未在 VDB |
| **Portwell** | Portwell Inc. | 需验证 | **未在 VDB** |
| ThrottleStop | EV cross-signed | **被阻止** | LOLDrivers |
| ASTRA64 | Cross-signed 2006 | **被阻止** | 未收录 |
| ArgusMonitor | EV | **被阻止** | 未收录 |
| KernCoreLib64 | Cross-signed WinIo | **被阻止** | WinIo 被收录 |
| TVicPort64 | Cross-signed 2006 | **被阻止** | 未收录 |

---

## 五、更新推荐链

```
Win11 ≤23H2:
  LnvMSRIO → SIVX64 → AsIO3(CVE-2026-8070) → IOMap64 → Portwell → ASTRA64

Win11 24H2+ (已更新):
  LnvMSRIO → SIVX64 → IOMap64 → Portwell
  (cross-signed 驱动需先绕过 CI 策略)

Win10 (任何版本):
  LnvMSRIO → SIVX64 → IOMap64 → Portwell → KernCoreLib64 → TVicPort64
```

---

## 六、紧急行动项

### 立即 (今天)
1. ✅ SIVX64 证书到期 — **WHCP 签名的驱动二进制不受证书到期影响** (研究确认)
2. 下载 Armoury Crate 6.0~6.4.12 提取 AsIO3.sys 用于 CVE-2026-8070 逆向
3. 下载 portwell.sys: `github.com/KeServiceDescriptorTable/vulnerable-drivers`
4. 下载 KernCoreLib64.sys: `github.com/readmsr/MSI_FeatureManager_CVE`
5. 下载 TVicPort64.sys: `github.com/magicsword-io/LOLDrivers` 或 entechtaiwan.com

### 短期 (本周)
6. 逆向 CVE-2026-8070 — 定位设备对象权限错误的确切位置
7. 验证 IOMap64.sys 在 ASUS 主板系统上的 EAC 兼容性
8. 验证 April 2026 CI 策略在你的系统上是评估模式还是强制模式
   ```cmd
   CiTool.exe --list-policies
   ```
9. 检查 LnvMSRIO 是否已被加入 MSFT VDB (hash 匹配检查)

### 中期
10. 为 Portwell.sys 写 Rust backend (IOCTL 完整，功能最全)
11. 为 IOMap64.sys 写 Rust backend (映射+滑动窗口)

---

## 七、参考源索引

| 来源 | URL |
|------|-----|
| CVE-2026-8070 NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-8070 |
| CVE-2026-8918 NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-8918 |
| AsIO3 Talos 博客 | https://blog.talosintelligence.com/decrement-by-one-to-rule-them-all/ |
| CVE-2025-3464 PoC | https://github.com/jeffaf/CVE-2025-3464-AsIO3-LPE |
| IOMap64 RevEng.AI | https://reveng.ai/blog/physmem-e-when-kernel-drivers-peek-into-memory |
| IOMap64 CVE-2024-33223 | https://github.com/DriverHunter/Win-Driver-EXP/tree/main/CVE-2024-33223 |
| KernCoreLib64 PoC | https://github.com/readmsr/MSI_FeatureManager_CVE |
| CVE-2026-57851 文章 | https://medium.com/@dorukcerit/cve-2026-57851 |
| Portwell CISA | https://www.cisa.gov/news-events/ics-advisories/icsa-26-062-04 |
| TVicPort64 CVE-2026-30769 | https://gist.github.com/lleekkoo/6c73fa4e137aca6f5dfe6aec4f6a7b29 |
| KDU Providers | https://github.com/hfiref0x/KDU/blob/master/Help/providers.md |
| physmem_drivers 130+ | https://github.com/namazso/physmem_drivers |
| Windows Driver Policy | https://support.microsoft.com/en-us/windows/the-windows-driver-policy |
| NeacController PoC | https://github.com/smallzhong/NeacController |
| Prefetch KASLR bypass | https://github.com/exploits-forsale/prefetch-tool |
