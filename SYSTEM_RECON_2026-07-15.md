# 系统侦察报告 — 2026-07-15

> 目标系统实时数据（只读操作，零风险）

---

## 系统环境

| 属性 | 值 |
|------|-----|
| OS | Windows 11 25H2 (Build 26200.0) |
| 机型 | Generic Research Workstation |
| VBS | Running (status=2) |
| HVCI/Memory Integrity | **关闭** (SecurityServicesRunning={0}) |
| Vulnerable Driver Blocklist | **已禁用** (registry value=0) |
| CI 策略 | 8 个 .cip 文件存在，但 VDB 未强制执行 |
| 管理员 | 当前会话非 Admin (需要 UAC 提升才能操作驱动) |

---

## 已加载驱动 (可直接利用)

| 驱动 | 服务名 | 状态 | 路径 | PDO |
|------|--------|------|------|-----|
| **AsIO3.sys** | Asusgio3 | **Running** (Boot-start) | `C:\Windows\system32\drivers\AsIO3.sys` | `\Device\0000004c` |
| **uiomap.sys** (IOMap64) | uiomap | **Running** (Boot-start) | DriverStore `uiomap.inf_amd64_...` | PCI device |
| AsusSAIO.sys | AsusSAIO | Running | DriverStore | — |
| AsusPTPFilter.sys | AsusPTPDrv | Running | DriverStore | — |

---

## AsIO3 详细状态

| 属性 | 值 |
|------|-----|
| 版本 | **1.03.02** (PRE-PATCH, 受 CVE-2025-3464 影响) |
| SHA-256 | `0AE0784538379CBCCD4ACCD32FBE74A0C62E30CA6A9A55299CDCF0C7A6B2FA4D` |
| 大小 | 69,768 bytes |
| 设备对象 | `\Device\Asusgio3` (存在于 NT 对象目录) |
| Symlink | `\GLOBAL??\Asusgio3` → 存在但 CreateFile 返回 FILE_NOT_FOUND |
| 原因 | 设备只接受已通过 PID 注册的进程 (AsusCertService 认证) |
| AsusCertService | v1.03.02, Running, `C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\` |
| 命名管道 | `\\.\pipe\asuscert` — 当前未活跃 (error 3 = PATH_NOT_FOUND) |

### 访问路径

```
正常路径 (需要 ASUS 签名):
  AsusCertService → pipe → 验证签名 → IOCTL 0xA040A490 注册 PID → 进程可打开设备

CVE-2025-3464 路径 (hardlink bypass):
  创建 hardlink → 启动暂停 → swap → 签名验证读到 AsusCertService.exe → PID 注册成功

CVE-2026-8070 路径 (如果升级到 AC 6.0-6.4.12):
  直接 CreateFile("\\.\Asusgio3") → 权限错误导致低权限可打开
```

### 当前版本 (1.03.02) 的限制

- pipe `\\.\pipe\asuscert` 返回 PATH_NOT_FOUND — AsusCertService 可能未创建管道 (需要特定操作触发)
- CreateFile 设备路径失败 — PID 未注册
- **结论: 需要先触发 AsusCertService 创建管道，或使用 CVE-2025-3464 hardlink bypass**

---

## uiomap 状态 — 不是 IOMap64！

| 属性 | 值 |
|------|-----|
| 服务名 | uiomap |
| 实际身份 | **Microsoft UIO Mapper Driver** (非 ASUS IOMap64!) |
| 厂商 | Microsoft |
| 版本 | 10.0.26100.8521 |
| INF | `uiomap.inf` — 系统自带 PnP 驱动 |
| 功能 | UIO (Userspace I/O) 映射，用于 PCI 设备直通 |
| 与 IOMap64 关系 | **无关** — 名字相似但完全不同的驱动 |

**修正**: 之前误认为系统运行了 ASUS IOMap64.sys。实际运行的是 Microsoft 的 UIO Mapper 驱动（系统自带）。要使用 IOMap64 漏洞需要手动加载 `D:/Project/report/binaries/IOMap64.sys`。

---

## 其他服务

| 服务 | 状态 |
|------|------|
| SysMain (Superfetch) | **Running, Automatic** |
| EasyAntiCheat | **未运行** |
| VRChat | **未运行** |

---

## 对攻击路径的影响

### 最优路径 (基于系统侦察)

**由于 AsIO3 和 IOMap64 已加载但无法直接 CreateFile 打开，且不需要加载 LnvMSRIO (HVCI off + VDB disabled)，推荐路径为：**

```
方案 A (最简单): 加载 LnvMSRIO.sys
  优势: 零访问控制，直接 CreateFile("\\.\WinMsrDev")
  风险: PiDDBCacheTable 记录 (但 VDB disabled 所以不被阻止)
  步骤: sc create → sc start → CreateFile → IOCTL

方案 B (零加载): 利用 AsIO3 CVE-2025-3464
  优势: 驱动已在系统上运行，无需加载新驱动
  风险: 需要 hardlink 竞态成功
  步骤: hardlink bypass → PID 注册 → CreateFile → IOCTL

方案 C (零加载): 通过 uiomap 设备接口
  优势: 驱动已运行
  风险: 需要找到正确的设备接口 GUID
  步骤: SetupDiGetClassDevs → 获取接口路径 → CreateFile → IOCTL
```

**推荐: 方案 A (LnvMSRIO)**. 系统 HVCI 关闭且 VDB 禁用，直接加载最简洁无依赖。

---

## EPROCESS 偏移修正 (Vergilius Project 验证)

| 字段 | 旧值 (错误) | 正确值 (Build 26200) | 来源 |
|------|------------|---------------------|------|
| ActiveProcessLinks | ~~0x540~~ | **0x1D8** | Vergilius _EPROCESS 25H2 |
| Protection | ~~0x87A~~ | **0x5FA** | Vergilius _EPROCESS 25H2 |
| Token | 未确认 | **0x248** | Vergilius _EPROCESS 25H2 |
| KTHREAD.Process | 0x220 | 0x220 ✓ | Vergilius _KTHREAD 25H2 |
| UniqueProcessId | 0x1D0 | 0x1D0 ✓ | 确认 |
| ImageFileName | 0x338 | 0x338 ✓ | 确认 |
| DirectoryTableBase | 0x028 | 0x028 ✓ | 确认 |
| GS:0x188 | — | CurrentThread (KPRCB+8) ✓ | dennisbabkin.com |

**exploit_test_results.txt 中的 0x540/0x87A 偏移来自更早的 Windows build (22H2/23H2)。已在 extractor 代码中修正。**

---

## Corsair 逆向 — 完整 11 IOCTL 表

从二进制逆向确认 (非文档推断):

| IOCTL | 功能 | 输入大小 | 内核 API |
|-------|------|---------|----------|
| 0x225348 | PCI config 读 | 20B | HalGetBusDataByOffset |
| 0x225358 | Port I/O 读 | 10B | IN dx |
| **0x225374** | **物理内存映射** | variable | MmMapIoSpace + MmMapLockedPages |
| 0x22537C | 版本查询 | 0 | 返回 0x01000018 |
| 0x225388 | MSR 读 | 4B | RDMSR |
| **0x22934C** | **MMIO 读 (直接物理读)** | 10B | MmMapIoSpace |
| **0x229350** | **MMIO 写 (直接物理写)** | 10B | MmMapIoSpace |
| 0x229354 | Port I/O 写 | 10B | OUT dx |
| 0x229378 | 释放映射 | 8B | linked list ops |
| 0x229380 | PCI config 写 | 20B+ | HalSetBusDataByOffset |
| 0x229384 | MSR 写 | 12B | WRMSR |

### 新发现的直接读写 IOCTL (0x22934C / 0x229350)

```c
// Input structure for MMIO Read/Write (10 bytes):
struct MmioParams {
    QWORD physical_address;  // +0x00
    WORD  access_size;       // +0x08 (1=byte, 2=word, 4=dword)
};
// Write: value comes from SystemBuffer[4] (overlapping with address bytes 4-7?)
```

这比 0x225374 (map+copy+unmap) 更简洁：单次 IOCTL 完成一次物理地址读写，无需管理映射句柄。

---

## AES 扫描代码验证

- Rust cargo test: **10/10 通过**
- Python 独立验证: **3/3 通过**
- NIST FIPS-197 Appendix A 向量正确
- Key expansion 和 schedule validation 逻辑无 bug
