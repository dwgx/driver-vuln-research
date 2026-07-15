# 待解决问题清单 + 新驱动发现方向

> 2026-07-15 — 系统性梳理所有悬而未决的问题和值得探索的新方向

---

## 一、待解决技术问题

### A. 环境验证（需要在目标系统执行）

| # | 问题 | 命令 | 影响 |
|---|------|------|------|
| A1 | CI 策略状态 (评估/强制模式) | `CiTool.exe --list-policies` | 决定 cross-sign 驱动能否加载 |
| A2 | HVCI/内存完整性状态 | `Get-CimInstance -ClassName Win32_DeviceGuard` | 决定 VDB 是否生效 |
| A3 | LnvMSRIO 当前可加载性 | `sc create test type=kernel binPath=...; sc start test` | 确认主武器是否仍可用 |
| A4 | Superfetch/SysMain 服务 | `sc query SysMain` | VtoP 方案可行性 |
| A5 | Armoury Crate 版本和 AsIO3 版本 | `wmic product where "name like '%Armoury%'" get version` | CVE-2026-8070 可行性 |
| A6 | Windows Build 精确版本 | `winver` 或 `[System.Environment]::OSVersion` | 内核偏移正确性 |
| A7 | EAC 进程列表 | `tasklist /fi "imagename eq EasyAntiCheat*"` | 确认 EAC 运行状态 |
| A8 | VRChat 进程 PID 和保护级别 | `Get-Process VRChat` + Process Explorer 查看 Protection | PPL 状态确认 |

### B. 核心技术不确定性

| # | 问题 | 当前假设 | 验证方法 |
|---|------|---------|---------|
| B1 | LnvMSRIO 是否在 MSFT VDB 上 | 可能未在（低关注度工具驱动） | 对比 `C:\Windows\System32\CodeIntegrity\driversipolicy.p7b` 中的 hash |
| B2 | 物理内存读是否绕过 EAC 的 NtReadVirtualMemory hook | 是（物理读不经过 SSDT hook） | 实测：物理读 VRChat 页面 vs API 读 |
| B3 | Superfetch 是否返回 EAC 保护进程的 PFN | 未知 | 测试 NtQuerySystemInformation(79) 对 VRChat PID |
| B4 | AES-128 key 在 VRChat 堆中的存活时间 | 假设长期驻留 | 多次采样确认 key 是否稳定 |
| B5 | AES key schedule 是否展开存储在内存中 | Unity/IL2CPP 通常展开 | 扫描确认 176 字节模式是否存在 |
| B6 | EAC 是否检测 Superfetch 查询模式 | 不检测（标准 API） | 测试后观察是否触发封禁 |
| B7 | KPCR 物理地址是否在安全范围内 | 是（内核地址总在安全范围） | 验证 MSR 0xC0000101 返回值的物理映射 |
| B8 | EPROCESS.Protection (+0x87A) 写零后 EAC 是否重新检测 | 未知 | PPL 清除后观察行为 |
| B9 | Build 26200 的 EPROCESS 偏移是否正确 | 从 exploit_test_results.txt 确认 | 比对 PDB 或动态验证 |
| B10 | 多核系统 KPCR 是否每核不同 | 是 | 需要设置线程亲和性到 CPU0 |

### C. 代码实现问题

| # | 问题 | 状态 | 需要做 |
|---|------|------|-------|
| C1 | superfetch_vtop.rs 是否能编译 | 未测试 | `cargo check` |
| C2 | iomap64_backend.rs 输入结构 padding 是否正确 | 未验证 | 对比 IOMap64.sys 中 dispatch handler 实际读取偏移 |
| C3 | portwell.sys 输入缓冲区大小要求 | 未知 | 逆向驱动确认 InputBufferLength 检查 |
| C4 | Superfetch PFN batch 最大查询数量限制 | 文档说数千，未确认上限 | 测试递增数量直到失败 |
| C5 | MmpfnIdentity 中的 ProcessId 字段如何匹配目标进程 | Flags bits[63:48] 或 VirtualAddress 字段 | 需确认 Win11 25H2 的 PFN 归属判定 |

---

## 二、新驱动发现方向

### D. 尚未调查的已知 CVE 驱动

| # | 驱动 | CVE | 厂商 | 为什么值得查 |
|---|------|-----|------|------------|
| D1 | **AMD PdFwKrnl.sys** | CVE-2023-20598 | AMD | KDU #44, WHCP 签名(?), 物理内存 R/W |
| D2 | **AMD affdriver.sys** | — | AMD | KDU #61, 未被黑名单, 未研究 |
| D3 | **Intel PmxDrv.sys** | — | Intel | KDU #52, Intel ME Tools driver, WHCP 签名 |
| D4 | **Teledyne CorMem.sys** | — | Teledyne | KDU #58, Sapera Memory Manager, MapMem 代码基 |
| D5 | **Shangke WinHwDrv.sys** | — | Shangke | KDU #60, 未知厂商, 未研究 |
| D6 | **LECO LECOMA.sys** | — | LECO | KDU #64, 未知, 未研究 |
| D7 | **Matrox mtxC9CB.sys** | — | Matrox | KDU #62, 显卡厂商, 未研究 |
| D8 | **Wincor Nixdorf wnBios64.sys** | — | Wincor Nixdorf | KDU #46, ATM/POS 设备, 可能 WHCP |
| D9 | **EVGA EleetX1.sys** | — | EVGA | KDU #47, EVGA 超频工具, WinRing0 基 |
| D10 | **ASRock AppShopDrv103.sys** | — | ASRock | KDU #49, RWEverything 基, 多版本存在 |

### E. 未被覆盖的漏洞类别

| # | 方向 | 描述 | 为什么值得探索 |
|---|------|------|---------------|
| E1 | **GPU 驱动** | NVIDIA NvDrv (KDU #40), AMD 驱动族 | WHCP 签名，不在 cross-sign 限制范围 |
| E2 | **打印机/扫描仪驱动** | HP EtdSupport (KDU #35), Canon/Epson | OEM 驱动通常安全审计薄弱 |
| E3 | **UPS/电源管理驱动** | APC, CyberPower 系列 | 工控领域，关注度极低 |
| E4 | **虚拟化/管理程序驱动** | VMware/VBox 子系统驱动 | 可能有物理内存映射能力 |
| E5 | **音频驱动** | Realtek/Creative 内核组件 | 高安装率，签名有效 |
| E6 | **BIOS/固件更新驱动** | AMI amifldrv64, Phoenix | 物理内存 R/W 是核心功能 |
| E7 | **硬件监控新品** | HWiNFO64, AIDA64 内核驱动 | 同类 SIV/ArgusMonitor，可能有新的 |
| E8 | **存储控制器驱动** | Intel RST, AMD StoreMI 子驱动 | 需要 DMA 访问，可能暴露物理内存 |
| E9 | **网络适配器诊断** | Broadcom, Marvell 诊断工具 | 类似 Realtek rtkio64 |
| E10 | **安全软件自身漏洞** | 杀毒/EDR 的内核驱动 | 讽刺但真实：防护软件自己有 R/W 原语 |

### F. 搜索关键词和资源

| # | 搜索方向 | 搜索查询 | 目标来源 |
|---|---------|---------|---------|
| F1 | GitHub 新 CVE PoC | `site:github.com "physical memory" "read write" driver CVE 2026` | GitHub |
| F2 | Exploit-DB 内核驱动 | `site:exploit-db.com kernel driver privilege escalation 2026` | Exploit-DB |
| F3 | 中文安全社区 | `内核驱动 物理内存 漏洞 提权 2026 site:52pojie.cn OR site:kanxue.com` | 看雪/吾爱 |
| F4 | arXiv 学术论文 | `"IOCTL" "vulnerable driver" "physical memory" arxiv 2026` | arXiv |
| F5 | LOLDrivers 新增 | `github.com/magicsword-io/LOLDrivers/commits/main` | LOLDrivers Git 历史 |
| F6 | KDU 新 Provider | `github.com/hfiref0x/KDU/releases` latest | KDU Releases |
| F7 | Windows Update Catalog | 搜索被撤回的驱动更新 | catalog.update.microsoft.com |
| F8 | CISA ICS-CERT | `site:cisa.gov driver "physical memory" OR "privilege escalation"` | CISA |
| F9 | 韩国安全研究 | `site:github.com Korean CVE driver exploit 2026` | GitHub Korea |
| F10 | VulnCheck/NVD 新增 | NVD search: CWE-782 (Exposed IOCTL) + kernel + 2026 | NVD |

### G. 特定高价值目标深挖

| # | 目标 | 理由 | 行动 |
|---|------|------|------|
| G1 | **HWiNFO64 内核驱动** | 极高安装率的硬件监控，一定有物理内存读能力 | 找 CVE 或自行逆向 |
| G2 | **AIDA64 驱动** | 同上，FinalWire 出品 | 搜索已知漏洞 |
| G3 | **CPU-Z cpuz_x64.sys** | KDU 已有 (#14?), 但版本很多，新版可能未被黑名单 | 检查 VDB hash 覆盖 |
| G4 | **PassMark DirectIo64** | KDU #14/#27, 两个产品 (PerformanceTest/OSForensics) | 版本差异检查 |
| G5 | **Dell dbutil 新版** | CVE-2021-21551 极有名, 但 Dell 可能有新的未修补变体 | 搜索 Dell BIOS 2024+ 驱动 |
| G6 | **Lenovo 其他驱动** | LnvMSRIO 是 Lenovo 出品, 同厂商可能有更多 | 搜索 Lenovo Diagnostics 驱动族 |
| G7 | **微星 (MSI) 其他驱动** | KernCoreLib64 是 MSI, 微星有很多 OEM 工具 | MSI Center, Dragon Center 驱动 |
| G8 | **技嘉 (Gigabyte) 新驱动** | gdrv.sys 被黑名单, 但 App Center/RGB Fusion 可能有新的 | 搜索 Gigabyte 2024+ 签名驱动 |
| G9 | **Razer Synapse rzpnk.sys** | KDU #43, 游戏外设厂商, 高安装率 | 检查是否仍可利用 |
| G10 | **七彩虹 (Colorful) iGame 驱动** | 中国 GPU 厂商, 可能有未被西方安全社区发现的驱动 | 搜索中文论坛 |

---

## 三、方法论扩展

### H. 非驱动方案（降低检测风险）

| # | 方法 | 描述 | 优势 | 劣势 |
|---|------|------|------|------|
| H1 | **WER (Windows Error Reporting) dump** | 崩溃 VRChat → 扫描 dump 文件 | 零驱动，零检测 | 破坏性 |
| H2 | **MiniDumpWriteDump** | 如果有 SeDebugPrivilege | 标准 API | EAC 可能 hook |
| H3 | **ETW (Event Tracing) 侧信道** | 监控 .NET/CLR 事件 | 无内存读取 | 信息有限 |
| H4 | **DLL 注入到非保护进程** | 通过共享内存交换数据 | 不触碰 VRChat | 需要 IPC 通道 |
| H5 | **Hypervisor 方案** | Type-1 或 Type-2 虚拟化 | 完全不可见 | 极其复杂 |
| H6 | **UEFI rootkit** | 固件级物理内存访问 | 无内核态存在 | 复杂 + 高风险 |
| H7 | **DMA 硬件** | PCIe screamer / Thunderbolt DMA | 完全独立于 OS | 需要硬件 |
| H8 | **内核回调滥用** | PsSetCreateProcessNotifyRoutine 等 | 合法回调 | 需要自签驱动 |
| H9 | **Windows Defender 排除** | 使用 WD 排除规则隐藏操作 | 降低 AV 检测 | 不影响 EAC |
| H10 | **Task Scheduler + COM 对象** | 利用系统服务的高权限 COM | 无额外驱动 | 能力有限 |

### I. EAC 绕过研究方向

| # | 方向 | 描述 | 状态 |
|---|------|------|------|
| I1 | EAC 内核模块加载检测精确时序 | 确认 EAC 扫描间隔和方式 | 部分已知 (PiDDB/MmUnloaded) |
| I2 | EAC 用户态 hook 列表 | 哪些 ntdll/kernel32 函数被 hook | 需要 hook 扫描 |
| I3 | EAC 与 Superfetch API 交互 | 是否监控 NtQuerySystemInformation class 79 | 未知 |
| I4 | EAC 对物理内存驱动的具体检测逻辑 | 是检测驱动还是检测 IOCTL 调用 | 需要逆向 EAC 模块 |
| I5 | EAC 通信协议 (client → server) | 上报了什么遥测数据 | 需要流量分析 |
| I6 | EAC 更新频率 | 检测规则多久更新一次 | 观察 |
| I7 | EAC 对 token stealing 的检测 | 是否校验进程 token 完整性 | 未知 |
| I8 | EAC 对 PreviousMode 修改的检测 | 23H2+ OS 自动检测, 但旧 OS 上 EAC 是否也检测 | 未知 |
| I9 | EAC 对 ObCallback 的利用 | EAC 是否注册了对象回调来拦截驱动操作 | 需要逆向 |
| I10 | EAC 内核态驱动 (EasyAntiCheat.sys) hash/cert | 是否可以 patch EAC 自身 | 极高风险 |

---

## 四、信息搜集优先级

### 立即可做 (无需目标系统)

1. **搜索 HWiNFO64 / AIDA64 内核驱动 CVE** — 极高安装率
2. **搜索 AMD PdFwKrnl / affdriver CVE 和 PoC** — WHCP 签名
3. **搜索 Intel PmxDrv 技术细节** — Intel ME Tools, WHCP
4. **LOLDrivers 最近 30 天新增驱动** — 新发现的漏洞驱动
5. **中文安全社区 (看雪/吾爱) 搜索 2026 内核驱动提权** — 可能有西方未覆盖的发现
6. **搜索七彩虹/影驰等国产 GPU 厂商驱动** — 未被国际安全社区审计
7. **KDU v1.4.8/v1.4.9 新增的 provider 58-64 的详细分析**
8. **NVD CWE-782 (Exposed IOCTL) 2026 年新增条目全部检索**
9. **Exploit-DB 2026 Q2-Q3 kernel driver local 类别**
10. **搜索 Razer/Corsair/Logitech 外设驱动漏洞** — 游戏玩家系统高安装率

### 需要目标系统 (执行验证)

11. A1-A8 环境检查命令
12. LnvMSRIO 加载测试
13. Superfetch 对 VRChat PFN 查询测试
14. AsIO3 版本确认 + CreateFile 低权限测试 (CVE-2026-8070)
15. EAC hook 扫描 (检查哪些 API 被 inline hook)

---

## 五、驱动发现方法论 — 自动化思路

### 批量 CVE 检索脚本

```python
# 搜索 NVD 中所有符合条件的 Windows 内核驱动 CVE
# 条件: CWE-782 OR CWE-119 OR CWE-732, Windows, kernel, 2024-2026
import requests

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "cweId": "CWE-782",  # Exposed IOCTL with Insufficient Access Control
    "pubStartDate": "2024-01-01T00:00:00.000",
    "pubEndDate": "2026-07-31T23:59:59.999",
    "keywordSearch": "kernel driver physical memory",
    "resultsPerPage": 100
}
# 同样搜索 CWE-119 (memory buffer), CWE-732 (incorrect permission)
```

### LOLDrivers 自动监控

```bash
# 监控 LOLDrivers 仓库新增
git clone https://github.com/magicsword-io/LOLDrivers.git
cd LOLDrivers
git log --since="2026-06-01" --name-only -- yaml/
# 每个新 yaml 文件 = 一个新发现的可利用驱动
```

### 驱动签名有效性批量检查

```python
# 对所有候选驱动检查是否在 MSFT VDB 上
# 下载 VDB hash list, 与本地 binaries/ 目录对比
```

---

## 六、总结

| 类别 | 数量 | 最高优先级 |
|------|------|-----------|
| 环境验证问题 | 8 | A1 (CI策略) + A3 (LnvMSRIO加载) |
| 技术不确定性 | 10 | B3 (Superfetch对EAC进程) |
| 代码验证 | 5 | C1 (编译测试) |
| 新驱动 CVE | 10 | D1 (AMD PdFwKrnl) + D3 (Intel PmxDrv) |
| 未覆盖类别 | 10 | E1 (GPU驱动) + E7 (HWiNFO) |
| 搜索方向 | 10 | F3 (中文社区) + F5 (LOLDrivers新增) |
| 高价值深挖 | 10 | G1 (HWiNFO64) + G6 (Lenovo 其他) |
| 非驱动方案 | 10 | H1 (WER dump) + H7 (DMA硬件) |
| EAC 研究 | 10 | I1 (时序) + I4 (检测逻辑) |
| **总计** | **83 个待解决项** | |
