# 大规模驱动发现报告 — 2026-07-15 (Massive Discovery)

> 13 agents, 439 tool calls, 1M+ tokens 并行搜索全网结果
> 重大发现：6 个 WHQL 签名 + HVCI 兼容 + 不在黑名单 的驱动

---

## 核心发现：HVCI-Compatible Tier 1 驱动 (LoadsDespiteHVCI: TRUE)

这些驱动可以在 **完全更新的 Windows 11 25H2 + HVCI 开启** 的系统上加载：

| # | 驱动 | 厂商 | 能力 | 访问控制 | VDB | VT 检测 | 来源 |
|---|------|------|------|---------|-----|---------|------|
| 1 | **WDTKernel.sys** | Dell | PhysMem R/W + Port I/O + PCI | Unknown | 不在 | 0/73 | MS Update Catalog |
| 2 | **SparkIO.sys** | Clevo (台湾 ODM) | PhysMem Read + Port + PCI + SMBus | **零** (STATUS_SUCCESS) | 不在 | 0/77 | CVE-2022-37415 PoC |
| 3 | **devhost.sys** | 深圳奥联 | 页表遍历 + CR3 + MmCopyMemory | djb2 hash resolve | 不在 | 0/77 | Nextron 披露 |
| 4 | **WinIo64.sys** (WHQL variant) | WinIo Library | PhysicalMemory 映射 + Port I/O | Unknown | 不在 | 0/73 | KDU |
| 5 | **bsitf.sys** | ASUS | PhysMem + MDL + Port + PCI + BIOS Flash | Unknown | 不在 | 0/73 | ASUS 固件包 |
| 6 | **CorsairLLAccess64.sys** | Corsair | PhysMem R/W + MSR R/W + Port + PCI | Unknown | 不在 | 2/70 | Corsair iCUE |

### 为什么这些是游戏规则改变者

我们之前的问题：April 2026 CI 策略阻止 cross-signed 驱动，只有 WHCP 签名的能加载。

**这 6 个全部是 WHCP/WHQL 签名，LoadsDespiteHVCI=TRUE。** 即使 Memory Integrity 开启，它们仍然加载。而且全部不在 Microsoft Vulnerable Driver Blocklist 上。

### 最高优先级目标：SparkIO.sys

- **零访问控制** — IRP_MJ_CREATE 无条件返回 STATUS_SUCCESS
- **WHQL 签名** — 不受签名策略限制
- **有公开 CVE + PoC** — CVE-2022-37415, gist.github.com/alfarom256
- **极高安装量** — Clevo 是 XMG/Eluktronics/EVOO/Origin PC/System76/Sager 的 ODM
- **0/77 VT 检测** — 完全干净

---

## Tier 2：高价值非 HVCI 目标 (HVCI 关闭时可用)

| # | 驱动 | 厂商 | 能力 | CVE | 特殊价值 |
|---|------|------|------|-----|---------|
| 7 | **HWiNFO64A.SYS** | REALiX | PhysMem R/W (0x85FE2608) | CVE-2018-8061 | WHQL签名(新版), 50M+用户 |
| 8 | **nipalk.sys** | National Instruments | PhysMem R/W + VA→PA + DMA | CVE-2021-38304 | 零访问控制, 796KB |
| 9 | **EnergyDriver.sys** | Intel | 无限制 MSR R/W + PhysMem | 无 | Intel 签名, Power Gadget |
| 10 | **pstrip64.sys** | EnTech Taiwan | PhysMem 映射 | CVE-2026-29923 | 零权限检查 |
| 11 | **AppShopDrv103.sys** | ASRock | PhysMem + MSR + CR0-4 + Port | 无 | 30+ IOCTL, AES 加密但 key 硬编码 |
| 12 | **BiosToolCommonDriver.sys** | AMD | PhysMem + MSR + Port + PCI + SPI Flash | 无 | 18 IOCTL, AMD 签名 |
| 13 | **AMDRyzenMasterDriverV17** | AMD | PhysMem R/W (0x81112F08/0C) | CVE-2023-20564 | 完整 PoC, HVCI 阻止 |

---

## AMD 驱动族完整评估

| 驱动 | CVE | 物理内存 | 签名 | HVCI | 结论 |
|------|-----|---------|------|------|------|
| AMDRyzenMasterDriverV17 | CVE-2023-20564 | Full R/W | Cross-sign | **阻止** | 仅 Win10/HVCI-off |
| AMDRyzenMasterDriverV15 | CVE-2020-12928 | Full R/W | Cross-sign | **阻止** | 同上 |
| PdFwKrnl.sys | CVE-2023-20598 | Code Exec (Low IL) | AMD cert | **阻止** | KDU #44, 被 VDB |
| atdcm64a.sys | 无 CVE | Full R/W (via PML4) | Cross-sign | **阻止** | 3 部分 exploit 博客 |
| BiosToolCommonDriver.sys | 无 | Full + MSR + SPI | AMD Sectigo | 不阻止 | **可用** (非 WHQL 但未被 VDB) |

**结论**: AMD 主流驱动全部被 HVCI 阻止。唯一例外是 BiosToolCommonDriver.sys (非 WHQL 但不在 VDB 上)。

---

## GPU 厂商评估

### NVIDIA
- nvoclock (KDU #40): 物理内存 R/W, 但是旧版 cross-signed, 被阻止
- nvlddmkm.sys: WHQL 签名但漏洞都是 DoS/info leak, 无物理内存原语
- **结论**: NVIDIA 主驱动不暴露直接物理内存 IOCTL

### Intel
- PmxDrv.sys (KDU #52): Intel ME Tools, 需要 Intel ME 解锁模式
- iqvw64e.sys (CVE-2015-2291): 在 VDB 上, 被阻止
- **EnergyDriver.sys** (Intel Power Gadget): 无限制 MSR R/W — **高价值**
- **结论**: Intel EnergyDriver 是最佳候选 (但非 WHQL, HVCI 下不加载)

---

## 游戏外设评估

| 厂商 | 驱动 | 能力 | 状态 |
|------|------|------|------|
| **Corsair** | CorsairLLAccess64.sys | PhysMem + MSR + Port | **WHQL, HVCI 兼容, 高价值** |
| Razer | rzpnk.sys (KDU #43) | 代码执行 | 在 VDB 上, 被阻止 |
| NZXT | 使用 WinRing0 | PhysMem + MSR | WinRing0 被 Defender 标记 |
| Logitech | 无内核驱动 | N/A | 不可用 |
| SteelSeries | 无公开内核原语 | N/A | 不可用 |

**结论**: Corsair iCUE 是唯一同时满足 WHQL + HVCI + 物理内存+MSR 的游戏外设驱动。

---

## HWiNFO64 详细分析

| 属性 | 值 |
|------|-----|
| **驱动** | HWiNFO64A.SYS |
| **设备** | `\\.\HWiNFO32` |
| **CVE** | CVE-2018-8061 |
| **IOCTL** | `0x85FE2608` — 任意物理内存 R/W |
| **输入** | {phys_addr: u64, size: u32, dest_va: u64} |
| **访问控制** | 无 (≤v8.98) |
| **签名** | WHQL (新版本) |
| **用户量** | 50M+ |
| **PoC** | https://github.com/otavioarj/SIOCtl |
| **VDB** | 不在 |

**关键问题**: 漏洞版本 (≤8.98) 可能是旧签名; 新版可能已修补。需要确认哪个版本同时有 WHQL 签名且仍有漏洞。

---

## 中文/国际社区发现

- **devhost.sys (深圳奥联)**: WHQL, 页表遍历, djb2 hash 隐藏导入 — 中国安全公司出品
- **Korean msFuzz**: 韩国 BoB 团队自动化 fuzzing 框架, 找到多个驱动漏洞
- **QIOMem.sys**: 现已有 CVE-2026-56129 + 公开 PoC (github.com/valium007/qiomem)
- 七彩虹/影驰等国产 GPU 未发现独立内核驱动漏洞

---

## 更新后的推荐链

### 终极推荐链 (2026-07-15, HVCI+25H2 全兼容)

```
SparkIO.sys → CorsairLLAccess64.sys → WDTKernel.sys → LnvMSRIO → SIVX64
(WHQL+零控制)  (WHQL+MSR+PhysMem)     (WHQL+Dell)      (WHCP)     (WHCP)
```

### 如果 HVCI 关闭

```
LnvMSRIO → HWiNFO64A(≤8.98) → nipalk.sys → EnergyDriver → SIVX64
```

---

## 下载优先级

| 优先级 | 驱动 | 获取方式 |
|--------|------|---------|
| P0 | SparkIO.sys | VirusTotal (CVE-2022-37415 hash), Clevo 控制中心安装包 |
| P0 | CorsairLLAccess64.sys | 旧版 Corsair iCUE 安装包 (WHQL 样本 hash: 01e024d3...) |
| P0 | WDTKernel.sys | Microsoft Update Catalog (Dell Watchdog Timer) |
| P1 | devhost.sys | VirusTotal (Nextron 披露) |
| P1 | HWiNFO64A.SYS (≤8.98) | HWiNFO 官网旧版下载 |
| P1 | bsitf.sys | ASUS 固件更新包提取 |
| P2 | nipalk.sys | National Instruments DAQmx 安装包 |
| P2 | EnergyDriver.sys | Intel Power Gadget 3.6 (已废弃) |
| P2 | BiosToolCommonDriver.sys | Razer Blade 16 BIOS 更新包 |

---

## 参考源

| 来源 | 链接 |
|------|------|
| LOLDrivers 完整项目 | https://github.com/magicsword-io/LOLDrivers |
| SparkIO CVE-2022-37415 PoC | https://gist.github.com/alfarom256/220cb75816ca2b5556e7fc8d8d2803a0 |
| CVE-2023-20564 PoC (AMD) | https://github.com/NtGabrielGomes/CVE-2023-20564 |
| AMD Ryzen Master V17 exploit | https://github.com/tijme/amd-ryzen-master-driver-v17-exploit |
| AMD atdcm64a LPE | https://github.com/MrAle98/ATDCM64a-LPE |
| AMD atdcm64a blog (3 parts) | https://security.humanativaspa.it/exploiting-amd-atdcm64a.sys-arbitrary-pointer-dereference-part-1 |
| HWiNFO CVE-2018-8061 PoC | https://github.com/otavioarj/SIOCtl |
| QIOMem CVE-2026-56129 PoC | https://github.com/valium007/qiomem |
| Corsair CVE-2020-8808 | LOLDrivers #300 |
| devhost.sys 分析 | Nextron Research (LOLDrivers #333) |
| Intel EnergyDriver | LOLDrivers #331 |
| NI nipalk.sys | LOLDrivers #300 |
