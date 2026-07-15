# BYOVD 新驱动发现 — Deep Research Report

> 生成时间: 2026-07-11 | 搜索方法: 97 agent fan-out, 15 sources fetched, 68 claims extracted, 25 verified (20 confirmed, 5 refuted)

---

## 执行摘要

在排除已知的 SIVX64、AsIO3、ASTRA64、ArgusMonitor、RTCore64、DBUtil、ene.sys、WinRing0 后，发现以下**新的可利用签名驱动**：

---

## Tier 1：顶级候选（不在黑名单 + 有完整 PoC）

### LnvMSRIO.sys — Lenovo ⭐ 最佳

| 属性 | 值 |
|------|------|
| CVE | CVE-2025-8061 |
| CVSS | 7.0 (HIGH) |
| 厂商 | Lenovo |
| 功能 | MmMapIoSpace 任意物理内存 R/W |
| WDAC 黑名单 | ❌ 不在 |
| LOLDrivers | ❌ 不在 |
| KDU 集成 | ✅ 已支持 |
| PoC | spawn451/CVE-2025-8061-Exploit, symeonp/Lenovo-CVE-2025-8061, segura2010/lenovo-dispatcher-poc |
| 来源 | Quarkslab 安全研究博客 |
| 签名 | Lenovo (WHCP) |
| 获取方式 | Lenovo Vantage / System Update 自带 |

**Quarkslab 明确说**：iqvw64e.sys 已被 Microsoft 检测并黑名单化，LnvMSRIO 是未被检测的替代品。

---

### BS_RCIO64.sys — Biostar

| 属性 | 值 |
|------|------|
| CVE | CVE-2021-44852 |
| 厂商 | Biostar |
| 功能 | IOCTL 0x226040 (读) / 0x226044 (写) 物理内存 |
| **特殊能力** | **低完整性级别即可打开**（不需要 admin！） |
| WDAC 黑名单 | ❌ 不在 |
| LOLDrivers | ❌ 不在 |
| SHA-256 | `D205286BFFDF09BC033C09E95C519C1C267B40C2EE8BAB703C6A2D86741CCD3E` |
| 来源 | NephoSec 研究 + GitHub CrackerCat/CVE-2021-44852 |

**极其危险**：连 admin 权限都不需要。任何用户级进程都能打开设备读写物理内存。

---

### pstrip64.sys — EnTech Taiwan (PowerStrip)

| 属性 | 值 |
|------|------|
| CVE | CVE-2026-29923 |
| CVSS | 7.8 (HIGH) |
| 厂商 | EnTech Taiwan（ASTRA64 同一家） |
| 功能 | 任意物理内存映射，非特权用户可访问 |
| WDAC 黑名单 | ❌ 不在（SentinelOne 建议手动添加） |
| LOLDrivers | 2026-06-25 加入（披露后 2.5 个月） |
| 披露日期 | 2026-04-09 |
| 来源 | SentinelOne + Packet Storm 218394 |

---

## Tier 2：有 CVE 但部分受限

### ThrottleStop.sys — TechPowerUp

| 属性 | 值 |
|------|------|
| CVE | CVE-2025-7771 |
| CVSS | 8.7 (HIGH) |
| 功能 | MmMapIoSpace 物理 R/W，EPROCESS 操作，PPL bypass |
| 签名 | TechPowerUp LLC (DigiCert EV) |
| LOLDrivers | ⚠️ 2025-05-29 已加入 |
| SHA-256 | `16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0` |
| 实战利用 | MedusaLocker 勒索软件（巴西）、Gentlemen 勒索（Trend Micro 报告） |

**最强大但已被追踪。** 如果不在意 LOLDrivers 检测，这是功能最全的。

---

## Tier 3：其他有趣发现

| 驱动 | CVE | 厂商 | 能力 | 备注 |
|------|-----|------|------|------|
| K7RKScan.sys | CVE-2025-52915 | K7 Computing | 内核读写 | 印度杀软 |
| GameDriverX64.sys | CVE-2025-61155 | Fedeen Games | 物理内存 | Tower of Fantasy 反作弊 |
| STProcessMonitor.sys | CVE-2025-70795 | Safetica | 进程操作 | DLP 软件 |
| xhunter1.sys | CVE-2026-3609 | Wellbia (韩国) | 内核 R/W | XIGNCODE3 |
| 鲁大师监控驱动 | CVE-2025-67246 | Ludashi | MmMapIoSpace | 中国硬件监控 |

---

## 学术发现

**论文**: "The Windows IOCTL Census" (arXiv 2606.07732, 2026年6月)

分析了 Windows Update Catalog 中 **27,087 个签名驱动**：
- LOLDrivers 只覆盖了其中 **4 个**
- Microsoft WDAC 黑名单覆盖 **7 个**
- 发现 **330 个危险 IOCTL handler** 跨 **228 个驱动**（宽松 DACL + 未验证输入）
- **结论：公开黑名单覆盖率 < 0.05%**

---

## 获取建议

### 最容易获取
1. **LnvMSRIO.sys** — 任何 Lenovo 机器自带，或从 Lenovo 支持网站下载驱动包
2. **BS_RCIO64.sys** — Biostar 主板工具（Racing GT / Vivid LED DJ）
3. **ThrottleStop.sys** — TechPowerUp 官网免费下载

### 需要特定硬件
4. **pstrip64.sys** — PowerStrip 显卡超频工具（EnTech Taiwan 官网）
5. **鲁大师驱动** — 鲁大师安装包自带

---

## 与现有武器库对比

| 驱动 | 访问控制 | 范围限制 | 黑名单 | 获取难度 | 综合评分 |
|------|---------|---------|--------|---------|---------|
| **SIVX64** (现有) | SeLoadDriverPrivilege | 无 | ❌ | 已有 | ⭐⭐⭐⭐ |
| **ArgusMonitor** (现有) | 无 | 无 | ❌ | 已有 | ⭐⭐⭐⭐ |
| **ASTRA64** (现有) | 无 | 无 | ❌ | 已有 | ⭐⭐⭐⭐ |
| **LnvMSRIO** (新) | ? | 无 | ❌ | 需下载 | ⭐⭐⭐⭐⭐ |
| **BS_RCIO64** (新) | **无需 admin** | 无 | ❌ | 需下载 | ⭐⭐⭐⭐⭐ |
| **ThrottleStop** (新) | 无 | 无 | ⚠️ LOLDrivers | 易下载 | ⭐⭐⭐ |

---

## 来源

- [Quarkslab: Exploiting Lenovo Driver CVE-2025-8061](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html)
- [NVD CVE-2025-8061](https://nvd.nist.gov/)
- [GitHub: spawn451/CVE-2025-8061-Exploit](https://github.com/spawn451/CVE-2025-8061-Exploit)
- [GitHub: xM0kht4r/CVE-2025-7771](https://github.com/xM0kht4r/CVE-2025-7771)
- [SentinelOne: CVE-2026-29923](https://www.sentinelone.com/vulnerability-database/cve-2026-29923/)
- [NephoSec: Biostar Exploit](https://nephosec.com/biostar-exploit/)
- [arXiv 2606.07732: The Windows IOCTL Census](https://arxiv.org/html/2606.07732)
- [Kaspersky Securelist: MedusaLocker BYOVD Campaign (August 2025)](https://securelist.com/)
- [GitHub: BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD)
