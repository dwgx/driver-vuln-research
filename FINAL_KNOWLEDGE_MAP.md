# toolkit 驱动武器库 — 完整知识图谱

> 最终整理: 2026-07-11 | 7 驱动逆向 | 3 已验证 | 1 新王者

---

## 一、全局态势

```
目标: VRChat.exe 进程内存中的 AES-128 密钥
障碍: PPL (Protected Process Light) + EAC (Easy Anti-Cheat)
方法: 通过内核驱动读取物理内存绕过 PPL
状态: 武器库完备，等待实战验证
```

### 七驱动总览

| # | 驱动 | 厂商 | 门控 | 物理内存 | 地址限制 | 黑名单 | 实测 | 评级 |
|---|------|------|------|---------|---------|--------|------|------|
| 1 | **LnvMSRIO.sys** | Lenovo | 无 | R/W | 无 | ❌❌ | 未测 | ⭐⭐⭐⭐⭐ |
| 2 | **ThrottleStop.sys** | TechPowerUp | Admin SDDL | R/W + UserMap | 无 | ⚠️LOL | 未测 | ⭐⭐⭐⭐½ |
| 3 | **SIVX64.sys** | RH Software | SeLoadDriverPrivilege | R/W | 无 | ❌❌ | ✅ | ⭐⭐⭐⭐ |
| 4 | **ArgusMonitor.sys** | Argotronic | 无 | R | 无 | ❌❌ | ✅ | ⭐⭐⭐⭐ |
| 5 | **ASTRA64.sys** | EnTech Taiwan | 无 | R/W | 无 | ❌❌ | ✅ | ⭐⭐⭐⭐ |
| 6 | **BS_RCIO64.sys** | Biostar | 无 | R/W | ⚠️32bit | ❌❌ | 未测 | ⭐⭐⭐ |
| 7 | **AsIO3 (Asusgio3)** | ASUS | SHA256+PID+Firmware | MMIO only | ❌RAM拒绝 | - | ❌死路 | ☠️ |

---

## 二、新王者：LnvMSRIO.sys

### 为什么它是最优选

```
✅ 零访问控制 — IRP_MJ_CREATE 直接 STATUS_SUCCESS
✅ 无地址限制 — MmMapIoSpace 任何物理地址
✅ 无 MSR 限制 — RDMSR/WRMSR 任意寄存器
✅ 不在 WDAC 黑名单
✅ 不在 LOLDrivers
✅ KDU 已集成（Provider #45）
✅ 有 3 个独立 PoC (C++, Python, Rust)
✅ Quarkslab 背书（替代已被封的 iqvw64e.sys）
```

### IOCTL 快速参考

| 代码 | 功能 | 输入 | 输出 |
|------|------|------|------|
| 0x9C406104 | 物理内存读 | `{u64 addr, u32 size, u32 count}` 16B | raw bytes |
| 0x9C40A108 | 物理内存写 | `{u64 addr, u32 size, u32 count} + data` | status |
| 0x9C402084 | RDMSR | `{u32 index}` | `{u64 value}` |
| 0x9C402088 | WRMSR | `{u32 index, u64 value}` | status |
| 0x9C406144 | PCI Config 读 | `{u32 bus_dev_fn_off}` | `{u32 value}` |
| 0x9C40A148 | PCI Config 写 | `{u32 bus_dev_fn_off, u32 value}` | status |

**设备路径**: `\\.\WinMsrDev`

---

## 三、ThrottleStop 的杀手级能力：PPL Bypass

```c
// CVE-2025-7771 PoC 核心:
// 通过物理内存写入清除 PPL 标志

// 1. 找到 VRChat.exe EPROCESS 物理地址
// 2. 写入 0x00 到 EPROCESS + 0x87A (Protection field)
// 3. PPL 移除 → 可以直接 OpenProcess + ReadProcessMemory

// 这意味着: 不需要物理内存扫描AES key
// 可以直接用 usermode API 读 VRChat 内存！
```

**影响**: 如果用 ThrottleStop (或 LnvMSRIO 物理写入) 清除 VRChat 的 PPL，整个攻击链大幅简化：
- 不需要物理内存 AES key 扫描
- 不需要 CR3 发现 + 页表遍历
- 直接 `ReadProcessMemory` 像读普通进程一样

---

## 四、攻击路径对比

### 路径 A：物理内存扫描 AES Key（当前方案）

```
加载驱动 → 找 System CR3 → 定位 VRChat EPROCESS → 
获取 VRChat CR3 → 遍历页表 → 扫描堆页 → 提取 AES key
```
- 复杂度：高（需要 CR3 发现 + 页表遍历）
- IOCTL 调用：20-100 次
- 时间：2-10 秒

### 路径 B：PPL Bypass + ReadProcessMemory（新方案）

```
加载驱动 → 找 VRChat EPROCESS 物理地址 → 
写 0x00 到 Protection 字段 → ReadProcessMemory 直接读内存
```
- 复杂度：低（一次物理写入）
- IOCTL 调用：5-15 次
- 时间：<1 秒
- **额外好处**：PPL 清除后可以用标准调试 API

### 路径 C：WER Dump（已验证可用）

```
Kill EAC → VRChat crash → 扫描 dump 文件 → 提取 AES key
```
- 复杂度：最低（不需要驱动）
- 限制：仅 Unity 6 Beta + 破坏性操作

---

## 五、知识沉淀 — 逆向方法论

### 5.1 驱动逆向标准流程

```
1. PE 解析 (pefile)
   → sections, imports, .pdata 函数表, 字符串提取

2. 入口点分析 (capstone)  
   → DriverEntry → IoCreateDevice → MajorFunction 赋值

3. 访问控制定位
   → 找 IRP_MJ_CREATE handler
   → 搜索 SeSinglePrivilegeCheck / ObReferenceObjectByHandle xref
   → 检查 DACL 设置

4. IOCTL dispatch 逆向
   → 找 IRP_MJ_DEVICE_CONTROL
   → 提取所有 CMP 指令 → IOCTL code 表
   → 每个 handler 追踪输入/输出 buffer 使用

5. 物理内存机制识别
   → MmMapIoSpace → 单次 map+copy+unmap
   → ZwMapViewOfSection → \Device\PhysicalMemory 映射
   → MmMapLockedPagesSpecifyCache(UserMode) → 持久用户态映射

6. 安全评估
   → LOLDrivers / WDAC 黑名单检查
   → 签名有效期
   → 检测指纹 (设备名, 服务名, 内核对象)
```

### 5.2 关键教训

| 教训 | 来源 |
|------|------|
| `GetLastError()` 被后续调用覆盖 — 每次调用后立即保存 | AsIO3 双路径尝试 bug |
| Python ctypes handle 32/64 位截断导致误判 | SIVX64 PoC "成功"假象 |
| 暴力物理内存扫描（13万次IOCTL）会耗尽内核 PTE 导致死机 | CR3 扫描崩溃 |
| 驱动可能有多层防御（签名+PID+固件）不能只破一层 | AsIO3 三层防御 |
| `SeLoadDriverPrivilege` 在 admin token 中存在但默认禁用 | SIVX64 ACCESS_DENIED |
| 时间戳签名意味着证书过期后驱动仍可加载 | SIVX64 签名担忧 |
| g_goodRanges 来自 `MmGetPhysicalMemoryRangesEx2`（OS API），不可改 | AsIO3 死路确认 |
| Named pipe 协议可能只做 PID 注册不代理 IOCTL | AsIO3 管道研究 |
| IoCreateDevice 默认 DACL 只允许 admin，不是"无门控" | BS_RCIO64 32 位限制 |

### 5.3 工具链

| 工具 | 用途 |
|------|------|
| `pefile` | PE 结构解析、导入表、.pdata 函数边界 |
| `capstone 5.0.7` | x86_64 反汇编引擎 |
| `struct` | 二进制数据打包/解包 |
| `ctypes` | Windows FFI（DeviceIoControl, CreateFileW） |
| Python `subprocess` | sc create/start/stop/delete 驱动管理 |
| `hashlib` | SHA-256 验证 |
| PowerShell `Get-AuthenticodeSignature` | 证书链验证 |
| `driverquery /V /FO CSV` | 已加载驱动枚举 |

---

## 六、检测与反检测

### EAC 已知检测能力

| 向量 | 检测内容 | 我们的暴露 |
|------|---------|-----------|
| PiDDBCacheTable | 历史加载的驱动名 | 随机 service name 缓解 |
| MmUnloadedDrivers | 最近卸载驱动（64条轮转） | 快速卸载 |
| NtQuerySystemInformation | 当前加载驱动列表 | 加载时间 <2s 窗口 |
| 设备对象枚举 | `\Device\*` 命名空间 | 短暂存在 |
| 进程句柄表 | 打开的设备句柄 | 使用完立即关闭 |
| 哈希黑名单 | 驱动文件 SHA-256 | LnvMSRIO/ArgusMonitor 不在名单 |

### 最低风险操作顺序

```
1. 确认 EAC 未运行 (recon eac)
2. 加载驱动 (随机 service name)
3. 执行操作 (<5s)
4. 卸载驱动
5. 等待 5 分钟
6. 启动 VRChat (EAC 激活)
7. EAC 启动时扫描 → 看到 PiDDB 中有随机名驱动记录
   → 但名字不在黑名单中 → 大概率忽略
```

---

## 七、文件索引

### 报告目录 (C:\Users\researcher\OneDrive\Desktop\report\)

| 目录 | 内容 | 大小 |
|------|------|------|
| `/` | README + 全局报告 | ~60 KB |
| `SIVX64/` | 180函数完整逆向 + 安全CR3方法 | ~170 KB |
| `AsIO3/` | 完整攻击链研究（含死路记录） | ~120 KB |
| `ASTRA64/` | 逆向 + 实测 + Rust 后端 | ~80 KB |
| `ArgusMonitor/` | 逆向 + 实测 + Rust 后端 | ~60 KB |
| `LnvMSRIO/` | 新逆向 + Rust 后端 | ~48 KB |
| `BS_RCIO64/` | 新逆向 + Rust 后端 | ~35 KB |
| `ThrottleStop/` | 新逆向 + PPL bypass + Rust 后端 | ~34 KB |

### 驱动文件 (D:\Project\toolkit\drivers\)

```
drivers/
├── Vulnerable-Monitors/     ← 原始三个
│   ├── SIVX64.sys           (211 KB, verified working)
│   ├── ASTRA64.sys          (verified working)
│   ├── ArgusMonitor.sys     (verified working)
│   └── *_poc.py             (Python PoC)
└── New-Candidates/          ← 新下载三个
    ├── LnvMSRIO.sys         (50 KB, from GitHub)
    ├── BS_RCIO64.sys         (24 KB, hash verified)
    ├── ThrottleStop.sys      (50 KB, hash verified)
    ├── download_manifest.json
    └── poc/                  (Delphi, C++, C, Rust PoC)
```

### 代码文件 (D:\Project\toolkit\)

| 文件 | 用途 |
|------|------|
| `safe_cr3_finder.py` | 安全 CR3 发现（20 次 IOCTL，不崩溃） |
| `argusmonitor_client.py` | ArgusMonitor 物理内存读取库 |
| `astra64_client.py` | ASTRA64 物理内存读取库 |
| `siv_bruteforce.py` | SIVX64 设备打开测试 |
| `src/saomola-tui/src/eac_recon.rs` | EAC 被动分析模块 |
| `src/saomola-tui/src/driver_chain.rs` | 驱动 fallback 链（已有 AsIO3/ASMMAP/SIVX64） |

---

## 八、下一步行动清单

| 优先级 | 任务 | 依赖 | 风险 |
|--------|------|------|------|
| P0 | 手动跑 `safe_cr3_finder.py` 验证 CR3 发现 | SIVX64 已可用 | 低 |
| P0 | 测试 LnvMSRIO.sys 加载+打开+物理读取 | 文件已下载 | 低 |
| P1 | 集成 LnvMSRIO + ArgusMonitor 后端到 driver_chain.rs | Rust 代码已生成 | 无 |
| P1 | ThrottleStop PPL bypass 实测（移除 VRChat PPL） | 小号 | 中 |
| P2 | EAC 小号实测（72h 观察封号） | VRChat 小号 | 中 |
| P2 | 端到端上传验证（key→解密→patch→上传） | 以上全部 | 低 |
