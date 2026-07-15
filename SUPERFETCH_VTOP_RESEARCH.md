# Superfetch VA→PA Deep Research Report
> 来源: deep-research workflow (100 agents, 969 tool calls, 2026-07-12)

## 核心发现

**Superfetch VA-to-PA translation** 是唯一不需要页表遍历、不会崩溃的方法。

### 原理

Windows 内核的 Superfetch 子系统维护了每个物理页（PFN）对应哪个虚拟地址的映射。通过 `NtQuerySystemInformation(SystemSuperfetchInformation)` 可以从用户态查询这个映射，完全不需要驱动参与。

### API 调用链

```
1. NtQuerySystemInformation(79, &superfetch_info, ...)
   - superfetch_info.InfoClass = 17 (SuperfetchMemoryRangesQuery)
   → 返回所有有效物理内存范围 [{BasePfn, PageCount}, ...]

2. NtQuerySystemInformation(79, &superfetch_info, ...)
   - superfetch_info.InfoClass = 6 (SuperfetchPfnQuery)
   - 输入: PFN 列表
   → 返回每个 PFN 对应的 VirtualAddress

3. 构建反向映射表: VirtualAddress → PhysicalAddress (PFN << 12)

4. 查询: translate(VA) → PA (O(1) 哈希查找)
```

### 关键数据结构

```c
// NtQuerySystemInformation class 79 的包装结构
struct SUPERFETCH_INFORMATION {
    ULONG Version;        // = 45
    ULONG Magic;          // = 0x4368756B ('kuhC')
    SUPERFETCH_INFO_CLASS InfoClass;  // 6 or 17
    // padding 4 bytes
    PVOID Data;           // → PF_PFN_PRIO_REQUEST or PF_MEMORY_RANGE_INFO
    ULONG Length;
    // padding 4 bytes
};

// PFN 查询请求/响应
struct PF_PFN_PRIO_REQUEST {
    ULONG Version;        // = 1
    ULONG RequestFlags;   // = 1
    ULONG PfnCount;
    MMPFN_IDENTITY PageData[];  // 24 bytes each
};

struct MMPFN_IDENTITY {
    UINT64 Flags;              // +0
    UINT64 PageFrameIndex;     // +8
    PVOID VirtualAddress;      // +16 (u2 union)
};

// 内存范围查询
struct PF_MEMORY_RANGE_INFO_V1 {
    ULONG Version;        // = 1
    ULONG RangeCount;
    struct { UINT64 BasePfn; UINT64 PageCount; } Ranges[];
};
```

### 权限要求

- `SE_PROF_SINGLE_PROCESS_PRIVILEGE` (privilege 13)
- `SE_DEBUG_PRIVILEGE` (privilege 20)
- 管理员权限即可

### 已有实现

| 语言 | 仓库 | 备注 |
|------|------|------|
| C++ | CVE-2025-7771/superfetch/superfetch.h | 完整实现，167 行 |
| Delphi | CVE-2025-8061-Exploit/SuperfetchVtop.pas | 10643 字节 |
| Rust (FFI) | CVE-2025-7771-ThrottleStop-rust/superfetch.rs | 调用 C++ 静态库 |
| C (lib) | github.com/jonomango/superfetch | 独立库 |

### 为什么安全

1. 地址翻译完全在用户态完成（NtQuerySystemInformation 是系统调用，内核处理）
2. 不调用 MmMapIoSpace
3. 不读任何物理地址
4. 返回的 PA 全部是 OS 确认的 RAM 页——不可能是 MMIO/PCI hole
5. 驱动只在最后一步被调用，且传入的地址已经过 Superfetch 确认

### 验证状态

- 3-0 投票通过（high confidence）
- 多个独立实现（spawn451, xM0kht4r, jonomango, Outflank）
- spawn451 的 PoC 明确是为 LnvMSRIO.sys 写的
- 测试于 Windows 11 24H2/25H2

---

## 其他研究发现

### 被否决的方法

| 方法 | 为什么不行 |
|------|-----------|
| NtQuerySystemInformation(SystemBigPoolInformation) | Win11 25H2 redact 地址（除非有 SeDebugPrivilege） |
| PFN 数据库直接读 | 需要知道 MmPfnDatabase 地址（需要页表遍历获取...） |
| 物理内存特征扫描 | 需要大量 IOCTL，有崩溃风险 |
| LSTAR MSR hijack | 需要 WRMSR + shellcode，Spectre/KVAS 缓解阻止 |

### LnvMSRIO 确认的危险

- Quarkslab 明确警告: MmMapIoSpace 无 NULL check、无 __try/__except
- reveng.ai 确认: MiShowBadMapper 路径导致 BSoD
- 结论: 永远不要给 LnvMSRIO 传未验证的物理地址

---

## 来源

- [Outflank: Mapping Virtual to Physical Addresses using Superfetch (2023-12)](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)
- [spawn451/CVE-2025-8061-Exploit](https://github.com/spawn451/CVE-2025-8061-Exploit)
- [xM0kht4r/CVE-2025-7771](https://github.com/xM0kht4r/CVE-2025-7771)
- [jonomango/superfetch](https://github.com/jonomango/superfetch)
- [Quarkslab: Exploiting Lenovo Driver Part 2](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html)
- [windows-internals.com: KASLR Leaks Restriction](https://windows-internals.com/kaslr-leaks-restriction/)
- [reveng.ai: PhysMem-E](https://reveng.ai/blog/physmem-e-when-kernel-drivers-peek-into-memory)
