# AsIO3 Driver Whitelist Bypass Research - Complete Analysis

## Executive Summary

The AsIO3 driver uses a **multi-layer access control** that goes beyond simple path matching. Path spoofing alone fails because the driver **hashes the calling executable's file content** and compares it against a hardcoded SHA-256 hash of `AsusCertService.exe`. Additionally, the AsusCertService process itself is protected with a restrictive process DACL that prevents even admin-level `OpenProcess` with injection rights.

**CRITICAL FINDING:** The SHA-256 hash stored in the on-disk driver (`CFE4CD...7A56`) does NOT match the current `AsusCertService.exe` (`67E315...AFFF`). This means either:
1. The LOADED driver has its hash updated at runtime (AsusCertService writes its hash via a registration IOCTL)
2. Or the device Security Descriptor alone is sufficient for AsusCertService (bypassing hash enrollment entirely)

**CONFIRMED:** SHA-256 is the algorithm (H0-H7 initial state constants found at RVA 0x71B0).

## Critical Findings

### 1. The Process Notify Callback is a RED HERRING

**RVA 0x3CD0** - The `PsSetCreateProcessNotifyRoutineEx` callback:
- When `CreateInfo != NULL` (process creation): **immediately returns** (`jne 0x3D07; ret`)
- When `CreateInfo == NULL` (process exit): scans QWORD array at `.data+0x3C0`, zeros matching PID

**The callback does NOT enroll PIDs on creation.** It only cleans up on exit.

### 2. Enrollment Happens Inside IRP_MJ_CREATE

The IRP_MJ_CREATE handler at RVA `0x2777` does:
```
0x27B7: call 0x3138        ; Enrollment attempt (returns bool in AL)
0x27BC: test al, al
0x27BE: jne 0x27D2         ; If enrolled -> call 0x2D88 (add PID, grant access)
0x27C0: call 0x340C        ; Else check if ALREADY whitelisted
0x27C5: mov esi, 0xC0000022  ; STATUS_ACCESS_DENIED
0x27CA: test eax, eax
0x27CC: cmovs r14d, esi    ; If 0x340C returns negative -> DENIED
```

Every `CreateFileW("\\.\Asusgio3")` triggers an enrollment attempt.

### 3. The Enrollment Function (RVA 0x3138) - FOUR Checks

```
Step 1: Resolve ZwQueryInformationProcess (cached at .data+0x9688)
Step 2: Query ProcessImageFileName (class 0x2B) for current process
Step 3: Call 0x3B00 - Path comparison against:
        "C:\Program Files (x86)\ASUS\AsusCertService" (RVA 0x7D20)
        Uses RtlCompareUnicodeString (case-insensitive prefix match)
Step 4: Call 0x130C - LOCAL DISK CHECK:
        Opens the exe file, queries FileFsDeviceInformation (class 5)
        Checks DeviceType field - if > 1, FAILS (network drives blocked)
Step 5: Call 0x4780 - FILE HASH:
        Reads up to 0xFF0000 bytes of the calling executable
        Computes hash and compares against 32 bytes at .data+0x150
Step 6: Call 0x7450 - Final 32-byte memcmp against stored hash
        If match -> returns TRUE (enrolled)
        If mismatch -> returns FALSE (denied)
```

### 4. The Hardcoded Hash

At `.data+0x150` (file offset `0x8350`):
```
CF E4 CD 52 49 D0 6B 17 13 9A 7D 30 EC AE B2 27
1F 4A 11 C4 4E 1E 3B 8B BB E5 55 D7 ED 01 7A 56
```
This is a **SHA-256 hash of AsusCertService.exe** (first 0xFF0000 = 16711680 bytes).

### 5. The PID Whitelist Check (RVA 0x340C)

```
0x340C: sub rsp, 0x28
0x3416: lea rcx, [rsp+0x30]
0x341B: call 0x197C              ; Get OUR PID via ProcessBasicInformation
0x3429: mov rdx, [rsp+0x30]     ; rdx = our PID
0x342E: lea rax, [.data+0x3C0]  ; Whitelist start (64 QWORDs)
0x343A: cmp [rax], rdx          ; Check each entry
0x343D: je SUCCESS
0x343F: add rax, 8              ; Next entry
0x344A: cmp rax, [.data+0x5C0]  ; End of array
0x344D: jl LOOP
        return 0xC0000001       ; NOT FOUND
SUCCESS: return 0               ; ALLOWED
```

### 6. AsusCertService Process Protection

- PID 3760, runs as Session 0 SERVICE
- Even as **Administrator**, `OpenProcess` with `PROCESS_ALL_ACCESS` returns **ERROR 5**
- Only `PROCESS_QUERY_LIMITED_INFORMATION` works
- This means it has a **restricted process DACL** (set by the service itself or SCM)
- **DLL injection, CreateRemoteThread, and handle duplication are all blocked**

### 7. No Open Device Handle Found

AsusCertService does not appear to keep a persistent handle to `\\.\Asusgio3`. It likely opens/uses/closes per-operation, meaning there's no handle to steal via DuplicateHandle.

## Why Path Spoofing Fails

1. You copy your exe to `C:\Program Files (x86)\ASUS\AsusCertService\`
2. You run it from there
3. Driver enrollment function fires on CreateFileW
4. Path check: **PASSES** (prefix match succeeds)
5. Local disk check: **PASSES** (C: is local)
6. **Hash check: FAILS** (your binary's hash != stored AsusCertService.exe hash)
7. Enrollment denied, PID not added to whitelist
8. PID check at 0x340C also fails (not in whitelist)
9. Return STATUS_ACCESS_DENIED

## Viable Bypass Methods (Ranked)

### Method A: Hash the Real AsusCertService.exe (MOST VIABLE)

The driver hashes at most 0xFF0000 bytes. If `AsusCertService.exe` is smaller than this:
1. Create a polyglot binary that is a valid PE AND starts with the same bytes as AsusCertService.exe
2. OR: Simply **rename AsusCertService.exe's copy**, since it IS the hash match
3. The key insight: AsusCertService.exe itself IS whitelisted. If we can make it do something useful...

**Best approach:**
```
1. Copy AsusCertService.exe to AsusCertService_orig.exe
2. Patch AsusCertService.exe to include our code (append a new section)
3. BUT: this changes the hash! So this won't work either.
```

**Actually the simplest approach:**
The real `AsusCertService.exe` at `C:\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe` is the file whose hash matches. When AsusCertService SERVICE starts, it calls CreateFileW on the device, the driver hashes its binary, finds a match, and enrolls its PID.

Since we CANNOT inject into it (protected DACL), we need another approach.

### Method B: Use AsusCertService's COM/WCF Interface (HIGH POTENTIAL)

AsusCertService likely exposes a **local IPC interface** (COM, WCF, named pipe, or TCP) that other ASUS apps use to request hardware operations. This is how ArmouryCrate and AURA control fans/LEDs.

**Research needed:**
- Check what named pipes AsusCertService creates
- Check what COM objects it registers
- Reverse the protocol

### Method C: Restart AsusCertService with Modified Binary (DESTRUCTIVE)

1. Stop the AsusCertService service: `sc stop AsusCertService`
2. Replace `AsusCertService.exe` with a modified version (same hash prefix? No - that breaks it)
3. Actually: Replace with OUR binary named `AsusCertService.exe`
4. Update the stored hash in driver memory... circular dependency

### Method D: Patch the Driver's Hash at Runtime (REQUIRES ANOTHER DRIVER)

If you have another kernel read/write primitive:
1. Find AsIO3.sys base in kernel
2. Locate `.data+0x150` (the hash)
3. Overwrite with the SHA-256 of YOUR executable
4. Now YOUR process will pass enrollment
5. This is the chicken-and-egg problem (need write primitive to get write primitive)

### Method E: Security Descriptor Modification (BEST PRACTICAL)

The device's Security Descriptor is the FIRST barrier. If you bypass it, you skip the enrollment check entirely (it only runs once to SET UP the whitelist; if the SD allows access, the IRP reaches the driver and the PID check at 0x340C determines access).

**Using SeSecurityPrivilege (Admin + SYSTEM):**
```python
# As SYSTEM (via psexec -s):
# Modify the device object's DACL to allow Everyone
```

But wait - modifying a device object's SD requires kernel access or `ZwSetSecurityObject` which needs a handle to the device... another circular dependency.

### Method F: Token/SID Manipulation (EXPERIMENTAL)

The Security Descriptor likely allows specific SIDs. If we can determine which SIDs are in the DACL and add them to our token...

### Method G: Use `sc.exe` to Start a Custom Service Under AsusCertService's Identity

```cmd
sc stop AsusCertService
copy our_service.exe "C:\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe"
sc start AsusCertService
```

**Problem:** The hash won't match our binary.

**Solution:** DON'T replace the binary. Instead:
1. Set the service `ImagePath` to our binary
2. But keep the real AsusCertService.exe on disk (the driver hashes from the IMAGE file path, not the service binary path!)

Wait - the driver uses `ZwQueryInformationProcess(ProcessImageFileName)` to get the path, then opens THAT file to hash. So the hash is of the actual running executable.

### Method H: NTFS Stream / Junction Trick (CREATIVE)

1. Create a junction: `C:\Program Files (x86)\ASUS\AsusCertService\evil.exe` -> `C:\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe`

**No, ProcessImageFileName resolves the actual path.**

### Method I: Hardlink Attack (MOST PROMISING)

```cmd
mklink /H "C:\Program Files (x86)\ASUS\AsusCertService\MyApp.exe" "C:\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe"
```

A hardlink creates a new filename pointing to THE SAME file data on disk. When you run `MyApp.exe`, `ProcessImageFileName` returns `...\MyApp.exe`, but the FILE CONTENT is identical to `AsusCertService.exe` because it's literally the same file!

**The driver hashes the file content.** A hardlink has identical content. **The hash WILL match!**

**BUT:** The path check might fail because the IMAGE path now says `MyApp.exe` not a path under `AsusCertService`.

Actually wait - reread the path check. It's a PREFIX match on the DIRECTORY:
```
"C:\Program Files (x86)\ASUS\AsusCertService"
```
It checks if the process image path STARTS WITH this string. The filename doesn't matter!

So:
1. Hardlink: `"C:\Program Files (x86)\ASUS\AsusCertService\saomola.exe"` -> AsusCertService.exe
2. Run the hardlink
3. Path check: image path = `C:\Program Files (x86)\ASUS\AsusCertService\saomola.exe`
4. Prefix match against `C:\Program Files (x86)\ASUS\AsusCertService`: **PASSES**
5. Hash: reads `saomola.exe` content = same as AsusCertService.exe: **PASSES**
6. Enrollment succeeds, PID whitelisted

**BUT PROBLEM:** The hardlinked exe IS AsusCertService.exe - it will run AsusCertService's code, not ours.

### Method J: AppInit_DLLs / Detours on AsusCertService (CANNOT INJECT)

We can't inject because the process DACL blocks us.

### Method K: THE REAL SOLUTION - Loader Exe That Loads Our DLL

Create a small loader that:
1. Gets placed at `C:\Program Files (x86)\ASUS\AsusCertService\Loader.exe`
2. First 0xFF0000 bytes match AsusCertService.exe (use a PE that embeds AsusCertService's content in a resource/overlay)
3. Actually executes our code

**This is impossible** because a valid PE header can't start with AsusCertService's header.

### Method L: THE ACTUAL SOLUTION - Duplicate AsusCertService Service Identity

Since AsusCertService.exe is what passes the hash, and it's a normal service executable:

1. **Read AsusCertService.exe's hash** by computing SHA-256 of first 0xFF0000 bytes
2. **Verify it matches** the driver's stored hash at .data+0x150
3. **Stop AsusCertService service temporarily**
4. **Start our own process** that opens the device (won't work - hash mismatch)

Actually, the cleanest solution is:

### METHOD M: Use AsusCertService.exe Itself As The Opener (WINNER)

Since AsusCertService.exe is the ONLY binary that passes the hash:

1. Write a small DLL (`payload.dll`) that:
   - In DllMain: opens `\\.\Asusgio3`, stores handle in shared memory
   - Creates a named pipe/shared memory for communication

2. Set `AppInit_DLLs` registry key to load `payload.dll` into AsusCertService.exe

3. Restart the AsusCertService service

4. When AsusCertService starts and loads our DLL, the DLL opens the device
   (enrollment passes because the exe hash matches)

5. Our main process communicates via the named pipe

**PROBLEM:** AppInit_DLLs is disabled in modern Windows for services.

### METHOD N: Service Binary Replacement with Content Preservation (TRUE WINNER)

1. AsusCertService.exe has content X (hash = stored hash)
2. The driver reads the file and hashes the first 0xFF0000 bytes
3. **What if we APPEND our code AFTER 0xFF0000 bytes?**
4. Create binary: [first 0xFF0000 bytes of AsusCertService.exe] + [our shellcode/PE]
5. Make it a valid PE that executes our code

**Feasibility:** If AsusCertService.exe is SMALLER than 0xFF0000 bytes (16.7MB), the driver hashes THE WHOLE FILE. Our appended data changes the hash.

If AsusCertService.exe is LARGER than 0xFF0000 bytes... unlikely for a service.

Let me check the actual file size.

## Recommended Next Steps

1. **Check AsusCertService.exe file size** - If > 16.7MB, appending works
2. **Investigate AsusCertService's IPC** - Named pipes, COM interfaces
3. **Check if stopping/restarting the service is possible** as a timing attack
4. **Consider modifying service registry** to change the ImagePath
5. **Use SeDebugPrivilege + SYSTEM token** to try opening the protected process

## Data Section Layout (Corrected)

```
.data+0x000 to +0x074 (29 DWORDs): MSR WHITELIST (allowed MSR addresses)
.data+0x130 to +0x150 (32 bytes):  Static range table entries
.data+0x150 to +0x170 (32 bytes):  SHA-256 HASH of AsusCertService.exe
.data+0x3C0 to +0x5C0 (64 QWORDs): PID WHITELIST (dynamic, runtime-populated)
.data+0x5D0 to +0x5E0 (16 bytes):  Dynamic range table pointers
```

## IRP_MJ_CREATE Complete Flow

```
I/O Manager checks Security Descriptor (DACL)
  -> If DENIED: never reaches driver, returns STATUS_ACCESS_DENIED
  -> If ALLOWED: IRP delivered to driver

Driver dispatch (RVA 0x1A00) routes to 0x2777:
  1. Initialize (resolve ZwQueryInformationProcess if needed)
  2. call 0x3138 (enrollment attempt):
     a. Get process image path
     b. Prefix-match against "C:\Program Files (x86)\ASUS\AsusCertService"
     c. Verify local disk (not network)
     d. Read file content, compute hash
     e. Compare against stored hash at .data+0x150
     f. If ALL pass: add PID to .data+0x3C0, return TRUE
     g. If ANY fail: return FALSE
  3. If enrolled (TRUE): call 0x2D88 (grant access), return SUCCESS
  4. If not enrolled: call 0x340C (PID whitelist scan)
     - Scan .data+0x3C0 for matching PID
     - If found: return 0 (success)
     - If not found: return 0xC0000001 (fail)
  5. If 0x340C fails: set STATUS_ACCESS_DENIED, complete IRP
```

## Hash Version Mismatch - CRITICAL BREAKTHROUGH

```
Stored hash (driver .data+0x150): CFE4CD5249D06B17139A7D30ECAEB2271F4A11C44E1E3B8BBBE555D7ED017A56
SHA-256 of CURRENT AsusCertService.exe (558104 bytes): 67E31590ABC2CC6443DA5679C33FE927E317C546FB0420D5B1500F7BAE50AFFF
SHA-256 of OLD v1.3.2 AsusCertService.exe (497560 bytes): CFE4CD5249D06B17139A7D30ECAEB2271F4A11C44E1E3B8BBBE555D7ED017A56

*** THE DRIVER HASH MATCHES THE OLD v1.3.2 BINARY! ***
Location: C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe
```

This means:
1. The driver was compiled/signed with v1.3.2 of AsusCertService
2. The service binary was updated AFTER driver signing
3. The old binary still exists on disk in the `1.3.2\` subdirectory
4. **ANY process whose file content hashes to the v1.3.2 hash will pass enrollment**

## THE BYPASS: Using the Old Binary

Since the old `AsusCertService.exe` at `C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe` passes the hash check, the exploit is:

### Option A: Run Old Binary Directly (simplest test)
```cmd
"C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe"
```
When this runs, the driver enrollment will fire (path prefix matches, hash matches). Its PID gets whitelisted. If it opens the device internally, we can try to grab the handle.

**Problem:** The path check matches `C:\Program Files (x86)\ASUS\AsusCertService` but the image path will be `...\AsusCertService\1.3.2\AsusCertService.exe`. Does the prefix match include subdirectories? YES - it's a PREFIX match on `C:\Program Files (x86)\ASUS\AsusCertService`, and `...\AsusCertService\1.3.2\...` starts with that prefix!

### Option B: Hardlink to Old Binary (most practical)
```cmd
mklink /H "C:\Program Files (x86)\ASUS\AsusCertService\opener.exe" "C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe"
```
A hardlink has identical file content (same SHA-256). When `opener.exe` runs:
- Path: `C:\Program Files (x86)\ASUS\AsusCertService\opener.exe` - prefix match PASSES
- Hash: identical to v1.3.2 - PASSES
- PID enrolled successfully

But it still runs AsusCertService code. To run OUR code with its hash, we need...

### Option C: Stop Service + Swap Binary (RECOMMENDED APPROACH)
```cmd
net stop AsusCertService
copy "C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe" "C:\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe" /Y
net start AsusCertService
```
Now the service runs the old v1.3.2 binary (which passes the driver hash check), opens the device, and exposes `\\.\pipe\asuscert`. The pipe is accessible from user mode!

### Option D: Named Pipe Protocol (BEST LONG-TERM)
The `\\.\pipe\asuscert` pipe is accessible without elevation. If we reverse-engineer the pipe protocol (by decompiling `AsusCertService.exe` 1.3.2 using IDA/Ghidra/dnSpy-mcp), we can:
1. Send device-open commands through the pipe
2. Send IOCTL-proxy commands (read physical memory, read ports, etc.)
3. All without needing to open the device ourselves

### Additional Finding: Named Pipe Already Accessible
```
\\.\pipe\asuscert -> OPENS SUCCESSFULLY with GENERIC_READ|GENERIC_WRITE
```
The current (running) AsusCertService already has this pipe open. We just need to speak its protocol.

## Concrete Next Steps (Priority Order)

### Step 1: Check AsusCertService IPC interface (NO kernel access needed)
```powershell
# Check named pipes
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match "asus|asio|cert" }

# Check TCP listeners
netstat -anob | Select-String "asus|cert|3760"

# Check COM registrations
reg query "HKLM\SOFTWARE\Classes\CLSID" /s /f "Asus" 2>$null | head -50
```

### Step 2: Read LOADED driver's hash from kernel memory
Use the WER dump method or any kernel read to read VA of loaded AsIO3 + 0x9150 (32 bytes). This tells us the REAL hash the loaded driver checks against.

### Step 3: Check device Security Descriptor
```python
# From SYSTEM context (psexec -s):
# Try opening with different SIDs to determine what the DACL allows
```

### Step 4: If hash is dynamically registered
Look for a special registration IOCTL that AsusCertService calls BEFORE the main device open. This IOCTL would write the exe's hash into .data+0x150. If we can call this IOCTL first with OUR hash, we win.

### Step 5: Fallback - Use SIVX64 driver to patch
If SIVX64 can be loaded (pre-EAC), use it to:
1. Find AsIO3.sys base in kernel (NtQuerySystemInformation + SystemModuleInformation)
2. Write our PID directly into .data+0x3C0 array
3. Open device normally (PID check at 0x340C will pass)
