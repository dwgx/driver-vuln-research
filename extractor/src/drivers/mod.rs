pub mod lnvmsrio;
pub mod service;

use std::io;

/// Trait for physical memory access drivers
pub trait PhysicalMemoryDriver {
    fn read_physical(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>>;
    fn write_physical(&self, phys_addr: u64, data: &[u8]) -> io::Result<()>;
    fn read_physical_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let data = self.read_physical(phys_addr, 8)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }
    fn read_physical_u32(&self, phys_addr: u64) -> io::Result<u32> {
        let data = self.read_physical(phys_addr, 4)?;
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }
}
