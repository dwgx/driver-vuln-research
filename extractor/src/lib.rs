//! extractor — AES key extraction from protected processes
//!
//! Library re-exports for integration testing and external use.

pub mod drivers;
pub mod memory;
pub mod scan;

// Re-export key public types
pub use drivers::PhysicalMemoryDriver;
pub use memory::eprocess;
pub use memory::physical::SafePhysicalReader;
pub use scan::aes::{aes128_key_expand, is_valid_aes128_schedule};
pub use scan::pattern::{scan_page_for_aes_schedule, AesKeyResult};
