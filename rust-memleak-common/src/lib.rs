#![no_std]

pub const ALLOCS_MAX_ENTRIES: u32 = 1000000;
pub const COMBINED_ALLOCS_MAX_ENTRIES: u32 = 10240;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AllocInfo {
    pub size: u64,
    pub timestamp_ns: u64,
    pub stack_id: i64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AllocInfo {}

impl AllocInfo {
    pub fn new(size: u64, timestamp_ns: u64, stack_id: i64) -> Self {
        Self {
            size,
            timestamp_ns,
            stack_id,
        }
    }
}
