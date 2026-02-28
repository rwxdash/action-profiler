#![no_std]
#![no_main]

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code
)]
mod vmlinux;

mod block_io;
mod oom;
mod process;
mod sched;

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, RingBuf},
};
use profiler_common::CONFIG_MAX;

#[map]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

#[map]
pub(crate) static OOM_EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024, 0);

#[map]
pub(crate) static CONFIG: Array<u64> = Array::with_max_entries(CONFIG_MAX, 0);

#[map]
pub(crate) static IGNORED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
