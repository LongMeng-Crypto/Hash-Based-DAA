#![allow(non_snake_case)]

use risc0_zkvm_platform::syscall::sys_sha_buffer;

const DIGEST_WORDS: usize = 8;

/// Force the symbol to be kept even if Rust side doesn't reference it directly.
#[used]
#[no_mangle]
pub static RISC0_SHA_BUFFER_KEEP: unsafe extern "C" fn(*mut u32, *const u32, *const u8, u32) =
    risc0_sys_sha_buffer;

/// C ABI wrapper for RISC0 SHA syscall.
/// out_state / in_state: pointers to 8 u32 words (SHA-256 state words)
/// buf: pointer to blocks (each 64 bytes)
/// count: number of 64-byte blocks
#[no_mangle]
pub unsafe extern "C" fn risc0_sys_sha_buffer(
    out_state: *mut u32,
    in_state: *const u32,
    buf: *const u8,
    count: u32,
) {
    sys_sha_buffer(
        &mut *(out_state as *mut [u32; DIGEST_WORDS]),
        &*(in_state as *const [u32; DIGEST_WORDS]),
        buf,
        count,
    );
}