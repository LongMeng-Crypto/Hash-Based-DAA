#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

extern "C" {
    fn sphincs_wots_extreme(mode: u32) -> u64;
}

#[cfg(lambda_128)]
const SPX_N: u32 = 16;
#[cfg(lambda_192)]
const SPX_N: u32 = 24;
#[cfg(lambda_256)]
const SPX_N: u32 = 32;

fn wots_len(n: u32) -> u32 {
    // All current SPHINCS+ parameter sets use w=16, log_w=4, and len2=3.
    2 * n + 3
}

fn spx_d() -> u32 {
    match env!("SPHINCS_PARAMS") {
        "sphincs-sha2-128s" => 7,
        "sphincs-sha2-128f" => 22,
        "sphincs-sha2-192s" => 7,
        "sphincs-sha2-192f" => 22,
        "sphincs-sha2-256s" => 8,
        "sphincs-sha2-256f" => 17,
        _ => 0,
    }
}

fn main() {
    let mode: u32 = env::read();
    assert!(mode == 0 || mode == 1);
    let thash1_calls = unsafe { sphincs_wots_extreme(mode) };

    let mut journal = [0u8; 4 + 4 + 4 + 4 + 8];
    journal[0..4].copy_from_slice(&mode.to_le_bytes());
    journal[4..8].copy_from_slice(&SPX_N.to_le_bytes());
    journal[8..12].copy_from_slice(&spx_d().to_le_bytes());
    journal[12..16].copy_from_slice(&wots_len(SPX_N).to_le_bytes());
    journal[16..24].copy_from_slice(&thash1_calls.to_le_bytes());
    env::commit_slice(&journal);
}
