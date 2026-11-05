#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

extern "C" {

    // Implements prf one.
    fn sphincs_prf_one(
        out:        *mut u8,
        pk_seed:    *const u8,
        sk_seed:    *const u8,
        adrs_bytes: *const u8,
    );
}

#[cfg(lambda_128)] const SPX_N: usize = 16;
#[cfg(lambda_192)] const SPX_N: usize = 24;
#[cfg(lambda_256)] const SPX_N: usize = 32;

#[derive(Serialize, Deserialize)]
struct PrfOutputs {
    ok:   bool,
    sk_i: Vec<u8>,
}

// Implements main.
fn main() {

    let pk_seed:  Vec<u8> = env::read();
    let adrs:     Vec<u8> = env::read();
    let sk_i_pub: Vec<u8> = env::read();
    let sk_seed:  Vec<u8> = env::read();

    let mut sk_i_calc = alloc::vec![0u8; SPX_N];
    unsafe {
        sphincs_prf_one(
            sk_i_calc.as_mut_ptr(),
            pk_seed.as_ptr(),
            sk_seed.as_ptr(),
            adrs.as_ptr(),
        );
    }

    assert!(sk_i_calc == sk_i_pub, "PRF output mismatch");
    env::commit(&PrfOutputs { ok: true, sk_i: sk_i_pub });
}
