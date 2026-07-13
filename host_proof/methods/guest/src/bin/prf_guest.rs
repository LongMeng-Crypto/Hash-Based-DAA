#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

// Pull in the SHA-256 syscall hook so the C code gets hardware acceleration.
#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

// Thin C wrapper around prf_addr (see prf_wrapper.c).
// Computes: out = SHA-256(PK.seed||pad64 || ADRS^c(22B) || SK.seed)[0..n]
extern "C" {
    fn sphincs_prf_one(
        out:        *mut u8,
        pk_seed:    *const u8,
        sk_seed:    *const u8,
        adrs_bytes: *const u8,
    );
}

// SPX_N = hash output length for this security level (bytes)
#[cfg(lambda_128)] const SPX_N: usize = 16;
#[cfg(lambda_192)] const SPX_N: usize = 24;
#[cfg(lambda_256)] const SPX_N: usize = 32;

#[derive(Serialize, Deserialize)]
struct PrfOutputs {
    ok:   bool,
    sk_i: Vec<u8>,
}

fn main() {
    // Read order must match host write order exactly.
    //   pk_seed  : n bytes — public (PK.seed from SPHINCS+ keypair)
    //   adrs     : 32 bytes — public (FORS PRF address, type=FORSPRF)
    //   sk_i_pub : n bytes — public (expected PRF output, revealed in journal)
    //   sk_seed  : n bytes — PRIVATE witness (SK.seed, never committed)
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
