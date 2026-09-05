#![no_main]

#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

extern "C" {
    fn sphincs_issuer_wots_certificate_bytes() -> usize;
    fn sphincs_issuer_wots_witness_bytes() -> usize;
    fn sphincs_issuer_wots_relation(
        cert: *const u8,
        len: usize,
        pk: *const u8,
        witness: *const u8,
        witness_len: usize,
    ) -> i32;
}

/// Proves the complete top WOTS key and commits only its public certificate and issuer key.
fn main() {
    let pk_len: usize = env!("SPHINCS_PK_BYTES").parse().unwrap();
    let cert_len = unsafe { sphincs_issuer_wots_certificate_bytes() };
    let witness_len = unsafe { sphincs_issuer_wots_witness_bytes() };
    assert!(cert_len > 0 && cert_len <= 336 && witness_len > 0 && witness_len <= 2144);
    let mut pk = [0u8; 64];
    let mut cert = [0u8; 336];
    let mut witness = [0u8; 2144];
    env::read_slice(&mut pk[..pk_len]);
    env::read_slice(&mut cert[..cert_len]);
    env::read_slice(&mut witness[..witness_len]);
    assert_eq!(
        unsafe {
            sphincs_issuer_wots_relation(
                cert.as_ptr(),
                cert_len,
                pk.as_ptr(),
                witness.as_ptr(),
                witness_len,
            )
        },
        0
    );
    // The public path is checked by pi_I's verifier against this exact public journal.
    env::commit_slice(b"DAA-PI-I-FIXED-WOTS-v1");
    env::commit_slice(&pk[..pk_len]);
    env::commit_slice(&cert[..cert_len]);
}
