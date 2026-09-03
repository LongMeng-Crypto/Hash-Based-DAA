#![allow(dead_code)]

//! SHA-2 host-hook relations for the RISC0 guest.
//!
//! The domain byte is part of the hashed preimage.  SHA-256 uses RISC0's
//! accelerated guest implementation; SHA-384/512 use the no_std RustCrypto
//! implementations because RISC0 v3 has no SHA-512-family syscall.

const HOOK_DOMAIN: u8 = 0x03;

pub fn sha256_hook(s: &[u8; 16], et: &[u8; 32]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256};

    // 49 bytes plus SHA-256 padding fit in one 64-byte compression block.
    let mut preimage = [0u8; 49];
    preimage[0] = HOOK_DOMAIN;
    preimage[1..17].copy_from_slice(s);
    preimage[17..].copy_from_slice(et);
    let digest = Impl::hash_bytes(&preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

pub fn sha384_hook(s: &[u8; 24], et: &[u8; 48]) -> [u8; 48] {
    use sha2::{Digest, Sha384};

    let mut hasher = Sha384::new();
    hasher.update([HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    hasher.finalize().into()
}

pub fn sha512_hook(s: &[u8; 32], et: &[u8; 64]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut hasher = Sha512::new();
    hasher.update([HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    hasher.finalize().into()
}
