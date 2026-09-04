#![allow(dead_code)]

//! SHA-2 host-hook relations for the RISC0 guest.
//!
//! The domain byte is part of the hashed preimage.  SHA-256 uses RISC0's
//! accelerated guest implementation; SHA-384/512 use the no_std RustCrypto
//! implementations because RISC0 v3 has no SHA-512-family syscall.

const OURS_HOOK_DOMAIN: u8 = 0x03;
const CDENW23_HK_DOMAIN: u8 = 0x05;
const CDENW23_CET_DOMAIN: u8 = 0x06;

pub fn sha256_hook(s: &[u8; 16], et: &[u8; 32]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256};

    // 49 bytes plus SHA-256 padding fit in one 64-byte compression block.
    let mut preimage = [0u8; 49];
    preimage[0] = OURS_HOOK_DOMAIN;
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
    hasher.update([OURS_HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    hasher.finalize().into()
}

pub fn sha512_hook(s: &[u8; 32], et: &[u8; 64]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut hasher = Sha512::new();
    hasher.update([OURS_HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    hasher.finalize().into()
}

pub fn sha256_cdenw23_hooks(sst: &[u8; 32], et: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use risc0_zkvm::sha::{Impl, Sha256};

    let mut hk_preimage = [0u8; 33];
    hk_preimage[0] = CDENW23_HK_DOMAIN;
    hk_preimage[1..].copy_from_slice(sst);
    let hk_digest = Impl::hash_bytes(&hk_preimage);

    let mut cet_preimage = [0u8; 65];
    cet_preimage[0] = CDENW23_CET_DOMAIN;
    cet_preimage[1..33].copy_from_slice(sst);
    cet_preimage[33..].copy_from_slice(et);
    let cet_digest = Impl::hash_bytes(&cet_preimage);

    let mut hk = [0u8; 32];
    hk.copy_from_slice(hk_digest.as_bytes());
    let mut cet = [0u8; 32];
    cet.copy_from_slice(cet_digest.as_bytes());
    (hk, cet)
}

pub fn sha384_cdenw23_hooks(sst: &[u8; 48], et: &[u8; 48]) -> ([u8; 48], [u8; 48]) {
    use sha2::{Digest, Sha384};

    let mut hk_hasher = Sha384::new();
    hk_hasher.update([CDENW23_HK_DOMAIN]);
    hk_hasher.update(sst);
    let mut cet_hasher = Sha384::new();
    cet_hasher.update([CDENW23_CET_DOMAIN]);
    cet_hasher.update(sst);
    cet_hasher.update(et);
    (hk_hasher.finalize().into(), cet_hasher.finalize().into())
}

pub fn sha512_cdenw23_hooks(sst: &[u8; 64], et: &[u8; 64]) -> ([u8; 64], [u8; 64]) {
    use sha2::{Digest, Sha512};

    let mut hk_hasher = Sha512::new();
    hk_hasher.update([CDENW23_HK_DOMAIN]);
    hk_hasher.update(sst);
    let mut cet_hasher = Sha512::new();
    cet_hasher.update([CDENW23_CET_DOMAIN]);
    cet_hasher.update(sst);
    cet_hasher.update(et);
    (hk_hasher.finalize().into(), cet_hasher.finalize().into())
}
