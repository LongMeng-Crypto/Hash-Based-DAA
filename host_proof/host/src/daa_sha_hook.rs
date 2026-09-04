#![allow(dead_code)]

//! Native counterparts of the SHA-2 relations checked by the RISC0 guest.

use sha2::{Digest, Sha256, Sha384, Sha512};

const OURS_HOOK_DOMAIN: u8 = 0x03;
const CDENW23_HK_DOMAIN: u8 = 0x05;
const CDENW23_CET_DOMAIN: u8 = 0x06;

fn finish<const N: usize>(digest: impl AsRef<[u8]>) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(digest.as_ref());
    out
}

pub fn sha256_hook(s: &[u8; 16], et: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([OURS_HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
}

pub fn sha384_hook(s: &[u8; 24], et: &[u8; 48]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update([OURS_HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
}

pub fn sha512_hook(s: &[u8; 32], et: &[u8; 64]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update([OURS_HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
}

pub fn sha256_cdenw23_hooks(sst: &[u8; 32], et: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hk_hasher = Sha256::new();
    hk_hasher.update([CDENW23_HK_DOMAIN]);
    hk_hasher.update(sst);
    let mut cet_hasher = Sha256::new();
    cet_hasher.update([CDENW23_CET_DOMAIN]);
    cet_hasher.update(sst);
    cet_hasher.update(et);
    (finish(hk_hasher.finalize()), finish(cet_hasher.finalize()))
}

pub fn sha384_cdenw23_hooks(sst: &[u8; 48], et: &[u8; 48]) -> ([u8; 48], [u8; 48]) {
    let mut hk_hasher = Sha384::new();
    hk_hasher.update([CDENW23_HK_DOMAIN]);
    hk_hasher.update(sst);
    let mut cet_hasher = Sha384::new();
    cet_hasher.update([CDENW23_CET_DOMAIN]);
    cet_hasher.update(sst);
    cet_hasher.update(et);
    (finish(hk_hasher.finalize()), finish(cet_hasher.finalize()))
}

pub fn sha512_cdenw23_hooks(sst: &[u8; 64], et: &[u8; 64]) -> ([u8; 64], [u8; 64]) {
    let mut hk_hasher = Sha512::new();
    hk_hasher.update([CDENW23_HK_DOMAIN]);
    hk_hasher.update(sst);
    let mut cet_hasher = Sha512::new();
    cet_hasher.update([CDENW23_CET_DOMAIN]);
    cet_hasher.update(sst);
    cet_hasher.update(et);
    (finish(hk_hasher.finalize()), finish(cet_hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_sizes_match_security_level() {
        assert_eq!(sha256_hook(&[7; 16], &[9; 32]).len(), 32);
        assert_eq!(sha384_hook(&[7; 24], &[9; 48]).len(), 48);
        assert_eq!(sha512_hook(&[7; 32], &[9; 64]).len(), 64);
    }

    #[test]
    fn domain_byte_is_bound() {
        let s = [7u8; 16];
        let et = [9u8; 32];
        let domain = [OURS_HOOK_DOMAIN];
        let expected = Sha256::digest([domain.as_slice(), s.as_slice(), et.as_slice()].concat());
        assert_eq!(sha256_hook(&s, &et).as_slice(), expected.as_slice());
    }

    #[test]
    fn cdenw23_hooks_bind_both_public_outputs() {
        let sst = [7u8; 32];
        let et = [9u8; 32];
        let (hk, cet) = sha256_cdenw23_hooks(&sst, &et);
        let hk_domain = [CDENW23_HK_DOMAIN];
        let cet_domain = [CDENW23_CET_DOMAIN];
        let expected_hk = Sha256::digest([hk_domain.as_slice(), sst.as_slice()].concat());
        let expected_cet =
            Sha256::digest([cet_domain.as_slice(), sst.as_slice(), et.as_slice()].concat());
        assert_eq!(hk.as_slice(), expected_hk.as_slice());
        assert_eq!(cet.as_slice(), expected_cet.as_slice());

        let mut changed_et = et;
        changed_et[0] ^= 1;
        let (same_hk, changed_cet) = sha256_cdenw23_hooks(&sst, &changed_et);
        assert_eq!(same_hk, hk);
        assert_ne!(changed_cet, cet);
    }
}
