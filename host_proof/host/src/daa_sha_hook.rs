#![allow(dead_code)]

//! Native counterparts of the SHA-2 relations checked by the RISC0 guest.

use sha2::{Digest, Sha256, Sha384, Sha512};

const HOOK_DOMAIN: u8 = 0x03;

fn finish<const N: usize>(digest: impl AsRef<[u8]>) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(digest.as_ref());
    out
}

pub fn sha256_hook(s: &[u8; 16], et: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
}

pub fn sha384_hook(s: &[u8; 24], et: &[u8; 48]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update([HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
}

pub fn sha512_hook(s: &[u8; 32], et: &[u8; 64]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update([HOOK_DOMAIN]);
    hasher.update(s);
    hasher.update(et);
    finish(hasher.finalize())
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
        let expected = Sha256::digest([&[HOOK_DOMAIN], &s, &et].concat());
        assert_eq!(sha256_hook(&s, &et).as_slice(), expected.as_slice());
    }
}
