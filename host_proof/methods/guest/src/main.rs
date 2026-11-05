#![no_main]
#![no_std]
#[path = "../../../protocol_context.rs"]
mod protocol_context;

#[cfg(not(any(daa_tpm_sha2, daa_tpm_rijndael)))]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use risc0_zkvm::guest::env;

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_128))]
use aes::Aes128;
#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_192))]
use aes::Aes192;
#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_256))]
use aes::Aes256;

#[cfg(daa_tpm_sha2)]
mod daa_sha_hook;
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

extern "C" {

    // Implements crypto sign verify.
    fn crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;

}

// Parses usize.
const fn parse_usize(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut out = 0usize;
    while i < bytes.len() {
        out = out * 10 + (bytes[i] - b'0') as usize;
        i += 1;
    }
    out
}

const PK_BYTES: usize = parse_usize(env!("SPHINCS_PK_BYTES"));
const SIG_BYTES: usize = parse_usize(env!("SPHINCS_SIG_BYTES"));

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_128))]
const ET_BYTES: usize = 16;
#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), any(lambda_192, lambda_256)))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const ET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const ET_BYTES: usize = 64;

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), any(lambda_192, lambda_256)))]
const NONCE_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const NONCE_BYTES: usize = 24;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const NONCE_BYTES: usize = 32;

#[cfg(all(not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)), lambda_128))]
const HOOK_SECRET_BYTES: usize = 16;
#[cfg(all(not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)), lambda_192))]
const HOOK_SECRET_BYTES: usize = 24;
#[cfg(all(not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)), lambda_256))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, lambda_128))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, lambda_192))]
const HOOK_SECRET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha_chen23, lambda_256))]
const HOOK_SECRET_BYTES: usize = 64;

const HK_BYTES: usize = ET_BYTES;
#[cfg(not(daa_tpm_sha_chen23))]
const HOOK_PUBLIC_BYTES: usize = HK_BYTES;
#[cfg(daa_tpm_sha_chen23)]
const HOOK_PUBLIC_BYTES: usize = 2 * HK_BYTES;

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_128))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);

    for (byte, input) in block.iter_mut().zip(et_u.iter()) {
        *byte ^= input;
    }
    let mut out = [0u8; HK_BYTES];
    out.copy_from_slice(&block);
    out
}

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_192))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes192::new(GenericArray::from_slice(s));
    let mut hk = [0u8; HK_BYTES];
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk[off..off + 16].copy_from_slice(&block);
    }
    hk
}

#[cfg(all(not(any(daa_tpm_sha2, daa_tpm_rijndael)), lambda_256))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes256::new(GenericArray::from_slice(s));
    let mut hk = [0u8; HK_BYTES];
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk[off..off + 16].copy_from_slice(&block);
    }
    hk
}

#[cfg(all(
    daa_tpm_sha2,
    not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)),
    lambda_128
))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha256_hook(s, et_u)
}

#[cfg(all(
    daa_tpm_sha2,
    not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)),
    lambda_192
))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha384_hook(s, et_u)
}

#[cfg(all(
    daa_tpm_sha2,
    not(any(daa_tpm_sha_chen23, daa_tpm_rijndael)),
    lambda_256
))]

// Implements hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha512_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, lambda_128))]

// Implements cdenw23 hooks.
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha256_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, lambda_192))]

// Implements cdenw23 hooks.
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha384_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, lambda_256))]

// Implements cdenw23 hooks.
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha512_cdenw23_hooks(sst, et_u)
}

// Implements main.
fn main() {
    let mut pk = [0u8; PK_BYTES];
    let mut sig = [0u8; SIG_BYTES];
    let mut hk_pub = [0u8; HK_BYTES];
    #[cfg(daa_tpm_sha_chen23)]
    let mut cet_pub = [0u8; HK_BYTES];
    let mut hook_secret = [0u8; HOOK_SECRET_BYTES];
    let mut et_u = [0u8; ET_BYTES];
    let mut issuer_nonce = [0u8; NONCE_BYTES];
    let mut context = [0u8; protocol_context::BYTES];

    env::read_slice(&mut pk);
    env::read_slice(&mut sig);
    env::read_slice(&mut hk_pub);
    #[cfg(daa_tpm_sha_chen23)]
    env::read_slice(&mut cet_pub);
    env::read_slice(&mut hook_secret);
    env::read_slice(&mut et_u);
    env::read_slice(&mut issuer_nonce);
    env::read_slice(&mut context);

    let mut msg = [0u8; ET_BYTES + NONCE_BYTES];
    msg[..ET_BYTES].copy_from_slice(&et_u);
    msg[ET_BYTES..].copy_from_slice(&issuer_nonce);

    let ret = unsafe {
        crypto_sign_verify(
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
            pk.as_ptr(),
        )
    };
    assert!(ret == 0);

    #[cfg(not(daa_tpm_sha_chen23))]
    {
        let hk_calc = hook(&hook_secret, &et_u);
        assert!(hk_calc == hk_pub);
    }

    #[cfg(daa_tpm_sha_chen23)]
    {
        let (hk_calc, cet_calc) = cdenw23_hooks(&hook_secret, &et_u);
        assert!(hk_calc == hk_pub);
        assert!(cet_calc == cet_pub);
    }

    {
        let mut journal = [0u8; 4 + HOOK_PUBLIC_BYTES + PK_BYTES + protocol_context::BYTES];
        journal[..4].copy_from_slice(&1u32.to_le_bytes());
        journal[4..4 + HK_BYTES].copy_from_slice(&hk_pub);
        #[allow(unused_mut)]
        let mut public_end = 4 + HK_BYTES;
        #[cfg(daa_tpm_sha_chen23)]
        {
            journal[public_end..public_end + HK_BYTES].copy_from_slice(&cet_pub);
            public_end += HK_BYTES;
        }
        journal[public_end..public_end + PK_BYTES].copy_from_slice(&pk);
        journal[public_end + PK_BYTES..].copy_from_slice(&context);
        env::commit_slice(&journal);
    }
}

#[cfg(daa_tpm_rijndael)]
#[path = "../../../rijndael.rs"]
mod rijndael;
#[cfg(daa_tpm_rijndael)]
const ET_BYTES: usize = 32;
#[cfg(daa_tpm_rijndael)]
const NONCE_BYTES: usize = 16;
#[cfg(daa_tpm_rijndael)]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(daa_tpm_rijndael)]
// Evaluates the Rijndael-256 credential hook.
fn hook(s: &[u8; HOOK_SECRET_BYTES], et: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    rijndael::eval(s, et)
}
