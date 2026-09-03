#![no_main]
#![no_std]

#[cfg(not(daa_tpm_sha2))]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use risc0_zkvm::guest::env;
#[cfg(sphincs_opt5_padding)]
use risc0_zkvm_platform::syscall::sys_sha_buffer;

#[cfg(all(not(daa_tpm_sha2), lambda_128))]
use aes::Aes128;
#[cfg(all(not(daa_tpm_sha2), lambda_192))]
use aes::Aes192;
#[cfg(all(not(daa_tpm_sha2), lambda_256))]
use aes::Aes256;

#[cfg(daa_tpm_sha2)]
mod daa_sha_hook;
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

extern "C" {
    fn crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;

    #[cfg(sphincs_profile)]
    fn spx_profile_snapshot(out: *mut u64);
}

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

#[cfg(sphincs_opt5_padding)]
const OPT5_PAD_BLOCKS: usize = parse_usize(env!("SPHINCS_OPT5_PAD_BLOCKS"));

#[cfg(sphincs_profile)]
const PROFILE_WORDS: usize = 16;

// AES mode retains its historical wire format.  SHA mode uses full SHA-2
// digests for et/hk and keeps the issuer nonce at the security-parameter size.
#[cfg(all(not(daa_tpm_sha2), lambda_128))]
const ET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(lambda_192, lambda_256)))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const ET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const ET_BYTES: usize = 64;

#[cfg(all(not(daa_tpm_sha2), lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(lambda_192, lambda_256)))]
const NONCE_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const NONCE_BYTES: usize = 24;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const NONCE_BYTES: usize = 32;

#[cfg(lambda_128)]
const S_BYTES: usize = 16;
#[cfg(lambda_192)]
const S_BYTES: usize = 24;
#[cfg(lambda_256)]
const S_BYTES: usize = 32;

const HK_BYTES: usize = ET_BYTES;

#[cfg(all(not(daa_tpm_sha2), lambda_128))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; HK_BYTES];
    out.copy_from_slice(&block);
    out
}

// lambda = 192: AES-192, s=24B, et_u=32B → hk = AES_s(et_u[0..15]) || AES_s(et_u[16..31])
#[cfg(all(not(daa_tpm_sha2), lambda_192))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
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

// lambda = 256: AES-256, s=32B, et_u=32B → hk = AES_s(et_u[0..15]) || AES_s(et_u[16..31])
#[cfg(all(not(daa_tpm_sha2), lambda_256))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
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

#[cfg(all(daa_tpm_sha2, lambda_128))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha256_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, lambda_192))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha384_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, lambda_256))]
fn hook(s: &[u8; S_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha512_hook(s, et_u)
}

#[cfg(sphincs_opt5_padding)]
fn opt5_bin_forcing_padding() {
    const DIGEST_WORDS: usize = 8;
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut out = [0u32; DIGEST_WORDS];
    let mut block = [0u8; 64];
    let mut i = 0usize;
    while i < OPT5_PAD_BLOCKS {
        block[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        unsafe { sys_sha_buffer(&mut out, &state, block.as_ptr(), 1) };
        state = out;
        i += 1;
    }
    core::hint::black_box(state);
}

fn main() {
    let mut pk = [0u8; PK_BYTES];
    let mut sig = [0u8; SIG_BYTES];
    let mut hk_pub = [0u8; HK_BYTES];
    let mut s = [0u8; S_BYTES];
    let mut et_u = [0u8; ET_BYTES];
    let mut issuer_nonce = [0u8; NONCE_BYTES];

    env::read_slice(&mut pk);
    env::read_slice(&mut sig);
    env::read_slice(&mut hk_pub);
    env::read_slice(&mut s);
    env::read_slice(&mut et_u);
    env::read_slice(&mut issuer_nonce);

    let mut msg = [0u8; ET_BYTES + NONCE_BYTES];
    msg[..ET_BYTES].copy_from_slice(&et_u);
    msg[ET_BYTES..].copy_from_slice(&issuer_nonce);

    // 1) Verify SPHINCS+ signature over the reconstructed secret message
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

    // 2) Recompute and check the selected TPM hook.  The legacy skip switch is
    // deliberately AES-only; a SHA-mode receipt always proves the SHA hook.
    #[cfg(any(daa_tpm_sha2, not(skip_aes_check)))]
    {
        let hk_calc = hook(&s, &et_u);
        assert!(hk_calc == hk_pub);
    }

    #[cfg(sphincs_opt5_padding)]
    opt5_bin_forcing_padding();

    #[cfg(not(sphincs_profile))]
    {
        let mut journal = [0u8; 4 + HK_BYTES + PK_BYTES];
        journal[..4].copy_from_slice(&1u32.to_le_bytes());
        journal[4..4 + HK_BYTES].copy_from_slice(&hk_pub);
        journal[4 + HK_BYTES..].copy_from_slice(&pk);
        env::commit_slice(&journal);
    }

    #[cfg(sphincs_profile)]
    {
        let mut counters = [0u64; PROFILE_WORDS];
        unsafe { spx_profile_snapshot(counters.as_mut_ptr()) };

        let mut journal = [0u8; 4 + HK_BYTES + PK_BYTES + PROFILE_WORDS * 8];
        journal[..4].copy_from_slice(&1u32.to_le_bytes());
        journal[4..4 + HK_BYTES].copy_from_slice(&hk_pub);
        journal[4 + HK_BYTES..4 + HK_BYTES + PK_BYTES].copy_from_slice(&pk);
        let mut off = 4 + HK_BYTES + PK_BYTES;
        let mut i = 0;
        while i < PROFILE_WORDS {
            journal[off..off + 8].copy_from_slice(&counters[i].to_le_bytes());
            off += 8;
            i += 1;
        }
        env::commit_slice(&journal);
    }
}
