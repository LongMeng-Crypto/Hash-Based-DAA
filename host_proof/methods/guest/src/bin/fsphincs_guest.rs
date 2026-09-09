#![no_main]
#![no_std]

#[cfg(not(daa_tpm_sha2))]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
use aes::Aes128;
#[cfg(all(not(daa_tpm_sha2), fsphincs_192))]
use aes::Aes192;
#[cfg(all(not(daa_tpm_sha2), fsphincs_256))]
use aes::Aes256;
use risc0_zkvm::guest::env;

#[cfg(daa_tpm_sha2)]
#[path = "../daa_sha_hook.rs"]
mod daa_sha_hook;
#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

#[allow(dead_code)]
mod fs_params {
    include!(concat!(env!("OUT_DIR"), "/fsphincs_params.rs"));
}
const K: usize = fs_params::K;
const N: usize = 32;
const D: usize = fs_params::D;
const H: usize = 6;
const Q: u64 = 1024;
const MFORS_MSG_BYTES: usize = (K * D + 7) / 8;
const MFORS_SIG_BYTES: usize = K * (D + 1) * N;
const PK_BYTES: usize = N + MFORS_MSG_BYTES;
#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
const ET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(fsphincs_192, fsphincs_256)))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, not(any(fsphincs_192, fsphincs_256))))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, fsphincs_192))]
const ET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha2, fsphincs_256))]
const ET_BYTES: usize = 64;

#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
const NONCE_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(fsphincs_192, fsphincs_256)))]
const NONCE_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, not(any(fsphincs_192, fsphincs_256))))]
const NONCE_BYTES: usize = 16;
#[cfg(all(daa_tpm_sha2, fsphincs_192))]
const NONCE_BYTES: usize = 24;
#[cfg(all(daa_tpm_sha2, fsphincs_256))]
const NONCE_BYTES: usize = 32;
#[cfg(all(not(daa_tpm_sha_chen23), not(any(fsphincs_192, fsphincs_256))))]
const HOOK_SECRET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha_chen23), fsphincs_192))]
const HOOK_SECRET_BYTES: usize = 24;
#[cfg(all(not(daa_tpm_sha_chen23), fsphincs_256))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, not(any(fsphincs_192, fsphincs_256))))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, fsphincs_192))]
const HOOK_SECRET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha_chen23, fsphincs_256))]
const HOOK_SECRET_BYTES: usize = 64;
const HK_BYTES: usize = ET_BYTES;
#[cfg(not(daa_tpm_sha_chen23))]
const HOOK_PUBLIC_BYTES: usize = HK_BYTES;
#[cfg(daa_tpm_sha_chen23)]
const HOOK_PUBLIC_BYTES: usize = 2 * HK_BYTES;
const MSG_BYTES: usize = ET_BYTES + NONCE_BYTES;

/* Stream one M-FORS layer; never buffer the complete credential in the guest. */
static mut LAYER_SIGNATURE: [u8; MFORS_SIG_BYTES] = [0; MFORS_SIG_BYTES];

extern "C" {
    fn fsphincs_verify_begin(
        value: *mut u8,
        leaf_index: *mut u64,
        randomizer: *const u8,
        msg: *const u8,
        msglen: usize,
        pk: *const u8,
    );
    fn fsphincs_verify_layer(
        value: *mut u8,
        layer_sig: *const u8,
        pub_seed: *const u8,
        layer: u32,
        node: u64,
    ) -> i32;
    fn fsphincs_verify_finish(value: *const u8, pk: *const u8) -> i32;
}

#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    let mut hk = [0u8; HK_BYTES];
    hk.copy_from_slice(&block);
    hk
}

#[cfg(all(not(daa_tpm_sha2), fsphincs_192))]
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

#[cfg(all(not(daa_tpm_sha2), fsphincs_256))]
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
    not(daa_tpm_sha_chen23),
    not(any(fsphincs_192, fsphincs_256))
))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha256_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), fsphincs_192))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha384_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), fsphincs_256))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha512_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, not(any(fsphincs_192, fsphincs_256))))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha256_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, fsphincs_192))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha384_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, fsphincs_256))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha512_cdenw23_hooks(sst, et_u)
}

fn main() {
    let mut pk = [0u8; PK_BYTES];
    let mut hk_pub = [0u8; HK_BYTES];
    #[cfg(daa_tpm_sha_chen23)]
    let mut cet_pub = [0u8; HK_BYTES];
    let mut hook_secret = [0u8; HOOK_SECRET_BYTES];
    let mut et_u = [0u8; ET_BYTES];
    let mut issuer_nonce = [0u8; NONCE_BYTES];
    let mut randomizer = [0u8; N];
    let mut value = [0u8; MFORS_MSG_BYTES];
    let mut node = 0u64;

    env::read_slice(&mut pk);
    env::read_slice(&mut hk_pub);
    #[cfg(daa_tpm_sha_chen23)]
    env::read_slice(&mut cet_pub);
    env::read_slice(&mut hook_secret);
    env::read_slice(&mut et_u);
    env::read_slice(&mut issuer_nonce);
    env::read_slice(&mut randomizer);

    let mut message = [0u8; MSG_BYTES];
    message[..ET_BYTES].copy_from_slice(&et_u);
    message[ET_BYTES..].copy_from_slice(&issuer_nonce);

    unsafe {
        fsphincs_verify_begin(
            value.as_mut_ptr(),
            &mut node,
            randomizer.as_ptr(),
            message.as_ptr(),
            MSG_BYTES,
            pk.as_ptr(),
        );
    }

    let layer_ptr = core::ptr::addr_of_mut!(LAYER_SIGNATURE).cast::<u8>();
    for step in 0..=H {
        let layer_sig = unsafe { core::slice::from_raw_parts_mut(layer_ptr, MFORS_SIG_BYTES) };
        env::read_slice(layer_sig);
        let layer = (H - step) as u32;
        let result = unsafe {
            fsphincs_verify_layer(value.as_mut_ptr(), layer_ptr, pk.as_ptr(), layer, node)
        };
        assert!(result == 0);
        if step != H {
            node /= Q;
        }
    }
    assert!(unsafe { fsphincs_verify_finish(value.as_ptr(), pk.as_ptr()) } == 0);

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

    /* Match the SPHINCS+ DAA host statement: verification success, the
     * selected public hook value, and issuer public key. */
    let mut journal = [0u8; 4 + HOOK_PUBLIC_BYTES + PK_BYTES];
    journal[..4].copy_from_slice(&1u32.to_le_bytes());
    journal[4..4 + HK_BYTES].copy_from_slice(&hk_pub);
    #[allow(unused_mut)]
    let mut public_end = 4 + HK_BYTES;
    #[cfg(daa_tpm_sha_chen23)]
    {
        journal[public_end..public_end + HK_BYTES].copy_from_slice(&cet_pub);
        public_end += HK_BYTES;
    }
    journal[public_end..].copy_from_slice(&pk);
    env::commit_slice(&journal);
}
