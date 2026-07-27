#![no_main]
#![no_std]

use risc0_zkvm::guest::env;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(not(fsphincs_256))]
use aes::Aes128;
#[cfg(fsphincs_256)]
use aes::Aes256;

#[path = "../sha_syscalls.rs"]
mod sha_syscalls;

risc0_zkvm::guest::entry!(main);

#[cfg(not(fsphincs_256))]
const K: usize = 35;
#[cfg(fsphincs_256)]
const K: usize = 70;
const N: usize = 32;
const D: usize = 16;
const H: usize = 6;
const Q: u64 = 1024;
const MFORS_MSG_BYTES: usize = K * D / 8;
const MFORS_SIG_BYTES: usize = K * (D + 1) * N;
const PK_BYTES: usize = N + MFORS_MSG_BYTES;
#[cfg(not(fsphincs_256))]
const ET_GR_BYTES: usize = 16;
#[cfg(fsphincs_256)]
const ET_GR_BYTES: usize = 32;
const S_BYTES: usize = ET_GR_BYTES;
const HK_BYTES: usize = ET_GR_BYTES;
const MSG_BYTES: usize = 2 * ET_GR_BYTES;

/* One M-FORS layer is streamed at a time. This is 19,040 B for k=35 and
 * 38,080 B for k=70, replacing the former 133/267 KiB whole-signature .bss. */
static mut LAYER_SIGNATURE: [u8; MFORS_SIG_BYTES] = [0; MFORS_SIG_BYTES];

extern "C" {
    fn fsphincs_verify_begin(
        value: *mut u8,
        leaf_index: *mut u64,
        randomizer: *const u8,
        msg: *const u8,
        msglen: usize,
    );
    fn fsphincs_verify_layer(
        value: *mut u8,
        layer_sig: *const u8,
        pub_seed: *const u8,
        layer: u32,
        node: u64,
    ) -> i32;
    fn fsphincs_verify_finish(
        value: *const u8,
        pk: *const u8,
    ) -> i32;
}

#[cfg(not(fsphincs_256))]
fn aes_hook(s: &[u8; S_BYTES], et_u: &[u8; ET_GR_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    let mut hk = [0u8; HK_BYTES];
    hk.copy_from_slice(&block);
    hk
}

#[cfg(fsphincs_256)]
fn aes_hook(s: &[u8; S_BYTES], et_u: &[u8; ET_GR_BYTES]) -> [u8; HK_BYTES] {
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

fn main() {
    let mut pk = [0u8; PK_BYTES];
    let mut hk_pub = [0u8; HK_BYTES];
    let mut s = [0u8; S_BYTES];
    let mut et_u = [0u8; ET_GR_BYTES];
    let mut issuer_nonce = [0u8; ET_GR_BYTES];
    let mut randomizer = [0u8; N];
    let mut value = [0u8; MFORS_MSG_BYTES];
    let mut node = 0u64;

    env::read_slice(&mut pk);
    env::read_slice(&mut hk_pub);
    env::read_slice(&mut s);
    env::read_slice(&mut et_u);
    env::read_slice(&mut issuer_nonce);
    env::read_slice(&mut randomizer);

    let mut message = [0u8; MSG_BYTES];
    message[..ET_GR_BYTES].copy_from_slice(&et_u);
    message[ET_GR_BYTES..].copy_from_slice(&issuer_nonce);

    unsafe {
        fsphincs_verify_begin(
            value.as_mut_ptr(),
            &mut node,
            randomizer.as_ptr(),
            message.as_ptr(),
            MSG_BYTES,
        );
    }

    let layer_ptr = core::ptr::addr_of_mut!(LAYER_SIGNATURE).cast::<u8>();
    for step in 0..=H {
        let layer_sig =
            unsafe { core::slice::from_raw_parts_mut(layer_ptr, MFORS_SIG_BYTES) };
        env::read_slice(layer_sig);
        let layer = (H - step) as u32;
        let result = unsafe {
            fsphincs_verify_layer(
                value.as_mut_ptr(),
                layer_ptr,
                pk.as_ptr(),
                layer,
                node,
            )
        };
        assert!(result == 0);
        if step != H {
            node /= Q;
        }
    }
    assert!(unsafe { fsphincs_verify_finish(value.as_ptr(), pk.as_ptr()) } == 0);

    let hk_calc = aes_hook(&s, &et_u);
    assert!(hk_calc == hk_pub);

    /* Match the existing SPHINCS+ DAA host statement exactly: verification
     * success, the public AES hook value, and issuer public key. */
    let mut journal = [0u8; 4 + HK_BYTES + PK_BYTES];
    journal[..4].copy_from_slice(&1u32.to_le_bytes());
    journal[4..4 + HK_BYTES].copy_from_slice(&hk_pub);
    journal[4 + HK_BYTES..].copy_from_slice(&pk);
    env::commit_slice(&journal);
}
