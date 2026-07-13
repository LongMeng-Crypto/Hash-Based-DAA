// DAA Issuer Setup Phase (standalone, no zkVM)
//
// Models the one-time issuer key generation step from Chen et al. (PQCrypto 2023):
//   1. Generate SPHINCS+ master key pair: (mpk, msk) = KeyGen()
//   2. Self-certify: issuer signs mpk with msk  →  cert = Sign(msk, mpk)
//
// This runs entirely on the host CPU — no RISC0 proving involved.
// Run with:
//   SPHINCS_PARAMS=sphincs-sha2-128s SPHINCS_THASH=simple cargo run --bin issuer_setup --release

use std::time::Instant;

extern "C" {
    fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_sign(sm: *mut u8, smlen: *mut u64, m: *const u8, mlen: u64, sk: *const u8) -> i32;
    fn crypto_sign_open(
        m: *mut u8,
        mlen: *mut u64,
        sm: *const u8,
        smlen: u64,
        pk: *const u8,
    ) -> i32;
    fn sphincs_sig_bytes() -> usize;
    fn sphincs_pk_bytes() -> usize;
    fn sphincs_sk_bytes() -> usize;
}

// Required by the SPHINCS+ C reference implementation.
#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    use rand::RngCore;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::sync::{Mutex, OnceLock};

    static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([42u8; 32])))
        .lock()
        .unwrap();
    let slice = std::slice::from_raw_parts_mut(out, outlen);
    rng.fill_bytes(slice);
}

fn main() {
    let pk_bytes = unsafe { sphincs_pk_bytes() };
    let sk_bytes = unsafe { sphincs_sk_bytes() };
    let sig_bytes = unsafe { sphincs_sig_bytes() };

    println!(
        "DAA Issuer Setup — params={} thash={} backend={}",
        env!("SPHINCS_PARAMS"),
        env!("SPHINCS_THASH"),
        env!("SPHINCS_HASH_BACKEND"),
    );
    println!(
        "SPHINCS+ sizes: mpk={} B, msk={} B, sig={} B",
        pk_bytes, sk_bytes, sig_bytes
    );

    // ── 1) Master key generation ──────────────────────────────────────────────
    let mut mpk = vec![0u8; pk_bytes];
    let mut msk = vec![0u8; sk_bytes];

    let t_keygen = Instant::now();
    let r = unsafe { crypto_sign_keypair(mpk.as_mut_ptr(), msk.as_mut_ptr()) };
    let keygen_ms = t_keygen.elapsed().as_micros() as f64 / 1000.0;
    assert_eq!(r, 0, "KeyGen failed");

    // ── 2) Self-certify: Sign mpk with msk ───────────────────────────────────
    // cert = Sign(msk, mpk)  — issuer certifies its own public key
    let mut sm_buf = vec![0u8; sig_bytes + pk_bytes + 64];
    let mut smlen: u64 = 0;

    let t_sign = Instant::now();
    let r = unsafe {
        crypto_sign(
            sm_buf.as_mut_ptr(),
            &mut smlen as *mut u64,
            mpk.as_ptr(),
            pk_bytes as u64,
            msk.as_ptr(),
        )
    };
    let sign_ms = t_sign.elapsed().as_micros() as f64 / 1000.0;
    assert_eq!(r, 0, "Sign(msk, mpk) failed");
    sm_buf.truncate(smlen as usize);

    let cert_sig = &sm_buf[..sig_bytes];

    // ── 3) Verify the self-certificate (sanity check) ─────────────────────────
    let mut recovered = vec![0u8; pk_bytes + 64];
    let mut rlen: u64 = 0;
    let t_verify = Instant::now();
    let r = unsafe {
        crypto_sign_open(
            recovered.as_mut_ptr(),
            &mut rlen as *mut u64,
            sm_buf.as_ptr(),
            smlen,
            mpk.as_ptr(),
        )
    };
    let verify_ms = t_verify.elapsed().as_micros() as f64 / 1000.0;
    assert_eq!(r, 0, "Verify self-cert failed");
    assert_eq!(
        &recovered[..rlen as usize],
        mpk.as_slice(),
        "Recovered message != mpk"
    );

    // ── 4) Print results ──────────────────────────────────────────────────────
    println!("keygen = {:.2} ms", keygen_ms);
    println!("sign(msk, mpk) = {:.2} ms", sign_ms);
    println!("verify self-cert = {:.2} ms", verify_ms);
    println!("cert sig size = {} bytes", cert_sig.len());
    println!("issuer setup ok");
}
