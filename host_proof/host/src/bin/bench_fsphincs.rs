use std::time::Instant;

extern "C" {
    fn fsphincs_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn fsphincs_sign_signature(sig: *mut u8, siglen: *mut usize,
        msg: *const u8, msglen: usize, sk: *const u8) -> i32;
    fn fsphincs_verify(sig: *const u8, siglen: usize,
        msg: *const u8, msglen: usize, pk: *const u8) -> i32;
    fn fsphincs_pk_bytes() -> usize;
    fn fsphincs_sk_bytes() -> usize;
    fn fsphincs_sig_bytes() -> usize;
}

#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::sync::{Mutex, OnceLock};
    static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([0x46; 32])))
        .lock().unwrap();
    rng.fill_bytes(std::slice::from_raw_parts_mut(out, outlen));
}

fn main() {
    let iterations: usize = std::env::var("FSPHINCS_BENCH_ITERS")
        .ok().and_then(|x| x.parse().ok()).unwrap_or(1);
    let (pk_len, sk_len, sig_len) = unsafe {
        (fsphincs_pk_bytes(), fsphincs_sk_bytes(), fsphincs_sig_bytes())
    };
    let msg = b"F-SPHINCS+ DAA issuer credential benchmark";
    println!("F-SPHINCS+-SHA256 parameters: n=256 d=16 k=35 q=1024 h=6");
    println!("sizes: pk={pk_len} B sk={sk_len} B sig={sig_len} B");

    for run in 1..=iterations {
        let mut pk = vec![0; pk_len];
        let mut sk = vec![0; sk_len];
        let t = Instant::now();
        assert_eq!(unsafe { fsphincs_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) }, 0);
        let keygen = t.elapsed();

        let mut sig = vec![0; sig_len];
        let mut actual = 0usize;
        let t = Instant::now();
        assert_eq!(unsafe {
            fsphincs_sign_signature(sig.as_mut_ptr(), &mut actual, msg.as_ptr(),
                                    msg.len(), sk.as_ptr())
        }, 0);
        let sign = t.elapsed();
        assert_eq!(actual, sig_len);

        let t = Instant::now();
        assert_eq!(unsafe {
            fsphincs_verify(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(),
                            pk.as_ptr())
        }, 0);
        let verify = t.elapsed();

        let mut bad = sig.clone();
        bad[sig_len / 2] ^= 1;
        assert_ne!(unsafe {
            fsphincs_verify(bad.as_ptr(), bad.len(), msg.as_ptr(), msg.len(),
                            pk.as_ptr())
        }, 0, "mutated signature accepted");

        println!("run {run}: keygen={:.3}s sign={:.3}s verify={:.3}ms",
            keygen.as_secs_f64(), sign.as_secs_f64(),
            verify.as_secs_f64() * 1000.0);
    }
}
