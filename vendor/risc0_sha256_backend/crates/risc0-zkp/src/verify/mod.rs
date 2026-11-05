// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cryptographic algorithms for verifying a ZK proof of compute

mod fri;
mod merkle;
mod read_iop;

use alloc::{vec, vec::Vec};
use core::{
    cell::{RefCell, RefMut},
    fmt,
    iter::zip,
    ops::DerefMut,
};

pub(crate) use merkle::MerkleTreeVerifier;
pub use read_iop::ReadIOP;
use risc0_core::field::{Elem, ExtElem, Field, RootsOfUnity};

use crate::{
    adapter::{
        CircuitCoreDef, ProtocolInfo, PROOF_SYSTEM_INFO, REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE,
        REGISTER_GROUP_DATA,
    },
    core::{digest::Digest, hash::HashSuite, log2_ceil},
    taps::TapSet,
    INV_RATE, MAX_CYCLES_PO2, QUERIES,
};

const VERIFY_TRACE_ENABLED: bool = false;

macro_rules! trace_if_enabled {
    ($($args:tt)*) => {
        if VERIFY_TRACE_ENABLED {
            #[cfg(not(target_os = "zkvm"))]
            tracing::debug!($($args)*);
        }
    }
}

#[derive(PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    ReceiptFormatError,
    ControlVerificationError {
        control_id: Digest,
    },
    ImageVerificationError,
    MerkleQueryOutOfRange {
        idx: usize,
        rows: usize,
    },
    InvalidProof,
    JournalDigestMismatch,
    ClaimDigestMismatch {
        expected: Digest,
        received: Digest,
    },
    UnexpectedExitCode,
    InvalidHashSuite,
    VerifierParametersMissing,
    VerifierParametersMismatch {
        expected: Digest,
        received: Digest,
    },
    ProofSystemInfoMismatch {
        expected: ProtocolInfo,
        received: ProtocolInfo,
    },
    CircuitInfoMismatch {
        expected: ProtocolInfo,
        received: ProtocolInfo,
    },
    UnresolvedAssumption {
        digest: Digest,
    },
}

impl fmt::Debug for VerificationError {

    // Implements fmt.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for VerificationError {

    // Implements fmt.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerificationError::ReceiptFormatError => write!(f, "invalid receipt format"),
            VerificationError::ControlVerificationError { control_id } => {
                write!(f, "control_id mismatch: {control_id}")
            }
            VerificationError::ImageVerificationError => write!(f, "image_id mismatch"),
            VerificationError::MerkleQueryOutOfRange { idx, rows } => write!(
                f,
                "requested Merkle validation on row {idx}, but only {rows} rows exist",
            ),
            VerificationError::InvalidProof => write!(f, "verification indicates proof is invalid"),
            VerificationError::JournalDigestMismatch => {
                write!(f, "journal digest mismatch detected")
            }
            VerificationError::ClaimDigestMismatch { expected, received } => {
                write!(f, "claim digest does not match the expected digest {received}; expected {expected}")
            }
            VerificationError::UnexpectedExitCode => write!(f, "unexpected exit_code"),
            VerificationError::InvalidHashSuite => write!(f, "invalid hash suite"),
            VerificationError::VerifierParametersMissing => {
                write!(f, "verifier parameters were not found in verifier context for the given receipt type")
            }
            VerificationError::VerifierParametersMismatch { expected, received } => {
                write!(f, "receipt was produced for a version of the verifier with parameters digest {received}; expected {expected}")
            }
            VerificationError::ProofSystemInfoMismatch { expected, received } => {
                write!(f, "receipt was produced for a version of the verifier with proof system info {received}; expected {expected}")
            }
            VerificationError::CircuitInfoMismatch { expected, received } => {
                write!(f, "receipt was produced for a version of the verifier with circuit info {received}; expected {expected}")
            }
            VerificationError::UnresolvedAssumption { digest } => {
                write!(f, "receipt contains an unresolved assumption: {digest}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}

trait VerifyParams<F: Field> {
    const CHECK_SIZE: usize = INV_RATE * F::ExtElem::EXT_SIZE;
}

#[stability::unstable]
pub struct Verifier<'a, F>
where
    F: Field,
{
    taps: &'a TapSet<'a>,
    suite: &'a HashSuite<F>,
    iop: RefCell<ReadIOP<'a, F>>,
    po2: usize,
    tot_cycles: usize,

    merkle_verifiers: Vec<Option<MerkleTreeVerifier<'a>>>,
}

impl<F: Field> VerifyParams<F> for Verifier<'_, F> {}

impl<'a, F: Field> Verifier<'a, F> {

    #[stability::unstable]

    // Creates the operation result.
    pub fn new(taps: &'a TapSet<'a>, suite: &'a HashSuite<F>, seal: &'a [u32]) -> Self {
        trace_if_enabled!("Starting verify");
        Self {
            taps,
            suite,
            po2: 0,
            tot_cycles: 0,
            iop: RefCell::new(ReadIOP::new(seal, suite.rng.as_ref())),
            merkle_verifiers: core::iter::repeat_with(|| None)
                .take(taps.num_groups())
                .collect(),
        }
    }

    #[stability::unstable]

    // Implements iop.
    pub fn iop(&self) -> RefMut<'_, ReadIOP<'a, F>> {
        self.iop.borrow_mut()
    }

    #[stability::unstable]

    // Implements commit circuit info.
    pub fn commit_circuit_info(&mut self, circuit_info: &ProtocolInfo) {
        trace_if_enabled!("Verifying protocol={PROOF_SYSTEM_INFO} circuit {circuit_info}");

        let hashfn = self.suite.hashfn.as_ref();
        self.iop()
            .commit(&hashfn.hash_elem_slice(&PROOF_SYSTEM_INFO.encode()));
        self.iop()
            .commit(&hashfn.hash_elem_slice(&circuit_info.encode()));
    }

    #[stability::unstable]

    // Verifies group.
    pub fn verify_group(&mut self, reg_group_id: usize) -> Result<&Digest, VerificationError> {

        if self.merkle_verifiers[reg_group_id].is_some() {
            tracing::debug!(
                "Reg group id {reg_group_id} ({}) may only occur once",
                self.taps.group_name(reg_group_id)
            );
            return Err(VerificationError::ReceiptFormatError);
        }
        let group_size = self.taps.group_size(reg_group_id);
        let domain = INV_RATE * self.tot_cycles;
        let hashfn = self.suite.hashfn.as_ref();

        let merkle =
            MerkleTreeVerifier::new(self.iop().deref_mut(), hashfn, domain, group_size, QUERIES)?;
        self.merkle_verifiers[reg_group_id] = Some(merkle);
        let root = self.merkle_verifiers[reg_group_id].as_ref().unwrap().root();
        trace_if_enabled!(
            "{} (group id={reg_group_id}) root: {root:?}",
            self.taps.group_name(reg_group_id)
        );
        Ok(root)
    }

    #[stability::unstable]

    // Reads rng.
    pub fn read_rng(&mut self, elems: usize) -> Vec<F::Elem> {
        let mix = (0..elems).map(|_| self.iop().random_elem()).collect();
        trace_if_enabled!("Got mix values from IOP: {mix:?}");
        mix
    }

    #[allow(clippy::too_many_arguments)]

    // Implements fri eval taps.
    fn fri_eval_taps(
        &self,
        combo_u: &[F::ExtElem],
        check_row: &[F::Elem],
        back_one: F::Elem,
        x: F::Elem,
        z: F::ExtElem,
        rows: &[&[F::Elem]],
        tap_mix_pows: &[F::ExtElem],
        check_mix_pows: &[F::ExtElem],
    ) -> F::ExtElem {
        let mut tot = vec![F::ExtElem::ZERO; self.taps.combos_size() + 1];
        let combo_count = self.taps.combos_size();
        let x = F::ExtElem::from_subfield(&x);

        for (reg, cur) in zip(self.taps.regs(), tap_mix_pows.iter()) {
            tot[reg.combo_id()] += *cur * rows[reg.group()][reg.offset()];
        }
        for (i, cur) in zip(0..Self::CHECK_SIZE, check_mix_pows.iter()) {
            tot[combo_count] += *cur * check_row[i];
        }
        let mut ret = F::ExtElem::ZERO;
        for i in 0..combo_count {
            let num = tot[i]
                - self.poly_eval(
                    &combo_u
                        [self.taps.combo_begin[i] as usize..self.taps.combo_begin[i + 1] as usize],
                    x,
                );
            let mut divisor = F::ExtElem::ONE;
            for back in self.taps.get_combo(i).slice() {
                divisor *= x - z * back_one.pow(*back as usize);
            }
            ret += num * divisor.inv();
        }
        let check_num = tot[combo_count] - combo_u[self.taps.tot_combo_backs];
        let check_div = x - z.pow(INV_RATE);
        ret += check_num * check_div.inv();
        ret
    }

    #[stability::unstable]

    // Verifies validity.
    pub fn verify_validity(
        &mut self,
        validity_fn: impl Fn(&F::ExtElem, &[F::ExtElem]) -> F::ExtElem,
    ) -> Result<(), VerificationError> {

        for (reg_group_id, verifier) in self.merkle_verifiers.iter().enumerate() {
            if !verifier.is_some() {
                panic!(
                    "Missing merkle verifier for reg group {reg_group_id} ({})",
                    self.taps.group_name(reg_group_id)
                );
            }
        }

        let poly_mix = self.iop().random_ext_elem();
        trace_if_enabled!("Poly mix: {poly_mix:?}");

        let hashfn = self.suite.hashfn.as_ref();
        let domain = INV_RATE * self.tot_cycles;
        let check_merkle = MerkleTreeVerifier::new(
            self.iop().deref_mut(),
            hashfn,
            domain,
            Self::CHECK_SIZE,
            QUERIES,
        )?;
        trace_if_enabled!("Check merkle root: {}", check_merkle.root());

        cfg_if::cfg_if! {
            if #[cfg(feature = "circuit_debug")] {
                let z_slice = self.iop().read_field_elem_slice(F::ExtElem::EXT_SIZE);
                let z = F::ExtElem::from_subelems(z_slice.iter().cloned());
            } else {
                let z = self.iop().random_ext_elem();
            }
        }

        trace_if_enabled!("Z = {z:?}");
        let back_one = F::Elem::ROU_REV[self.po2];

        let num_taps = self.taps.tap_size();
        let coeff_u = self
            .iop()
            .read_field_elem_slice(num_taps + Self::CHECK_SIZE)?;
        let hash_u = hashfn.hash_ext_elem_slice(coeff_u);
        self.iop().commit(&hash_u);

        let mut cur_pos = 0;
        let mut eval_u = Vec::with_capacity(num_taps);
        for reg in self.taps.regs() {
            for i in 0..reg.size() {
                let x = z * back_one.pow(reg.back(i));
                let fx = self.poly_eval(&coeff_u[cur_pos..(cur_pos + reg.size())], x);
                eval_u.push(fx);
            }
            cur_pos += reg.size();
        }
        assert_eq!(eval_u.len(), num_taps, "Miscalculated capacity for eval_us");

        #[cfg(not(target_os = "zkvm"))]
        tracing::debug!("> compute_polynomial");

        let result = validity_fn(&poly_mix, &eval_u);
        trace_if_enabled!("Computed polynomial: {result:?}");

        let mut check = F::ExtElem::default();
        let remap = [0, 2, 1, 3];
        let fp0 = F::Elem::ZERO;
        let fp1 = F::Elem::ONE;
        for (i, rmi) in remap.iter().enumerate() {
            check += coeff_u[num_taps + rmi]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp1, fp0, fp0, fp0]);
            check += coeff_u[num_taps + rmi + 4]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp1, fp0, fp0]);
            check += coeff_u[num_taps + rmi + 8]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp0, fp1, fp0]);
            check += coeff_u[num_taps + rmi + 12]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp0, fp0, fp1]);
        }
        let three = F::Elem::from_u64(3);
        check *= (F::ExtElem::from_subfield(&three) * z).pow(self.tot_cycles) - F::ExtElem::ONE;
        trace_if_enabled!("Check = {check:?}");
        if check != result {
            tracing::debug!("check != result");
            return Err(VerificationError::InvalidProof);
        }

        let mix = self.iop().random_ext_elem();
        trace_if_enabled!("FRI mix = {mix:?}");

        let mut combo_u: Vec<F::ExtElem> = vec![F::ExtElem::ZERO; self.taps.tot_combo_backs + 1];
        let mut cur_mix = F::ExtElem::ONE;
        cur_pos = 0;
        let mut tap_mix_pows = Vec::with_capacity(self.taps.reg_count());
        for reg in self.taps.regs() {
            for i in 0..reg.size() {
                combo_u[self.taps.combo_begin[reg.combo_id()] as usize + i] +=
                    cur_mix * coeff_u[cur_pos + i];
            }
            tap_mix_pows.push(cur_mix);
            cur_mix *= mix;
            cur_pos += reg.size();
        }
        assert_eq!(
            tap_mix_pows.len(),
            self.taps.reg_count(),
            "Miscalculated capacity for tap_mix_pows"
        );
        trace_if_enabled!("cur_mix: {cur_mix:?}, cur_pos: {cur_pos}");

        let mut check_mix_pows = Vec::with_capacity(Self::CHECK_SIZE);
        for _ in 0..Self::CHECK_SIZE {
            combo_u[self.taps.tot_combo_backs] += cur_mix * coeff_u[cur_pos];
            cur_pos += 1;
            check_mix_pows.push(cur_mix);
            cur_mix *= mix;
        }
        assert_eq!(
            check_mix_pows.len(),
            Self::CHECK_SIZE,
            "Miscalculated capacity for check_mix_pows"
        );
        let gen = <F::Elem as RootsOfUnity>::ROU_FWD[log2_ceil(domain)];
        let hashfn = self.suite.hashfn.as_ref();
        self.fri_verify(|idx| {
            let x = gen.pow(idx);
            let rows= self
                .merkle_verifiers
                .iter()
                .map(|merkle: &Option<MerkleTreeVerifier>| -> Result<&'a [F::Elem], VerificationError> {
                    merkle.as_ref()
                        .unwrap()
                        .verify(self.iop().deref_mut(), hashfn, idx)
                })
                .collect::<Result<Vec<_>,_>>()?;
            let check_row = check_merkle.verify(self.iop().deref_mut(), hashfn, idx)?;
            let ret = self.fri_eval_taps(&combo_u, check_row, back_one, x, z, &rows, &tap_mix_pows, &check_mix_pows);
            Ok(ret)
        })?;
        Ok(())
    }

    #[stability::unstable]

    // Reads slice with po2.
    pub fn read_slice_with_po2(
        &mut self,
        size: usize,
    ) -> Result<(&'a [F::Elem], usize), VerificationError> {
        let slice = self.iop().read_field_elem_slice(size + 1)?;
        self.iop().commit(&self.suite.hashfn.hash_elem_slice(slice));

        let (out, &[po2_elem]) = slice.split_at(size) else {
            unreachable!("slice returned by read_field_elem_slice is wrong size");
        };
        let (&[po2], &[]) = po2_elem.to_u32_words().split_at(1) else {
            unreachable!("po2 elem is larger than u32");
        };
        if po2 as usize > MAX_CYCLES_PO2 {
            tracing::error!("po2 in seal is larger than the max po2: {po2} > {MAX_CYCLES_PO2}");
            return Err(VerificationError::ReceiptFormatError);
        }
        self.po2 = po2 as usize;
        self.tot_cycles = 1usize.checked_shl(po2).unwrap();
        Ok((out, self.po2))
    }

    // Implements poly eval.
    fn poly_eval(&self, coeffs: &[F::ExtElem], x: F::ExtElem) -> F::ExtElem {
        let mut mul_x = F::ExtElem::ONE;
        let mut tot = F::ExtElem::ZERO;
        for coeff in coeffs {
            tot += *coeff * mul_x;
            mul_x *= x;
        }
        tot
    }
}

// Verifies the operation result.
pub fn verify<F, C, CheckCode>(
    circuit: &C,
    suite: &HashSuite<F>,
    seal: &[u32],
    check_code: CheckCode,
) -> Result<(), VerificationError>
where
    F: Field,
    C: CircuitCoreDef<F>,
    CheckCode: Fn(u32, &Digest) -> Result<(), VerificationError>,
{
    if seal.is_empty() {
        return Err(VerificationError::ReceiptFormatError);
    }

    let mut verifier = Verifier::<F>::new(circuit.get_taps(), suite, seal);
    verifier.commit_circuit_info(&C::CIRCUIT_INFO);

    let (out, po2) = verifier.read_slice_with_po2(C::OUTPUT_SIZE)?;

    let code_root = verifier.verify_group(REGISTER_GROUP_CODE)?;

    check_code(po2 as u32, code_root)?;

    verifier.verify_group(REGISTER_GROUP_DATA)?;

    let mix = verifier.read_rng(C::MIX_SIZE);

    verifier.verify_group(REGISTER_GROUP_ACCUM)?;

    verifier
        .verify_validity(|poly_mix, eval_u| circuit.poly_ext(poly_mix, eval_u, &[out, &mix]).tot)?;

    verifier.iop().verify_complete()?;
    Ok(())
}
