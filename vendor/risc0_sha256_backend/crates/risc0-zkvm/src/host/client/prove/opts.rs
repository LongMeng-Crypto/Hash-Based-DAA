// Copyright 2025 RISC Zero, Inc.
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

//! Module containing the [ProverOpts] struct and related functionality.

#[cfg(feature = "prove")]
use anyhow::Result;
use risc0_circuit_recursion::control_id::ALLOWED_CONTROL_IDS;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

use crate::receipt::DEFAULT_MAX_PO2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProverOpts {

    #[serde(default)]
    pub security_profile: SecurityProfile,

    pub hashfn: String,

    pub prove_guest_errors: bool,

    pub receipt_kind: ReceiptKind,

    pub control_ids: Vec<Digest>,

    pub(crate) max_segment_po2: usize,

    pub(crate) dev_mode: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptKind {

    Composite,

    Succinct,

    Groth16,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityProfile {

    #[default]
    Legacy97,
}

impl Default for ProverOpts {

    // Implements default.
    fn default() -> Self {
        Self {
            security_profile: SecurityProfile::Legacy97,
            hashfn: "poseidon2".to_string(),
            prove_guest_errors: false,
            receipt_kind: ReceiptKind::Composite,
            control_ids: ALLOWED_CONTROL_IDS.to_vec(),
            max_segment_po2: DEFAULT_MAX_PO2,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }
}

impl ProverOpts {

    #[stability::unstable]

    // Implements from max po2.
    pub fn from_max_po2(po2_max: usize) -> Self {
        Self {
            security_profile: SecurityProfile::Legacy97,
            hashfn: "poseidon2".to_string(),
            prove_guest_errors: false,
            receipt_kind: ReceiptKind::Composite,
            control_ids: crate::receipt::succinct::allowed_control_ids("poseidon2", po2_max)
                .unwrap()
                .collect(),
            max_segment_po2: po2_max,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }

    #[stability::unstable]

    // Implements all po2s.
    pub fn all_po2s() -> Self {
        Self::from_max_po2(risc0_zkp::MAX_CYCLES_PO2)
    }

    // Implements fast.
    pub fn fast() -> Self {
        Self::composite()
    }

    // Implements composite.
    pub fn composite() -> Self {
        Self {
            security_profile: SecurityProfile::Legacy97,
            hashfn: "poseidon2".to_string(),
            prove_guest_errors: false,
            receipt_kind: ReceiptKind::Composite,
            control_ids: ALLOWED_CONTROL_IDS.to_vec(),
            max_segment_po2: DEFAULT_MAX_PO2,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }

    // Implements succinct.
    pub fn succinct() -> Self {
        Self {
            security_profile: SecurityProfile::Legacy97,
            hashfn: "poseidon2".to_string(),
            prove_guest_errors: false,
            receipt_kind: ReceiptKind::Succinct,
            control_ids: ALLOWED_CONTROL_IDS.to_vec(),
            max_segment_po2: DEFAULT_MAX_PO2,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }

    // Implements groth16.
    pub fn groth16() -> Self {
        Self {
            security_profile: SecurityProfile::Legacy97,
            hashfn: "poseidon2".to_string(),
            prove_guest_errors: false,
            receipt_kind: ReceiptKind::Groth16,
            control_ids: ALLOWED_CONTROL_IDS.to_vec(),
            max_segment_po2: DEFAULT_MAX_PO2,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }

    // Implements with hashfn.
    pub fn with_hashfn(self, hashfn: String) -> Self {
        Self { hashfn, ..self }
    }

    // Implements with security profile.
    pub fn with_security_profile(self, security_profile: SecurityProfile) -> Self {
        Self {
            security_profile,
            ..self
        }
    }

    // Implements with prove guest errors.
    pub fn with_prove_guest_errors(self, prove_guest_errors: bool) -> Self {
        Self {
            prove_guest_errors,
            ..self
        }
    }

    // Implements with receipt kind.
    pub fn with_receipt_kind(self, receipt_kind: ReceiptKind) -> Self {
        Self {
            receipt_kind,
            ..self
        }
    }

    // Implements with control ids.
    pub fn with_control_ids(self, control_ids: Vec<Digest>) -> Self {
        Self {
            control_ids,
            ..self
        }
    }

    #[stability::unstable]

    // Implements with segment po2 max.
    pub fn with_segment_po2_max(self, max_segment_po2: usize) -> Self {
        Self {
            max_segment_po2,
            ..self
        }
    }

    // Implements with dev mode.
    pub fn with_dev_mode(self, dev_mode: bool) -> Self {
        if cfg!(feature = "disable-dev-mode") && dev_mode {
            panic!("zkVM: Inconsistent settings -- please resolve. \
                The RISC0_DEV_MODE environment variable is set but dev mode has been disabled by feature flag.");
        }
        Self { dev_mode, ..self }
    }

    // Implements dev mode.
    pub fn dev_mode(&self) -> bool {
        self.dev_mode
    }

    #[cfg(feature = "prove")]

    // Hashes suite.
    pub(crate) fn hash_suite(
        &self,
    ) -> Result<risc0_zkp::core::hash::HashSuite<risc0_zkp::field::baby_bear::BabyBear>> {
        risc0_zkp::core::hash::hash_suite_from_name(&self.hashfn)
            .ok_or_else(|| anyhow::anyhow!("unsupported hash suite: {}", self.hashfn))
    }
}

#[cfg(test)]
mod tests {
    use super::{ProverOpts, ReceiptKind, SecurityProfile};

    #[test]

    // Implements legacy97 remains the default profile.
    fn legacy97_remains_the_default_profile() {
        let opts = ProverOpts::default();
        assert_eq!(opts.security_profile, SecurityProfile::Legacy97);
        assert_eq!(opts.hashfn, "poseidon2");
        assert_eq!(opts.receipt_kind, ReceiptKind::Composite);
    }

    #[test]

    // Implements constructors and hash selection preserve legacy97.
    fn constructors_and_hash_selection_preserve_legacy97() {
        for opts in [
            ProverOpts::composite(),
            ProverOpts::succinct(),
            ProverOpts::composite().with_hashfn("sha-256".to_owned()),
            ProverOpts::succinct().with_hashfn("sha-256".to_owned()),
        ] {
            assert_eq!(opts.security_profile, SecurityProfile::Legacy97);
        }
    }

    #[test]

    // Implements legacy97 can be selected explicitly.
    fn legacy97_can_be_selected_explicitly() {
        let opts = ProverOpts::default().with_security_profile(SecurityProfile::Legacy97);
        assert_eq!(opts.security_profile, SecurityProfile::Legacy97);
    }
}
