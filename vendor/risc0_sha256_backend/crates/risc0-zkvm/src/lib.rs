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

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

extern crate alloc;

mod claim;
pub mod guest;
#[cfg(not(target_os = "zkvm"))]
mod host;
mod mmr;
mod receipt;
pub mod serde;
pub mod sha;

pub use ::serde::de::DeserializeOwned;
pub use anyhow::Result;
pub use risc0_binfmt::{ExitCode, InvalidExitCodeError, SystemState};
pub use risc0_zkp::core::digest::{digest, Digest};
pub use risc0_zkvm_platform::{align_up, declare_syscall, memory::GUEST_MAX_MEM, PAGE_SIZE};

#[cfg(not(target_os = "zkvm"))]
#[cfg(any(feature = "client", feature = "prove"))]
pub use bytes::Bytes;

#[cfg(not(target_os = "zkvm"))]
#[cfg(feature = "prove")]
pub use self::host::{
    api::server::Server as ApiServer,
    client::prove::{local::LocalProver, local_executor},
    recursion::{
        self,
        prove::{prove_registered_zkr, prove_zkr, register_zkr},
        RECURSION_PO2,
    },
    server::{
        exec::executor::ExecutorImpl,
        prove::{
            dev_mode::{DevModeDelay, DevModeProver},
            get_prover_server, HalPair, ProverServer,
        },
        session::{
            FileSegmentRef, NullSegmentRef, PreflightResults, Segment, SegmentRef, Session,
            SessionEvents, SimpleSegmentRef,
        },
    },
};

#[cfg(not(target_os = "zkvm"))]
#[cfg(feature = "bonsai")]
pub use self::host::client::prove::bonsai::BonsaiProver;

#[cfg(not(target_os = "zkvm"))]
#[cfg(feature = "client")]
pub use {
    self::host::{
        api::{
            client::Client as ApiClient, Asset, AssetRequest, Connector, RedisParams, SegmentInfo,
            SessionInfo,
        },
        client::{
            env::{ExecutorEnv, ExecutorEnvBuilder},
            prove::{
                default::DefaultProver,
                default_executor, default_prover,
                external::ExternalProver,
                opts::{ProverOpts, ReceiptKind, SecurityProfile},
                Executor, Prover,
            },
        },
    },
    risc0_circuit_rv32im::trace::{TraceCallback, TraceEvent},
};

#[cfg(not(target_os = "zkvm"))]
#[cfg(feature = "client")]
pub mod rpc {
    pub use super::host::rpc::*;
}

#[cfg(not(target_os = "zkvm"))]
#[cfg(feature = "client")]
pub use self::host::client::env::{CoprocessorCallback, ProveKeccakRequest};

#[cfg(not(target_os = "zkvm"))]
pub use {
    self::host::{
        prove_info::{ProveInfo, SessionStats},
        recursion::{ALLOWED_CONTROL_IDS, ALLOWED_CONTROL_ROOT},
    },
    risc0_binfmt::compute_image_id,
    risc0_groth16::Seal as Groth16Seal,
};

pub use self::{
    claim::{
        maybe_pruned::{MaybePruned, PrunedValueError},
        receipt::{Assumption, Assumptions, Input, Output, ReceiptClaim, UnionClaim},
        work::{Work, WorkClaim},
        Unknown,
    },
    receipt::{
        AssumptionReceipt, CompositeReceipt, CompositeReceiptVerifierParameters, FakeReceipt,
        GenericReceipt, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerAssumptionReceipt,
        InnerReceipt, Journal, Receipt, ReceiptMetadata, SegmentReceipt,
        SegmentReceiptVerifierParameters, SuccinctReceipt, SuccinctReceiptVerifierParameters,
        VerifierContext, DEFAULT_MAX_PO2,
    },
};

use semver::Version;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Returns version.
pub fn get_version() -> Result<Version, semver::Error> {
    Version::parse(VERSION)
}

#[cfg(feature = "std")]
#[deprecated(
    note = "dev-mode can be enabled programatically, so this function is no longer authoritative. \
            Use `ProverOpts::is_dev_mode` or `VerifierContext::is_dev_mode`"
)]

// Checks dev mode.
pub fn is_dev_mode() -> bool {
    is_dev_mode_enabled_via_environment()
}

#[cfg(all(feature = "std", not(target_os = "zkvm")))]

// Checks dev mode enabled via environment.
fn is_dev_mode_enabled_via_environment() -> bool {
    let is_env_set = std::env::var("RISC0_DEV_MODE")
        .ok()
        .map(|x| x.to_lowercase())
        .filter(|x| x == "1" || x == "true" || x == "yes")
        .is_some();

    let dev_mode_disabled = cfg!(feature = "disable-dev-mode");

    if dev_mode_disabled && is_env_set {
        panic!("zkVM: Inconsistent settings -- please resolve. \
            The RISC0_DEV_MODE environment variable is set but dev mode has been disabled by feature flag.");
    }

    !dev_mode_disabled && is_env_set
}

#[cfg(any(not(feature = "std"), target_os = "zkvm"))]

// Checks dev mode enabled via environment.
fn is_dev_mode_enabled_via_environment() -> bool {
    false
}

#[cfg(feature = "metal")]
#[test]

// Implements metal implies prove.
fn metal_implies_prove() {

    let _prover = get_prover_server(&ProverOpts::default());
}
