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

#[cfg(feature = "bonsai")]
pub(crate) mod bonsai;
pub(crate) mod default;
pub(crate) mod external;
#[cfg(feature = "prove")]
pub(crate) mod local;
pub(crate) mod opts;

use core::ops::Deref;
use std::{path::PathBuf, rc::Rc};

use anyhow::{anyhow, Result};

#[cfg(feature = "bonsai")]
use self::bonsai::BonsaiProver;

use self::{default::DefaultProver, external::ExternalProver, opts::ProverOpts};

use crate::{
    get_version, host::prove_info::ProveInfo, ExecutorEnv, Receipt, SessionInfo, VerifierContext,
};

pub trait Prover {

    // Returns name.
    fn get_name(&self) -> String;

    // Proves the operation result.
    fn prove(&self, env: ExecutorEnv<'_>, elf: &[u8]) -> Result<ProveInfo> {
        let opts = ProverOpts::default();
        let ctx = VerifierContext::default();
        self.prove_with_ctx(env, &ctx, elf, &opts)
    }

    // Proves with opts.
    fn prove_with_opts(
        &self,
        env: ExecutorEnv<'_>,
        elf: &[u8],
        opts: &ProverOpts,
    ) -> Result<ProveInfo> {
        let ctx = VerifierContext::default().with_dev_mode(opts.dev_mode());
        self.prove_with_ctx(env, &ctx, elf, opts)
    }

    // Proves with ctx.
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
        opts: &ProverOpts,
    ) -> Result<ProveInfo>;

    // Implements compress.
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt>;
}

impl<P: Prover + ?Sized> Prover for Rc<P> {

    // Returns name.
    fn get_name(&self) -> String {
        self.deref().get_name()
    }

    // Proves with ctx.
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
        opts: &ProverOpts,
    ) -> Result<ProveInfo> {
        self.deref().prove_with_ctx(env, ctx, elf, opts)
    }

    // Implements compress.
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt> {
        self.deref().compress(opts, receipt)
    }
}

pub trait Executor {

    // Implements execute.
    fn execute(&self, env: ExecutorEnv<'_>, elf: &[u8]) -> Result<SessionInfo>;
}

// Implements default prover.
pub fn default_prover() -> Rc<dyn Prover> {
    let explicit = std::env::var("RISC0_PROVER").unwrap_or_default();
    if !explicit.is_empty() {
        return match explicit.to_lowercase().as_str() {
            "actor" => Rc::new(DefaultProver::new(get_r0vm_path().unwrap()).unwrap()),
            #[cfg(feature = "bonsai")]
            "bonsai" => Rc::new(BonsaiProver::new("bonsai")),
            "ipc" => Rc::new(ExternalProver::new("ipc", get_r0vm_path().unwrap())),
            #[cfg(feature = "prove")]
            "local" => Rc::new(self::local::LocalProver::new("local")),
            _ => unimplemented!("Unsupported prover: {explicit}"),
        };
    }

    #[cfg(feature = "bonsai")]
    {
        if !crate::is_dev_mode_enabled_via_environment()
            && std::env::var("BONSAI_API_URL").is_ok()
            && std::env::var("BONSAI_API_KEY").is_ok()
        {
            return Rc::new(BonsaiProver::new("bonsai"));
        }
    }

    if cfg!(feature = "prove") {
        #[cfg(feature = "prove")]
        return Rc::new(self::local::LocalProver::new("local"));
    }

    Rc::new(ExternalProver::new("ipc", get_r0vm_path().unwrap()))
}

// Implements default executor.
pub fn default_executor() -> Rc<dyn Executor> {
    let explicit = std::env::var("RISC0_EXECUTOR").unwrap_or_default();
    if !explicit.is_empty() {
        return match explicit.to_lowercase().as_str() {
            "ipc" => Rc::new(ExternalProver::new("ipc", get_r0vm_path().unwrap())),
            #[cfg(feature = "prove")]
            "local" => Rc::new(self::local::LocalProver::new("local")),
            _ => unimplemented!("Unsupported executor: {explicit}"),
        };
    }

    if cfg!(feature = "prove") {
        #[cfg(feature = "prove")]
        return Rc::new(self::local::LocalProver::new("local"));
    }

    Rc::new(ExternalProver::new("ipc", get_r0vm_path().unwrap()))
}

#[cfg(feature = "prove")]

// Implements local executor.
pub fn local_executor() -> Rc<dyn Executor> {
    Rc::new(self::local::LocalProver::new("local"))
}

// Returns r0vm path.
pub(crate) fn get_r0vm_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("RISC0_SERVER_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }

    let mut version = get_version().map_err(|err| anyhow!(err))?;
    tracing::debug!("version: {version}");

    if let Ok(rzup) = rzup::Rzup::new() {
        if let Ok(dir) = rzup.get_version_dir(&rzup::Component::R0Vm, &version) {
            return Ok(dir.join("r0vm"));
        }

        version.patch = 0;
        version.build = Default::default();

        if let Ok(dir) = rzup.get_version_dir(&rzup::Component::R0Vm, &version) {
            return Ok(dir.join("r0vm"));
        }
    }

    Ok("r0vm".into())
}
