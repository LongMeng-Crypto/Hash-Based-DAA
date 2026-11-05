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

//! This module defines [Session] and [Segment] which provides a way to share
//! execution traces between the execution phase and the proving phase.

use std::{collections::BTreeSet, fs, path::PathBuf};

use anyhow::{ensure, Context, Result};
use enum_map::EnumMap;
use risc0_binfmt::{PovwJobId, SystemState};
use risc0_circuit_keccak::{compute_keccak_digest, KECCAK_CONTROL_ROOT};
use risc0_circuit_rv32im::{execute::EcallMetric, TerminateState};
use serde::{Deserialize, Serialize};

use crate::{
    host::{
        client::env::{ProveKeccakRequest, SegmentPath},
        prove_info::SessionStats,
    },
    mmr::{GuestPeak, MerkleMountainAccumulator},
    sha::Digest,
    Assumption, AssumptionReceipt, Assumptions, ExitCode, Journal, MaybePruned, Output,
    ReceiptClaim, Work,
};

use super::exec::syscall::{SyscallKind, SyscallMetric};

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct PageFaults {
    pub(crate) reads: BTreeSet<u32>,
    pub(crate) writes: BTreeSet<u32>,
}

#[non_exhaustive]
pub struct Session {

    pub segments: Vec<Box<dyn SegmentRef>>,

    pub input: Digest,

    pub journal: Option<Journal>,

    pub exit_code: ExitCode,

    pub assumptions: Vec<(Assumption, AssumptionReceipt)>,

    pub mmr_assumptions: Vec<AssumptionReceipt>,

    pub hooks: Vec<Box<dyn SessionEvents>>,

    pub user_cycles: u64,

    pub paging_cycles: u64,

    pub reserved_cycles: u64,

    pub total_cycles: u64,

    pub pre_state: SystemState,

    pub post_state: SystemState,

    pub(crate) pending_keccaks: Vec<ProveKeccakRequest>,

    pub(crate) ecall_metrics: Vec<(String, EcallMetric)>,

    pub(crate) syscall_metrics: EnumMap<SyscallKind, SyscallMetric>,

    pub(crate) povw_job_id: Option<PovwJobId>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Segment {

    pub index: u32,

    pub(crate) inner: risc0_circuit_rv32im::execute::Segment,

    pub(crate) output: Option<Output>,
}

impl Segment {

    // Implements po2.
    pub fn po2(&self) -> usize {
        self.inner.po2 as usize
    }

    // Implements user cycles.
    pub(crate) fn user_cycles(&self) -> u32 {
        self.inner.suspend_cycle
    }
}

pub struct PreflightResults {
    pub(crate) inner: risc0_circuit_rv32im::prove::PreflightResults,

    pub(crate) terminate_state: Option<TerminateState>,
    pub(crate) output: Option<Output>,
    pub(crate) segment_index: u32,
}

impl PreflightResults {

    // Implements segment index.
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }
}

pub trait SegmentRef: Send {

    // Implements resolve.
    fn resolve(&self) -> Result<Segment>;
}

pub trait SessionEvents {

    #[allow(unused)]

    // Implements on pre prove segment.
    fn on_pre_prove_segment(&self, segment: &Segment) {}

    #[allow(unused)]

    // Implements on post prove segment.
    fn on_post_prove_segment(&self, segment: &Segment) {}
}

impl Session {

    // Adds hook.
    pub fn add_hook<E: SessionEvents + 'static>(&mut self, hook: E) {
        self.hooks.push(Box::new(hook));
    }

    // Implements claim.
    pub fn claim(&self) -> Result<ReceiptClaim> {

        let output = if self.exit_code.expects_output() {
            self.journal
                .as_ref()
                .map(|journal| -> Result<_> {
                    Ok(Output {
                        journal: journal.bytes.clone().into(),
                        assumptions: self
                            .unresolved_assumptions()
                            .context("failed to compute unresolved_assumptions")?
                            .into(),
                    })
                })
                .transpose()?
        } else {
            ensure!(
                self.journal.is_none(),
                "Session with exit code {:?} has a journal",
                self.exit_code
            );
            ensure!(
                self.assumptions.is_empty(),
                "Session with exit code {:?} has encoded assumptions",
                self.exit_code
            );
            None
        };

        Ok(ReceiptClaim {
            pre: self.pre_state.clone().into(),
            post: self.post_state.clone().into(),
            exit_code: self.exit_code,
            input: MaybePruned::Pruned(self.input),
            output: output.into(),
        })
    }

    // Implements keccak root assumption.
    fn keccak_root_assumption(&self) -> Result<Option<Assumption>> {
        let mut keccak_receipts = MerkleMountainAccumulator::<GuestPeak>::new();
        for proof_request in self.pending_keccaks.iter() {
            let claim = compute_keccak_digest(bytemuck::cast_slice(proof_request.input.as_slice()));
            tracing::debug!("adding keccak assumption: {}", claim);
            keccak_receipts.insert(Assumption {
                claim,
                control_root: KECCAK_CONTROL_ROOT,
            })?;
        }

        if !keccak_receipts.is_empty() {
            let root_assumption = keccak_receipts.root()?;
            tracing::debug!("keccak root assumption for session: {:?}", root_assumption);
            return Ok(Some(root_assumption));
        }
        Ok(None)
    }

    // Implements unresolved assumptions.
    fn unresolved_assumptions(&self) -> Result<Assumptions> {
        let keccak_root_assumption = self
            .keccak_root_assumption()
            .context("failed to compute keccak root assumption")?;
        Ok(self
            .assumptions
            .iter()
            .filter_map(|(_, receipt)| match receipt {
                AssumptionReceipt::Proven(_) => None,
                AssumptionReceipt::Unresolved(assumption) => {
                    if let Some(ref keccak) = keccak_root_assumption {
                        if keccak == assumption {
                            return None;
                        }
                    }
                    Some(assumption.clone())
                }
            })
            .collect::<Vec<_>>()
            .into())
    }

    // Implements work.
    pub fn work(&self) -> Option<Work> {
        self.povw_job_id.map(|povw_job_id| Work {
            nonce_min: povw_job_id.nonce(0),
            nonce_max: povw_job_id.nonce(self.segments.len() as u32),
            value: self.total_cycles,
        })
    }

    // Implements log.
    pub fn log(&self) {
        if std::env::var_os("RISC0_INFO").is_none() {
            return;
        }

        let pct = |cycles: u64| cycles as f64 / self.total_cycles as f64 * 100.0;

        tracing::info!("number of segments: {}", self.segments.len());
        tracing::info!("{} total cycles", self.total_cycles);
        tracing::info!(
            "{} user cycles ({:.2}%)",
            self.user_cycles,
            pct(self.user_cycles)
        );
        tracing::info!(
            "{} paging cycles ({:.2}%)",
            self.paging_cycles,
            pct(self.paging_cycles)
        );
        tracing::info!(
            "{} reserved cycles ({:.2}%)",
            self.reserved_cycles,
            pct(self.reserved_cycles)
        );

        tracing::info!("ecalls");
        let mut ecall_metrics = self.ecall_metrics.clone();
        ecall_metrics.sort_by(|a, b| a.1.cycles.cmp(&b.1.cycles));
        for (name, metric) in ecall_metrics.iter().rev() {
            tracing::info!(
                "\t{} {name} calls, {} cycles, ({:.2}%)",
                metric.count,
                metric.cycles,
                pct(metric.cycles)
            );
        }

        tracing::info!("syscalls");
        let mut syscall_metrics: Vec<_> = self.syscall_metrics.iter().collect();
        syscall_metrics.sort_by(|a, b| a.1.count.cmp(&b.1.count));
        for (name, metric) in syscall_metrics.iter().rev() {
            tracing::info!("\t{} {name:?} calls", metric.count);
        }
    }

    // Implements stats.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            segments: self.segments.len(),
            total_cycles: self.total_cycles,
            user_cycles: self.user_cycles,
            paging_cycles: self.paging_cycles,
            reserved_cycles: self.reserved_cycles,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NullSegmentRef;

impl SegmentRef for NullSegmentRef {

    // Implements resolve.
    fn resolve(&self) -> anyhow::Result<Segment> {
        unimplemented!()
    }
}

// Implements null callback.
pub fn null_callback(_: Segment) -> Result<Box<dyn SegmentRef>> {
    Ok(Box::new(NullSegmentRef))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SimpleSegmentRef {
    segment: Segment,
}

impl SegmentRef for SimpleSegmentRef {

    // Implements resolve.
    fn resolve(&self) -> Result<Segment> {
        Ok(self.segment.clone())
    }
}

impl SimpleSegmentRef {

    // Creates the operation result.
    pub fn new(segment: Segment) -> Self {
        Self { segment }
    }
}

pub struct FileSegmentRef {
    path: PathBuf,
    _dir: SegmentPath,
}

impl SegmentRef for FileSegmentRef {

    // Implements resolve.
    fn resolve(&self) -> Result<Segment> {
        let contents = fs::read(&self.path)?;
        let segment = bincode::deserialize(&contents)?;
        Ok(segment)
    }
}

impl FileSegmentRef {

    // Creates the operation result.
    pub fn new(segment: &Segment, dir: &SegmentPath) -> Result<Self> {
        let path = dir.path().join(format!("{}.bincode", segment.index));
        fs::write(&path, bincode::serialize(&segment)?)?;
        Ok(Self {
            path,
            _dir: dir.clone(),
        })
    }
}
