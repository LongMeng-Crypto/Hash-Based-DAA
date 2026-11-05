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

//! This module defines the [ExecutorEnv] and [ExecutorEnvBuilder].

use std::{
    cell::RefCell,
    collections::HashMap,
    io::{BufRead, BufReader, Cursor, Read, Write},
    mem,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

use anyhow::{bail, Result};
use bytemuck::Pod;
use bytes::Bytes;
use risc0_binfmt::PovwJobId;
use risc0_circuit_keccak::{KeccakState, KECCAK_PO2_RANGE};
use risc0_zkp::core::digest::Digest;
use risc0_zkvm_platform::{self, fileno};
use serde::Serialize;
use tempfile::TempDir;

use crate::{
    host::client::{
        posix_io::PosixIo,
        slice_io::{slice_io_from_fn, SliceIo, SliceIoTable},
    },
    serde::to_vec,
    AssumptionReceipt, TraceCallback,
};

#[derive(Default)]
pub struct ExecutorEnvBuilder<'a> {
    inner: ExecutorEnv<'a>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub enum SegmentPath {
    TempDir(Arc<TempDir>),
    Path(PathBuf),
}

impl SegmentPath {

    // Implements path.
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::TempDir(dir) => dir.path(),
            Self::Path(path) => path.as_path(),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProveKeccakRequest {

    pub claim_digest: Digest,

    pub po2: usize,

    pub control_root: Digest,

    pub input: Vec<KeccakState>,
}

pub trait CoprocessorCallback {

    // Proves keccak.
    fn prove_keccak(&mut self, request: ProveKeccakRequest) -> Result<()>;
}

pub type CoprocessorCallbackRef<'a> = Rc<RefCell<dyn CoprocessorCallback + 'a>>;

#[derive(Default)]
pub(crate) struct AssumptionReceipts(pub(crate) Vec<AssumptionReceipt>);

#[derive(Default)]
pub struct ExecutorEnv<'a> {
    pub(crate) env_vars: HashMap<String, String>,
    pub(crate) args: Vec<String>,
    pub(crate) keccak_max_po2: Option<u32>,
    pub(crate) segment_limit_po2: Option<u32>,
    pub(crate) session_limit: Option<u64>,
    pub(crate) posix_io: Rc<RefCell<PosixIo<'a>>>,
    pub(crate) slice_io: Rc<RefCell<SliceIoTable<'a>>>,
    pub(crate) input: Vec<u8>,
    pub(crate) trace: Vec<Rc<RefCell<dyn TraceCallback + 'a>>>,
    pub(crate) assumptions: Rc<RefCell<AssumptionReceipts>>,
    pub(crate) segment_path: Option<SegmentPath>,
    pub(crate) pprof_out: Option<PathBuf>,
    pub(crate) input_digest: Option<Digest>,
    pub(crate) coprocessor: Option<CoprocessorCallbackRef<'a>>,
    pub(crate) povw_job_id: Option<PovwJobId>,
}

impl<'a> ExecutorEnv<'a> {

    // Implements builder.
    pub fn builder() -> ExecutorEnvBuilder<'a> {
        ExecutorEnvBuilder::default()
    }
}

impl<'a> ExecutorEnvBuilder<'a> {

    // Builds the operation result.
    pub fn build(&mut self) -> Result<ExecutorEnv<'a>> {
        let mut inner = mem::take(&mut self.inner);

        if !inner.input.is_empty() {
            let reader = Cursor::new(inner.input.clone());
            inner
                .posix_io
                .borrow_mut()
                .with_read_fd(fileno::STDIN, reader);
        }

        if inner.pprof_out.is_none() {
            if let Ok(env_var) = std::env::var("RISC0_PPROF_OUT") {
                inner.pprof_out = Some(env_var.into());
            }
        }

        if let Ok(po2) = std::env::var("RISC0_KECCAK_PO2") {
            let po2 = po2.parse::<u32>()?;
            if !KECCAK_PO2_RANGE.contains(&(po2 as usize)) {
                bail!(
                    "invalid keccak po2 {po2}. Expected range: {:?}",
                    KECCAK_PO2_RANGE
                );
            }
            inner.keccak_max_po2 = Some(po2);
        }

        Ok(inner)
    }

    // Implements segment limit po2.
    pub fn segment_limit_po2(&mut self, limit: u32) -> &mut Self {
        self.inner.segment_limit_po2 = Some(limit);
        self
    }

    // Implements keccak max po2.
    pub fn keccak_max_po2(&mut self, limit: u32) -> Result<&mut Self> {
        if !KECCAK_PO2_RANGE.contains(&(limit as usize)) {
            bail!(
                "invalid keccak po2 {limit}. Expected range: {:?}",
                KECCAK_PO2_RANGE
            );
        }
        self.inner.keccak_max_po2 = Some(limit);
        Ok(self)
    }

    // Implements session limit.
    pub fn session_limit(&mut self, limit: Option<u64>) -> &mut Self {
        self.inner.session_limit = limit;
        self
    }

    // Implements env vars.
    pub fn env_vars(&mut self, vars: HashMap<String, String>) -> &mut Self {
        self.inner.env_vars = vars;
        self
    }

    // Implements args.
    pub fn args(&mut self, args: &[String]) -> &mut Self {
        self.inner.args.extend_from_slice(args);
        self
    }

    // Implements env var.
    pub fn env_var(&mut self, name: &str, val: &str) -> &mut Self {
        self.inner
            .env_vars
            .insert(name.to_string(), val.to_string());
        self
    }

    // Writes the operation result.
    pub fn write<T: Serialize>(&mut self, data: &T) -> Result<&mut Self> {
        Ok(self.write_slice(&to_vec(data)?))
    }

    // Writes slice.
    pub fn write_slice<T: Pod>(&mut self, slice: &[T]) -> &mut Self {
        self.inner
            .input
            .extend_from_slice(bytemuck::cast_slice(slice));
        self
    }

    // Writes frame.
    pub fn write_frame(&mut self, payload: &[u8]) -> &mut Self {
        let len = payload.len() as u32;
        self.inner.input.extend_from_slice(&len.to_le_bytes());
        self.inner.input.extend_from_slice(payload);
        self
    }

    // Implements stdin.
    pub fn stdin(&mut self, reader: impl Read + 'a) -> &mut Self {
        self.read_fd(fileno::STDIN, BufReader::new(reader))
    }

    // Implements stdout.
    pub fn stdout(&mut self, writer: impl Write + 'a) -> &mut Self {
        self.write_fd(fileno::STDOUT, writer)
    }

    // Implements stderr.
    pub fn stderr(&mut self, writer: impl Write + 'a) -> &mut Self {
        self.write_fd(fileno::STDERR, writer)
    }

    // Reads fd.
    pub fn read_fd(&mut self, fd: u32, reader: impl BufRead + 'a) -> &mut Self {
        self.inner.posix_io.borrow_mut().with_read_fd(fd, reader);
        self
    }

    // Writes fd.
    pub fn write_fd(&mut self, fd: u32, writer: impl Write + 'a) -> &mut Self {
        self.inner.posix_io.borrow_mut().with_write_fd(fd, writer);
        self
    }

    // Implements slice io.
    pub fn slice_io(&mut self, channel: &str, handler: impl SliceIo + 'a) -> &mut Self {
        self.inner
            .slice_io
            .borrow_mut()
            .with_handler(channel, handler);
        self
    }

    // Implements io callback.
    pub fn io_callback<C: AsRef<str>>(
        &mut self,
        channel: C,
        callback: impl Fn(Bytes) -> Result<Bytes> + 'a,
    ) -> &mut Self {
        self.inner
            .slice_io
            .borrow_mut()
            .with_handler(channel.as_ref(), slice_io_from_fn(callback));
        self
    }

    // Adds assumption.
    pub fn add_assumption(&mut self, assumption: impl Into<AssumptionReceipt>) -> &mut Self {
        self.inner
            .assumptions
            .borrow_mut()
            .0
            .push(assumption.into());
        self
    }

    // Implements trace callback.
    pub fn trace_callback(&mut self, callback: impl TraceCallback + 'a) -> &mut Self {
        self.inner.trace.push(Rc::new(RefCell::new(callback)));
        self
    }

    // Implements segment path.
    pub fn segment_path<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.inner.segment_path = Some(SegmentPath::Path(path.as_ref().to_path_buf()));
        self
    }

    // Implements enable profiler.
    pub fn enable_profiler<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.inner.pprof_out = Some(path.as_ref().to_path_buf());
        self
    }

    // Implements input digest.
    pub fn input_digest(&mut self, digest: Digest) -> &mut Self {
        self.inner.input_digest = Some(digest);
        self
    }

    // Implements coprocessor callback.
    pub fn coprocessor_callback(&mut self, callback: impl CoprocessorCallback + 'a) -> &mut Self {
        self.inner.coprocessor = Some(Rc::new(RefCell::new(callback)));
        self
    }

    // Implements coprocessor callback ref.
    pub fn coprocessor_callback_ref(&mut self, callback: CoprocessorCallbackRef<'a>) -> &mut Self {
        self.inner.coprocessor = Some(callback);
        self
    }

    // Implements povw.
    pub fn povw(&mut self, povw_job_id: impl Into<PovwJobId>) -> &mut Self {
        self.inner.povw_job_id = Some(povw_job_id.into());
        self
    }
}
