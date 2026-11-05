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

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use prost::Message;
use risc0_zkp::core::digest::Digest;

use super::{
    malformed_err, pb, Asset, AssetRequest, ConnectionWrapper, Connector, ParentProcessConnector,
    SessionInfo,
};
use crate::{
    claim::receipt::UnionClaim,
    get_version,
    host::{api::SegmentInfo, client::prove::get_r0vm_path},
    receipt::{AssumptionReceipt, SegmentReceipt, SuccinctReceipt},
    ExecutorEnv, Journal, ProveInfo, ProverOpts, Receipt, ReceiptClaim, Unknown,
};

pub(crate) enum Compat {
    Narrow,
    Wide,
}

pub struct Client {
    connector: Box<dyn Connector>,
    compat: Compat,
    version_override: Option<semver::Version>,
}

impl Default for Client {

    // Implements default.
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl Client {

    // Creates the operation result.
    pub fn new() -> Result<Self> {
        Self::new_sub_process("r0vm")
    }

    // Creates sub process.
    pub fn new_sub_process<P: AsRef<Path>>(server_path: P) -> Result<Self> {
        let connector = ParentProcessConnector::new_narrow_version(server_path)?;
        Ok(Self::with_connector(Box::new(connector)))
    }

    // Creates sub process compat.
    pub fn new_sub_process_compat<P: AsRef<Path>>(
        server_path: P,
        version_override: semver::Version,
    ) -> Result<Self> {
        let connector = ParentProcessConnector::new(server_path)?;
        Ok(Self {
            connector: Box::new(connector),
            compat: Compat::Wide,
            version_override: Some(version_override),
        })
    }

    // Implements from env.
    pub fn from_env() -> Result<Self> {
        Client::new_sub_process(get_r0vm_path()?)
    }

    // Implements with connector.
    pub fn with_connector(connector: Box<dyn Connector>) -> Self {
        Self {
            connector,
            compat: Compat::Narrow,
            version_override: None,
        }
    }

    // Proves the operation result.
    pub fn prove(
        &self,
        env: &ExecutorEnv<'_>,
        opts: &ProverOpts,
        binary: Asset,
    ) -> Result<ProveInfo> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Prove(
                pb::api::ProveRequest {
                    env: Some(self.make_execute_env(env, binary.try_into()?)?),
                    opts: Some(opts.clone().into()),
                    receipt_out: Some(pb::api::AssetRequest {
                        kind: Some(pb::api::asset_request::Kind::Inline(())),
                    }),
                },
            )),
        };
        conn.send(request)?;

        let asset = self.prove_handler(&mut conn, env)?;

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        let prove_info_bytes = asset.as_bytes()?;
        let prove_info_pb = pb::core::ProveInfo::decode(prove_info_bytes)?;
        prove_info_pb.try_into()
    }

    // Implements execute.
    pub fn execute<F>(
        &self,
        env: &ExecutorEnv<'_>,
        binary: Asset,
        segments_out: AssetRequest,
        segment_callback: F,
    ) -> Result<SessionInfo>
    where
        F: FnMut(SegmentInfo, Asset) -> Result<()>,
    {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Execute(
                pb::api::ExecuteRequest {
                    env: Some(self.make_execute_env(env, binary.try_into()?)?),
                    segments_out: Some(segments_out.try_into()?),
                },
            )),
        };

        conn.send(request)?;

        let result = self.execute_handler(segment_callback, &mut conn, env);

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Proves segment.
    pub fn prove_segment(
        &self,
        opts: &ProverOpts,
        segment: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SegmentReceipt> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::ProveSegment(
                pb::api::ProveSegmentRequest {
                    opts: Some(opts.clone().into()),
                    segment: Some(segment.try_into()?),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        conn.send(request).context("tx request failed")?;

        let reply: pb::api::ProveSegmentReply = conn.recv().context("rx reply failed")?;

        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("ProveSegmentReply.kind"))?
        {
            pb::api::prove_segment_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("ProveSegmentReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SegmentReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::prove_segment_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Proves keccak.
    pub fn prove_keccak(
        &self,
        proof_request: crate::host::client::env::ProveKeccakRequest,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<Unknown>> {
        use crate::host::api::convert::keccak_input_to_bytes;

        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::ProveKeccak(
                pb::api::ProveKeccakRequest {
                    claim_digest: Some(proof_request.claim_digest.into()),
                    po2: proof_request.po2 as u32,
                    control_root: Some(proof_request.control_root.into()),
                    input: keccak_input_to_bytes(&proof_request.input),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        tracing::trace!("tx: {request:?}");
        conn.send(request)?;

        let reply: pb::api::ProveKeccakReply = conn.recv()?;

        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("ProveKeccakReply.kind"))?
        {
            pb::api::prove_keccak_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("ProveKeccakReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::prove_keccak_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements lift.
    pub fn lift(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Lift(pb::api::LiftRequest {
                opts: Some(opts.clone().into()),
                receipt: Some(receipt.try_into()?),
                receipt_out: Some(receipt_out.try_into()?),
            })),
        };

        conn.send(request)?;

        let reply: pb::api::LiftReply = conn.recv()?;

        let result = match reply.kind.ok_or_else(|| malformed_err("LiftReply.kind"))? {
            pb::api::lift_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("LiftReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::lift_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements join.
    pub fn join(
        &self,
        opts: &ProverOpts,
        left_receipt: Asset,
        right_receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Join(pb::api::JoinRequest {
                opts: Some(opts.clone().into()),
                left_receipt: Some(left_receipt.try_into()?),
                right_receipt: Some(right_receipt.try_into()?),
                receipt_out: Some(receipt_out.try_into()?),
            })),
        };

        conn.send(request)?;

        let reply: pb::api::JoinReply = conn.recv()?;

        let result = match reply.kind.ok_or_else(|| malformed_err("JoinReply.kind"))? {
            pb::api::join_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("JoinReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::join_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements union.
    pub fn union(
        &self,
        opts: &ProverOpts,
        a_receipt: Asset,
        b_receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<UnionClaim>> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Union(
                pb::api::UnionRequest {
                    opts: Some(opts.clone().into()),
                    left_receipt: Some(a_receipt.try_into()?),
                    right_receipt: Some(b_receipt.try_into()?),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        conn.send(request)?;

        let reply: pb::api::UnionReply = conn.recv()?;

        let result = match reply.kind.ok_or_else(|| malformed_err("UnionReply.kind"))? {
            pb::api::union_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("UnionReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::union_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements resolve.
    pub fn resolve(
        &self,
        opts: &ProverOpts,
        conditional_receipt: Asset,
        assumption_receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Resolve(
                pb::api::ResolveRequest {
                    opts: Some(opts.clone().into()),
                    conditional_receipt: Some(conditional_receipt.try_into()?),
                    assumption_receipt: Some(assumption_receipt.try_into()?),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        conn.send(request)?;

        let reply: pb::api::ResolveReply = conn.recv()?;

        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("ResolveReply.kind"))?
        {
            pb::api::resolve_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("ResolveReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::resolve_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements identity p254.
    pub fn identity_p254(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::IdentityP254(
                pb::api::IdentityP254Request {
                    opts: Some(opts.clone().into()),
                    receipt: Some(receipt.try_into()?),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        conn.send(request)?;

        let reply: pb::api::IdentityP254Reply = conn.recv()?;

        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("IdentityP254Reply.kind"))?
        {
            pb::api::identity_p254_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("IdentityP254Reply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::identity_p254_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements compress.
    pub fn compress(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<Receipt> {
        let mut conn = self.connect()?;

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Compress(
                pb::api::CompressRequest {
                    opts: Some(opts.clone().into()),
                    receipt: Some(receipt.try_into()?),
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };

        conn.send(request)?;

        let reply: pb::api::CompressReply = conn.recv()?;

        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("CompressReply.kind"))?
        {
            pb::api::compress_reply::Kind::Ok(result) => {
                let receipt_bytes = result
                    .receipt
                    .ok_or_else(|| malformed_err("CompressReply.Ok.receipt"))?
                    .as_bytes()?;
                let receipt_pb = pb::core::Receipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::compress_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Verifies the operation result.
    pub fn verify(&self, receipt: Asset, image_id: impl Into<Digest>) -> Result<()> {
        let mut conn = self.connect().context("connect")?;
        let image_id = image_id.into();

        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Verify(
                pb::api::VerifyRequest {
                    receipt: Some(receipt.try_into().context("convert receipt asset")?),
                    image_id: Some(image_id.into()),
                },
            )),
        };

        conn.send(request).context("send")?;

        let reply: pb::api::GenericReply = conn.recv().context("error from server")?;
        let result = match reply
            .kind
            .ok_or_else(|| malformed_err("GenericReply.kind"))?
        {
            pb::api::generic_reply::Kind::Ok(ok) => Ok(ok),
            pb::api::generic_reply::Kind::Error(err) => Err(err.into()),
        };

        let code = conn.close().context("close")?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    // Implements connect.
    fn connect(&self) -> Result<ConnectionWrapper> {
        let mut conn = self.connector.connect()?;

        let client_version = get_version().map_err(|err| anyhow!(err))?;
        let client_version = self.version_override.as_ref().unwrap_or(&client_version);
        let request = pb::api::HelloRequest {
            version: Some(client_version.clone().into()),
        };

        conn.send(request)?;

        let reply: pb::api::HelloReply = conn.recv()?;

        match reply.kind.ok_or_else(|| malformed_err("HelloReply.kind"))? {
            pb::api::hello_reply::Kind::Ok(reply) => {
                let server_version: semver::Version = reply
                    .version
                    .ok_or_else(|| malformed_err("HelloReply.Ok.version"))?
                    .try_into()
                    .map_err(|err: semver::Error| anyhow!(err))?;

                if !self.compat.check(client_version, &server_version) {
                    let msg = format!("incompatible server version: {server_version}");
                    tracing::warn!("{msg}");
                    bail!(msg);
                }
            }
            pb::api::hello_reply::Kind::Error(err) => {
                let code = conn.close()?;
                tracing::debug!("Child finished with: {code}");
                bail!(err);
            }
        }

        Ok(conn)
    }

    // Creates execute env.
    fn make_execute_env(
        &self,
        env: &ExecutorEnv<'_>,
        binary: pb::api::Asset,
    ) -> Result<pb::api::ExecutorEnv> {
        Ok(pb::api::ExecutorEnv {
            binary: Some(binary),
            env_vars: env.env_vars.clone(),
            args: env.args.clone(),
            slice_ios: env.slice_io.borrow().inner.keys().cloned().collect(),
            read_fds: env.posix_io.borrow().read_fds(),
            write_fds: env.posix_io.borrow().write_fds(),
            segment_limit_po2: env.segment_limit_po2,
            keccak_max_po2: env.keccak_max_po2,
            session_limit: env.session_limit,
            trace_events: (!env.trace.is_empty()).then_some(()),
            coprocessor: env.coprocessor.is_some(),
            pprof_out: env
                .pprof_out
                .as_ref()
                .map(|x| x.to_string_lossy().into())
                .unwrap_or_default(),
            assumptions: env
                .assumptions
                .borrow()
                .0
                .iter()
                .map(|a| {
                    Ok(match a {
                        AssumptionReceipt::Proven(inner) => pb::api::AssumptionReceipt {
                            kind: Some(pb::api::assumption_receipt::Kind::Proven(
                                Asset::Inline(
                                    pb::core::InnerReceipt::try_from(inner.clone())?
                                        .encode_to_vec()
                                        .into(),
                                )
                                .try_into()?,
                            )),
                        },
                        AssumptionReceipt::Unresolved(assumption) => pb::api::AssumptionReceipt {
                            kind: Some(pb::api::assumption_receipt::Kind::Unresolved(
                                Asset::Inline(
                                    pb::core::Assumption::try_from(assumption.clone())?
                                        .encode_to_vec()
                                        .into(),
                                )
                                .try_into()?,
                            )),
                        },
                    })
                })
                .collect::<Result<_>>()?,
            segment_path: env
                .segment_path
                .as_ref()
                .map(|x| x.path().to_string_lossy().into())
                .unwrap_or_default(),
            povw_job_id: env
                .povw_job_id
                .map(|x| x.to_bytes().to_vec())
                .unwrap_or_default(),
        })
    }

    // Implements execute handler.
    fn execute_handler<F>(
        &self,
        segment_callback: F,
        conn: &mut ConnectionWrapper,
        env: &ExecutorEnv<'_>,
    ) -> Result<SessionInfo>
    where
        F: FnMut(SegmentInfo, Asset) -> Result<()>,
    {
        let mut segment_callback = segment_callback;
        let mut segments = Vec::new();
        loop {
            let reply: pb::api::ServerReply = conn.recv()?;

            match reply
                .kind
                .ok_or_else(|| malformed_err("ServerReply.kind"))?
            {
                pb::api::server_reply::Kind::Ok(request) => {
                    match request
                        .kind
                        .ok_or_else(|| malformed_err("ServerReply.Ok.kind"))?
                    {
                        pb::api::client_callback::Kind::Io(io) => {
                            let msg: pb::api::OnIoReply = self.on_io(env, io).into();

                            conn.send(msg)?;
                        }
                        pb::api::client_callback::Kind::SegmentDone(segment) => {
                            let reply: pb::api::GenericReply = segment
                                .segment
                                .map_or_else(
                                    || Err(malformed_err("ServerReply.Ok.SegmentDone.segment")),
                                    |segment| {
                                        let asset = segment
                                            .segment
                                            .ok_or_else(|| {
                                                malformed_err(
                                                    "ServerReply.Ok.SegmentDone.segment.segment",
                                                )
                                            })?
                                            .try_into()?;
                                        let info = SegmentInfo {
                                            po2: segment.po2,
                                            cycles: segment.cycles,
                                        };
                                        segments.push(info.clone());
                                        segment_callback(info, asset)
                                    },
                                )
                                .into();

                            conn.send(reply)?;
                        }
                        pb::api::client_callback::Kind::SessionDone(session) => {
                            return match session.session {
                                Some(session) => {
                                    let receipt_claim = match session.receipt_claim {
                                        Some(claim) => Some(
                                            pb::core::ReceiptClaim::decode(claim.as_bytes()?)?
                                                .try_into()?,
                                        ),
                                        None => None,
                                    };

                                    Ok(SessionInfo {
                                        segments,
                                        journal: Journal::new(session.journal),
                                        exit_code: session
                                            .exit_code
                                            .ok_or_else(|| malformed_err("SessionInfo.exit_code"))?
                                            .try_into()?,
                                        receipt_claim,
                                    })
                                }
                                None => Err(malformed_err("ServerReply.ok.SessionDone.session")),
                            }
                        }
                        pb::api::client_callback::Kind::ProveDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                    }
                }
                pb::api::server_reply::Kind::Error(err) => return Err(err.into()),
            }
        }
    }

    // Proves handler.
    fn prove_handler(
        &self,
        conn: &mut ConnectionWrapper,
        env: &ExecutorEnv<'_>,
    ) -> Result<pb::api::Asset> {
        loop {
            let reply: pb::api::ServerReply = conn.recv()?;

            match reply
                .kind
                .ok_or_else(|| malformed_err("ServerReply.kind"))?
            {
                pb::api::server_reply::Kind::Ok(request) => {
                    match request
                        .kind
                        .ok_or_else(|| malformed_err("ServerReply.Ok.kind"))?
                    {
                        pb::api::client_callback::Kind::Io(io) => {
                            let msg: pb::api::OnIoReply = self.on_io(env, io).into();

                            conn.send(msg)?;
                        }
                        pb::api::client_callback::Kind::SegmentDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                        pb::api::client_callback::Kind::SessionDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                        pb::api::client_callback::Kind::ProveDone(done) => {
                            return done.prove_info.ok_or_else(|| {
                                malformed_err("ServerReply.Ok.ProveDone.prove_info")
                            })
                        }
                    }
                }
                pb::api::server_reply::Kind::Error(err) => return Err(err.into()),
            }
        }
    }

    // Implements on io.
    fn on_io(&self, env: &ExecutorEnv<'_>, request: pb::api::OnIoRequest) -> Result<Bytes> {
        match request
            .kind
            .ok_or_else(|| malformed_err("OnIoRequest.kind"))?
        {
            pb::api::on_io_request::Kind::Posix(posix) => {
                let cmd = posix
                    .cmd
                    .ok_or_else(|| malformed_err("OnIoRequest.Posix.cmd"))?;
                match cmd
                    .kind
                    .ok_or_else(|| malformed_err("OnIoRequest.Posix.cmd.kind"))?
                {
                    pb::api::posix_cmd::Kind::Read(nread) => {
                        self.on_posix_read(env, posix.fd, nread as usize)
                    }
                    pb::api::posix_cmd::Kind::Write(from_guest) => {
                        self.on_posix_write(env, posix.fd, from_guest.into())?;
                        Ok(Bytes::new())
                    }
                }
            }
            pb::api::on_io_request::Kind::Slice(slice_io) => {
                self.on_slice(env, &slice_io.name, slice_io.from_guest.into())
            }
            pb::api::on_io_request::Kind::Trace(event) => {
                self.on_trace(env, event)?;
                Ok(Bytes::new())
            }
            pb::api::on_io_request::Kind::Coprocessor(request) => {
                self.on_coprocessor(env, request)?;
                Ok(Bytes::new())
            }
        }
    }

    // Implements on posix read.
    fn on_posix_read(&self, env: &ExecutorEnv<'_>, fd: u32, nread: usize) -> Result<Bytes> {
        tracing::debug!("on_posix_read: {fd}, {nread}");
        let mut from_host = vec![0; nread];
        let posix_io = env.posix_io.borrow();
        let reader = posix_io.get_reader(fd)?;
        let nread = reader.borrow_mut().read(&mut from_host)?;
        let slice = from_host[..nread].to_vec();
        Ok(slice.into())
    }

    // Implements on posix write.
    fn on_posix_write(&self, env: &ExecutorEnv<'_>, fd: u32, from_guest: Bytes) -> Result<()> {
        tracing::debug!("on_posix_write: {fd}");
        let posix_io = env.posix_io.borrow();
        let writer = posix_io.get_writer(fd)?;
        writer.borrow_mut().write_all(&from_guest)?;
        Ok(())
    }

    // Implements on slice.
    fn on_slice(&self, env: &ExecutorEnv<'_>, name: &str, from_guest: Bytes) -> Result<Bytes> {
        let table = env.slice_io.borrow();
        let slice_io = table
            .inner
            .get(name)
            .ok_or_else(|| anyhow!("Unknown I/O channel name: {name}"))?;
        let result = slice_io.borrow_mut().handle_io(name, from_guest)?;
        Ok(result)
    }

    // Implements on trace.
    fn on_trace(&self, env: &ExecutorEnv<'_>, event: pb::api::TraceEvent) -> Result<()> {
        for trace_callback in env.trace.iter() {
            trace_callback
                .borrow_mut()
                .trace_callback(event.clone().try_into()?)?;
        }
        Ok(())
    }

    // Implements on coprocessor.
    fn on_coprocessor(
        &self,
        env: &ExecutorEnv<'_>,
        coprocessor_request: pb::api::CoprocessorRequest,
    ) -> Result<()> {
        match coprocessor_request
            .kind
            .ok_or_else(|| malformed_err("OnCoprocessorRequest.kind"))?
        {
            pb::api::coprocessor_request::Kind::ProveKeccak(proof_request) => {
                let proof_request = proof_request.try_into()?;
                let coprocessor = env
                    .coprocessor
                    .clone()
                    .ok_or_else(|| malformed_err("OnCoprocessorRequest.ProveKeccak.coprocessor"))?;
                let mut coprocessor = coprocessor.borrow_mut();
                coprocessor.prove_keccak(proof_request)
            }
        }
    }
}

impl From<Result<Bytes, anyhow::Error>> for pb::api::OnIoReply {

    // Implements from.
    fn from(result: Result<Bytes, anyhow::Error>) -> Self {
        Self {
            kind: Some(match result {
                Ok(bytes) => pb::api::on_io_reply::Kind::Ok(bytes.into()),
                Err(err) => pb::api::on_io_reply::Kind::Error(err.into()),
            }),
        }
    }
}

impl Compat {

    // Checks the operation result.
    pub(crate) fn check(&self, requested: &semver::Version, server: &semver::Version) -> bool {
        match self {
            Compat::Narrow => {
                if requested.pre.is_empty() {
                    requested.major == server.major && requested.minor == server.minor
                } else {
                    requested == server
                }
            }
            Compat::Wide => requested.major == server.major,
        }
    }
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::Compat;

    #[test]

    // Checks version narrow.
    fn check_version_narrow() {

        // Tests the operation result.
        fn test(requested: &str, server: &str) -> bool {
            Compat::Narrow.check(
                &Version::parse(requested).unwrap(),
                &Version::parse(server).unwrap(),
            )
        }

        assert!(test("0.18.0", "0.18.0"));
        assert!(test("0.18.0", "0.18.1"));
        assert!(test("0.18.1", "0.18.1"));
        assert!(test("0.18.1", "0.18.2"));
        assert!(test("0.18.1", "0.18.0"));
        assert!(!test("0.18.0", "0.19.0"));

        assert!(test("1.0.0", "1.0.0"));
        assert!(test("1.0.0", "1.0.1"));
        assert!(test("1.1.0", "1.1.0"));
        assert!(test("1.1.0", "1.1.1"));
        assert!(!test("1.0.0", "0.18.0"));
        assert!(!test("1.0.0", "2.0.0"));
        assert!(!test("1.1.0", "1.0.0"));
        assert!(test("1.0.3", "1.0.1"));

        assert!(test("0.19.0-alpha.1", "0.19.0-alpha.1"));
        assert!(!test("0.19.0-alpha.1", "0.19.0-alpha.2"));
    }

    #[test]

    // Checks wide version.
    fn check_wide_version() {

        // Tests the operation result.
        fn test(requested: &str, server: &str) -> bool {
            Compat::Wide.check(
                &Version::parse(requested).unwrap(),
                &Version::parse(server).unwrap(),
            )
        }

        assert!(test("0.1.0", "0.1.0"));
        assert!(test("0.1.0", "0.1.1"));
        assert!(test("0.1.0", "0.2.0"));
        assert!(test("0.1.0-rc.1", "0.2.0"));
        assert!(test("1.1.0", "1.0.0"));
        assert!(!test("1.0.0", "2.0.0"));
    }
}
