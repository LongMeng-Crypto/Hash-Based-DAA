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

use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bonsai_sdk::blocking::Client;

use super::Prover;
use crate::{
    compute_image_id, AssumptionReceipt, ExecutorEnv, InnerAssumptionReceipt, InnerReceipt,
    ProveInfo, ProverOpts, Receipt, ReceiptKind, SessionStats, VerifierContext, VERSION,
};

pub struct BonsaiProver {
    name: String,
}

impl BonsaiProver {

    // Creates the operation result.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

// Returns inner assumption receipt.
fn get_inner_assumption_receipt(assumption: &AssumptionReceipt) -> Result<&InnerAssumptionReceipt> {
    match assumption {
        AssumptionReceipt::Proven(receipt) => {
            if !matches!(receipt, InnerAssumptionReceipt::Succinct(_)) {
                bail!(
                    "Bonsai only supports succinct assumption receipts. \
                    Use `ProverOpts::succinct()` when proving any assumptions."
                );
            };
            Ok(receipt)
        }
        AssumptionReceipt::Unresolved(_) => {
            bail!("only proven assumptions can be uploaded to Bonsai.")
        }
    }
}

impl Prover for BonsaiProver {

    // Returns name.
    fn get_name(&self) -> String {
        self.name.clone()
    }

    // Proves with ctx.
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
        opts: &ProverOpts,
    ) -> Result<ProveInfo> {
        let client = Client::from_env(VERSION)?;

        let image_id = compute_image_id(elf)?;
        let image_id_hex = hex::encode(image_id);
        client.upload_img(&image_id_hex, elf.to_vec())?;

        let input_id = client.upload_input(env.input)?;

        let mut receipts_ids = vec![];
        for assumption in env.assumptions.borrow().0.iter() {
            let inner_receipt = get_inner_assumption_receipt(assumption)?;
            let serialized_receipt = bincode::serialize(inner_receipt)?;
            let receipt_id = client.upload_receipt(serialized_receipt)?;
            receipts_ids.push(receipt_id);
        }

        let session = client.create_session_with_limit(
            image_id_hex,
            input_id,
            receipts_ids,
            false,
            env.session_limit,
        )?;
        tracing::debug!("Bonsai proving SessionID: {}", session.uuid);

        let polling_interval = if let Ok(ms) = std::env::var("BONSAI_POLL_INTERVAL_MS") {
            Duration::from_millis(ms.parse().context("invalid bonsai poll interval")?)
        } else {
            Duration::from_secs(1)
        };
        let succinct_prove_info = loop {

            let res = session.status(&client)?;
            if res.status == "RUNNING" {
                std::thread::sleep(polling_interval);
                continue;
            }
            if res.status == "SUCCEEDED" {

                let receipt_url = res
                    .receipt_url
                    .ok_or_else(|| anyhow!("API error, missing receipt on completed session"))?;

                let stats = res
                    .stats
                    .context("Missing stats object on Bonsai status res")?;
                tracing::debug!(
                    "Bonsai usage: cycles: {} total_cycles: {}",
                    stats.cycles,
                    stats.total_cycles
                );

                let receipt_buf = client.download(&receipt_url)?;
                let receipt: Receipt = bincode::deserialize(&receipt_buf)?;

                if opts.prove_guest_errors {
                    receipt.verify_integrity_with_context(ctx)?;
                } else {
                    receipt.verify_with_context(ctx, image_id)?;
                }
                break ProveInfo {
                    receipt,
                    work_receipt: None,
                    stats: SessionStats {
                        segments: stats.segments,
                        total_cycles: stats.total_cycles,
                        user_cycles: stats.cycles,

                        paging_cycles: 0,
                        reserved_cycles: 0,
                    },
                };
            } else {
                bail!(
                    "Bonsai prover workflow [{}] exited: {} err: {}",
                    session.uuid,
                    res.status,
                    res.error_msg
                        .unwrap_or("Bonsai workflow missing error_msg".into()),
                );
            }
        };
        match opts.receipt_kind {

            ReceiptKind::Composite | ReceiptKind::Succinct => {
                return Ok(succinct_prove_info);
            }

            ReceiptKind::Groth16 => {}
        }

        let snark_session = client.create_snark(session.uuid)?;
        let snark_receipt_url = loop {
            let res = snark_session.status(&client)?;
            match res.status.as_str() {
                "RUNNING" => {
                    std::thread::sleep(polling_interval);
                    continue;
                }
                "SUCCEEDED" => {
                    break res.output.with_context(|| {
                        format!(
                            "Bonsai prover workflow [{}] reported success, but provided no receipt",
                            snark_session.uuid
                        )
                    })?;
                }
                _ => {
                    bail!(
                        "Bonsai prover workflow [{}] exited: {} err: {}",
                        snark_session.uuid,
                        res.status,
                        res.error_msg
                            .unwrap_or("Bonsai workflow missing error_msg".into()),
                    );
                }
            }
        };

        let receipt_buf = client.download(&snark_receipt_url)?;
        let groth16_receipt: Receipt = bincode::deserialize(&receipt_buf)?;
        groth16_receipt
            .verify_integrity_with_context(ctx)
            .context("failed to verify Groth16Receipt returned by Bonsai")?;

        Ok(ProveInfo {
            receipt: groth16_receipt,
            work_receipt: None,
            stats: succinct_prove_info.stats,
        })
    }

    // Implements compress.
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt> {
        match (&receipt.inner, opts.receipt_kind) {

            (InnerReceipt::Composite(_), ReceiptKind::Composite)
            | (InnerReceipt::Succinct(_), ReceiptKind::Composite | ReceiptKind::Succinct)
            | (
                InnerReceipt::Groth16(_),
                ReceiptKind::Composite | ReceiptKind::Succinct | ReceiptKind::Groth16,
            ) => Ok(receipt.clone()),

            (InnerReceipt::Fake { .. }, _) => {
                ensure!(
                    opts.dev_mode(),
                    "dev mode must be enabled to compress fake receipts"
                );
                Ok(receipt.clone())
            }

            (_, ReceiptKind::Succinct) => {
                bail!("BonsaiProver does not support compression on existing receipts");
            }
            (_, ReceiptKind::Groth16) => {

                bail!([
                    "BonsaiProver does not support compression on existing receipts",
                    "Set receipt_kind on ProverOpts in initial prove request to get a Groth16Receipt."
                ].join(""));
            }
        }
    }
}
