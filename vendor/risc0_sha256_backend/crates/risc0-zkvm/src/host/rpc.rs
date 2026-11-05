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

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{AssumptionReceipt, Journal, Receipt};

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {

    pub binary: Vec<u8>,

    pub input: Vec<u8>,

    pub assumptions: Vec<AssumptionReceipt>,

    pub segment_limit_po2: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobInfo {

    pub status: JobStatus,

    pub elapsed_time: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JobStatus {

    Running(String),

    Succeeded(ProofResult),

    Failed(TaskError),

    TimedOut,

    Aborted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofResult {

    pub session: Arc<Session>,

    pub receipt: Arc<Receipt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {

    pub segment_count: usize,

    pub user_cycles: u64,

    pub total_cycles: u64,

    pub journal: Option<Journal>,

    pub assumptions: Vec<Arc<AssumptionReceipt>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaskError {

    Generic(String),
}

impl JobStatus {

    // Implements bonsai status.
    pub fn bonsai_status(&self) -> &str {
        match self {
            JobStatus::Running(_) => "RUNNING",
            JobStatus::Succeeded(_) => "SUCCEEDED",
            JobStatus::Failed(_) => "FAILED",
            JobStatus::TimedOut => "TIMED_OUT",
            JobStatus::Aborted => "ABORTED",
        }
    }
}

impl From<anyhow::Error> for TaskError {

    // Implements from.
    fn from(value: anyhow::Error) -> Self {
        Self::Generic(value.to_string())
    }
}
