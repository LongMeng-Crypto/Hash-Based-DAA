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

use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};

use anyhow::Result;
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_zkp::core::hash::poseidon_254::Poseidon254HashSuite;
use risc0_zkvm_methods::{
    multi_test::MultiTestSpec, HELLO_COMMIT_ELF, HELLO_COMMIT_ID, MULTI_TEST_ELF, MULTI_TEST_ID,
    MULTI_TEST_PATH,
};
use tempfile::{tempdir, TempDir};
use test_log::test;

use super::{Asset, AssetRequest, ConnectionWrapper, Connector, TcpConnection};
use crate::{
    receipt::SuccinctReceipt, recursion::MerkleGroup, ApiClient, ApiServer, ExecutorEnv,
    InnerReceipt, ProveKeccakRequest, ProverOpts, Receipt, ReceiptClaim, SegmentReceipt,
    SessionInfo, SuccinctReceiptVerifierParameters, Unknown, VerifierContext,
};

struct TestClientConnector {
    listener: TcpListener,
}

impl TestClientConnector {

    // Creates the operation result.
    fn new() -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind("127.0.0.1:0")?,
        })
    }
}

impl Connector for TestClientConnector {

    // Implements connect.
    fn connect(&self) -> Result<ConnectionWrapper> {
        let (stream, _) = self.listener.accept()?;
        Ok(ConnectionWrapper::new(Arc::new(Mutex::new(
            TcpConnection::new(stream),
        ))))
    }
}

struct TestClient {
    work_dir: TempDir,
    client: ApiClient,
    addr: SocketAddr,
    segments: Vec<Asset>,
}

impl TestClient {

    // Creates the operation result.
    fn new() -> Self {
        let connector = TestClientConnector::new().unwrap();
        let addr = connector.listener.local_addr().unwrap();
        let client = ApiClient::with_connector(Box::new(connector));
        Self {
            work_dir: tempdir().unwrap(),
            client,
            addr,
            segments: Vec::new(),
        }
    }

    // Returns work path.
    fn get_work_path(&self) -> PathBuf {
        self.work_dir.path().to_path_buf()
    }

    // Implements execute.
    fn execute(&mut self, env: ExecutorEnv<'_>, binary: Asset) -> SessionInfo {
        with_server(self.addr, || {
            let segments_out = AssetRequest::Path(self.get_work_path());
            self.client
                .execute(&env, binary, segments_out, |_info, asset| {
                    self.segments.push(asset);
                    Ok(())
                })
        })
    }

    #[cfg(feature = "redis")]

    // Implements execute redis.
    fn execute_redis(
        &mut self,
        env: ExecutorEnv<'_>,
        binary: Asset,
        params: super::RedisParams,
    ) -> SessionInfo {
        with_server(self.addr, || {
            let segments_out = AssetRequest::Redis(params);
            self.client
                .execute(&env, binary, segments_out, |_info, asset| {
                    let Asset::Redis(_key) = asset else {
                        anyhow::bail!("wrong asset type");
                    };
                    Ok(())
                })
        })
    }

    // Proves the operation result.
    fn prove(&self, env: &ExecutorEnv<'_>, opts: &ProverOpts, binary: Asset) -> Receipt {
        with_server(self.addr, || self.client.prove(env, opts, binary)).receipt
    }

    // Proves segment.
    fn prove_segment(&self, opts: &ProverOpts, segment: Asset) -> SegmentReceipt {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.prove_segment(opts, segment, receipt_out)
        })
    }

    // Proves keccak.
    fn prove_keccak(&self, request: ProveKeccakRequest) -> SuccinctReceipt<Unknown> {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.prove_keccak(request, receipt_out)
        })
    }

    // Implements lift.
    fn lift(&self, opts: &ProverOpts, receipt: Asset) -> SuccinctReceipt<ReceiptClaim> {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.lift(opts, receipt, receipt_out)
        })
    }

    // Implements join.
    fn join(
        &self,
        opts: &ProverOpts,
        left_receipt: Asset,
        right_receipt: Asset,
    ) -> SuccinctReceipt<ReceiptClaim> {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client
                .join(opts, left_receipt, right_receipt, receipt_out)
        })
    }

    // Implements resolve.
    fn resolve(
        &self,
        opts: &ProverOpts,
        conditional_receipt: Asset,
        assumption_receipt: Asset,
    ) -> SuccinctReceipt<ReceiptClaim> {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client
                .resolve(opts, conditional_receipt, assumption_receipt, receipt_out)
        })
    }

    // Implements identity p254.
    fn identity_p254(&self, opts: &ProverOpts, receipt: Asset) -> SuccinctReceipt<ReceiptClaim> {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.identity_p254(opts, receipt, receipt_out)
        })
    }
}

// Implements with server.
fn with_server<T, F: FnOnce() -> Result<T>>(addr: SocketAddr, f: F) -> T {
    let addr = addr.to_string();
    let handle = thread::Builder::new()
        .name("server".into())
        .spawn(move || {
            let server = ApiServer::new_tcp(addr);
            server.run().unwrap();
        })
        .unwrap();

    let result = f().unwrap();
    handle.join().unwrap();
    result
}

#[test]

// Implements execute.
fn execute() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());
    TestClient::new().execute(env, binary);
}

#[test]

// Proves the operation result.
fn prove() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Path(MULTI_TEST_PATH.into());
    let opts = ProverOpts::default();
    let receipt = TestClient::new().prove(&env, &opts, binary);
    receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]

// Proves segment elf.
fn prove_segment_elf() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());

    let mut client = TestClient::new();

    let session = client.execute(env, binary);
    assert_eq!(session.segments.len(), client.segments.len());

    let ctx = VerifierContext::default();
    for segment in client.segments.iter() {
        let opts = ProverOpts::default();
        let receipt = client.prove_segment(&opts, segment.clone());
        receipt.verify_integrity_with_context(&ctx).unwrap();
    }
}

#[test]

// Implements lift join identity.
fn lift_join_identity() {
    let segment_limit_po2 = 16;
    let cycles = 1 << segment_limit_po2;
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::BusyLoop { cycles })
        .unwrap()
        .segment_limit_po2(segment_limit_po2)
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());

    let mut client = TestClient::new();

    let session = client.execute(env, binary);
    assert_eq!(session.segments.len(), client.segments.len());

    let opts = &ProverOpts::default();

    let receipt = client.prove_segment(opts, client.segments[0].clone());
    let mut rollup = client.lift(opts, receipt.try_into().unwrap());

    for segment in &client.segments[1..] {
        let receipt = client.prove_segment(opts, segment.clone());
        let rec_receipt = client.lift(opts, receipt.try_into().unwrap());

        rollup = client.join(
            opts,
            rollup.try_into().unwrap(),
            rec_receipt.try_into().unwrap(),
        );
        rollup
            .verify_integrity_with_context(&VerifierContext::default())
            .unwrap();
    }
    let p254_receipt = client.identity_p254(opts, rollup.clone().try_into().unwrap());

    let verifier_parameters = SuccinctReceiptVerifierParameters {
        control_root: MerkleGroup::new(vec![BN254_IDENTITY_CONTROL_ID])
            .unwrap()
            .calc_root(Poseidon254HashSuite::new_suite().hashfn.as_ref()),
        inner_control_root: Some(ALLOWED_CONTROL_ROOT),
        ..Default::default()
    };
    p254_receipt
        .verify_integrity_with_context(
            &VerifierContext::empty()
                .with_suites(BTreeMap::from([(
                    "poseidon_254".to_string(),
                    Poseidon254HashSuite::new_suite(),
                )]))
                .with_succinct_verifier_parameters(verifier_parameters),
        )
        .unwrap();

    let rollup_receipt = Receipt::new(InnerReceipt::Succinct(rollup), session.journal.bytes);
    rollup_receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]

// Implements lift resolve.
fn lift_resolve() {
    let mut client = TestClient::new();

    let hello_commit_binary = Asset::Inline(HELLO_COMMIT_ELF.into());
    let assumption_session = client.execute(ExecutorEnv::default(), hello_commit_binary);
    assert_eq!(assumption_session.segments.len(), 1);
    assert_eq!(client.segments.len(), 1);

    let opts = &ProverOpts::default();

    let assumption_segment_receipt = client.prove_segment(opts, client.segments[0].clone());
    assumption_segment_receipt
        .verify_integrity_with_context(&VerifierContext::default())
        .unwrap();
    let assumption_succinct_receipt =
        client.lift(opts, assumption_segment_receipt.try_into().unwrap());
    assumption_succinct_receipt
        .verify_integrity_with_context(&VerifierContext::default())
        .unwrap();

    let mut client = TestClient::new();

    let env = ExecutorEnv::builder()
        .add_assumption(assumption_succinct_receipt.claim.clone())
        .write(&MultiTestSpec::SysVerify(vec![(
            HELLO_COMMIT_ID.into(),
            b"hello world".to_vec(),
        )]))
        .unwrap()
        .build()
        .unwrap();
    let multi_test_binary = Asset::Inline(MULTI_TEST_ELF.into());
    let composition_session = client.execute(env, multi_test_binary);
    assert_eq!(assumption_session.segments.len(), 1);
    assert_eq!(client.segments.len(), 1);

    let composition_segment_receipt = client.prove_segment(opts, client.segments[0].clone());
    composition_segment_receipt
        .verify_integrity_with_context(&VerifierContext::default())
        .unwrap();
    let composition_succinct_receipt =
        client.lift(opts, composition_segment_receipt.try_into().unwrap());
    composition_succinct_receipt
        .verify_integrity_with_context(&VerifierContext::default())
        .unwrap();

    let succinct_receipt = client.resolve(
        opts,
        composition_succinct_receipt.try_into().unwrap(),
        assumption_succinct_receipt.try_into().unwrap(),
    );

    let receipt = Receipt::new(
        InnerReceipt::Succinct(succinct_receipt),
        composition_session.journal.bytes,
    );
    receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]
#[should_panic(expected = "MultiTestSpec::Panic invoked")]

// Implements guest error forwarding.
fn guest_error_forwarding() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::Panic)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());
    TestClient::new().execute(env, binary);
}

mod keccak_po2 {
    use std::{cell::RefCell, rc::Rc};

    use anyhow::Result;
    use risc0_zkvm_methods::{multi_test::MultiTestSpec, MULTI_TEST_ELF};
    use test_log::test;

    use super::Asset;
    use crate::{
        host::api::tests::TestClient, receipt::SuccinctReceipt, CoprocessorCallback, ExecutorEnv,
        ProveKeccakRequest, Unknown,
    };

    pub const KECCAK_TEST_PO2: u32 = 15;
    struct Coprocessor {
        pub(crate) receipt: Option<SuccinctReceipt<Unknown>>,
    }

    impl Coprocessor {

        // Creates the operation result.
        fn new() -> Self {
            Self { receipt: None }
        }
    }

    impl CoprocessorCallback for Coprocessor {

        // Proves keccak.
        fn prove_keccak(&mut self, proof_request: ProveKeccakRequest) -> Result<()> {
            assert_eq!(proof_request.po2, KECCAK_TEST_PO2 as usize);
            let client = TestClient::new();
            let receipt = client.prove_keccak(proof_request);
            self.receipt = Some(receipt);
            Ok(())
        }
    }

    #[test]

    // Implements keccak max po2.
    fn keccak_max_po2() {
        let mut client = TestClient::new();

        let spec = &MultiTestSpec::KeccakUpdate2;
        let coprocessor = Rc::new(RefCell::new(Coprocessor::new()));

        let env = ExecutorEnv::builder()
            .coprocessor_callback_ref(coprocessor.clone())
            .write(&spec)
            .unwrap()
            .keccak_max_po2(KECCAK_TEST_PO2)
            .unwrap()
            .build()
            .unwrap();

        let _session = client.execute(env, Asset::Inline(MULTI_TEST_ELF.into()));
    }
}

#[test(tokio::test)]
#[cfg(feature = "redis")]

// Implements redis asset.
async fn redis_asset() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind to port 6379");
    let url = listener.local_addr().unwrap().to_string();

    let _ = mini_redis::server::run(
        listener,
        tokio::task::spawn_blocking(move || {
            let redis_params = super::RedisParams {
                url: format!("redis://{url}"),
                key: "key".to_string(),
                ttl: 180,
            };

            let binary = Asset::Inline(MULTI_TEST_ELF.into());
            let env = ExecutorEnv::builder()
                .write(&MultiTestSpec::DoNothing)
                .unwrap()
                .build()
                .unwrap();
            let mut client = TestClient::new();
            let _session_info = client.execute_redis(env, binary, redis_params);
        }),
    )
    .await;
}

#[test(tokio::test)]
#[cfg(feature = "redis")]
#[ignore]

// Implements redis asset external node.
async fn redis_asset_external_node() {
    let url = "127.0.0.1:6379";
    let redis_params = super::RedisParams {
        url: format!("redis://{url}"),
        key: "key".to_string(),
        ttl: 180,
    };

    let binary = Asset::Inline(MULTI_TEST_ELF.into());
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::BusyLoop { cycles: 1000000000 })
        .unwrap()
        .build()
        .unwrap();
    let mut client = TestClient::new();
    let _session_info = client.execute_redis(env, binary, redis_params);
}
