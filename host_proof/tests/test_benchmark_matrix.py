import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('benchmark', ROOT/'scripts/benchmark.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class BenchmarkMatrixTests(unittest.TestCase):
    # Isolates benchmark selectors from the invoking shell.
    def setUp(self):
        self.environment = patch.dict(os.environ, os.environ.copy(), clear=True)
        self.environment.start()
        for key in ('PARAMS_LIST', 'HOOK_MODES', 'HOST_SCHEMES', 'SETUP_MODES', 'RECEIPTS',
                    'CREDENTIALS', 'ITERATIONS', 'SEGMENT_PO2', 'DAA_HOST_CUDA', 'SUITES',
                    'DRY_RUN', 'BENCH_OUTPUT_DIR', 'PARAMETERS', 'PHASES', 'SECURITY', 'PROFILE', 'SCHEME',
                    'ANCHOR_MODE', 'HOST_HOOK_MODE', 'FSPHINCS_PARAMS_LIST', 'SEGMENT_PO2_LIST',
                    'RECEIPT_LIST', 'RUN_SETUP'):
            os.environ.pop(key, None)
        self.addCleanup(self.environment.stop)

    # Checks the paper's parameter and receipt coverage without duplicate cases.
    def test_complete_matrices(self):
        cases = BENCH.matrix(BENCH.SUITES, BENCH.configuration())
        self.assertEqual({s: sum(c['suite'] == s for c in cases) for s in BENCH.SUITES},
                         dict(credentials=12, setup=24, tpm=3, host=82, protocol=124))
        self.assertEqual(len(cases), len({c['id'] for c in cases}))
        protocol = [c for c in cases if c['suite'] == 'protocol']
        self.assertEqual(sum(c['setup'] == 'fixed-wots' for c in protocol), 42)
        self.assertEqual(sum(c['hook'] == 'sha2-5f' for c in protocol), 12)
        for case in protocol:
            self.assertEqual(case['host'] == 'fsphincs', case['setup'] == 'fsphincs-seed')
            if case['hook'] == 'sha2-5f':
                self.assertEqual(case['host'], 'fsphincs')
            if case['hook'] == 'rijndael-3f':
                self.assertTrue(case['param'].startswith('128'))
            if case['host'] == 'recursive-zk':
                self.assertEqual(case['receipt'], 'succinct')

    # Rejects incompatible or empty selections before any expensive operation.
    def test_selection_validation(self):
        os.environ.update(PARAMS_LIST='sha2-128f,128f')
        cfg = BENCH.configuration()
        self.assertEqual(cfg['params'], ('128f',))
        self.assertEqual(len(BENCH.matrix(('protocol',), cfg)), 26)
        os.environ.update(HOST_SCHEMES='recursive-zk', RECEIPTS='composite')
        with self.assertRaises(ValueError):
            BENCH.matrix(('host',), BENCH.configuration())
        os.environ['RECEIPTS'] = 'groth16'
        with self.assertRaises(ValueError):
            BENCH.configuration()

    # Rejects a stale selector instead of silently launching an unintended full sweep.
    def test_rejected_selector(self):
        os.environ['ANCHOR_MODE'] = 'fixed-top-wots'
        with self.assertRaisesRegex(ValueError, 'SETUP_MODES'):
            BENCH.configuration()

    # Checks CPU/GPU routing and removes inherited execution-only or fake-proof settings.
    def test_explicit_prover_environment(self):
        os.environ.update(RISC0_DEV_MODE='1', FSPHINCS_EXECUTE_ONLY='1', RISC0_SKIP_BUILD='1',
                          DAA_TPM_BACKEND='aes', DAA_HOST_CUDA='0')
        cfg = BENCH.configuration()
        for case in BENCH.matrix(('host', 'protocol'), cfg):
            env = BENCH.environment(case, cfg)
            command, _ = BENCH.commands(case, cfg, Path('/tmp/daa-benchmark-test-output'))
            self.assertEqual(env['RISC0_DEV_MODE'], '0')
            self.assertNotIn('RISC0_SKIP_BUILD', env)
            self.assertNotIn('FSPHINCS_EXECUTE_ONLY', env)
            self.assertEqual(env['DAA_TPM_BACKEND'], case['hook'].split('-')[0])
            self.assertEqual(env['RISC0_IDENTITY_WRAP'], '1' if case['host'] == 'recursive-zk' else '0')
            if case['suite'] == 'host':
                self.assertNotIn('--features', command)
            else:
                self.assertIn('--json', command)
                self.assertIn('--issuer-anchor-mode', command)
        cfg['cuda'] = '1'
        case = BENCH.matrix(('host',), cfg)[0]
        self.assertIn('cuda', BENCH.commands(case, cfg, Path('/tmp'))[0])

    # Confirms every shell entrypoint can preview its matrix without creating output.
    def test_dry_run_entrypoints(self):
        paths = ['/usr/local/bin', '/usr/bin', '/bin']
        os.environ['PATH'] = ':'.join(paths)
        names = ('run_all_benchmarks.sh', 'benchmark_credentials.sh', 'benchmark_issuer_anchors.sh',
                 'benchmark_host.sh', 'benchmark_protocol.sh', 'benchmark_tpm_aes_vole.sh',
                 'benchmark_tpm_rijndael_dm.sh', 'benchmark_tpm_sha_relations.sh')
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'unused'
            os.environ.update(DRY_RUN='1', BENCH_OUTPUT_DIR=str(output))
            for name in names:
                text = subprocess.check_output(['bash', str(ROOT/'scripts'/name)], text=True)
                plan = json.loads(text)
                self.assertTrue(plan['cases'])
                if name == 'run_all_benchmarks.sh':
                    self.assertNotIn('protocol', plan['counts'])
                self.assertFalse(output.exists())

    # Rejects incomplete or partly unsuccessful protocol repetitions.
    def test_protocol_statuses(self):
        case = dict(suite='protocol', id='protocol-test')
        good = 'iteration 1: verify=true link_same=true link_diff=false\n'
        bad = 'iteration 2: verify=false link_same=true link_diff=false\n'
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output/'protocol-test.json').write_text(json.dumps(dict(iterations=2, averages=dict(entries=[], sizes=[]))))
            with self.assertRaises(RuntimeError):
                BENCH.metrics(case, good, output)
            with self.assertRaises(RuntimeError):
                BENCH.metrics(case, good+bad, output)
            BENCH.metrics(case, good+good.replace('iteration 1', 'iteration 2'), output)

    # Checks Host repetition counts and the resulting arithmetic means through the CLI.
    def test_host_repetitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cargo = tmp/'cargo'
            cargo.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
assert os.environ['RISC0_DEV_MODE'] == '0'
assert os.environ['DAA_TPM_BACKEND'] == 'sha2'
assert os.environ['DAA_TPM_SHA_SCHEME'] == 'chen23'
p = Path(os.environ['TEST_COUNTER'])
n = int(p.read_text())+1 if p.exists() else 1
p.write_text(str(n))
print(f'prover_us={10*n}\\nverifier_us={n}\\nproof_bytes=100\\nseal_bytes=80')
''')
            cargo.chmod(0o755)
            os.environ.update(PATH=str(tmp)+':/usr/local/bin:/usr/bin:/bin', TEST_COUNTER=str(tmp/'counter'),
                              PARAMS_LIST='128f', HOOK_MODES='sha2-5f', HOST_SCHEMES='fsphincs',
                              RECEIPTS='succinct', ITERATIONS='3', DAA_HOST_CUDA='0', BENCH_OUTPUT_DIR=str(tmp/'out'))
            subprocess.run([sys.executable, str(ROOT/'scripts/benchmark.py'), 'host'], check=True, stdout=subprocess.DEVNULL)
            self.assertEqual((tmp/'counter').read_text(), '3')
            with (tmp/'out/summary.tsv').open() as stream:
                rows = {r['metric']: r['value'] for r in csv.DictReader(stream, delimiter='\t')}
            self.assertEqual(rows['prover_us'], '20')
            self.assertEqual(rows['verifier_us'], '2')


if __name__ == '__main__':
    unittest.main()
