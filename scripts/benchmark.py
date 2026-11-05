#!/usr/bin/env python3
import argparse
import csv
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
PARAMS = ('128s', '128f', '192s', '192f', '256s', '256f')
HOOKS = ('aes-3f', 'rijndael-3f', 'sha2-3f', 'sha2-5f')
HOSTS = ('recursive-zk', 'zk-wots', 'fsphincs')
SETUPS = ('sphincs-seed', 'fsphincs-seed', 'fixed-wots')
SUITES = ('credentials', 'setup', 'tpm', 'host', 'protocol')


# Parses a validated selection while removing duplicate work.
def selection(name, default, allowed, normalize=lambda x: x):
    values = tuple(dict.fromkeys(normalize(x) for x in os.environ.get(name, default).replace(',', ' ').split()))
    if not values or any(x not in allowed for x in values):
        raise ValueError(f'{name} must select from: {", ".join(allowed)}')
    return values


# Validates benchmark options before building or creating output files.
def configuration():
    selectors = dict(ANCHOR_MODE='SETUP_MODES', HOST_HOOK_MODE='HOOK_MODES',
                     FSPHINCS_PARAMS_LIST='PARAMS_LIST', SEGMENT_PO2_LIST='SEGMENT_PO2',
                     RECEIPT_LIST='RECEIPTS', RUN_SETUP='SUITES')
    for name, replacement in selectors.items():
        if name in os.environ:
            raise ValueError(f'use {replacement} instead of {name}')
    iterations = int(os.environ.get('ITERATIONS', '1'))
    segment = int(os.environ.get('SEGMENT_PO2', '20'))
    cuda = os.environ.get('DAA_HOST_CUDA', '1')
    if not 1 <= iterations <= 4294967295:
        raise ValueError('ITERATIONS must be a positive 32-bit integer')
    if not 14 <= segment <= 22 or cuda not in ('0', '1'):
        raise ValueError('SEGMENT_PO2 must be 14..22 and DAA_HOST_CUDA must be 0 or 1')
    return dict(
        iterations=iterations, segment=segment, cuda=cuda,
        params=selection('PARAMS_LIST', ' '.join(PARAMS), PARAMS, lambda x: x.removeprefix('sha2-')),
        hooks=selection('HOOK_MODES', ' '.join(HOOKS), HOOKS),
        hosts=selection('HOST_SCHEMES', ' '.join(HOSTS), HOSTS),
        setups=selection('SETUP_MODES', ' '.join(SETUPS), SETUPS),
        receipts=selection('RECEIPTS', 'composite succinct', ('composite', 'succinct')),
        credentials=selection('CREDENTIALS', 'sphincs fsphincs', ('sphincs', 'fsphincs')),
    )


# Creates the supported paper and protocol benchmark matrices.
def matrix(suites, cfg):
    cases = []
    def add(suite, **fields):
        identity = '-'.join(str(x) for x in fields.values())
        cases.append(dict(suite=suite, id=f'{suite}-{identity}', **fields))
    for suite in suites:
        if suite == 'credentials':
            for param in cfg['params']:
                for credential in cfg['credentials']:
                    add(suite, param=param, credential=credential)
        elif suite == 'setup':
            for param in cfg['params']:
                for setup in cfg['setups']:
                    receipts = cfg['receipts'] if setup == 'fixed-wots' else ('native',)
                    for receipt in receipts:
                        add(suite, param=param, setup=setup, receipt=receipt)
        elif suite == 'tpm':
            for primitive in ('aes', 'rijndael', 'sha2'):
                params = [p for p in cfg['params'] if primitive != 'rijndael' or p.startswith('128')]
                if params:
                    add(suite, primitive=primitive, params=','.join(params))
        else:
            for hook in cfg['hooks']:
                for param in cfg['params']:
                    if hook == 'rijndael-3f' and not param.startswith('128'):
                        continue
                    for host in cfg['hosts']:
                        if hook == 'sha2-5f' and host != 'fsphincs':
                            continue
                        setups = ('none',) if suite == 'host' else tuple(
                            s for s in cfg['setups'] if (s == 'fsphincs-seed') == (host == 'fsphincs'))
                        for setup in setups:
                            for receipt in cfg['receipts']:
                                if host == 'recursive-zk' and receipt != 'succinct':
                                    continue
                                fields = dict(param=param, hook=hook, host=host, receipt=receipt)
                                if suite == 'protocol':
                                    fields['setup'] = setup
                                add(suite, **fields)
    if not cases:
        raise ValueError('the selected options contain no supported benchmark cases')
    return cases


# Sets explicit prover inputs so inherited demo settings cannot change a measurement.
def environment(case, cfg):
    env = os.environ.copy()
    for key in ('RISC0_SKIP_BUILD', 'FSPHINCS_EXECUTE_ONLY', 'FSPHINCS_SECURITY', 'FSPHINCS_K',
                'DAA_HOST_SCHEME', 'DAA_CREDENTIAL_SCHEME', 'DAA_TPM_BACKEND', 'DAA_TPM_SHA_SCHEME',
                'SPHINCS_PARAMS', 'FSPHINCS_PARAMS', 'RISC0_RECEIPT_KIND', 'RISC0_IDENTITY_WRAP'):
        env.pop(key, None)
    env.update(RISC0_PROVER='local', RISC0_DEV_MODE='0', RISC0_BACKEND_HASH='sha-256',
               DAA_HOST_CUDA=cfg['cuda'], DAA_DETERMINISTIC='1',
               RISC0_SEGMENT_LIMIT_PO2=str(cfg['segment']), SPHINCS_THASH='simple',
               CARGO_TARGET_DIR=os.environ.get('CARGO_TARGET_DIR', str(Path.home()/'.cache/daa-full-target')))
    if 'param' in case:
        env.update(SPHINCS_PARAMS='sphincs-sha2-'+case['param'], FSPHINCS_PARAMS=case['param'])
    if case['suite'] in ('host', 'protocol'):
        primitive, relation = case['hook'].split('-')
        env.update(DAA_TPM_BACKEND=primitive, DAA_TPM_SHA_SCHEME='chen23' if relation == '5f' else 'ours',
                   DAA_HOST_SCHEME=case['host'], DAA_CREDENTIAL_SCHEME='fsphincs' if case['host'] == 'fsphincs' else 'sphincs',
                   RISC0_RECEIPT_KIND=case['receipt'], RISC0_IDENTITY_WRAP='1' if case['host'] == 'recursive-zk' else '0')
    elif case['suite'] == 'setup':
        env.update(RISC0_RECEIPT_KIND='composite' if case['receipt'] == 'native' else case['receipt'], RISC0_IDENTITY_WRAP='0')
        if case['setup'] != 'fixed-wots':
            env['RISC0_SKIP_BUILD'] = '1'
    return env


# Builds one command and any native preparation command for a matrix entry.
def commands(case, cfg, output):
    suite = case['suite']
    iterations = str(cfg['iterations'])
    cargo = ['cargo', 'run', '--locked', '--release']
    if suite == 'credentials':
        spx = ROOT/'host_proof/methods/guest/c_src/sphincs_ref'
        fs = spx.parent/'fsphincs_ref'
        native_dir = Path(os.environ.get('CREDENTIAL_BUILD_DIR', str(Path.home()/'.cache/daa-native-credentials')))
        binary = native_dir/f"{case['credential']}-{case['param']}"
        build = shlex.split(os.environ.get('CC', 'cc')) + ['-O3', '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-I'+str(spx), '-DPARAMS=sphincs-sha2-'+case['param'], str(ROOT/'host_proof/native/credential_benchmark.c')]
        if case['credential'] == 'fsphincs':
            build.insert(build.index('-I'+str(spx)), '-I'+str(fs))
            build += ['-DDAA_BENCH_FSPHINCS', '-DFSPHINCS_PARAMS='+case['param'], str(fs/'fsphincs.c'), str(fs/'issuer_anchor.c')]
            sources = ['sha2.c']
        else:
            sources = ['sign.c', 'address.c', 'fors.c', 'merkle.c', 'wots.c', 'wotsx1.c', 'utils.c', 'utilsx1.c', 'sha2.c', 'hash_sha2.c', 'thash_sha2_simple.c']
        build += [str(spx/s) for s in sources] + ['-o', str(binary)]
        return [str(binary), iterations], build
    if suite == 'tpm':
        names = dict(aes='benchmark_tpm_aes_vole.sh', rijndael='benchmark_tpm_rijndael_dm.sh', sha2='benchmark_tpm_sha_relations.sh')
        return ['bash', str(ROOT/'scripts'/names[case['primitive']])], None
    if suite == 'host':
        binary = 'bench_fsphincs_risc0' if case['host'] == 'fsphincs' else 'daa_sha256_backend_host'
        cmd = cargo + ['-p', 'daa_sha256_backend_host', '--bin', binary]
        if cfg['cuda'] == '1':
            cmd += ['--features', 'cuda']
        return cmd, None
    cmd = cargo + ['-p', 'daa_cli', '--', 'bench-issuer-anchor' if suite == 'setup' else 'bench',
                   '--params', 'sha2-'+case['param'], '--iterations', iterations, '--backend', 'sha-256',
                   '--segment-po2', str(cfg['segment'])]
    credential = 'fsphincs' if case['setup'] == 'fsphincs-seed' else 'sphincs'
    cmd += ['--issuer-anchor-mode', 'fixed-top-wots' if case['setup'] == 'fixed-wots' else 'seed-anchor']
    if suite == 'setup':
        cmd += ['--credential-scheme', credential, '--proof-mode', 'real-tpm']
    else:
        primitive, relation = case['hook'].split('-')
        cmd += ['--tpm-backend', primitive, '--tpm-sha-scheme', 'chen23' if relation == '5f' else 'ours',
                '--host-scheme', case['host'], '--proof-mode', 'real', '--json', str(output/(case['id']+'.json'))]
    return cmd, None


# Streams one process to the console and its per-case log.
def execute(command, env, logfile):
    print('$ '+shlex.join(command), flush=True)
    with logfile.open('w') as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in process.stdout:
            print(line, end='', flush=True)
            log.write(line)
            lines.append(line)
        if process.wait():
            raise RuntimeError(f'benchmark failed; see {logfile}')
    return ''.join(lines)


# Extracts the separately reported timings and sizes without averaging compilation costs.
def metrics(case, text, output):
    values = dict(re.findall(r'^([A-Za-z_][\w.]*)=([0-9]+(?:\.[0-9]+)?)\s*$', text, re.M))
    required = dict(credentials=('keygen_ms', 'sign_ms', 'verify_ms', 'signature_bytes'),
                    setup=('keygen_ms', 'pi_i_prover_ms', 'pi_i_verifier_ms', 'pi_i_proof_bytes'),
                    host=('prover_us', 'verifier_us', 'proof_bytes', 'seal_bytes'))
    if any(key not in values for key in required.get(case['suite'], ())):
        raise RuntimeError('benchmark output is missing required measurements: '+case['id'])
    if case['suite'] == 'tpm':
        if case['primitive'] in ('aes', 'rijndael'):
            for phase, param, prove, verify, size in re.findall(r'^(join|sign)\t(\d+[sf])\t([0-9.]+)\t([0-9.]+)\t(\d+)\s*$', text, re.M):
                prefix = param+'.'+phase
                values.update({prefix+'.prover_ms': prove, prefix+'.verifier_ms': verify, prefix+'.proof_bytes': size})
        else:
            param, relation = '', ''
            for line in text.splitlines():
                header = re.search(r'scheme=(\S+) security=(\d+) profile=([sf])', line)
                if header:
                    scheme, level, profile = header.groups()
                    param, relation = level+profile, '5f' if 'Chen23' in scheme else '3f'
                if line.startswith(('join ', 'sign ')):
                    phase = 'join-1f' if line.startswith('join ') else 'sign-'+relation
                    for key, value in re.findall(r'(prover_ms|verifier_ms|proof_bytes)=([0-9.]+)', line):
                        values[param+'.'+phase+'.'+key] = value
        expected = len(case['params'].split(',')) * (3 if case['primitive'] == 'sha2' else 2)
        if sum(key.endswith('.proof_bytes') for key in values) != expected:
            raise RuntimeError('TPM output does not cover the selected relations: '+case['id'])
    if case['suite'] == 'protocol':
        trace = json.loads((output/(case['id']+'.json')).read_text())
        data = trace['averages']
        values.update({entry['name']+'.us': str(entry['micros']) for entry in data['entries']})
        values.update({entry['name']+'.bytes': str(entry['bytes']) for entry in data['sizes']})
        statuses = re.findall(r'^iteration\s+\d+: verify=(true|false) link_same=(true|false) link_diff=(true|false)$', text, re.M)
        if len(statuses) != trace['iterations'] or any(status != ('true', 'true', 'false') for status in statuses):
            raise RuntimeError('full protocol did not report successful verification and linking for every repetition')
    return values


# Runs a selected suite or prints its complete matrix without building anything.
def main():
    parser = argparse.ArgumentParser(description='DAA paper and full-protocol benchmark suites')
    parser.add_argument('suite', choices=SUITES+('paper', 'all'))
    parser.add_argument('--tpm-backend', choices=('aes', 'rijndael', 'sha2'))
    parser.add_argument('--list', action='store_true', help='print the matrix without building or proving')
    args = parser.parse_args()
    cfg = configuration()
    if args.suite == 'paper':
        suites = selection('SUITES', 'credentials setup tpm host', SUITES+('all',))
        if 'all' in suites:
            suites = SUITES
    else:
        suites = SUITES if args.suite == 'all' else (args.suite,)
    cases = matrix(suites, cfg)
    if args.tpm_backend:
        if args.suite != 'tpm':
            raise ValueError('--tpm-backend selects a native TPM suite only')
        cases = [c for c in cases if c['primitive'] == args.tpm_backend]
        if not cases:
            raise ValueError('no supported TPM parameters selected')
    if args.list or os.environ.get('DRY_RUN') == '1':
        print(json.dumps(dict(counts={s: sum(c['suite'] == s for c in cases) for s in suites}, cases=cases), indent=2))
        return
    output = Path(os.environ.get('BENCH_OUTPUT_DIR', str(ROOT/'results/benchmarks'/datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output/'cases.json').write_text(json.dumps(dict(configuration=cfg, cases=cases), indent=2)+'\n')
    with (output/'summary.tsv').open('w') as summary:
        writer = csv.writer(summary, delimiter='\t')
        writer.writerow(('case', 'metric', 'value', 'log'))
        for number, case in enumerate(cases, 1):
            print(f'[{number}/{len(cases)}] {case["id"]}', flush=True)
            env = environment(case, cfg)
            if case['suite'] == 'tpm':
                env.update(ITERATIONS=str(cfg['iterations']), PARAMETERS=case['params'], PARAMS_LIST=case['params'],
                           PHASES='join,sign', SCHEME='all', SECURITY='all', PROFILE='all',
                           TPM_AES_LOG_DIR=str(output), TPM_RDM_LOG_DIR=str(output))
            cmd, build = commands(case, cfg, output)
            if build:
                Path(cmd[0]).parent.mkdir(parents=True, exist_ok=True)
                execute(build, env, output/(case['id']+'-build.log'))
            repetitions = cfg['iterations'] if case['suite'] == 'host' else 1
            samples, logs = [], []
            for run in range(1, repetitions+1):
                log = output/(case['id']+f'-run{run}.log')
                text = execute(cmd, env, log)
                samples.append(metrics(case, text, output))
                logs.append(log.name)
            if any(sample.keys() != samples[0].keys() for sample in samples):
                raise RuntimeError('inconsistent measurement fields between repetitions')
            for key in samples[0]:
                value = sum(Decimal(sample[key]) for sample in samples) / repetitions
                writer.writerow((case['id'], key, str(value), ','.join(logs)))
            summary.flush()
    print(f'benchmark_complete=1\noutput={output}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f'error: {error}', file=sys.stderr)
        sys.exit(1)
