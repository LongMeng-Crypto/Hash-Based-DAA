use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use daa_core::{run_full, BenchmarkTrace, ProofMode, ProtocolConfig};

/// Starts the CLI and prints fatal errors.
fn main() {
    if let Err(err) = real_main() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

/// Parses the top-level command and dispatches it.
fn real_main() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("run-full");
    let opts = CliOptions::parse(&args[1..])?;

    match command {
        "run-full" => run_full_cmd(opts),
        "bench" => bench_cmd(opts),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command '{other}'. Try 'help'.")),
    }
}

/// Runs the complete protocol once and prints the trace.
fn run_full_cmd(opts: CliOptions) -> Result<(), String> {
    let config = opts.config();
    let output = run_full(config).map_err(|err| err.to_string())?;

    println!("DAA full protocol run");
    println!("  verify accepted           : {}", output.accepted);
    println!("  link same basename        : {}", output.linked_same_bsn);
    println!(
        "  link different basename   : {}",
        output.linked_different_bsn
    );
    println!(
        "  signature rho             : {} bytes",
        output.signature.rho.len()
    );
    println!(
        "  signature slt             : {} bytes",
        output.signature.slt.len()
    );
    println!(
        "  signature hk              : {} bytes",
        output.signature.hk.len()
    );
    println!(
        "  pi_tpm                    : {} bytes ({})",
        output.signature.pi_tpm.size_bytes(),
        output.signature.pi_tpm.backend
    );
    println!(
        "  pi_host                   : {} bytes ({})",
        output.signature.pi_host.size_bytes(),
        output.signature.pi_host.backend
    );
    println!();
    print_trace(&output.trace);
    Ok(())
}

/// Runs repeated complete-protocol benchmarks and reports averages.
fn bench_cmd(opts: CliOptions) -> Result<(), String> {
    let iterations = opts.iterations.max(1);
    let started = Instant::now();
    let mut aggregate = Vec::new();

    for i in 0..iterations {
        let mut config = opts.config();
        config.deterministic_seed ^= i as u64;
        let output = run_full(config).map_err(|err| err.to_string())?;
        println!(
            "iteration {:>3}: verify={} link_same={} link_diff={}",
            i + 1,
            output.accepted,
            output.linked_same_bsn,
            output.linked_different_bsn
        );
        aggregate.push(output.trace);
    }

    let merged = merge_traces(&aggregate);
    println!();
    println!("DAA benchmark summary over {iterations} iteration(s)");
    println!(
        "wall time: {:.3} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    print_trace(&merged);

    if let Some(path) = opts.json {
        write_json(&path, iterations, &merged)?;
        println!();
        println!("wrote JSON benchmark trace to {}", path.display());
    }

    Ok(())
}

/// Prints a benchmark trace as a compact table.
fn print_trace(trace: &BenchmarkTrace) {
    println!("{:<32} {:>14}", "step", "time (ms)");
    println!("{:-<47}", "");
    for entry in trace.entries() {
        println!("{:<32} {:>14.3}", entry.name, entry.micros as f64 / 1000.0);
    }
}

/// Averages multiple benchmark traces by entry name.
fn merge_traces(traces: &[BenchmarkTrace]) -> BenchmarkTrace {
    let mut merged = BenchmarkTrace::new();
    if traces.is_empty() {
        return merged;
    }

    let mut names: Vec<String> = Vec::new();
    for trace in traces {
        for entry in trace.entries() {
            if !names.iter().any(|name| name == &entry.name) {
                names.push(entry.name.clone());
            }
        }
    }

    for name in names {
        let sum: u128 = traces
            .iter()
            .flat_map(|trace| trace.entries())
            .filter(|entry| entry.name == name)
            .map(|entry| entry.micros)
            .sum();
        merged.add(
            name,
            std::time::Duration::from_micros((sum / traces.len() as u128) as u64),
        );
    }

    merged
}

/// Writes averaged benchmark results as JSON.
fn write_json(path: &PathBuf, iterations: usize, trace: &BenchmarkTrace) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create JSON output directory {}: {err}",
                    parent.display()
                )
            })?;
        }
    }
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"iterations\": {iterations},\n"));
    json.push_str("  \"averages\": ");
    let trace_json = trace.to_json();
    let trace_body = trace_json
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or("");
    json.push_str("{");
    json.push_str(trace_body);
    json.push_str("\n  }\n}\n");
    fs::write(path, json)
        .map_err(|err| format!("failed to write JSON output {}: {err}", path.display()))
}

#[derive(Debug, Clone)]
struct CliOptions {
    params: String,
    backend: String,
    proof_mode: ProofMode,
    segment_po2: Option<u32>,
    iterations: usize,
    json: Option<PathBuf>,
}

impl CliOptions {
    /// Parses CLI flags into benchmark options.
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut opts = Self {
            params: "sha2-128s".to_string(),
            backend: "sha-256".to_string(),
            proof_mode: ProofMode::Real128s,
            segment_po2: None,
            iterations: 1,
            json: None,
        };

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--params" => {
                    i += 1;
                    opts.params = value(args, i, "--params")?;
                }
                "--backend" => {
                    i += 1;
                    opts.backend = value(args, i, "--backend")?;
                }
                "--proof-mode" => {
                    i += 1;
                    opts.proof_mode = ProofMode::from_name(&value(args, i, "--proof-mode")?)
                        .map_err(|err| err.to_string())?;
                }
                "--segment-po2" => {
                    i += 1;
                    opts.segment_po2 = Some(
                        value(args, i, "--segment-po2")?
                            .parse()
                            .map_err(|_| "--segment-po2 must be a positive integer".to_string())?,
                    );
                }
                "--iterations" => {
                    i += 1;
                    opts.iterations = value(args, i, "--iterations")?
                        .parse()
                        .map_err(|_| "--iterations must be a positive integer".to_string())?;
                }
                "--json" => {
                    i += 1;
                    opts.json = Some(PathBuf::from(value(args, i, "--json")?));
                }
                "--help" | "-h" => {
                    print_help();
                    process::exit(0);
                }
                other => return Err(format!("unknown option '{other}'")),
            }
            i += 1;
        }

        Ok(opts)
    }

    /// Converts CLI options into a protocol configuration.
    fn config(&self) -> ProtocolConfig {
        ProtocolConfig::default()
            .with_params(self.params.clone())
            .with_backend(self.backend.clone())
            .with_proof_mode(self.proof_mode)
            .with_risc0_segment_limit_po2(self.segment_po2)
    }
}

/// Reads the value following a flag.
fn value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

/// Prints the CLI help text.
fn print_help() {
    println!("DAA full protocol CLI");
    println!();
    println!("Commands:");
    println!("  run-full      Run setup, join, sign, verify, link, revoke once");
    println!("  bench         Run repeated full protocol benchmarks");
    println!();
    println!("Options:");
    println!("  --params NAME       SPHINCS/security label, default sha2-128s");
    println!("  --backend NAME      host proof backend label, default sha-256");
    println!(
        "  --proof-mode MODE   real-128s, real-tpm, or simulated; real-128s covers all real params"
    );
    println!("  --segment-po2 N     RISC0 segment limit, use 20 for small-segment CUDA");
    println!("  --iterations N      benchmark iterations, default 1");
    println!("  --json PATH         write benchmark averages as JSON");
}
