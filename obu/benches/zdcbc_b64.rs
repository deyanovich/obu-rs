use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obu::ZdcbcB64;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct BenchmarkSpec {
    id: String,
    operation: String,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    precompute: Option<PrecomputeSpec>,
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct PrecomputeSpec {
    #[allow(dead_code)]
    operation: String,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    plaintext: String,
}

fn load_benchmark_specs() -> Vec<BenchmarkSpec> {
    let possible_paths = vec![
        PathBuf::from("benches/benchmarks_zdcbc_b64.jsonl"),
        PathBuf::from("oboron/benches/benchmarks_zdcbc_b64.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/benchmarks_zdcbc_b64.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            eprintln!("Found zdcbc.b64 benchmarks at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read benchmarks");
            let specs: Vec<BenchmarkSpec> = data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse"))
                .collect();
            eprintln!("Loaded {} zdcbc.b64 benchmark specifications", specs.len());
            return specs;
        }
    }

    eprintln!("Warning: benchmarks_zdcbc_b64.jsonl not found");
    vec![]
}

fn run_zdcbc_b64_benchmarks(c: &mut Criterion) {
    let specs = load_benchmark_specs();

    if specs.is_empty() {
        eprintln!("No zdcbc.b64 specs loaded");
        return;
    }

    // Create ob once, OUTSIDE the timed loop
    let ob = ZdcbcB64::new_keyless().unwrap();

    let mut bench_count = 0;
    for spec in specs {
        match spec.operation.as_str() {
            "enc" => {
                if let Some(plaintext) = spec.plaintext {
                    bench_count += 1;
                    // Only the enc operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.enc(black_box(&plaintext)).unwrap());
                    });
                }
            }
            "dec" => {
                if let Some(precompute) = spec.precompute {
                    // Precompute outside timed loop
                    let ot = ob.enc(&precompute.plaintext).unwrap();
                    bench_count += 1;

                    // Only the dec operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.dec(black_box(&ot)).unwrap());
                    });
                }
            }
            _ => {
                eprintln!("Skipping unknown operation: {}", spec.operation);
            }
        }
    }
    eprintln!("Registered {} zdcbc.b64 benchmarks", bench_count);
}

criterion_group!(benches, run_zdcbc_b64_benchmarks);
criterion_main!(benches);
