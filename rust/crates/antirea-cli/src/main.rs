use antirea_validate::{build_and_validate_candidate, compile_multilang_rust_runtime};
use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage:\n  antirea-cli build --workspace <dir> --input-build <dir> --baseline <exe> --previous <exe> --output-dir <dir> --seed <u64>\n  antirea-cli compile-multilang --workspace <dir> --input-ir <ll> --dispatchers <sym1,sym2,...> --output-dir <dir> --seed <u64>"
        );
        process::exit(2);
    }

    let mut workspace = PathBuf::from(".");
    let mut input_build = None;
    let mut input_ir = None;
    let mut dispatchers: Vec<String> = Vec::new();
    let mut baseline = None;
    let mut previous = None;
    let mut output_dir = None;
    let mut seed: u64 = 131220261031;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" => {
                workspace = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--input-build" => {
                input_build = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--input-ir" => {
                input_ir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--dispatchers" => {
                dispatchers = args[i + 1]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                i += 2;
            }
            "--baseline" => {
                baseline = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--previous" => {
                previous = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--output-dir" => {
                output_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--seed" => {
                seed = args[i + 1].parse().expect("Invalid --seed u64");
                i += 2;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                process::exit(2);
            }
        }
    }

    match args[1].as_str() {
        "build" | "build-and-validate" => {
            let input_build = input_build.expect("--input-build required");
            let baseline = baseline.expect("--baseline required");
            let previous = previous.expect("--previous required");
            let output_dir = output_dir.expect("--output-dir required");
            match build_and_validate_candidate(
                &workspace,
                &input_build,
                &baseline,
                &previous,
                &output_dir,
                seed,
            ) {
                Ok(report) => {
                    println!("{report}");
                }
                Err(err) => {
                    eprintln!("ERROR: {err}");
                    process::exit(1);
                }
            }
        }
        "compile-multilang" => {
            let input_ir = input_ir.expect("--input-ir required");
            let output_dir = output_dir.expect("--output-dir required");
            if dispatchers.is_empty() {
                eprintln!("--dispatchers required");
                process::exit(2);
            }
            match compile_multilang_rust_runtime(
                &workspace,
                &input_ir,
                &dispatchers,
                &output_dir,
                seed,
            ) {
                Ok(report) => {
                    println!("{report}");
                }
                Err(err) => {
                    eprintln!("ERROR: {err}");
                    process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown command: {other}");
            process::exit(2);
        }
    }
}
