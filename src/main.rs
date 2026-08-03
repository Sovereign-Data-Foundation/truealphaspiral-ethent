use clap::Parser;
use std::{collections::HashSet, fs, path::PathBuf, process};
use tas_verifier::{verify_tas_v1, Decision, VerificationContext};

#[derive(Parser, Debug)]
#[command(author, version, about = "TAS v1 conformance verifier")]
struct Args {
    #[arg(value_name = "PAYLOAD_FILE")]
    payload_path: PathBuf,
    #[arg(short = 'n', long = "seen-nonces", value_name = "NONCES_FILE")]
    seen_nonces_path: Option<PathBuf>,
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    output: Option<PathBuf>,
    #[arg(long)]
    full_result: bool,
}

fn run(args: Args) -> Result<Decision, String> {
    let payload = fs::read(&args.payload_path)
        .map_err(|error| format!("cannot read {}: {error}", args.payload_path.display()))?;
    let mut nonces = HashSet::new();
    if let Some(path) = args.seen_nonces_path {
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        nonces.extend(
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        );
    }
    let result = verify_tas_v1(
        &payload,
        &VerificationContext {
            seen_nonces: &nonces,
        },
    );
    let output = if args.full_result {
        serde_json::to_string_pretty(&result)
    } else {
        serde_json::to_string_pretty(&result.receipt)
    }
    .map_err(|error| format!("cannot serialize receipt: {error}"))?;
    if let Some(path) = args.output {
        fs::write(&path, output)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    } else {
        println!("{output}");
    }
    Ok(result.decision)
}

fn main() {
    match run(Args::parse()) {
        Ok(Decision::Admitted) => {}
        Ok(Decision::Refused) => process::exit(1),
        Err(error) => {
            eprintln!("tas-verifier: {error}");
            process::exit(2);
        }
    }
}
