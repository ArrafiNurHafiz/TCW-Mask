use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::process::exit;
use tcw_mask::attack::{simulate_attack, AttackMode};
use tcw_mask::bench::run_tvla;
use tcw_mask::bundle::ShareBundle;
use tcw_mask::cli::{Cli, Commands};
use tcw_mask::commitment::PedersenGenerators;
use tcw_mask::cpa::simulate_cpa_attack;
use tcw_mask::field::FieldElement;
use tcw_mask::proactive::refresh_shares;
use tcw_mask::sharing::{reconstruct_secret, split_secret};

fn main() {
    let cli = Cli::parse();
    let mut rng = OsRng;
    let gens = PedersenGenerators::default();

    match cli.command {
        Commands::Generate { out } => {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            key_bytes[31] &= 0x7F; // ensure < 2^255
            let hex_key = hex::encode(key_bytes);
            if let Some(path) = out {
                fs::write(&path, &hex_key).expect("Failed to write key file");
                println!("Master key written to {}", path.display());
            } else {
                println!("{}", hex_key);
            }
        }
        Commands::Split { key, k, n, out_dir } => {
            let key_str = if let Ok(content) = fs::read_to_string(&key) {
                content.trim().to_string()
            } else {
                key.trim().to_string()
            };
            let master_fe = FieldElement::from_hex(&key_str).expect("Invalid master key hex");
            let raw_shares =
                split_secret(master_fe, k, n, &mut rng).expect("Failed to split secret");

            fs::create_dir_all(&out_dir).expect("Failed to create out directory");
            let mut session_bytes = [0u8; 16];
            rng.fill_bytes(&mut session_bytes);
            let session_id = hex::encode(session_bytes);

            for (idx, share) in raw_shares.iter().enumerate() {
                let share_idx = (idx + 1) as u32;
                let bundle = ShareBundle::create(
                    share,
                    share_idx,
                    k as u32,
                    n as u32,
                    &session_id,
                    &gens,
                    &mut rng,
                );
                let json = serde_json::to_string_pretty(&bundle).unwrap();
                let file_path = out_dir.join(format!("share_{}.json", share_idx));
                fs::write(&file_path, json).expect("Failed to write share bundle");
                println!(
                    "Exported share bundle {} to {}",
                    share_idx,
                    file_path.display()
                );
            }
            println!(
                "Split complete: {} shares generated with threshold {}.",
                n, k
            );
        }
        Commands::Verify { shares } => {
            let mut all_valid = true;
            for path in &shares {
                let content = fs::read_to_string(path)
                    .unwrap_or_else(|_| panic!("Cannot read {}", path.display()));
                let bundle: ShareBundle = serde_json::from_str(&content).expect("Invalid JSON");
                match bundle.verify_integrity(&gens) {
                    Ok(_) => println!("[VALID] Share {} in {}", bundle.index, path.display()),
                    Err(e) => {
                        println!("[INVALID] Share {}: {}", bundle.index, e);
                        all_valid = false;
                    }
                }
            }
            if !all_valid {
                eprintln!("Verification failed for one or more shares.");
                exit(1);
            }
            println!("All shares verified successfully.");
        }
        Commands::Reconstruct { shares, out } => {
            if shares.is_empty() {
                eprintln!("No share files provided");
                exit(1);
            }
            let mut raw_shares = Vec::new();
            let mut k = 0;
            let mut session_id = String::new();

            for path in &shares {
                let content = fs::read_to_string(path)
                    .unwrap_or_else(|_| panic!("Cannot read {}", path.display()));
                let bundle: ShareBundle = serde_json::from_str(&content).expect("Invalid JSON");
                if session_id.is_empty() {
                    session_id = bundle.session_id.clone();
                    k = bundle.threshold as usize;
                } else if bundle.session_id != session_id {
                    eprintln!(
                        "Error: Share bundle {} belongs to a different session!",
                        path.display()
                    );
                    exit(1);
                }

                let raw = bundle.extract_raw_share(&gens).unwrap_or_else(|e| {
                    eprintln!("Integrity error in {}: {}", path.display(), e);
                    exit(1);
                });
                raw_shares.push(raw);
            }

            let recovered = reconstruct_secret(&raw_shares, k).unwrap_or_else(|e| {
                eprintln!("Reconstruction failed: {}", e);
                exit(1);
            });
            let hex_out = recovered.expose_secret().to_hex();
            if let Some(out_path) = out {
                fs::write(&out_path, &hex_out).expect("Failed to write reconstructed key");
                println!("Master key reconstructed to {}", out_path.display());
            } else {
                println!("{}", hex_out);
            }
        }
        Commands::AttackSim { shares, mode } => {
            let mut bundles = Vec::new();
            for path in &shares {
                let content = fs::read_to_string(path).unwrap();
                let b: ShareBundle = serde_json::from_str(&content).unwrap();
                bundles.push(b);
            }
            let attack_mode = match mode.to_lowercase().as_str() {
                "tamper" => AttackMode::Tamper,
                "insufficient" => AttackMode::Insufficient,
                "replay" => AttackMode::Replay,
                other => {
                    eprintln!("Unknown attack mode: {}", other);
                    exit(1);
                }
            };
            let result = simulate_attack(&bundles, attack_mode);
            println!("\n=== Attack Simulation Result ===");
            println!("Mode:     {}", mode);
            println!(
                "Detected: {}",
                if result.detected {
                    "YES (PASSED DEFENSE)"
                } else {
                    "NO (FAILED DEFENSE)"
                }
            );
            println!("Details:  {}", result.message);
            if !result.detected {
                exit(1);
            }
        }
        Commands::Bench { iterations } => {
            println!(
                "Running TVLA timing assessment with {} iterations...",
                iterations
            );
            let res = run_tvla(iterations);
            println!("\n=== TVLA Timing Assessment ===");
            println!(
                "Mean Group A (Low Hamming):  {:.2} ns (std: {:.2})",
                res.mean_a_ns, res.std_a_ns
            );
            println!(
                "Mean Group B (High Hamming): {:.2} ns (std: {:.2})",
                res.mean_b_ns, res.std_b_ns
            );
            println!("Welch's t-score:             {:.4}", res.t_score);
            println!("Leakage Threshold:           |t| < 4.50 (p > 0.05)");
            println!(
                "Result:                      {}",
                if res.is_leakage_free {
                    "PASS (CONSTANT-TIME CONFIRMED)"
                } else {
                    "FAIL (POSSIBLE TIMING LEAK)"
                }
            );
        }
        Commands::Refresh { shares, out_dir } => {
            if shares.is_empty() {
                eprintln!("No shares provided for refresh");
                exit(1);
            }
            let mut bundles = Vec::new();
            for path in &shares {
                let content = fs::read_to_string(path)
                    .unwrap_or_else(|_| panic!("Cannot read {}", path.display()));
                let b: ShareBundle = serde_json::from_str(&content).expect("Invalid JSON");
                bundles.push(b);
            }
            let refreshed = refresh_shares(&bundles, &gens, &mut rng).unwrap_or_else(|e| {
                eprintln!("Refresh error: {}", e);
                exit(1);
            });
            fs::create_dir_all(&out_dir).expect("Failed to create out_dir");
            for b in &refreshed {
                let json = serde_json::to_string_pretty(b).unwrap();
                let file_path = out_dir.join(format!("share_{}.json", b.index));
                fs::write(&file_path, json).expect("Failed to write refreshed share");
                println!(
                    "Exported refreshed share {} (session: {}) to {}",
                    b.index,
                    b.session_id,
                    file_path.display()
                );
            }
            println!("Proactive refresh complete: shares advanced to new epoch.");
        }
        Commands::CpaSim { traces } => {
            println!(
                "Simulating Correlation Power Analysis (CPA) attack with {} traces...",
                traces
            );
            let res = simulate_cpa_attack(traces);
            println!("\n=== Correlation Power Analysis (CPA) Assessment ===");
            println!("Traces Simulated:            {}", res.traces);
            println!(
                "Unmasked Trace Correlation:  {:.4} (High Leakage: > 0.80)",
                res.unmasked_corr
            );
            println!(
                "Masked Trace Correlation:    {:.4} (Zero Leakage Target: < 0.10)",
                res.masked_corr
            );
            println!(
                "Status:                      {}",
                if res.is_masked_effective {
                    "PASS (VANDERMONDE MASKING EFFECTIVE)"
                } else {
                    "FAIL"
                }
            );
        }
    }
}
