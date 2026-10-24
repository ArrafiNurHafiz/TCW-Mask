use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "tcw-mask",
    author = "Arrafi Nur Hafiz <porto.rapydev.my.id>",
    version = "1.0",
    about = "Threshold Cryptographic Wrapping with Constant-Time Masking"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a fresh random 256-bit master key
    Generate {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Split a master key into n masked share bundles
    Split {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value_t = 3)]
        k: usize,
        #[arg(short, long, default_value_t = 5)]
        n: usize,
        #[arg(short, long)]
        out_dir: PathBuf,
    },
    /// Verify integrity and commitments of share bundles
    Verify {
        #[arg(short, long, num_args = 1..)]
        shares: Vec<PathBuf>,
    },
    /// Reconstruct master key from at least k share bundles
    Reconstruct {
        #[arg(short, long, num_args = 1..)]
        shares: Vec<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Simulate attack vectors (tamper, insufficient, replay)
    AttackSim {
        #[arg(short, long, num_args = 1..)]
        shares: Vec<PathBuf>,
        #[arg(short, long)]
        mode: String,
    },
    /// Run TVLA side-channel benchmark and Welch's t-test
    Bench {
        #[arg(short, long, default_value_t = 1000)]
        iterations: usize,
    },
}
