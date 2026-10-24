use crate::field::FieldElement;
use crate::sharing::{reconstruct_secret, split_secret};
use rand::rngs::OsRng;
use std::time::Instant;

pub struct TvlaResult {
    pub mean_a_ns: f64,
    pub mean_b_ns: f64,
    pub std_a_ns: f64,
    pub std_b_ns: f64,
    pub t_score: f64,
    pub is_leakage_free: bool,
}

pub fn calculate_t_score(a: &[f64], b: &[f64]) -> (f64, f64, f64, f64, f64) {
    let n_a = a.len() as f64;
    let n_b = b.len() as f64;
    let mean_a = a.iter().sum::<f64>() / n_a;
    let mean_b = b.iter().sum::<f64>() / n_b;

    let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let std_a = var_a.sqrt();
    let std_b = var_b.sqrt();

    let denom = ((var_a / n_a) + (var_b / n_b)).sqrt();
    let t = if denom > 0.0 { (mean_a - mean_b) / denom } else { 0.0 };

    (mean_a, mean_b, std_a, std_b, t)
}

pub fn run_tvla(iterations: usize) -> TvlaResult {
    let mut rng = OsRng;

    let mut times_a = Vec::with_capacity(iterations);
    let mut times_b = Vec::with_capacity(iterations);

    // Group A: Fixed zero/low-weight secret
    let secret_a = FieldElement::from_u64(0);
    // Group B: High-weight secret
    let secret_b = FieldElement::from_u64(0x7FFF_FFFF_FFFF_FFFF);

    let shares_a = split_secret(secret_a, 3, 5, &mut rng).unwrap();
    let shares_b = split_secret(secret_b, 3, 5, &mut rng).unwrap();

    let subset_a = &shares_a[..3];
    let subset_b = &shares_b[..3];

    for _ in 0..iterations {
        let t0 = Instant::now();
        let _ = reconstruct_secret(subset_a, 3).unwrap();
        times_a.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let _ = reconstruct_secret(subset_b, 3).unwrap();
        times_b.push(t1.elapsed().as_nanos() as f64);
    }

    let (mean_a, mean_b, std_a, std_b, t_score) = calculate_t_score(&times_a, &times_b);
    let is_leakage_free = t_score.abs() < 4.5;

    TvlaResult {
        mean_a_ns: mean_a,
        mean_b_ns: mean_b,
        std_a_ns: std_a,
        std_b_ns: std_b,
        t_score,
        is_leakage_free,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_t_score_identical_dist() {
        let a = vec![100.0, 102.0, 98.0, 101.0, 99.0];
        let b = vec![101.0, 99.0, 100.0, 102.0, 98.0];
        let (_, _, _, _, t) = calculate_t_score(&a, &b);
        assert!(t.abs() < 1.0);
    }
}
