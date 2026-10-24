use crate::field::FieldElement;
use crate::masking::{mask_share, VandermondeMatrix, BLOCK_SIZE};
use rand::rngs::OsRng;
use rand::RngCore;

pub struct CpaResult {
    pub unmasked_corr: f64,
    pub masked_corr: f64,
    pub traces: usize,
    pub is_masked_effective: bool,
}

fn hamming_weight_u8(b: u8) -> u32 {
    b.count_ones()
}

fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denom = (var_x * var_y).sqrt();
    if denom > 0.0 {
        cov / denom
    } else {
        0.0
    }
}

pub fn simulate_cpa_attack(traces: usize) -> CpaResult {
    let mut rng = OsRng;

    let mut secret_hw = Vec::with_capacity(traces);
    let mut unmasked_power = Vec::with_capacity(traces);
    let mut masked_power = Vec::with_capacity(traces);

    for _ in 0..traces {
        // Random secret share
        let mut s_bytes = [0u8; 32];
        rng.fill_bytes(&mut s_bytes);
        s_bytes[31] &= 0x7F;
        let share_val = FieldElement::from_bytes(&s_bytes);

        // Hypothetical secret leakage: HW of first byte of share
        let hw_secret = hamming_weight_u8(s_bytes[0]) as f64;
        secret_hw.push(hw_secret);

        // Simulated power trace of unmasked execution: HW(secret) + small noise
        let noise = ((rng.next_u32() % 100) as f64 - 50.0) / 100.0;
        let p_unmasked = hw_secret * 3.5 + noise;
        unmasked_power.push(p_unmasked);

        // Vandermonde masking
        let v = VandermondeMatrix::random(&mut rng);
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        r_bytes[31] &= 0x7F;
        let r = FieldElement::from_bytes(&r_bytes);

        let mut blinds = [FieldElement::ZERO; BLOCK_SIZE - 1];
        for b in &mut blinds {
            let mut b_bytes = [0u8; 32];
            rng.fill_bytes(&mut b_bytes);
            b_bytes[31] &= 0x7F;
            *b = FieldElement::from_bytes(&b_bytes);
        }

        let masked = mask_share(share_val, &v, r, &blinds);
        let masked_bytes = masked[0].to_bytes();
        let hw_masked = hamming_weight_u8(masked_bytes[0]) as f64;

        // Simulated power trace of masked execution: HW(masked) + noise
        let p_masked = hw_masked * 3.5 + noise;
        masked_power.push(p_masked);
    }

    let unmasked_corr = pearson_correlation(&secret_hw, &unmasked_power);
    let masked_corr = pearson_correlation(&secret_hw, &masked_power);
    let is_masked_effective = masked_corr.abs() < 0.10 && unmasked_corr.abs() > 0.80;

    CpaResult {
        unmasked_corr,
        masked_corr,
        traces,
        is_masked_effective,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpa_masking_mitigates_correlation() {
        let res = simulate_cpa_attack(1000);
        println!(
            "CPA Correlation -> Unmasked: {:.4}, Masked: {:.4}",
            res.unmasked_corr, res.masked_corr
        );
        assert!(res.unmasked_corr.abs() > 0.85);
        assert!(res.masked_corr.abs() < 0.12);
    }
}
