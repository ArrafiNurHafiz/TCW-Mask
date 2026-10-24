use crate::field::FieldElement;
use crate::polynomial::Polynomial;
use crate::zeroize_ext::Secret;
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct RawShare {
    pub x: FieldElement,
    pub y: FieldElement,
}

pub fn split_secret<R: RngCore>(
    secret: FieldElement,
    k: usize,
    n: usize,
    rng: &mut R,
) -> Result<Vec<RawShare>, String> {
    if k == 0 || n < k {
        return Err("Invalid threshold parameters (must satisfy 1 <= k <= n)".to_string());
    }
    let poly = Polynomial::random(secret, k - 1, rng);
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = FieldElement::from_u64(i as u64);
        let y = poly.evaluate(x);
        shares.push(RawShare { x, y });
    }
    Ok(shares)
}

pub fn reconstruct_secret(shares: &[RawShare], k: usize) -> Result<Secret<FieldElement>, String> {
    if shares.len() < k {
        return Err(format!("Insufficient shares: got {}, required {}", shares.len(), k));
    }
    let subset = &shares[..k];
    let mut secret = FieldElement::ZERO;

    for (j, share_j) in subset.iter().enumerate() {
        let mut num = FieldElement::ONE;
        let mut den = FieldElement::ONE;

        for (m, share_m) in subset.iter().enumerate() {
            if j != m {
                num = num.mul(&share_m.x);
                den = den.mul(&share_m.x.sub(&share_j.x));
            }
        }
        let basis = num.mul(&den.invert());
        let term = share_j.y.mul(&basis);
        secret = secret.add(&term);
    }

    Ok(Secret::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_split_and_reconstruct_k_of_n() {
        let mut rng = OsRng;
        let original = FieldElement::from_u64(1337420);
        let shares = split_secret(original, 3, 5, &mut rng).unwrap();

        // Any 3 shares
        let choice_1 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let rec_1 = reconstruct_secret(&choice_1, 3).unwrap();
        assert_eq!(rec_1.expose_secret().canonical(), original.canonical());

        let choice_2 = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let rec_2 = reconstruct_secret(&choice_2, 3).unwrap();
        assert_eq!(rec_2.expose_secret().canonical(), original.canonical());
    }
}
