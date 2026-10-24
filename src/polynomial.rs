use crate::field::FieldElement;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    pub coeffs: Vec<FieldElement>,
}

impl Polynomial {
    pub fn random<R: RngCore>(secret: FieldElement, degree: usize, rng: &mut R) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(secret);
        for _ in 0..degree {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes[31] &= 0x7F;
            coeffs.push(FieldElement::from_bytes(&bytes));
        }
        Self { coeffs }
    }

    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        let mut result = FieldElement::ZERO;
        for coeff in self.coeffs.iter().rev() {
            result = result.mul(&x).add(coeff);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_poly_f0_is_secret() {
        let mut rng = OsRng;
        let secret = FieldElement::from_u64(0xDEADBEEF);
        let poly = Polynomial::random(secret, 3, &mut rng);
        assert_eq!(
            poly.evaluate(FieldElement::ZERO).canonical(),
            secret.canonical()
        );
    }
}
