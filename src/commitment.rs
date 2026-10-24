use crate::field::FieldElement;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;
use subtle::ConstantTimeEq;

pub struct PedersenGenerators {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl Default for PedersenGenerators {
    fn default() -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"TCW_MASK_PEDERSEN_GENERATOR_H_V1");
        Self { g, h }
    }
}

pub fn field_to_scalar(fe: &FieldElement) -> Scalar {
    let bytes = fe.to_bytes();
    Scalar::from_bytes_mod_order(bytes)
}

pub fn commit_vector(
    gens: &PedersenGenerators,
    masked: &[FieldElement; 4],
    r: &FieldElement,
) -> [CompressedRistretto; 4] {
    let r_scalar = field_to_scalar(r);
    let mut comms = [CompressedRistretto([0u8; 32]); 4];
    for j in 0..4 {
        let m_scalar = field_to_scalar(&masked[j]);
        let point = (gens.g * m_scalar) + (gens.h * r_scalar);
        comms[j] = point.compress();
    }
    comms
}

pub fn verify_vector(
    gens: &PedersenGenerators,
    masked: &[FieldElement; 4],
    r: &FieldElement,
    expected_comms: &[CompressedRistretto; 4],
) -> bool {
    let r_scalar = field_to_scalar(r);
    let mut valid = true;
    for j in 0..4 {
        let m_scalar = field_to_scalar(&masked[j]);
        let computed = ((gens.g * m_scalar) + (gens.h * r_scalar)).compress();
        let eq = computed.as_bytes().ct_eq(expected_comms[j].as_bytes());
        if !bool::from(eq) {
            valid = false;
        }
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment_tamper_detection() {
        let gens = PedersenGenerators::default();
        let masked = [
            FieldElement::from_u64(10),
            FieldElement::from_u64(20),
            FieldElement::from_u64(30),
            FieldElement::from_u64(40),
        ];
        let r = FieldElement::from_u64(999);

        let comms = commit_vector(&gens, &masked, &r);
        assert!(verify_vector(&gens, &masked, &r, &comms));

        // Tamper 1 bit in masked[0]
        let mut tampered_masked = masked;
        tampered_masked[0] = FieldElement::from_u64(11);
        assert!(!verify_vector(&gens, &tampered_masked, &r, &comms));

        // Tamper r
        let tampered_r = FieldElement::from_u64(1000);
        assert!(!verify_vector(&gens, &masked, &tampered_r, &comms));
    }
}
