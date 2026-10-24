use crate::commitment::{commit_vector, verify_vector, PedersenGenerators};
use crate::field::FieldElement;
use crate::masking::{mask_share, unmask_share, VandermondeMatrix, BLOCK_SIZE};
use crate::sharing::RawShare;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShareBundle {
    pub version: u8,
    pub session_id: String,
    pub index: u32,
    pub threshold: u32,
    pub total_shares: u32,
    pub masked_vector: Vec<String>,
    pub alpha_nodes: Vec<String>,
    pub r_scalar: String,
    pub commitments: Vec<String>,
}

impl ShareBundle {
    pub fn create<R: RngCore>(
        share: &RawShare,
        index: u32,
        threshold: u32,
        total_shares: u32,
        session_id: &str,
        gens: &PedersenGenerators,
        rng: &mut R,
    ) -> Self {
        let v = VandermondeMatrix::random(rng);
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

        let masked = mask_share(share.y, &v, r, &blinds);
        let comms = commit_vector(gens, &masked, &r);

        ShareBundle {
            version: 1,
            session_id: session_id.to_string(),
            index,
            threshold,
            total_shares,
            masked_vector: masked.iter().map(|m| m.to_hex()).collect(),
            alpha_nodes: v.nodes.iter().map(|a| a.to_hex()).collect(),
            r_scalar: r.to_hex(),
            commitments: comms.iter().map(|c| hex::encode(c.as_bytes())).collect(),
        }
    }

    pub fn verify_integrity(&self, gens: &PedersenGenerators) -> Result<(), String> {
        if self.masked_vector.len() != 4 || self.alpha_nodes.len() != 4 || self.commitments.len() != 4 {
            return Err("Invalid bundle component lengths".to_string());
        }

        let mut masked = [FieldElement::ZERO; 4];
        for i in 0..4 {
            masked[i] = FieldElement::from_hex(&self.masked_vector[i])?;
        }
        let r = FieldElement::from_hex(&self.r_scalar)?;

        let mut expected_comms = [CompressedRistretto([0u8; 32]); 4];
        for i in 0..4 {
            let c_bytes = hex::decode(&self.commitments[i]).map_err(|e| e.to_string())?;
            if c_bytes.len() != 32 {
                return Err("Commitment point must be 32 bytes".to_string());
            }
            expected_comms[i] = CompressedRistretto::from_slice(&c_bytes).map_err(|e| e.to_string())?;
        }

        if !verify_vector(gens, &masked, &r, &expected_comms) {
            return Err(format!("Commitment verification failed for share {}", self.index));
        }

        Ok(())
    }

    pub fn extract_raw_share(&self, gens: &PedersenGenerators) -> Result<RawShare, String> {
        self.verify_integrity(gens)?;

        let mut masked = [FieldElement::ZERO; 4];
        for i in 0..4 {
            masked[i] = FieldElement::from_hex(&self.masked_vector[i])?;
        }
        let r = FieldElement::from_hex(&self.r_scalar)?;

        let mut nodes = [FieldElement::ZERO; 4];
        for i in 0..4 {
            nodes[i] = FieldElement::from_hex(&self.alpha_nodes[i])?;
        }
        let v = VandermondeMatrix { nodes };

        let unmasked_y = unmask_share(&masked, &v, r);
        let x = FieldElement::from_u64(self.index as u64);

        Ok(RawShare { x, y: unmasked_y })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_bundle_serde_and_unmask() {
        let mut rng = OsRng;
        let gens = PedersenGenerators::default();
        let share = RawShare {
            x: FieldElement::from_u64(1),
            y: FieldElement::from_u64(88888888),
        };

        let bundle = ShareBundle::create(&share, 1, 3, 5, "session_test_01", &gens, &mut rng);
        let json = serde_json::to_string(&bundle).unwrap();
        let deserialized: ShareBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(bundle, deserialized);
        let extracted = deserialized.extract_raw_share(&gens).unwrap();
        assert_eq!(extracted.y.canonical(), share.y.canonical());
    }
}
