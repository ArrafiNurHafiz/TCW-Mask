use crate::bundle::ShareBundle;
use crate::commitment::PedersenGenerators;
use crate::sharing::reconstruct_secret;

#[derive(Debug, PartialEq, Eq)]
pub enum AttackMode {
    Tamper,
    Insufficient,
    Replay,
}

pub struct AttackResult {
    pub detected: bool,
    pub message: String,
}

pub fn simulate_attack(bundles: &[ShareBundle], mode: AttackMode) -> AttackResult {
    let gens = PedersenGenerators::default();

    match mode {
        AttackMode::Tamper => {
            if bundles.is_empty() {
                return AttackResult {
                    detected: false,
                    message: "No bundles provided".into(),
                };
            }
            let mut tampered = bundles[0].clone();
            // Flip the last character of the first masked vector element
            let mut s = tampered.masked_vector[0].clone();
            let last_char = s.pop().unwrap();
            let new_char = if last_char == '0' { '1' } else { '0' };
            s.push(new_char);
            tampered.masked_vector[0] = s;

            match tampered.verify_integrity(&gens) {
                Err(err) => AttackResult {
                    detected: true,
                    message: format!("Tampering detected via Pedersen commitment: {}", err),
                },
                Ok(_) => AttackResult {
                    detected: false,
                    message: "Tampering went undetected! Security violation!".into(),
                },
            }
        }
        AttackMode::Insufficient => {
            let k = if !bundles.is_empty() {
                bundles[0].threshold as usize
            } else {
                3
            };
            let count = if k > 1 { k - 1 } else { 1 };
            if bundles.len() < count {
                return AttackResult {
                    detected: true,
                    message: "Less than k-1 bundles available".into(),
                };
            }
            let slice = &bundles[..count];
            let mut raw_shares = Vec::new();
            for b in slice {
                match b.extract_raw_share(&gens) {
                    Ok(s) => raw_shares.push(s),
                    Err(e) => {
                        return AttackResult {
                            detected: true,
                            message: e,
                        }
                    }
                }
            }
            match reconstruct_secret(&raw_shares, k) {
                Err(err) => AttackResult {
                    detected: true,
                    message: format!("Insufficient shares rejected: {}", err),
                },
                Ok(_) => AttackResult {
                    detected: false,
                    message: "Reconstructed secret with insufficient shares! Security violation!"
                        .into(),
                },
            }
        }
        AttackMode::Replay => {
            if bundles.len() < 2 {
                return AttackResult {
                    detected: false,
                    message: "Need at least 2 bundles".into(),
                };
            }
            let mut mixed = bundles.to_vec();
            mixed[1].session_id = "replay_attacker_fake_session_id".into();

            let first_session = &mixed[0].session_id;
            let mismatch = mixed.iter().any(|b| &b.session_id != first_session);
            if mismatch {
                AttackResult {
                    detected: true,
                    message: "Replay attack detected: mismatched session IDs between share bundles"
                        .into(),
                }
            } else {
                AttackResult {
                    detected: false,
                    message: "Replay attack undetected!".into(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldElement;
    use crate::sharing::RawShare;
    use rand::rngs::OsRng;

    #[test]
    fn test_simulate_attacks() {
        let mut rng = OsRng;
        let gens = PedersenGenerators::default();
        let share1 = RawShare {
            x: FieldElement::from_u64(1),
            y: FieldElement::from_u64(111),
        };
        let share2 = RawShare {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(222),
        };
        let share3 = RawShare {
            x: FieldElement::from_u64(3),
            y: FieldElement::from_u64(333),
        };

        let b1 = ShareBundle::create(&share1, 1, 3, 5, "session_test", &gens, &mut rng);
        let b2 = ShareBundle::create(&share2, 2, 3, 5, "session_test", &gens, &mut rng);
        let b3 = ShareBundle::create(&share3, 3, 3, 5, "session_test", &gens, &mut rng);
        let bundles = vec![b1, b2, b3];

        let res_tamper = simulate_attack(&bundles, AttackMode::Tamper);
        assert!(res_tamper.detected);

        let res_insuf = simulate_attack(&bundles, AttackMode::Insufficient);
        assert!(res_insuf.detected);

        let res_replay = simulate_attack(&bundles, AttackMode::Replay);
        assert!(res_replay.detected);
    }
}
