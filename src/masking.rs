use crate::field::FieldElement;
use rand::RngCore;

pub const BLOCK_SIZE: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VandermondeMatrix {
    pub nodes: [FieldElement; BLOCK_SIZE],
}

impl VandermondeMatrix {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut nodes = [FieldElement::ZERO; BLOCK_SIZE];
        let mut i = 0;
        while i < BLOCK_SIZE {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes[31] &= 0x7F;
            let cand = FieldElement::from_bytes(&bytes);
            if cand.canonical() == FieldElement::ZERO {
                continue;
            }
            let mut duplicate = false;
            for j in 0..i {
                if nodes[j].canonical() == cand.canonical() {
                    duplicate = true;
                    break;
                }
            }
            if !duplicate {
                nodes[i] = cand;
                i += 1;
            }
        }
        Self { nodes }
    }

    pub fn eval_row(&self, row: usize) -> [FieldElement; BLOCK_SIZE] {
        let alpha = self.nodes[row];
        let mut row_vals = [FieldElement::ONE; BLOCK_SIZE];
        let mut acc = FieldElement::ONE;
        for j in 0..BLOCK_SIZE {
            row_vals[j] = acc;
            acc = acc.mul(&alpha);
        }
        row_vals
    }

    pub fn mul_vec(&self, vec: &[FieldElement; BLOCK_SIZE]) -> [FieldElement; BLOCK_SIZE] {
        let mut out = [FieldElement::ZERO; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            let row = self.eval_row(i);
            let mut sum = FieldElement::ZERO;
            for j in 0..BLOCK_SIZE {
                sum = sum.add(&row[j].mul(&vec[j]));
            }
            out[i] = sum;
        }
        out
    }

    pub fn invert(&self) -> [[FieldElement; BLOCK_SIZE]; BLOCK_SIZE] {
        let mut inv = [[FieldElement::ZERO; BLOCK_SIZE]; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            let alpha_j = self.nodes[j];
            let mut denom = FieldElement::ONE;
            for l in 0..BLOCK_SIZE {
                if l != j {
                    denom = denom.mul(&alpha_j.sub(&self.nodes[l]));
                }
            }
            let denom_inv = denom.invert();

            let mut poly = [FieldElement::ZERO; BLOCK_SIZE];
            poly[0] = FieldElement::ONE;
            let mut deg = 0;

            for l in 0..BLOCK_SIZE {
                if l != j {
                    let root = self.nodes[l];
                    let mut next = [FieldElement::ZERO; BLOCK_SIZE];
                    for d in 0..=deg {
                        next[d] = next[d].sub(&poly[d].mul(&root));
                        if d + 1 < BLOCK_SIZE {
                            next[d + 1] = next[d + 1].add(&poly[d]);
                        }
                    }
                    poly = next;
                    deg += 1;
                }
            }

            for k in 0..BLOCK_SIZE {
                inv[k][j] = poly[k].mul(&denom_inv);
            }
        }
        inv
    }
}

pub fn mask_share(
    share_val: FieldElement,
    v: &VandermondeMatrix,
    r: FieldElement,
    blinds: &[FieldElement; BLOCK_SIZE - 1],
) -> [FieldElement; BLOCK_SIZE] {
    let mut s_vec = [FieldElement::ZERO; BLOCK_SIZE];
    s_vec[0] = share_val;
    for i in 0..(BLOCK_SIZE - 1) {
        s_vec[i + 1] = blinds[i];
    }

    let vs = v.mul_vec(&s_vec);
    let mut masked = [FieldElement::ZERO; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        masked[i] = vs[i].add(&r);
    }
    masked
}

pub fn unmask_share(
    masked: &[FieldElement; BLOCK_SIZE],
    v: &VandermondeMatrix,
    r: FieldElement,
) -> FieldElement {
    let mut unshifted = [FieldElement::ZERO; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        unshifted[i] = masked[i].sub(&r);
    }

    let v_inv = v.invert();
    let mut s0 = FieldElement::ZERO;
    for j in 0..BLOCK_SIZE {
        s0 = s0.add(&v_inv[0][j].mul(&unshifted[j]));
    }
    s0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_vandermonde_matrix_inversion() {
        let mut rng = OsRng;
        let v = VandermondeMatrix::random(&mut rng);
        let inv = v.invert();

        // Check V * V^-1 == I
        for i in 0..BLOCK_SIZE {
            let row = v.eval_row(i);
            for j in 0..BLOCK_SIZE {
                let mut sum = FieldElement::ZERO;
                for k in 0..BLOCK_SIZE {
                    sum = sum.add(&row[k].mul(&inv[k][j]));
                }
                let expected = if i == j { FieldElement::ONE } else { FieldElement::ZERO };
                assert_eq!(sum.canonical(), expected.canonical());
            }
        }
    }

    #[test]
    fn test_mask_unmask_roundtrip() {
        let mut rng = OsRng;
        let v = VandermondeMatrix::random(&mut rng);
        let secret_share = FieldElement::from_u64(987654321);
        let r = FieldElement::from_u64(12345);
        let blinds = [
            FieldElement::from_u64(111),
            FieldElement::from_u64(222),
            FieldElement::from_u64(333),
        ];

        let masked = mask_share(secret_share, &v, r, &blinds);
        let recovered = unmask_share(&masked, &v, r);
        assert_eq!(recovered.canonical(), secret_share.canonical());
    }
}
