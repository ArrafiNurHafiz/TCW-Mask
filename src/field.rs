use std::fmt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// p = 2^255 - 19
pub const P_LIMBS: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

#[derive(Clone, Copy, Default, PartialEq, Eq, Zeroize)]
pub struct FieldElement(pub [u64; 4]);

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let a = self.canonical();
        let b = other.canonical();
        let mut res = Choice::from(1);
        for i in 0..4 {
            res &= a.0[i].ct_eq(&b.0[i]);
        }
        res
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl FieldElement {
    pub const ZERO: Self = FieldElement([0, 0, 0, 0]);
    pub const ONE: Self = FieldElement([1, 0, 0, 0]);

    pub fn from_u64(val: u64) -> Self {
        FieldElement([val, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let chunk = &bytes[i * 8..(i + 1) * 8];
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        let mut elem = FieldElement(limbs);
        elem.reduce();
        elem
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let norm = self.canonical();
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&norm.0[i].to_le_bytes());
        }
        bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("Hex string must be exactly 32 bytes (64 chars)".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    #[inline(always)]
    fn sub_p(limbs: [u64; 4]) -> ([u64; 4], u64) {
        let mut diff = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let res = (limbs[i] as u128)
                .wrapping_sub(P_LIMBS[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = res as u64;
            borrow = (res >> 127) & 1;
        }
        (diff, borrow as u64)
    }

    #[inline(always)]
    pub fn canonical(&self) -> Self {
        let (diff, borrow) = Self::sub_p(self.0);
        Self::conditional_select(&FieldElement(diff), self, Choice::from(borrow as u8))
    }

    #[inline(always)]
    pub fn reduce(&mut self) {
        let (diff, borrow) = Self::sub_p(self.0);
        *self = Self::conditional_select(&FieldElement(diff), self, Choice::from(borrow as u8));
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        let (diff, borrow) = Self::sub_p(sum);
        FieldElement::conditional_select(
            &FieldElement(diff),
            &FieldElement(sum),
            Choice::from(borrow as u8),
        )
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut diff = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let res = (self.0[i] as u128)
                .wrapping_sub(other.0[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = res as u64;
            borrow = (res >> 127) & 1;
        }

        let mut sum_p = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = (diff[i] as u128) + (P_LIMBS[i] as u128) + carry;
            sum_p[i] = s as u64;
            carry = s >> 64;
        }

        FieldElement::conditional_select(
            &FieldElement(diff),
            &FieldElement(sum_p),
            Choice::from(borrow as u8),
        )
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod =
                    (self.0[i] as u128) * (other.0[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
            let mut k = i + 4;
            while k < 8 && carry > 0 {
                let sum = (res[k] as u128) + carry;
                res[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        let bit255 = (res[3] >> 63) & 1;
        let mut r = [res[0], res[1], res[2], res[3] & 0x7FFF_FFFF_FFFF_FFFF];

        let mut carry = (bit255 as u128) * 19;
        for i in 0..4 {
            let term = (res[4 + i] as u128) * 38 + (r[i] as u128) + carry;
            r[i] = term as u64;
            carry = term >> 64;
        }

        let bit255_2 = (r[3] >> 63) & 1;
        r[3] &= 0x7FFF_FFFF_FFFF_FFFF;
        let mut carry2 = (carry * 38) + (bit255_2 as u128) * 19;
        for i in 0..4 {
            let term = (r[i] as u128) + carry2;
            r[i] = term as u64;
            carry2 = term >> 64;
        }

        let bit255_3 = (r[3] >> 63) & 1;
        r[3] &= 0x7FFF_FFFF_FFFF_FFFF;
        let mut carry3 = (bit255_3 as u128) * 19;
        for i in 0..4 {
            let term = (r[i] as u128) + carry3;
            r[i] = term as u64;
            carry3 = term >> 64;
        }

        let mut out = FieldElement(r);
        out.reduce();
        out
    }

    pub fn invert(&self) -> Self {
        // p - 2 = 2^255 - 21
        let p_minus_2_bits: [u64; 4] = [
            0xFFFF_FFFF_FFFF_FFEB,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFF,
        ];
        let mut res = FieldElement::ONE;
        let mut base = *self;

        for i in 0..4 {
            let mut limb = p_minus_2_bits[i];
            let num_bits = if i == 3 { 63 } else { 64 };
            for _ in 0..num_bits {
                let bit = limb & 1;
                let mul_res = res.mul(&base);
                res = FieldElement::conditional_select(&res, &mul_res, Choice::from(bit as u8));
                base = base.mul(&base);
                limb >>= 1;
            }
        }
        res
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp(0x{})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_field_add_sub() {
        let a = FieldElement::from_u64(100);
        let b = FieldElement::from_u64(250);
        let c = a.add(&b);
        assert_eq!(c.canonical(), FieldElement::from_u64(350));
        let d = c.sub(&b);
        assert_eq!(d.canonical(), a);
    }

    #[test]
    fn test_field_mul_inv() {
        let a = FieldElement::from_u64(1234567);
        let inv = a.invert();
        let prod = a.mul(&inv);
        assert_eq!(prod.canonical(), FieldElement::ONE);
    }

    #[test]
    fn test_field_sub_underflow() {
        let a = FieldElement::from_u64(10);
        let b = FieldElement::from_u64(25);
        let diff = a.sub(&b);
        let res = diff.add(&b);
        assert_eq!(res.canonical(), a);
    }

    #[test]
    fn test_field_hex_roundtrip() {
        let original = FieldElement([
            0x1234_5678_9ABC_DEF0,
            0x0FED_CBA9_8765_4321,
            0xAAAA_BBBB_CCCC_DDDD,
            0x1234_4321_1234_4321,
        ]);
        let hex = original.to_hex();
        let parsed = FieldElement::from_hex(&hex).unwrap();
        assert_eq!(parsed.canonical(), original.canonical());
    }

    proptest! {
        #[test]
        fn prop_add_commutative(a in any::<[u64; 4]>(), b in any::<[u64; 4]>()) {
            let mut fa = FieldElement(a);
            let mut fb = FieldElement(b);
            fa.reduce();
            fb.reduce();
            let sum1 = fa.add(&fb);
            let sum2 = fb.add(&fa);
            prop_assert_eq!(sum1.canonical(), sum2.canonical());
        }

        #[test]
        fn prop_distributive(a in any::<[u64; 4]>(), b in any::<[u64; 4]>(), c in any::<[u64; 4]>()) {
            let mut fa = FieldElement(a);
            let mut fb = FieldElement(b);
            let mut fc = FieldElement(c);
            fa.reduce();
            fb.reduce();
            fc.reduce();
            let lhs = fa.mul(&fb.add(&fc));
            let rhs = fa.mul(&fb).add(&fa.mul(&fc));
            prop_assert_eq!(lhs.canonical(), rhs.canonical());
        }
    }
}
