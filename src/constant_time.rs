use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[inline(always)]
pub fn ct_select_u64(a: u64, b: u64, choice: Choice) -> u64 {
    u64::conditional_select(&a, &b, choice)
}

#[inline(always)]
pub fn ct_select_bytes(a: &[u8; 32], b: &[u8; 32], choice: Choice) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&a[i], &b[i], choice);
    }
    out
}

#[inline(always)]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        Choice::from(0)
    } else {
        a.ct_eq(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_select_u64() {
        let x = 42u64;
        let y = 99u64;
        assert_eq!(ct_select_u64(x, y, Choice::from(0)), 42);
        assert_eq!(ct_select_u64(x, y, Choice::from(1)), 99);
    }

    #[test]
    fn test_ct_eq_bytes() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let mut c = [1u8; 32];
        c[31] = 2;
        assert!(bool::from(ct_eq_bytes(&a, &b)));
        assert!(!bool::from(ct_eq_bytes(&a, &c)));
    }
}
