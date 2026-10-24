use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    pub fn new(val: T) -> Self {
        Self { inner: val }
    }

    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_deref_and_expose() {
        let sec = Secret::new([0x42u8; 32]);
        assert_eq!(*sec.expose_secret(), [0x42u8; 32]);
    }
}
