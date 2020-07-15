use crate::errors::KeysError;
use core::fmt::Debug;

#[derive(Copy)]
pub struct Signature(pub(crate) [u8; 64]);

impl Signature {
    #[inline]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, KeysError> {
        if bytes.len() != 64 {
            return Err(KeysError::BytesLengthError(
                "signature".to_string(),
                64,
                bytes.len(),
            ));
        }

        let mut signature = [0u8; 64];

        signature.copy_from_slice(&bytes[..64]);
        Ok(Signature(signature))
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let (first, second) = self.0.split_at(32);
        write!(f, "Signature: {:?} {:?}", first, second)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        let (first, second) = self.0.split_at(32);
        let (first_other, second_other) = other.0.split_at(32);

        first == first_other && second == second_other
    }
}
