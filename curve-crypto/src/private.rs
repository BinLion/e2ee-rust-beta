use crate::errors::KeysError;
use crate::public::*;
use crate::signature::Signature;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRng;
use rand_core::RngCore;
use sha2::Sha512;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct PrivateKey(pub(crate) Scalar);

impl PrivateKey {
    pub fn new<T>(csprng: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        PrivateKey(clamp_scalar(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PrivateKey, KeysError> {
        if bytes.len() != 32 {
            return Err(KeysError::BytesLengthError(
                "privateKey".to_string(),
                32,
                bytes.len(),
            ));
        }

        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        Ok(PrivateKey(clamp_scalar(bits)))
    }

    pub fn dh(&self, thier_public: &PublicKey) -> SharedSecret {
        SharedSecret(&self.0 * thier_public.0)
    }

    #[allow(non_snake_case, missing_docs)]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let ed_public_point = &self.0 * &ED25519_BASEPOINT_TABLE;
        let y = ed_public_point.compress();
        let sign = y.to_bytes()[31] & 0x80;

        let mut h: Sha512 = Sha512::default();

        let R: CompressedEdwardsY;

        h.input(self.0.as_bytes());
        let nonce = Scalar::from_hash(h);
        R = (&nonce * &ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.input(R.as_bytes());
        h.input(y.as_bytes());
        h.input(&message);

        let hram = Scalar::from_hash(h);
        let k = Scalar::from_bits(self.0.to_bytes());
        let s = &(&hram * &k) + &nonce;

        let mut s_bytes = s.to_bytes();
        s_bytes[31] &= 0x7F;
        s_bytes[31] |= sign;

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(R.as_bytes());
        signature[32..].copy_from_slice(&s_bytes);

        Signature(signature)
    }
}

impl From<[u8; 32]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> PrivateKey {
        PrivateKey(clamp_scalar(bytes))
    }
}

impl From<&[u8]> for PrivateKey {
    fn from(bytes: &[u8]) -> PrivateKey {
        let mut bytes2 = [0u8; 32];
        bytes2.copy_from_slice(bytes);
        PrivateKey(clamp_scalar(bytes2))
    }
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}
