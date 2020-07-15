use crate::errors::KeysError;
use crate::private::PrivateKey;
use crate::signature::Signature;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
// use sha2::digest::Digest;
use sha2::Sha512;
use zeroize::Zeroize;

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) MontgomeryPoint);

impl PublicKey {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeysError> {
        if bytes.len() != 32 {
            return Err(KeysError::BytesLengthError(
                "publicKey".to_string(),
                32,
                bytes.len(),
            ));
        }

        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        Ok(PublicKey(MontgomeryPoint(bits)))
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), KeysError> {
        let mut sign: u8 = 0;
        if signature.0[63] & 0x80 != 0 {
            sign = 1;
        }

        self.0
            .to_edwards(sign)
            .map_or(Err(KeysError::NoEdwards), |edwards| {
                let y = edwards.compress();
                let mut h: Sha512 = Sha512::new();
                let R: EdwardsPoint;
                let k: Scalar;
                let minus_A: EdwardsPoint = -edwards;

                let (first, second) = signature.0.split_at(32);
                h.input(first);
                h.input(y.as_bytes());
                h.input(&message);

                k = Scalar::from_hash(h);
                let mut s = [0u8; 32];
                s.copy_from_slice(second);
                let s = Scalar::from_bits(s);
                R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &s);

                if R.compress().as_bytes() == first {
                    Ok(())
                } else {
                    Err(KeysError::SignatureError)
                }
            })
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> PublicKey {
        PublicKey(MontgomeryPoint(bytes))
    }
}

impl From<&[u8]> for PublicKey {
    fn from(bytes: &[u8]) -> PublicKey {
        let mut bytes2 = [0u8; 32];
        bytes2.copy_from_slice(bytes);
        PublicKey(MontgomeryPoint(bytes2))
    }
}

impl<'a> From<&'a PrivateKey> for PublicKey {
    fn from(private: &'a PrivateKey) -> PublicKey {
        PublicKey((&ED25519_BASEPOINT_TABLE * &private.0).to_montgomery())
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct SharedSecret(pub(crate) MontgomeryPoint);

impl SharedSecret {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}
