#[macro_use]
extern crate log;
extern crate curve25519_dalek;

mod errors;
mod private;
mod public;
mod signature;

pub use crate::errors::*;
pub use crate::private::*;
pub use crate::public::*;
pub use crate::signature::*;
use rand::rngs::OsRng;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let private = PrivateKey::new(&mut OsRng);
        let public: PublicKey = (&private).into();
        trace!(
            "generate keypair. private:{:02x?}, public:{:02x?}",
            private,
            public
        );
        KeyPair { private, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private.sign(&message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), KeysError> {
        self.public.verify(message, signature)
    }

    pub fn pair(private: PrivateKey, public: PublicKey) -> Self {
        Self { public, private }
    }
}
