use curve_crypto::{KeyPair, PrivateKey, PublicKey, Signature};
use prost::Message;
use rand_core::CryptoRng;
use rand_core::OsRng;
use rand_core::RngCore;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct IdentityKeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl IdentityKeyPair {
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let sk: PrivateKey = PrivateKey::new(csprng);
        let pk: PublicKey = (&sk).into();

        Self {
            public: pk,
            private: sk,
        }
    }

    pub fn pair(private: PrivateKey, public: PublicKey) -> Self {
        Self { public, private }
    }

    pub fn deserialize(buf: &[u8]) -> Result<IdentityKeyPair, prost::DecodeError> {
        match crate::storage_proto::IdentityKeyPairStructure::decode(&mut Cursor::new(buf)) {
            Err(e) => Err(e),
            Ok(pair) => {
                let public = PublicKey::from(pair.public_key.expect("prost decode29").as_slice());
                let private =
                    PrivateKey::from(pair.private_key.expect("prost decode30").as_slice());
                let identity_pair = IdentityKeyPair { public, private };
                Ok(identity_pair)
            }
        }
    }

    pub fn generate() -> Self {
        Self::new(&mut OsRng)
    }

    pub fn get_public(&self) -> &[u8] {
        self.public.as_bytes()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SignedPreKey {
    pub id: u32,
    pub keypair: KeyPair,
    pub signature: Signature,
    pub timestamp: u64,
}

impl SignedPreKey {
    pub fn new(identity_keypair: &IdentityKeyPair, id: u32) -> Self {
        let keypair = KeyPair::generate();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = identity_keypair.private.sign(keypair.public.as_bytes());

        Self {
            id,
            keypair,
            signature,
            timestamp,
        }
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct PreKeyRecord {
    pub key_id: u32,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl PreKeyRecord {
    pub fn new(key_id: u32) -> Self {
        Self {
            key_id,
            private_key: [1u8; 32],
            public_key: [2u8; 32],
        }
    }

    pub fn new_list(start: u32, count: u32) -> Vec<Self> {
        let mut list = Vec::new();
        for i in 0..count {
            list.push(Self::new((start + i) % (0xFFFFFF - 1) + 1));
        }

        list
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PreKey {
    pub id: u32,
    pub keypair: KeyPair,
}

impl PreKey {
    pub fn new(id: u32) -> Self {
        let keypair = KeyPair::generate();
        Self { id, keypair }
    }

    pub fn new_list(start: u32, count: u32) -> Vec<Self> {
        let mut list = Vec::new();
        for i in 0..count {
            list.push(PreKey::new((start + i) % (0xFFFFFF - 1) + 1));
        }

        list
    }
}

/// A pre key bundle for a peer, fetched from the keyserver.
#[derive(Default, Debug, Clone)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key: PublicKey,
    pub pre_key_id: u32,
    pub signed_pre_key: PublicKey,
    pub signed_data: Vec<u8>,
    pub signed_pre_key_id: u32,
    pub signature: Signature,
    pub identity_key: PublicKey,
}

impl PreKeyBundle {
    pub fn registration_id(&mut self, id: u32) -> &PreKeyBundle {
        self.registration_id = id;
        self
    }

    pub fn device_id(&mut self, id: u32) -> &PreKeyBundle {
        self.device_id = id;
        self
    }

    pub fn pre_key(&mut self, key: PublicKey) -> &PreKeyBundle {
        self.pre_key = key;
        self
    }

    pub fn pre_key_id(&mut self, id: u32) -> &PreKeyBundle {
        self.pre_key_id = id;
        self
    }

    pub fn signed_pre_key(&mut self, key: PublicKey) -> &PreKeyBundle {
        self.signed_pre_key = key;
        self
    }

    pub fn signed_pre_key_id(&mut self, id: u32) -> &PreKeyBundle {
        self.signed_pre_key_id = id;
        self
    }

    pub fn identity_key(&mut self, key: PublicKey) -> &PreKeyBundle {
        self.identity_key = key;
        self
    }

    pub fn signature(&mut self, sig: Signature) -> &PreKeyBundle {
        self.signature = sig;
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn gen_signed_key() {
        let identity = IdentityKeyPair::new(&mut OsRng);
        let signed_key = SignedPreKey::new(&identity, 1);
        println!("signed key: {:?}", signed_key);

        let result = identity
            .public
            .verify(signed_key.keypair.public.as_bytes(), &signed_key.signature);
        println!("verify result: {:?}", result);
    }

    #[test]
    fn gen_pre_key() {
        let pre_key = PreKey::new(2);
        println!("pre key: {:?}", pre_key);
    }

    #[test]
    fn gen_pre_key_list() {
        let pre_key_list = PreKey::new_list(0xFFFFF0, 5);
        println!("pre key list: {:?}", pre_key_list);
    }
}
