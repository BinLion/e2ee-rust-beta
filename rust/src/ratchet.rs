use crate::keys::*;
use crate::session_state::SessionState;
use curve_crypto::*;
use hkdf::Hkdf;
use hmac::*;
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct RootKey {
    pub key: Vec<u8>,
}

impl RootKey {
    pub fn create_chain(
        &self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &KeyPair,
    ) -> (RootKey, ChainKey) {
        let shared_secret = our_ratchet_key.private.dh(their_ratchet_key);
        println!(
            "dh shared_secret: {:02x?}, our_ratchet_key:{:02x?}, their_rathcet_key:{:02x?}",
            shared_secret.as_bytes(),
            our_ratchet_key,
            their_ratchet_key
        );
        let (_prk, hk) =
            Hkdf::<Sha256>::extract(Some(self.key.as_slice()), shared_secret.as_bytes());
        let mut derived_secrets = [0u8; 64];
        hk.expand("WhisperRatchet".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, second) = derived_secrets.split_at(32);
        let root = RootKey {
            key: first.to_vec(),
        };
        let chain = ChainKey::new(second, 0);

        (root, chain)
    }
}

impl From<&[u8]> for RootKey {
    fn from(key: &[u8]) -> RootKey {
        RootKey { key: key.to_vec() }
    }
}

impl From<&Vec<u8>> for RootKey {
    fn from(key: &Vec<u8>) -> RootKey {
        RootKey { key: key.to_vec() }
    }
}

const MESSAGE_KEY_SEED: [u8; 1] = [0x01];
const CHAIN_KEY_SEED: [u8; 1] = [0x02];

#[derive(Debug, Clone, Default)]
pub struct ChainKey {
    pub key: Vec<u8>,
    pub index: u32,
}

impl ChainKey {
    pub fn new(key: &[u8], index: u32) -> Self {
        Self {
            key: key.to_vec(),
            index,
        }
    }

    pub fn next(&self) -> Self {
        let mut mac = Hmac::<Sha256>::new_varkey(self.key.as_slice())
            .expect("HMAC can take a key of any size");
        mac.input(&CHAIN_KEY_SEED);
        let prk = mac.result().code();
        Self {
            key: prk.to_vec(),
            index: self.index + 1,
        }
    }

    pub fn get_message_keys(&self) -> MessageKeys {
        let mut mac = Hmac::<Sha256>::new_varkey(self.key.as_slice())
            .expect("HMAC can take a key of any size");
        mac.input(&MESSAGE_KEY_SEED);
        let keys = mac.result().code();

        let (_prk, hk) = Hkdf::<Sha256>::extract(None, keys.to_vec().as_slice());
        let mut derived_secrets = [0u8; 80];
        hk.expand("WhisperMessageKeys".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, other) = derived_secrets.split_at(32);
        let (second, third) = other.split_at(32);
        let mut cipher_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        let mut iv = [0u8; 16];
        cipher_key.copy_from_slice(first);
        mac_key.copy_from_slice(second);
        iv.copy_from_slice(third);

        MessageKeys {
            cipher_key,
            mac_key,
            iv,
            counter: self.index,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MessageKeys {
    pub cipher_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub iv: [u8; 16],
    pub counter: u32,
}

impl MessageKeys {
    pub fn cipher_key(mut self, key: &[u8]) -> MessageKeys {
        self.cipher_key.copy_from_slice(key);
        self
    }

    pub fn mac_key(mut self, key: &[u8]) -> MessageKeys {
        self.mac_key.copy_from_slice(key);
        self
    }

    pub fn iv(mut self, iv: &[u8]) -> MessageKeys {
        self.iv.copy_from_slice(iv);
        self
    }

    pub fn counter(mut self, counter: u32) -> MessageKeys {
        self.counter = counter;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct SenderChainKey {
    pub key: Vec<u8>,
    pub iteration: u32,
}

impl SenderChainKey {
    pub fn new(key: &[u8], iteration: u32) -> Self {
        Self {
            key: key.to_vec(),
            iteration,
        }
    }

    pub fn next(&self) -> Self {
        let mut mac = Hmac::<Sha256>::new_varkey(self.key.as_slice())
            .expect("HMAC can take a key of any size");
        mac.input(&CHAIN_KEY_SEED);
        let prk = mac.result().code();
        Self {
            key: prk.to_vec(),
            iteration: self.iteration + 1,
        }
    }

    pub fn get_message_keys(&self) -> SenderMessageKeys {
        let mut mac = Hmac::<Sha256>::new_varkey(self.key.as_slice())
            .expect("HMAC can take a key of any size");
        mac.input(&MESSAGE_KEY_SEED);
        let keys = mac.result().code();

        let (_prk, hk) = Hkdf::<Sha256>::extract(None, keys.to_vec().as_slice());
        let mut derived_secrets = [0u8; 48];
        hk.expand("WhisperGroup".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, other) = derived_secrets.split_at(16);
        let mut cipher_key = [0u8; 32];
        let mut iv = [0u8; 16];
        cipher_key.copy_from_slice(other);
        iv.copy_from_slice(first);

        SenderMessageKeys {
            cipher_key,
            seed: keys.to_vec(),
            iv,
            iteration: self.iteration,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SenderMessageKeys {
    pub cipher_key: [u8; 32],
    pub iv: [u8; 16],
    pub iteration: u32,
    pub seed: Vec<u8>,
}

impl SenderMessageKeys {
    pub fn new(iteration: u32, seed: Vec<u8>) -> SenderMessageKeys {
        //        let mut mac = Hmac::<Sha256>::new_varkey(self.key.as_slice()).expect("HMAC can take a key of any size");
        //        mac.input(&MESSAGE_KEY_SEED);
        //        let keys = mac.result().code();

        let (_prk, hk) = Hkdf::<Sha256>::extract(None, seed.as_slice());
        let mut derived_secrets = [0u8; 48];
        hk.expand("WhisperGroup".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, other) = derived_secrets.split_at(16);
        let mut cipher_key = [0u8; 32];
        let mut iv = [0u8; 16];
        cipher_key.copy_from_slice(other);
        iv.copy_from_slice(first);

        SenderMessageKeys {
            cipher_key,
            seed,
            iv,
            iteration,
        }
        //        let chain_key = SenderChainKey::new(seed.as_slice(), iteration);
        //        chain_key.get_message_keys()
    }

    pub fn cipher_key(mut self, key: &[u8]) -> SenderMessageKeys {
        self.cipher_key.copy_from_slice(key);
        self
    }

    pub fn iv(mut self, iv: &[u8]) -> SenderMessageKeys {
        self.iv.copy_from_slice(iv);
        self
    }

    pub fn iteration(mut self, iteration: u32) -> SenderMessageKeys {
        self.iteration = iteration;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnknownPreKeyMessage {
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: i32,
    pub base_key: PublicKey,
}

impl UnknownPreKeyMessage {
    pub fn pre_key_id(mut self, id: u32) -> UnknownPreKeyMessage {
        if id > 0 {
            self.pre_key_id = Some(id);
        }
        self
    }

    pub fn signed_pre_key_id(mut self, id: i32) -> UnknownPreKeyMessage {
        self.signed_pre_key_id = id;
        self
    }

    pub fn base_key(mut self, key: Vec<u8>) -> UnknownPreKeyMessage {
        self.base_key = key.as_slice().into();
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct AliceParameters {
    pub our_identity_key: IdentityKeyPair,
    pub our_base_key: KeyPair,
    pub their_identity_key: PublicKey,
    pub their_signed_pre_key: PublicKey,
    pub their_one_time_key: Option<PublicKey>,
    pub their_ratchet_key: PublicKey,
}

impl AliceParameters {
    pub fn our_identity_key(mut self, key_pair: IdentityKeyPair) -> AliceParameters {
        self.our_identity_key = key_pair;
        self
    }

    pub fn our_base_key(mut self, key_pair: KeyPair) -> AliceParameters {
        self.our_base_key = key_pair;
        self
    }

    pub fn their_identity_key(mut self, key: PublicKey) -> AliceParameters {
        self.their_identity_key = key;
        self
    }

    pub fn their_signed_pre_key(mut self, key: PublicKey) -> AliceParameters {
        self.their_signed_pre_key = key;
        self
    }

    pub fn their_one_time_key(mut self, key: Option<PublicKey>) -> AliceParameters {
        self.their_one_time_key = key;
        self
    }

    pub fn their_ratchet_key(mut self, key: PublicKey) -> AliceParameters {
        self.their_ratchet_key = key;
        self
    }

    pub fn init_session(&self, session: &mut SessionState) {
        session.set_remote_identity_key(&self.their_identity_key);
        session.set_local_identity_key(&self.our_identity_key.public);

        let sending_ratchet_key = KeyPair::generate();

        let mut secrets = Vec::new();
        secrets.append([0xFFu8; 32].to_vec().as_mut());
        secrets.append(
            self.our_identity_key
                .private
                .dh(&self.their_signed_pre_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        secrets.append(
            self.our_base_key
                .private
                .dh(&self.their_identity_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        secrets.append(
            self.our_base_key
                .private
                .dh(&self.their_signed_pre_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        if let Some(key) = self.their_one_time_key {
            secrets.append(
                self.our_base_key
                    .private
                    .dh(&key)
                    .as_bytes()
                    .to_vec()
                    .as_mut(),
            );
        }

        println!(
            "alice_secrets: {:02x?}, our_base_key:{:02x?}, their_one_time:{:02x?}",
            secrets.clone(),
            self.our_base_key,
            self.their_one_time_key
        );

        let (_prk, hk) = Hkdf::<Sha256>::extract(None, secrets.as_slice());
        let mut derived_secrets = [0u8; 64];
        hk.expand("WhisperText".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, second) = derived_secrets.split_at(32);
        //println!("alice_derived_secrets: {:x?}, {:x?}", first, second);
        let root: RootKey = first.into();
        let (root_key, chain_key) =
            root.create_chain(&self.their_ratchet_key, &sending_ratchet_key);

        session.add_receiver_chain(self.their_ratchet_key, ChainKey::new(second, 0));
        session.set_sender_chain(sending_ratchet_key, chain_key);
        session.set_root_key(root_key);
        println!("session111: {:?}", session);
    }
}

#[derive(Debug, Default)]
pub struct BobParameters {
    pub our_identity_key: IdentityKeyPair,
    pub our_signed_key: KeyPair,
    pub our_one_time_key: Option<KeyPair>,
    pub our_ratchet_key: KeyPair,
    pub their_identity_key: PublicKey,
    pub their_base_key: PublicKey,
}

impl BobParameters {
    pub fn our_identity_key(mut self, key_pair: IdentityKeyPair) -> BobParameters {
        self.our_identity_key = key_pair;
        self
    }

    pub fn our_signed_key(mut self, key_pair: KeyPair) -> BobParameters {
        self.our_signed_key = key_pair;
        self
    }

    pub fn our_one_time_key(mut self, key_pair: Option<KeyPair>) -> BobParameters {
        self.our_one_time_key = key_pair;
        self
    }

    pub fn our_ratchet_key(mut self, key_pair: KeyPair) -> BobParameters {
        self.our_ratchet_key = key_pair;
        self
    }

    pub fn their_identity_key(mut self, key: PublicKey) -> BobParameters {
        self.their_identity_key = key;
        self
    }

    pub fn their_base_key(mut self, key: PublicKey) -> BobParameters {
        self.their_base_key = key;
        self
    }

    pub fn init_session(&self, session: &mut SessionState) {
        session.set_remote_identity_key(&self.their_identity_key);
        session.set_local_identity_key(&self.our_identity_key.public);

        let mut secrets = Vec::new();
        secrets.append([0xFFu8; 32].to_vec().as_mut());
        secrets.append(
            self.our_signed_key
                .private
                .dh(&self.their_identity_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        secrets.append(
            self.our_identity_key
                .private
                .dh(&self.their_base_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        secrets.append(
            self.our_signed_key
                .private
                .dh(&self.their_base_key)
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        if let Some(key) = &self.our_one_time_key {
            secrets.append(
                key.private
                    .dh(&self.their_base_key)
                    .as_bytes()
                    .to_vec()
                    .as_mut(),
            );
        }

        debug!("bob secrets: {:02x?}", secrets);

        let (_prk, hk) = Hkdf::<Sha256>::extract(None, secrets.as_slice());
        let mut derived_secrets = [0u8; 64];
        hk.expand("WhisperText".as_bytes(), &mut derived_secrets)
            .expect("HKDF error");
        let (first, second) = derived_secrets.split_at(32);
        //        println!("bob_derived_secrets: {:x?} {:x?}", first, second);

        session.set_sender_chain(self.our_ratchet_key.clone(), ChainKey::new(second, 0));
        session.set_root_key(first.into());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test() {
        let key_pair = KeyPair::generate();
        let mut parameters = AliceParameters::default();
        parameters.our_base_key = key_pair.clone();
        parameters.our_identity_key = IdentityKeyPair::new(&mut OsRng);
        parameters.their_identity_key = key_pair.public;
        parameters.their_signed_pre_key = key_pair.public;
        parameters.their_ratchet_key = key_pair.public;
        parameters.their_one_time_key = None;

        println!("parameters: {:?}", parameters);
    }
}
