use crate::ratchet::{
    ChainKey, MessageKeys, RootKey, SenderChainKey, SenderMessageKeys, UnknownPreKeyMessage,
};
use curve_crypto::*;
use prost::Message;

const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionState {
    session_structure: crate::storage_proto::SessionStructure,
}

impl SessionState {
    pub fn get_structure(&self) -> &crate::storage_proto::SessionStructure {
        &self.session_structure
    }

    pub fn new(session_structure: crate::storage_proto::SessionStructure) -> SessionState {
        SessionState { session_structure }
    }

    pub fn get_alice_base_key(&self) -> &[u8] {
        match &self.session_structure.alice_base_key {
            None => &[0u8; 32],
            Some(key) => &key,
        }
    }

    pub fn set_alice_base_key(&mut self, alice_base_key: Vec<u8>) {
        self.session_structure.alice_base_key = Some(alice_base_key);
    }

    pub fn set_remote_identity_key(&mut self, key: &PublicKey) {
        self.session_structure.remote_identity_public = Some(key.as_bytes().to_vec());
    }

    pub fn get_remote_identity_key(&self) -> Option<PublicKey> {
        self.session_structure
            .remote_identity_public
            .as_ref()
            .and_then(|v| {
                if v.len() != 32 && v.len() != 33 {
                    return None;
                } else {
                    let mut bytes: Vec<u8> = v.to_vec();
                    if bytes.len() == 33 {
                        let _ = bytes.remove(0);
                    }
                    let key = PublicKey::from(bytes.as_slice());
                    Some(key)
                }
            })
    }

    pub fn set_local_identity_key(&mut self, key: &PublicKey) {
        self.session_structure.local_identity_public = Some(key.as_bytes().to_vec());
    }

    pub fn get_local_identity_key(&self) -> Option<PublicKey> {
        self.session_structure
            .local_identity_public
            .as_ref()
            .and_then(|v| {
                if v.len() != 32 && v.len() != 33 {
                    return None;
                } else {
                    let mut bytes: Vec<u8> = v.to_vec();
                    if bytes.len() == 33 {
                        let _ = bytes.remove(0);
                    }
                    let key = PublicKey::from(bytes.as_slice());
                    Some(key)
                }
            })
    }

    pub fn set_previous_counter(&mut self, counter: u32) {
        self.session_structure.previous_counter = Some(counter);
    }

    pub fn get_previous_counter(&self) -> u32 {
        match self.session_structure.previous_counter {
            None => 0,
            Some(id) => id,
        }
    }

    pub fn set_root_key(&mut self, key: RootKey) {
        self.session_structure.root_key = Some(key.key);
    }

    pub fn get_root_key(&self) -> RootKey {
        (self
            .session_structure
            .root_key
            .as_ref()
            .expect("prost decode5"))
        .into()
    }

    pub fn get_sender_ratchet_key(&self) -> Option<PublicKey> {
        match &self.session_structure.sender_chain {
            None => None,
            Some(chain) => chain.sender_ratchet_key.as_ref().and_then(|v| {
                if v.len() != 32 && v.len() != 33 {
                    return None;
                } else {
                    let mut bytes: Vec<u8> = v.to_vec();
                    if bytes.len() == 33 {
                        let _ = bytes.remove(0);
                    }
                    let key = PublicKey::from(bytes.as_slice());
                    Some(key)
                }
            }),
        }
    }

    pub fn get_sender_ratchet_key_pair(&self) -> Option<KeyPair> {
        match &self.session_structure.sender_chain {
            None => None,
            Some(chain) => chain.sender_ratchet_key.as_ref().and_then(|v| {
                if v.len() != 32 && v.len() != 33 {
                    return None;
                } else {
                    let mut bytes: Vec<u8> = v.to_vec();
                    if bytes.len() == 33 {
                        let _ = bytes.remove(0);
                    }
                    let key = PublicKey::from(bytes.as_slice());
                    let private = chain
                        .sender_ratchet_key_private
                        .as_ref()
                        .expect("prost decode7")
                        .as_slice()
                        .into();
                    Some(KeyPair::pair(private, key))
                }
            }),
        }
    }

    pub fn has_sender_chain(&self) -> bool {
        match self.session_structure.sender_chain {
            None => false,
            Some(_) => true,
        }
    }

    pub fn get_receiver_chain(
        &self,
        sender_ephemeral: &PublicKey,
    ) -> Option<(crate::storage_proto::session_structure::Chain, u32)> {
        let len = &self.session_structure.receiver_chains.len();
        if len < &1 {
            return None;
        }

        for i in 0..*len {
            let mut bytes: Vec<u8> = self.session_structure.receiver_chains[i]
                .sender_ratchet_key
                .as_ref()
                .expect("prost decode9")
                .to_vec();
            if bytes.len() == 33 {
                let _ = bytes.remove(0);
            }
            let sender_ratchet_key: PublicKey = bytes.as_slice().into();
            if sender_ratchet_key == *sender_ephemeral {
                return Some((self.session_structure.receiver_chains[i].clone(), i as u32));
            }
        }

        None
    }

    pub fn get_receiver_chain_key(&self, sender_ephemeral: &PublicKey) -> Option<ChainKey> {
        match self.get_receiver_chain(sender_ephemeral) {
            None => None,
            //Some(pair) => Some(ChainKey::new(pair.0.chain_key.unwrap().key.as_slice(), pair.0.chain_key.unwrap().index))
            Some(pair) => match pair.0.chain_key {
                None => None,
                Some(chain_key) => Some(ChainKey::new(
                    &chain_key.key.expect("prost decode10"),
                    chain_key.index.expect("prost decode11"),
                )),
            },
        }
    }

    pub fn add_receiver_chain(&mut self, sender_ratchet_key: PublicKey, chain_key: ChainKey) {
        let mut chain_key_structure =
            crate::storage_proto::session_structure::chain::ChainKey::default();
        chain_key_structure.index = Some(chain_key.index);
        chain_key_structure.key = Some(chain_key.key);

        let mut chain = crate::storage_proto::session_structure::Chain::default();
        chain.chain_key = Some(chain_key_structure);
        chain.sender_ratchet_key = Some(sender_ratchet_key.as_bytes().to_vec());

        self.session_structure.receiver_chains.push(chain);

        if self.session_structure.receiver_chains.len() > 5 {
            self.session_structure.receiver_chains.remove(0);
        }
    }

    pub fn set_sender_chain(&mut self, sender_ratchet_key_pair: KeyPair, chain_key: ChainKey) {
        let mut chain_key_structure =
            crate::storage_proto::session_structure::chain::ChainKey::default();
        chain_key_structure.index = Some(chain_key.index);
        chain_key_structure.key = Some(chain_key.key);

        let mut chain = crate::storage_proto::session_structure::Chain::default();
        chain.chain_key = Some(chain_key_structure);
        chain.sender_ratchet_key = Some(sender_ratchet_key_pair.public.as_bytes().to_vec());
        chain.sender_ratchet_key_private =
            Some(sender_ratchet_key_pair.private.as_bytes().to_vec());

        self.session_structure.sender_chain = Some(chain);
    }

    pub fn get_sender_chain_key(&self) -> Option<ChainKey> {
        self.session_structure
            .sender_chain
            .as_ref()
            .and_then(|chain| {
                chain.chain_key.as_ref().and_then(|chain_key| {
                    chain_key.key.as_ref().and_then(|key| {
                        chain_key
                            .index
                            .and_then(|index| Some(ChainKey::new(key.as_slice(), index)))
                    })
                })
            })
    }

    pub fn set_sender_chain_key(&mut self, next_chain_key: ChainKey) {
        let mut chain_key_structure =
            crate::storage_proto::session_structure::chain::ChainKey::default();
        chain_key_structure.index = Some(next_chain_key.index);
        chain_key_structure.key = Some(next_chain_key.key);

        let mut chain = &mut crate::storage_proto::session_structure::Chain::default();
        if let Some(chain1) = &mut self.session_structure.sender_chain {
            chain = chain1;
        }
        chain.chain_key = Some(chain_key_structure);

        self.session_structure.sender_chain = Some(chain.clone());
    }

    pub fn has_message_keys(&self, public_key: &PublicKey, counter: u32) -> bool {
        match self.get_receiver_chain(public_key) {
            None => return false,
            Some((chain, _)) => {
                for message_key in chain.message_keys {
                    if message_key.index.map_or(false, |idx| idx == counter) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn remove_message_keys(
        &mut self,
        public_key: &PublicKey,
        counter: u32,
    ) -> Option<MessageKeys> {
        match self.get_receiver_chain(public_key) {
            None => return None,
            Some((mut chain, index)) => {
                let len = chain.message_keys.len();
                if len == 0 {
                    return None;
                }

                for i in 0..len {
                    if chain.message_keys[i]
                        .index
                        .map_or(false, |idx| idx == counter)
                    {
                        let message_key = chain.message_keys.remove(i);
                        self.session_structure.receiver_chains[index as usize] = chain;
                        return Some(
                            MessageKeys::default()
                                .cipher_key(&message_key.cipher_key.expect("prost decode16"))
                                .mac_key(&message_key.mac_key.expect("prost decode17"))
                                .iv(&message_key.iv.expect("prost decode18"))
                                .counter(message_key.index.expect("prost decode19")),
                        );
                    }
                }
            }
        }

        None
    }

    pub fn set_message_keys(&mut self, public_key: &PublicKey, message_key: &MessageKeys) {
        match self.get_receiver_chain(public_key) {
            None => return,
            Some((mut chain, index)) => {
                let mut message_key_structure =
                    crate::storage_proto::session_structure::chain::MessageKey::default();
                message_key_structure.cipher_key = Some(message_key.cipher_key.to_vec());
                message_key_structure.mac_key = Some(message_key.mac_key.to_vec());
                message_key_structure.iv = Some(message_key.iv.to_vec());
                message_key_structure.index = Some(message_key.counter);

                chain.message_keys.push(message_key_structure);
                if chain.message_keys.len() > MAX_MESSAGE_KEYS {
                    chain.message_keys.remove(0);
                }

                self.session_structure.receiver_chains[index as usize] = chain;
            }
        }
    }

    pub fn set_receiver_chain_key(&mut self, public_key: &PublicKey, chain_key: ChainKey) {
        match self.get_receiver_chain(public_key) {
            None => return,
            Some((mut chain, index)) => {
                let mut chain_key_structure =
                    crate::storage_proto::session_structure::chain::ChainKey::default();
                chain_key_structure.index = Some(chain_key.index);
                chain_key_structure.key = Some(chain_key.key);

                chain.chain_key = Some(chain_key_structure);
                self.session_structure.receiver_chains[index as usize] = chain;
            }
        }
    }

    pub fn set_unknown_pre_key_message(
        &mut self,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: &PublicKey,
    ) {
        let mut pending = crate::storage_proto::session_structure::PendingPreKey::default();
        pending.signed_pre_key_id = Some(signed_pre_key_id as i32);
        pending.base_key = Some(base_key.as_bytes().to_vec());
        if let Some(id) = pre_key_id {
            pending.pre_key_id = Some(id);
        }

        self.session_structure.pending_pre_key = Some(pending);
    }

    pub fn has_unknown_pre_key_message(&self) -> bool {
        if let Some(key) = &self.session_structure.pending_pre_key {
            if let Some(id) = key.signed_pre_key_id {
                if id > 0 {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        false
    }

    pub fn clear_unknown_pre_key_message(&mut self) {
        self.session_structure.pending_pre_key = None;
    }

    pub fn get_unknown_pre_key_message(&self) -> Option<UnknownPreKeyMessage> {
        match &self.session_structure.pending_pre_key {
            None => None,
            Some(pre_key_message) => {
                let mut message = UnknownPreKeyMessage::default();
                let mut bytes: Vec<u8> = pre_key_message
                    .clone()
                    .base_key
                    .expect("prost decode21")
                    .to_vec();
                if bytes.len() == 33 {
                    let _ = bytes.remove(0);
                }
                message.signed_pre_key_id = pre_key_message
                    .clone()
                    .signed_pre_key_id
                    .expect("prost decode20");
                message.base_key = bytes.as_slice().into();
                message.pre_key_id = pre_key_message.clone().pre_key_id;
                Some(message)
            }
        }
    }

    pub fn set_remote_registration_id(&mut self, id: u32) {
        self.session_structure.remote_registration_id = Some(id);
    }

    pub fn get_remote_registration_id(&self) -> u32 {
        self.session_structure.remote_registration_id.unwrap_or(0)
    }

    pub fn set_local_registration_id(&mut self, id: u32) {
        self.session_structure.local_registration_id = Some(id);
    }

    pub fn get_local_registration_id(&self) -> u32 {
        self.session_structure.local_registration_id.unwrap_or(0)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.reserve(self.session_structure.encoded_len());
        self.session_structure.encode(&mut buf).unwrap();
        buf
    }
}

#[derive(Clone, Debug, Default)]
pub struct SenderKeyState {
    sender_key_structure: crate::storage_proto::SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn get_structure(&self) -> &crate::storage_proto::SenderKeyStateStructure {
        &self.sender_key_structure
    }

    pub fn new(
        sender_key_structure: crate::storage_proto::SenderKeyStateStructure,
    ) -> SenderKeyState {
        SenderKeyState {
            sender_key_structure,
        }
    }

    pub fn build(
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key_public: PublicKey,
        signature_key_private: Option<PrivateKey>,
    ) -> SenderKeyState {
        let mut sender_chain_key =
            crate::storage_proto::sender_key_state_structure::SenderChainKey::default();
        sender_chain_key.iteration = Some(iteration);
        sender_chain_key.seed = Some(chain_key);

        let mut signing_key =
            crate::storage_proto::sender_key_state_structure::SenderSigningKey::default();
        signing_key.public = Some(signature_key_public.to_bytes().to_vec());
        if let Some(private_key) = signature_key_private {
            signing_key.private = Some(private_key.to_bytes().to_vec());
        }

        let mut sender_key_structure = crate::storage_proto::SenderKeyStateStructure::default();
        sender_key_structure.sender_key_id = Some(id);
        sender_key_structure.sender_chain_key = Some(sender_chain_key);
        sender_key_structure.sender_signing_key = Some(signing_key);

        SenderKeyState {
            sender_key_structure,
        }
    }

    pub fn get_key_id(&self) -> u32 {
        self.sender_key_structure
            .sender_key_id
            .expect("prost decode25")
    }

    pub fn get_sender_chain_key(&self) -> SenderChainKey {
        let chain_key = self
            .sender_key_structure
            .sender_chain_key
            .as_ref()
            .expect("prost decode26");
        SenderChainKey::new(
            &chain_key.seed.as_ref().expect("prost decode27"),
            chain_key.iteration.expect("prost decode28"),
        )
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        let mut sender_chain_key =
            crate::storage_proto::sender_key_state_structure::SenderChainKey::default();
        sender_chain_key.iteration = Some(chain_key.iteration);
        sender_chain_key.seed = Some(chain_key.key);
        self.sender_key_structure.sender_chain_key = Some(sender_chain_key);
    }

    pub fn get_signing_key_public(&self) -> PublicKey {
        let key = self
            .sender_key_structure
            .sender_signing_key
            .as_ref()
            .expect("prost decode31");
        PublicKey::from(key.public.as_ref().expect("prost decode32").as_slice())
    }

    pub fn get_signing_key_private(&self) -> PrivateKey {
        let key = self
            .sender_key_structure
            .sender_signing_key
            .as_ref()
            .expect("prost decode33");
        PrivateKey::from(key.private.as_ref().expect("prost decode34").as_slice())
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> bool {
        for mk in &self.sender_key_structure.sender_message_keys {
            if mk.iteration.expect("prost decode 35") == iteration {
                return true;
            }
        }

        false
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: SenderMessageKeys) {
        let mut key_structure =
            crate::storage_proto::sender_key_state_structure::SenderMessageKey::default();
        key_structure.iteration = Some(sender_message_key.iteration);
        key_structure.seed = Some(sender_message_key.seed);

        self.sender_key_structure
            .sender_message_keys
            .push(key_structure);

        if self.sender_key_structure.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            self.sender_key_structure.sender_message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(&mut self, iteration: u32) -> Option<SenderMessageKeys> {
        let mut i = 0;
        for mk in &self.sender_key_structure.sender_message_keys {
            if mk.iteration.expect("prost decode 35") == iteration {
                let key = self.sender_key_structure.sender_message_keys.remove(i);
                return Some(SenderMessageKeys::new(
                    key.iteration.expect("prost decode 36"),
                    key.seed.expect("prost decode 37"),
                ));
            }
            i += 1;
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn session_state() {
        let mut ss = SessionState::default();

        ss.set_alice_base_key(vec![
            78, 193, 188, 44, 46, 236, 242, 47, 65, 93, 87, 230, 218, 115, 142, 225, 29, 224, 18,
            167, 72, 65, 124, 4, 64, 117, 253, 29, 230, 5, 116, 38,
        ]);
        let alice_base_key = ss.get_alice_base_key();
        println!("alice base key: {:?}", alice_base_key);

        println!("root_key: {:?}", ss.get_root_key());
        let root_key = RootKey { key: vec![1, 2, 3] };
        ss.set_root_key(root_key);
        println!("root_key: {:?}", ss.get_root_key());

        println!("remote identity key: {:?}", ss.get_remote_identity_key());
        let private_key = PrivateKey::new(&mut OsRng);
        let public_key: PublicKey = (&private_key).into();
        ss.set_remote_identity_key(&public_key);
        println!("remote identity key: {:?}", ss.get_remote_identity_key());

        println!("local identity key: {:?}", ss.get_local_identity_key());
        let private_key = PrivateKey::new(&mut OsRng);
        let public_key: PublicKey = (&private_key).into();
        ss.set_local_identity_key(&public_key);
        println!("local identity key: {:?}", ss.get_local_identity_key());

        println!("previous counter: {}", ss.get_previous_counter());
        ss.set_previous_counter(1);
        println!("previous counter: {}", ss.get_previous_counter());

        let mut chain = ChainKey::default();
        chain.index = 1;
        chain.key = vec![1, 3];
        let key_pair = KeyPair::generate();
        ss.set_sender_chain(key_pair, chain);

        let mut chain = ChainKey::default();
        chain.index = 2;
        chain.key = vec![2, 4];
        ss.set_sender_chain_key(chain);

        println!("sender_ratchet_key: {:?}", ss.get_sender_ratchet_key());

        println!(
            "sender_ratchet_key_pair: {:?}",
            ss.get_sender_ratchet_key_pair()
        );

        let mut chain = ChainKey::default();
        chain.index = 1;
        chain.key = vec![12, 13];
        ss.add_receiver_chain(public_key, chain);

        println!("has_sender_chain: {:?}", ss.has_sender_chain());

        println!("get_sender_chain_key: {:?}", ss.get_sender_chain_key());

        println!(
            "get_receiver_chain: {:?}",
            ss.get_receiver_chain(&public_key)
        );

        println!(
            "get_receiver_chain_key: {:?}",
            ss.get_receiver_chain_key(&public_key)
        );

        println!(
            "has_message_keys: {:?}",
            ss.has_message_keys(&public_key, 1)
        );

        let message_key1 = MessageKeys::default()
            .cipher_key(&[1u8; 32])
            .mac_key(&[1u8; 32])
            .iv(&[1u8; 16])
            .counter(1);
        let message_key2 = MessageKeys::default()
            .cipher_key(&[2u8; 32])
            .mac_key(&[2u8; 32])
            .iv(&[2u8; 16])
            .counter(2);
        ss.set_message_keys(&public_key, &message_key1);
        ss.set_message_keys(&public_key, &message_key2);

        println!(
            "remove_message_keys: {:?}",
            ss.remove_message_keys(&public_key, 1)
        );

        let mut chain = ChainKey::default();
        chain.index = 10;
        chain.key = vec![10, 30];
        ss.set_receiver_chain_key(&public_key, chain);

        // let our_base_key = KeyPair::generate();
        // let our_ratchet_key = KeyPair::generate();
        // let identity_key = KeyPair::generate();
        // ss.set_pending_key_exchange(1, our_base_key, our_ratchet_key, identity_key);
        //        println!("get_pending_key_exchange_sequence: {}", ss.get_pending_key_exchange_sequence());
        //        println!("get_pending_key_exchange_base_key: {:?}", ss.get_pending_key_exchange_base_key());
        //        println!("get_pending_key_exchange_ratchet_key: {:?}", ss.get_pending_key_exchange_ratchet_key());
        //        println!("get_pending_key_exchange_identity_key: {:?}", ss.get_pending_key_exchange_identity_key());
        //        println!("has_pending_key_exchange: {:?}", ss.has_pending_key_exchange());

        ss.set_remote_registration_id(11);
        ss.set_local_registration_id(12);

        println!(
            "get_remote_registration_id: {:?}",
            ss.get_remote_registration_id()
        );
        println!(
            "get_local_registration_id: {:?}",
            ss.get_local_registration_id()
        );
        println!("state: {:?}", ss);

        let vec = ss.serialize();
        println!("serialize: {:?}", vec);
    }
}
