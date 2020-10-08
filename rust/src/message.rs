// use crate::keys::*;
use curve_crypto::{PrivateKey, PublicKey, Signature};
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use std::io::Cursor;

pub trait CiphertextMessage {
    fn serialize(&self) -> Vec<u8>;
    fn get_type(&self) -> u8;
}

#[derive(Debug, Clone)]
pub struct SignalMessage {
    version: u8,
    pub sender_ratchet_key: PublicKey,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
    pub serialized: Vec<u8>,
    pub alice_base_key: Vec<u8>,
}

impl SignalMessage {
    pub fn new(
        mac_key: [u8; 32],
        sender_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: Vec<u8>,
        sender_identity_key: PublicKey,
        receiver_identity_key: PublicKey,
        base_key: &[u8],
    ) -> Self {
        let mut message = crate::message_proto::Message::default();
        let mut ratchet_key = sender_key.as_bytes().to_vec();
        ratchet_key.insert(0, 5u8);
        message.ratchet_key = Some(ratchet_key);
        message.counter = Some(counter);
        message.previous_counter = Some(previous_counter);
        message.ciphertext = Some(ciphertext.clone());
        message.alice_base_key = Some(base_key.to_vec());

        let mut buf = Vec::new();
        buf.reserve(message.encoded_len());
        message.encode(&mut buf).unwrap();
        let len = buf.len();

        let version_byte: u8 = (3 << 4 | 3) & 0xFF;
        buf.insert(0, version_byte);

        let mut mac = SignalMessage::get_mac(
            &sender_identity_key,
            &receiver_identity_key,
            &mac_key,
            buf.as_slice(),
        );
        debug!(
            "mac: {:02x?}, sender_identity:{:02x?}, receiver_identity_key:{:02x?}, buf:{:02x?}",
            mac, sender_identity_key, receiver_identity_key, buf
        );
        let mut serialized = Vec::new();
        serialized.reserve(len + 8);
        //        let version_byte: u8 = (3 << 4 | 3) & 0xFF;
        //        serialized.push(version_byte);
        serialized.append(&mut buf);
        serialized.append(&mut mac);
        //serialized[0..len].copy_from_slice(&buf);
        //serialized[len..len+8].copy_from_slice(&mac[0..8]);
        Self {
            version: 3,
            sender_ratchet_key: sender_key,
            counter,
            previous_counter,
            ciphertext,
            serialized,
            alice_base_key: base_key.to_vec(),
        }
    }

    fn get_mac(
        sender_identity_key: &PublicKey,
        receiver_identity_key: &PublicKey,
        mac_key: &[u8],
        serialized: &[u8],
    ) -> Vec<u8> {
        let mut hmac = Hmac::<Sha256>::new_varkey(mac_key).unwrap();
        hmac.input(&[5u8]);
        hmac.input(sender_identity_key.as_bytes());
        hmac.input(&[5u8]);
        hmac.input(receiver_identity_key.as_bytes());
        hmac.input(serialized);

        let output = hmac.result_reset().code();
        output[0..8].to_vec()
    }

    pub fn verify_mac(
        &self,
        sender_identity: &PublicKey,
        receiver_identity: &PublicKey,
        mac_key: &[u8],
    ) -> Result<(), i32> {
        let len = self.serialized.len();
        let (info, their_mac) = self.serialized.split_at(len - 8);
        let our_mac = SignalMessage::get_mac(sender_identity, receiver_identity, mac_key, info);
        if our_mac != their_mac {
            debug!("verify_mac. mak_key:{:02x?}, info:{:02x?}", mac_key, info);
            return Err(1000);
        }
        Ok(())
    }

    pub fn deserialize(serialized: &[u8]) -> Result<SignalMessage, prost::DecodeError> {
        let (version_byte, msg) = serialized.split_at(1);
        let version = (version_byte[0] & 0xFF) >> 4;
        let len = msg.len();
        let (info, _) = msg.split_at(len - 8);
        match crate::message_proto::Message::decode(&mut Cursor::new(info)) {
            Err(e) => Err(e),
            Ok(message) => {
                let mut ratchet_key = message.ratchet_key.expect("message proto");
                if ratchet_key.len() == 33 && ratchet_key[0] == 5 {
                    ratchet_key.remove(0);
                }
                let sm = SignalMessage {
                    version,
                    serialized: serialized.to_vec(),
                    sender_ratchet_key: PublicKey::from(ratchet_key.as_slice()),
                    counter: message.counter.expect("message proto"),
                    previous_counter: message.previous_counter.expect("message proto"),
                    ciphertext: message.ciphertext.expect("message proto"),
                    alice_base_key: message.alice_base_key.expect("message proto. no alice base key"),
                };

                Ok(sm)
            }
        }
    }
}

impl CiphertextMessage for SignalMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized.clone()
    }

    fn get_type(&self) -> u8 {
        return 2;
    }
}

#[derive(Debug)]
pub struct PreKeySignalMessage {
    pub version: u8,
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_key_id: u32,
    pub base_key: PublicKey,
    pub identity_key: PublicKey,
    pub message: SignalMessage,
    pub serialized: Vec<u8>,
}

impl PreKeySignalMessage {
    pub fn new(
        base_key: PublicKey,
        identity_key: PublicKey,
        registration_id: u32,
        pre_key_id: Option<u32>,
        signed_key_id: u32,
        message: SignalMessage,
    ) -> Self {
        let mut msg = crate::message_proto::PreKeyMessage::default();
        msg.signed_pre_key_id = Some(signed_key_id);
        let mut base_key_bytes = base_key.as_bytes().to_vec();
        base_key_bytes.insert(0, 5u8);
        msg.base_key = Some(base_key_bytes);
        let mut identity_key_bytes = identity_key.as_bytes().to_vec();
        identity_key_bytes.insert(0, 5u8);
        msg.identity_key = Some(identity_key_bytes);
        msg.message = Some(message.serialize());
        msg.registration_id = Some(registration_id);
        msg.pre_key_id = pre_key_id;

        let mut buf = Vec::new();
        buf.reserve(msg.encoded_len());
        msg.encode(&mut buf).unwrap();
        let len = buf.len();

        let mut serialized = Vec::new();
        serialized.reserve(len + 1);
        let version_byte: u8 = (3 << 4 | 3) & 0xFF;
        serialized.push(version_byte);
        serialized.append(&mut buf);

        //        let version_byte: u8 = (3 << 4 | 3) & 0xFF;
        //        serialized.insert(0, version_byte);

        Self {
            version: 3,
            registration_id,
            pre_key_id,
            signed_key_id,
            base_key,
            identity_key,
            message,
            serialized,
        }
    }

    pub fn deserialize(serialized: &[u8]) -> Result<PreKeySignalMessage, prost::DecodeError> {
        let (version_byte, msg) = serialized.split_at(1);
        let version = (version_byte[0] & 0xFF) >> 4;
        match crate::message_proto::PreKeyMessage::decode(&mut Cursor::new(msg)) {
            Err(e) => Err(e),
            Ok(message) => {
                //                let mut pre_key_id = None;
                //                if message.pre_key_id > 0 {
                //                    pre_key_id = Some(message.pre_key_id);
                //                }
                let mut base_key = message.base_key.expect("message proto");
                if base_key.len() == 33 && base_key[0] == 5 {
                    base_key.remove(0);
                }

                let mut identity_key = message.identity_key.expect("message proto");
                if identity_key.len() == 33 && identity_key[0] == 5 {
                    identity_key.remove(0);
                }
                let pre_key_id = message.pre_key_id;
                let sm = PreKeySignalMessage {
                    version,
                    serialized: serialized.to_vec(),
                    base_key: PublicKey::from(base_key.as_slice()),
                    identity_key: PublicKey::from(identity_key.as_slice()),
                    registration_id: message.registration_id.expect("message proto"),
                    signed_key_id: message.signed_pre_key_id.expect("message proto"),
                    message: SignalMessage::deserialize(
                        message.message.expect("message proto").as_slice(),
                    )
                    .unwrap(),
                    pre_key_id,
                };

                Ok(sm)
            }
        }
    }
}

impl CiphertextMessage for PreKeySignalMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized.clone()
    }

    fn get_type(&self) -> u8 {
        return 3;
    }
}

#[derive(Debug)]
pub struct SenderKeyMessage {
    pub key_id: u32,
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
    pub serialized: Vec<u8>,
}

impl SenderKeyMessage {
    pub fn new(
        key_id: u32,
        iteration: u32,
        ciphertext: Vec<u8>,
        signature_key: PrivateKey,
    ) -> Self {
        let mut msg = crate::message_proto::SenderKeyMessage::default();
        msg.id = Some(key_id);
        msg.iteration = Some(iteration);
        msg.ciphertext = Some(ciphertext.clone());
        let mut serialized = Vec::new();
        serialized.reserve(msg.encoded_len());
        msg.encode(&mut serialized).unwrap();

        let sig = signature_key.sign(&serialized);
        serialized.append(&mut sig.to_bytes().to_vec());

        Self {
            key_id,
            iteration,
            ciphertext,
            serialized,
        }
    }

    //    fn get_signature(signature_key: &PrivateKey, data: &[u8]) -> Signature {
    //        signature_key.sign(data)
    //    }

    pub fn verify_signature(&self, key: &PublicKey) -> Result<(), i32> {
        let (data, sig) = self.serialized.split_at(self.serialized.len() - 64);
        let signature = Signature::from_bytes(sig).unwrap();
        match key.verify(data, &signature) {
            Err(_) => return Err(1001),
            Ok(_) => return Ok(()),
        };
    }

    pub fn deserialize(serialized: &[u8]) -> Result<SenderKeyMessage, prost::DecodeError> {
        let len = serialized.len();
        if len <= 64 {
            return Err(prost::DecodeError::new("message len is less than 64"));
        }
        let (info, _) = serialized.split_at(len - 64);
        match crate::message_proto::SenderKeyMessage::decode(&mut Cursor::new(info)) {
            Err(e) => Err(e),
            Ok(message) => {
                if message.id.is_none() {
                    return Err(prost::DecodeError::new("message id is none"));
                }
                if message.iteration.is_none() {
                    return Err(prost::DecodeError::new("message iteration is none"));
                }
                if message.ciphertext.is_none() {
                    return Err(prost::DecodeError::new("message ciphertext is none"));
                }
                let sm = SenderKeyMessage {
                    serialized: serialized.to_vec(),
                    key_id: message.id.expect("message proto"),
                    iteration: message.iteration.expect("message proto"),
                    ciphertext: message.ciphertext.expect("message proto"),
                };

                Ok(sm)
            }
        }
    }
}

impl CiphertextMessage for SenderKeyMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized.clone()
    }

    fn get_type(&self) -> u8 {
        return 4;
    }
}

#[derive(Debug)]
pub struct SenderKeyDistributionMessage {
    pub id: u32,
    pub iteration: u32,
    pub chain_key: Vec<u8>,
    pub signature_key: PublicKey,
    pub serialized: Vec<u8>,
}

impl SenderKeyDistributionMessage {
    pub fn new(id: u32, iteration: u32, chain_key: Vec<u8>, signature_key: PublicKey) -> Self {
        let mut msg = crate::message_proto::SenderKeyDistributionMessage::default();
        msg.id = Some(id);
        msg.iteration = Some(iteration);
        msg.chain_key = Some(chain_key.clone());
        msg.signing_key = Some(signature_key.as_bytes().to_vec());
        let mut serialized = Vec::new();
        serialized.reserve(msg.encoded_len());
        msg.encode(&mut serialized).unwrap();

        Self {
            id,
            iteration,
            chain_key,
            signature_key,
            serialized,
        }
    }

    pub fn deserialize(
        serialized: &[u8],
    ) -> Result<SenderKeyDistributionMessage, prost::DecodeError> {
        match crate::message_proto::SenderKeyDistributionMessage::decode(&mut Cursor::new(
            serialized,
        )) {
            Err(e) => Err(e),
            Ok(message) => {
                debug!("SenderKeyDistributionMessage: {:02x?}", message);
                let sm = SenderKeyDistributionMessage {
                    serialized: serialized.to_vec(),
                    id: message.id.expect("SenderKeyDistributionMessage proto1"),
                    iteration: message
                        .iteration
                        .expect("SenderKeyDistributionMessage proto2"),
                    chain_key: message
                        .chain_key
                        .expect("SenderKeyDistributionMessage proto3"),
                    signature_key: PublicKey::from(
                        message
                            .signing_key
                            .expect("SenderKeyDistributionMessage proto4")
                            .as_slice(),
                    ),
                };

                Ok(sm)
            }
        }
    }
}

impl CiphertextMessage for SenderKeyDistributionMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized.clone()
    }

    fn get_type(&self) -> u8 {
        return 5;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use curve_crypto::KeyPair;

    #[test]
    fn message() {
        let mac_key = [1u8; 32];
        let sender_key_pair = KeyPair::generate();
        let sender_identity = KeyPair::generate();
        let receiver_identity = KeyPair::generate();
        let message = SignalMessage::new(
            mac_key.clone(),
            sender_key_pair.clone().public,
            111,
            222,
            vec![11, 22],
            sender_identity.clone().public,
            receiver_identity.clone().public,
        );

        let result =
            message.verify_mac(&sender_identity.public, &receiver_identity.public, &mac_key);
        println!("verfify result: {:?}", result);
        println!("message: {:?}", message);

        let message2 = SignalMessage::deserialize(message.serialized.as_slice());
        println!("message2: {:?}", message2);

        let pre_key_message = PreKeySignalMessage::new(
            sender_key_pair.clone().public,
            sender_identity.clone().public,
            10,
            Some(11),
            12,
            message2.unwrap(),
        );
        println!("pre_key_message: {:?}", pre_key_message);
        let pre_key_message2 =
            PreKeySignalMessage::deserialize(pre_key_message.serialized.as_slice());
        println!("pre_key_message2: {:?}", pre_key_message2);

        let send_key_message =
            SenderKeyMessage::new(22, 1, vec![32, 33], sender_key_pair.clone().private);
        println!("send_key_message: {:?}", send_key_message);
        let send_key_message2 =
            SenderKeyMessage::deserialize(send_key_message.serialized.as_slice());
        println!("send_key_message2: {:?}", send_key_message2);
        let result = send_key_message.verify_signature(&sender_key_pair.clone().public);
        println!("verfify result: {:?}", result);
    }
}
