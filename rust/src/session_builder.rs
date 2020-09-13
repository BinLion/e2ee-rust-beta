use crate::address::{Address, SenderKeyName};
use crate::errors::MyError;
use crate::keys::*;
use crate::message::*;
use crate::ratchet::*;
use crate::session_record::{SenderKeyRecord, SessionRecord};
use crate::session_state::{SenderKeyState, SessionState};
use crate::store::*;
use core::borrow::BorrowMut;
use curve_crypto::*;
use rand_core::OsRng;
use rand_core::RngCore;

pub struct GroupSessionBuilder<'a> {
    pub sender_key_store: &'a mut dyn SenderKeyStore,
    pub sender: SenderKeyName,
}

impl<'a> GroupSessionBuilder<'a> {
    pub fn new(sender_key_store: &'a mut dyn SenderKeyStore, sender: SenderKeyName) -> Self {
        Self {
            sender_key_store,
            sender,
        }
    }

    pub fn process(
        &mut self,
        sender: &SenderKeyName,
        distribution_message: SenderKeyDistributionMessage,
    ) {
        let sender_record = self.sender_key_store.load_sender_key(sender);
        debug!(
            "process distribution_message. load sender record: {:?}",
            sender_record
        );
        let mut r = SenderKeyRecord::default();
        match sender_record {
            None => {}
            Some(record) => {
                r = record.clone();
            }
        }
        r.add_sender_key_state(
            distribution_message.id,
            distribution_message.iteration,
            distribution_message.chain_key,
            distribution_message.signature_key,
        );
        self.sender_key_store.store_sender_key(sender.clone(), r);
    }

    pub fn get_distribution_message(
        &mut self,
        sender: &SenderKeyName,
    ) -> Result<SenderKeyDistributionMessage> {
        let option = self.sender_key_store.load_sender_key(sender);
        debug!("get SenderKeyDistributionMessage. record:{:02x?}", option);
        match option {
            None => {
                error!("no sender key record");
                return Err(MyError::SessionError {
                    code: 2000,
                    name: "get_destribution_message".to_string(),
                    msg: "no sender key record".to_string(),
                });
            }
            Some(record) => {
                let state_opt = record.get_sender_key_state();
                if state_opt.is_none() {
                    error!("no state in sender key record");
                    return Err(MyError::SessionError {
                        code: 2001,
                        name: "get_destribution_message".to_string(),
                        msg: "no state in sender key record".to_string(),
                    });
                }
                let state = state_opt.unwrap();
                Ok(SenderKeyDistributionMessage::new(
                    state.get_key_id(),
                    state.get_sender_chain_key().iteration,
                    state.get_sender_chain_key().key,
                    state.get_signing_key_public(),
                ))
            }
        }
    }

    pub fn create(&mut self, sender: &SenderKeyName) -> Result<SenderKeyDistributionMessage> {
        let mut rng = OsRng::default();
        let id = rng.next_u32();
        let mut sender_key = [0u8; 32];
        rng.fill_bytes(&mut sender_key);
        let signing_key = KeyPair::generate();
        let mut record = SenderKeyRecord::default();
        record.set_sender_key_state(id, 0, sender_key.to_vec(), signing_key);
        self.sender_key_store
            .store_sender_key(sender.clone(), record.clone());
        let state_opt = record.get_sender_key_state();
        if state_opt.is_none() {
            error!("no state in sender key record");
            return Err(MyError::SessionError {
                code: 2001,
                name: "create_destribution_message".to_string(),
                msg: "no state in sender key record".to_string(),
            });
        }
        let state = state_opt.unwrap();

        debug!("crate SenderKeyDistributionMessage. state:{:02x?}", state);
        Ok(SenderKeyDistributionMessage::new(
            state.get_key_id(),
            state.get_sender_chain_key().iteration,
            state.get_sender_chain_key().key,
            state.get_signing_key_public(),
        ))
    }

    //    pub fn create(&mut self, sender: &SenderKeyName) -> Result<SenderKeyDistributionMessage> {
    //        let option = self.sender_key_store.load_sender_key(sender);
    //        println!("crate SenderKeyDistributionMessage. record:{:02x?}", option);
    //        match option {
    //            None => {
    //                let mut rng = OsRng::default();
    //                let id = rng.next_u32();
    //                let mut sender_key = [0u8;32];
    //                rng.fill_bytes(&mut sender_key);
    //                let signing_key = KeyPair::new(&mut OsRng);
    //                let mut record = SenderKeyRecord::default();
    //                record.set_sender_key_state(id, 0, sender_key.to_vec(), signing_key);
    //                self.sender_key_store.store_sender_key(sender.clone(), record.clone());
    //                let state_opt = record.get_sender_key_state();
    //                if state_opt.is_none() {
    //                    println!("no state in sender key record");
    //                    return Err(MyError::SessionError("no state in sender key record"));
    //                }
    //                let state = state_opt.unwrap();
    //
    //                println!("crate SenderKeyDistributionMessage. state:{:02x?}", state);
    //                Ok(SenderKeyDistributionMessage::new(state.get_key_id(), state.get_sender_chain_key().iteration,
    //                                                     state.get_sender_chain_key().key, state.get_signing_key_public()))
    //            },
    //            Some(record) => {
    //                let state_opt = record.get_sender_key_state();
    //                if state_opt.is_none() {
    //                    println!("no state in sender key record");
    //                    return Err(MyError::SessionError("no state in sender key record"));
    //                }
    //                let state = state_opt.unwrap();
    //                Ok(SenderKeyDistributionMessage::new(state.get_key_id(), state.get_sender_chain_key().iteration,
    //                                                     state.get_sender_chain_key().key, state.get_signing_key_public()))
    //            }
    //        }
    //    }

    pub fn encrypt(&mut self, padded_message: Vec<u8>) -> Result<Vec<u8>> {
        let mut option = self.sender_key_store.load_sender_key(&self.sender);
        match option.borrow_mut() {
            None => {
                return Err(MyError::SessionError {
                    code: 2003,
                    name: "group encrypt".to_string(),
                    msg: "load_sender_key is none".to_string(),
                });
            }
            Some(record) => {
                let mut state_option = record.get_sender_key_state();
                match state_option.as_mut() {
                    None => {
                        return Err(MyError::SessionError {
                            code: 2004,
                            name: "group encrypt".to_string(),
                            msg: "get_sender_key_state is none".to_string(),
                        });
                    }
                    Some(status) => {
                        let message_keys = status.get_sender_chain_key().get_message_keys();
                        let len = padded_message.len();
                        let mut buffer: Vec<_> = std::iter::repeat(0).take(len + 16).collect();

                        buffer[0..len].copy_from_slice(padded_message.as_slice());

                        debug!("encrypt message keys: {:02x?}", message_keys);
                        debug!("encrypt message data: {:02x?}", buffer);
                        let cipher_message = aes256_cbc_pkcs7_encrypt(
                            &message_keys.cipher_key,
                            &message_keys.iv,
                            &mut buffer,
                            len,
                        );

                        let message = SenderKeyMessage::new(
                            status.get_key_id(),
                            message_keys.iteration,
                            cipher_message.to_vec(),
                            status.get_signing_key_private(),
                        );
                        status.set_sender_chain_key(status.get_sender_chain_key().next());
                        record.reset_sender_key_state(status.clone());

                        self.sender_key_store
                            .store_sender_key(self.sender.clone(), record.clone());

                        Ok(message.serialize())
                    }
                }
            }
        }
    }

    pub fn decrypt(&mut self, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let mut record_option = self.sender_key_store.load_sender_key(&self.sender);
        debug!("group decrypt: record:{:02x?}", record_option);
        match record_option.borrow_mut() {
            None => {
                return Err(MyError::SessionError {
                    code: 2006,
                    name: "group decrypt".to_string(),
                    msg: "no sender key record".to_string(),
                });
            }
            Some(record) => {
                let mut result = SenderKeyMessage::deserialize(&cipher_text);
                debug!("group decrypt: sender key message:{:02x?}", result);
                match result.as_mut() {
                    Err(_e) => {
                        return Err(MyError::SessionError {
                            code: 2007,
                            name: "group decrypt".to_string(),
                            msg: "SenderKeyMessage deserialize fail".to_string(),
                        });
                    }
                    Ok(message) => {
                        let state_opt = record.get_sender_key_state_by_id(message.key_id);
                        if state_opt.is_none() {
                            return Err(MyError::SessionError {
                                code: 2008,
                                name: "group decrypt".to_string(),
                                msg: "get_sender_key_state_by_id is none".to_string(),
                            });
                        }
                        let mut state = state_opt.unwrap();

                        let result = message.verify_signature(&state.get_signing_key_public());
                        if result.is_err() {
                            return Err(MyError::SessionError {
                                code: 2009,
                                name: "group decrypt".to_string(),
                                msg: "verify signature fail".to_string(),
                            });
                        }

                        let message_keys = Self::get_message_keys(&mut state, message.iteration)?;

                        record.reset_sender_key_state(state.clone());

                        debug!(
                            "group decrypt. message_keys:{:02x?}, state:{:02x?}",
                            message_keys, state
                        );
                        let plain_text = aes256_cbc_pkcs7_decrypt(
                            &message_keys.cipher_key,
                            &message_keys.iv,
                            &mut message.ciphertext,
                        )?;

                        self.sender_key_store
                            .store_sender_key(self.sender.clone(), record.clone());

                        Ok(plain_text.to_vec())
                    }
                }
            }
        }
    }

    fn get_message_keys(state: &mut SenderKeyState, iteration: u32) -> Result<SenderMessageKeys> {
        let mut chain_key = state.get_sender_chain_key();
        let mut message_keys = SenderMessageKeys::default();
        trace!("message_keys: {:?}", message_keys);
        if chain_key.iteration > iteration {
            if state.has_sender_message_key(iteration) {
                message_keys = state.remove_sender_message_key(iteration).unwrap();
                debug!("message:{:02x?}, state:{:02x?}", message_keys, state);
                return Ok(message_keys);
            } else {
                debug!("received message with old counter");
                // return Err(MyError::SessionError {
                //     code: 2010,
                //     name: "DuplicateMessageException".to_string(),
                //     msg: "receive message with old counter".to_string(),
                // });
                return Err(MyError::DuplicateMessageException);
            }
        }

        if iteration > chain_key.iteration + 2000 {
            debug!("Over 2000 messages into the future");
            return Err(MyError::SessionError {
                code: 2010,
                name: "get_message_keys".to_string(),
                msg: "Over 2000 message into the future".to_string(),
            });
        }

        while chain_key.iteration < iteration {
            state.add_sender_message_key(chain_key.get_message_keys());
            message_keys = chain_key.get_message_keys();
            debug!(
                "get_message_keys:{:02x?}, state:{:02x?}",
                message_keys, state
            );
            chain_key = chain_key.next();
        }

        state.set_sender_chain_key(chain_key.next());
        //        record.reset_sender_key_state(state.clone());
        message_keys = chain_key.get_message_keys();
        return Ok(message_keys);
    }
}
//pub struct SessionBuilder {
//    pub session_store: Box<dyn SessionStore>,
//    pub pre_key_store: Box<dyn PreKeyStore>,
//    pub signed_pre_key_store: Box<dyn SignedPreKeyStore>,
//    pub identity_store: Box<dyn IdentityKeyStore>,
//    pub address: Address,
//}

pub struct SessionBuilder<'a> {
    pub session_store: &'a mut dyn SessionStore,
    pub pre_key_store: &'a mut dyn PreKeyStore,
    pub signed_pre_key_store: &'a mut dyn SignedPreKeyStore,
    pub identity_store: &'a mut dyn IdentityKeyStore,
    pub address: Address,
}

impl<'a> SessionBuilder<'a> {
    //    pub fn new(session_store: Box<dyn SessionStore>,
    //               pre_key_store: Box<dyn PreKeyStore>,
    //               signed_pre_key_store: Box<dyn SignedPreKeyStore>,
    //               identity_store: Box<dyn IdentityKeyStore>,
    //               address: Address) -> Self {
    //        Self {
    //            session_store, pre_key_store, signed_pre_key_store, identity_store, address
    //        }
    //    }

    pub fn new(
        session_store: &'a mut dyn SessionStore,
        pre_key_store: &'a mut dyn PreKeyStore,
        signed_pre_key_store: &'a mut dyn SignedPreKeyStore,
        identity_store: &'a mut dyn IdentityKeyStore,
        address: Address,
    ) -> Self {
        Self {
            session_store,
            pre_key_store,
            signed_pre_key_store,
            identity_store,
            address,
        }
    }

    //    pub fn new2(store: Box<dyn Store>, address: Address) -> Self {
    //        Self {
    //            session_store: store as Box<dyn SessionStore>,
    //            pre_key_store: store as Box<dyn PreKeyStore>,
    //            signed_pre_key_store: store as Box<dyn SignedPreKeyStore>,
    //            identity_store: store as Box<dyn IdentityKeyStore>,
    //            address
    //        }
    //    }

    pub fn process_with_key_bundle(&mut self, pre_key: PreKeyBundle) -> Result<()> {
        debug!("process_with_key_bundle. key_bundle:{:?}", pre_key);
        if !self.identity_store.is_trusted_identity(
            &self.address,
            &pre_key.identity_key,
            crate::store::Direction::SENDING,
        ) {
            error!("process_with_key_bundle. is not trusted identity");
            return Err(MyError::SessionError {
                code: 2020,
                name: "process with key bundle".to_string(),
                msg: "identity is not tursted".to_string(),
            });
        }

        if pre_key.signed_pre_key_id > 0 {
            if let Err(_) = pre_key
                .identity_key
                .verify(pre_key.signed_data.as_slice(), &pre_key.signature)
            {
                error!("process_with_key_bundle. verify signed key fail");
                return Err(MyError::SessionError {
                    code: 2021,
                    name: "process with key bundle".to_string(),
                    msg: "verify signed key fail".to_string(),
                });
            }
        }

        if pre_key.signed_pre_key_id == 0 {
            error!("process_with_key_bundle. signed pre key id is 0");
            return Err(MyError::SessionError {
                code: 2022,
                name: "process with key bundle".to_string(),
                msg: "signed pre key id is 0".to_string(),
            });
        }

        let our_identity_key = self.identity_store.get_identity_key_pair();
        if our_identity_key.is_none() {
            return Err(MyError::SessionError {
                code: 2023,
                name: "process with key bundle".to_string(),
                msg: "get identity keypair is none".to_string(),
            });
        }

        let session_record_opt = self.session_store.load_session(&self.address)?;
        let mut session_record = session_record_opt.unwrap_or(SessionRecord::default());

        let our_base_key = KeyPair::generate();
        let mut their_one_time_key: Option<PublicKey> = None;
        let mut their_one_time_key_id: Option<u32> = None;
        if pre_key.pre_key_id > 0 {
            their_one_time_key = Some(pre_key.pre_key);
            their_one_time_key_id = Some(pre_key.pre_key_id);
        }

        let mut parameters = AliceParameters::default();
        parameters.our_base_key = our_base_key.clone();
        parameters.our_identity_key = our_identity_key.unwrap();
        parameters.their_identity_key = pre_key.identity_key;
        parameters.their_signed_pre_key = pre_key.signed_pre_key;
        parameters.their_ratchet_key = pre_key.signed_pre_key;
        parameters.their_one_time_key = their_one_time_key;

        if !session_record.is_fresh() {
            session_record.promote_state(SessionState::default());
        }

        let mut session_state = SessionState::default();
        parameters.init_session(&mut session_state);

        session_state.set_unknown_pre_key_message(
            their_one_time_key_id,
            pre_key.signed_pre_key_id,
            &our_base_key.public,
        );
        session_state.set_local_registration_id(self.identity_store.get_local_registration_id());
        session_state.set_remote_registration_id(pre_key.registration_id);
        session_state.set_alice_base_key(our_base_key.public.as_bytes().to_vec());
        session_record.session_state = session_state;

        self.identity_store
            .save_identity(self.address.clone(), pre_key.identity_key);
        let _ = self
            .session_store
            .store_session(self.address.clone(), session_record);

        Ok(())
    }

    pub fn process_with_message(
        &self,
        session_record: &mut SessionRecord,
        message: &PreKeySignalMessage,
    ) -> Result<u32> {
        trace!(
            "process_with_message begin. record: {:?}, message:{:?}",
            session_record,
            message
        );
        let their_identity_key = message.identity_key;
        if !self.identity_store.is_trusted_identity(
            &self.address,
            &their_identity_key,
            crate::store::Direction::RECEIVING,
        ) {
            trace!("process_with_message1");
            return Err(MyError::SessionError {
                code: 2030,
                name: "process with message".to_string(),
                msg: "identity is not trusted".to_string(),
            });
        }

        if session_record.has_session_state(message.base_key.as_bytes()) {
            trace!("process_with_message2");
            return Ok(0);
        }

        //let our_signed_key = self.signed_pre_key_store.load_signed_pre_key(message.signed_key_id).expect("process_with_message2").keypair;
        let our_signed_key_opt = self
            .signed_pre_key_store
            .load_signed_pre_key(message.signed_key_id);
        if our_signed_key_opt.is_none() {
            trace!("process_with_message. load signed pre key is none");
            return Err(MyError::NoSignedKeyException);
            // return Err(MyError::SessionError {
            //     code: 2031,
            //     name: "process with message".to_string(),
            //     msg: "load signed pre key is none".to_string(),
            // });
        }

        let our_signed_key = our_signed_key_opt.unwrap().keypair;

        let our_identity_key = self.identity_store.get_identity_key_pair();
        if our_identity_key.is_none() {
            return Err(MyError::SessionError {
                code: 2033,
                name: "process with message".to_string(),
                msg: "identity is not trusted".to_string(),
            });
        }

        let mut parameters = BobParameters::default();
        parameters.their_base_key = message.base_key;
        parameters.their_identity_key = message.identity_key;
        parameters.our_identity_key = our_identity_key.unwrap();
        parameters.our_signed_key = our_signed_key.clone();
        parameters.our_ratchet_key = our_signed_key;

        if let Some(id) = message.pre_key_id {
            let pre_key_opt = self.pre_key_store.load_pre_key(id);
            if pre_key_opt.is_none() {
                trace!("process_with_message. load pre key is none");
                // return Err(MyError::SessionError {
                //     code: 2032,
                //     name: "process with message".to_string(),
                //     msg: "load pre key is none".to_string(),
                // });
                return Err(MyError::NoPreKeyException);
            }
            parameters.our_one_time_key = Some(pre_key_opt.expect("process_with_message1").keypair);
        }

        if !session_record.is_fresh() {
            session_record.promote_state(SessionState::default());
        }

        //let mut session_state = SessionState::default();
        let mut session_state = session_record.clone().get_session_state();
        parameters.init_session(&mut session_state);
        session_state.set_local_registration_id(self.identity_store.get_local_registration_id());
        session_state.set_remote_registration_id(message.registration_id);
        session_state.set_alice_base_key(message.base_key.as_bytes().to_vec());
        session_record.session_state = session_state;

        if let Some(id) = message.pre_key_id {
            return Ok(id);
        }

        Ok(0)
    }

    pub fn encrypt(&mut self, padded_message: Vec<u8>) -> Result<Box<dyn CiphertextMessage>> {
        let session_record_opt = self.session_store.load_session(&self.address)?;
        trace!("e2ee-encrypt. load session: {:?}", session_record_opt);

        session_record_opt.map_or(
            Err(MyError::SessionError {
                code: 2040,
                name: "encrypt message".to_string(),
                msg: "load session is none".to_string(),
            }),
            |mut session_record| {
                trace!("e2ee-encrypt. session_record: {:?}", session_record);
                let mut session_state = session_record.clone().get_session_state();
                let chain_key = session_state.get_sender_chain_key().expect("encrypt ...");
                trace!("e2ee-encrypt. chain_key: {:?}", chain_key);
                let message_keys = chain_key.get_message_keys();
                let sender_ephemeral = session_state.get_sender_ratchet_key().expect("encrypt");
                trace!("e2ee-encrypt. sender_ephemeral: {:?}", sender_ephemeral);
                let previous_counter = session_state.get_previous_counter();

                let len = padded_message.len();
                let mut buffer: Vec<_> = std::iter::repeat(0).take(len + 16).collect();

                buffer[0..len].copy_from_slice(padded_message.as_slice());

                trace!("e2ee-encrypt message keys: {:02x?}", message_keys);
                trace!("e2ee-encrypt message data: {:02x?}", buffer);
                let cipher_message = aes256_cbc_pkcs7_encrypt(
                    &message_keys.cipher_key,
                    &message_keys.iv,
                    &mut buffer,
                    len,
                );
                trace!("e2ee-encrypt: cipher_message: {:02x?}", cipher_message);

                let signal_message = SignalMessage::new(
                    message_keys.mac_key,
                    sender_ephemeral,
                    chain_key.index,
                    previous_counter,
                    cipher_message.to_vec(),
                    session_state.get_local_identity_key().unwrap(),
                    session_state.get_remote_identity_key().unwrap(),
                );

                trace!("e2ee-encrypt. signal_message: {:?}", signal_message);

                session_state.set_sender_chain_key(chain_key.next());
                session_record.session_state = session_state.clone();
                self.identity_store.save_identity(
                    self.address.clone(),
                    session_state.get_remote_identity_key().unwrap(),
                );
                trace!("e2ee-encrypt. before store session: {:?}", session_record);
                let _ = self
                    .session_store
                    .store_session(self.address.clone(), session_record)?;

                if session_state.has_unknown_pre_key_message() {
                    trace!("e2ee-encrypt. has unknow_message");
                    let unknown_pre_key_message =
                        session_state.get_unknown_pre_key_message().unwrap();
                    trace!(
                        "e2ee-encrypt. unknow_message: {:?}",
                        unknown_pre_key_message
                    );
                    let local_registration_id = session_state.get_local_registration_id();
                    let pre_key_message = PreKeySignalMessage::new(
                        unknown_pre_key_message.base_key,
                        session_state.get_local_identity_key().unwrap(),
                        local_registration_id,
                        unknown_pre_key_message.pre_key_id,
                        unknown_pre_key_message.signed_pre_key_id as u32,
                        signal_message,
                    );
                    return Ok(Box::new(pre_key_message));
                }

                trace!("e2ee-encrypt. success");
                Ok(Box::new(signal_message))
            },
        )
    }

    pub fn pre_key_message_decrypt(
        &mut self,
        pre_key_message: PreKeySignalMessage,
    ) -> Result<Vec<u8>> {
        trace!("in rust pre_key_message_decrypt. start load session");
        let session_record_opt = self.session_store.load_session(&self.address)?;
        // if session_record_opt.is_none() {
        //     return Err(MyError::SessionError {
        //         code: 2050,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "load session is none".to_string(),
        //     });
        // }
        let mut session_record = session_record_opt.unwrap_or(SessionRecord::default());

        trace!(
            "in rust pre_key_message_decrypt. end load session: {:?}",
            session_record
        );
        let preid = self.process_with_message(&mut session_record, &pre_key_message)?;
        trace!("in rust pre_key_message_decrypt. preid: {:?}", preid);
        // if preid.is_err() {
        //     return Err(MyError::SessionError {
        //         code: 2051,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "process pre key message error".to_string(),
        //     });
        // }

        let encrypted = pre_key_message.message;

        let mut session_state = session_record.session_state.clone();

        let plain_text_ret = self.decrypt_with_state(&mut session_state, encrypted.clone());
        if plain_text_ret.is_err() {
            for (idx, state) in session_record.previous_states.clone().iter().enumerate() {
                trace!("prekey message decrypt. index:{}, state:{:?}", idx, state);
                session_state = state.clone();
                let ret = self.decrypt_with_state(&mut session_state, encrypted.clone());
                if ret.is_ok() {
                    self.identity_store.save_identity(
                        self.address.clone(),
                        session_state.get_remote_identity_key().unwrap(),
                    );
                    // session_record.session_state = session_state;
                    session_record.remove_previous_state(idx);
                    session_record.promote_state(session_state);
                    let _ = self
                        .session_store
                        .store_session(self.address.clone(), session_record);
                    if preid > 0 {
                        let _ = self.pre_key_store.remove_pre_key(preid);
                    }
                    return Ok(ret.unwrap().to_vec());
                }
            }
            return plain_text_ret;
        } else {
            self.identity_store.save_identity(
                self.address.clone(),
                session_state.get_remote_identity_key().unwrap(),
            );
            session_record.session_state = session_state;
            let _ = self
                .session_store
                .store_session(self.address.clone(), session_record);
            if preid > 0 {
                let _ = self.pre_key_store.remove_pre_key(preid);
            }
            return Ok(plain_text_ret.unwrap().to_vec());
        }
        // if !session_state.has_sender_chain() {
        //     trace!("pre_key_message_decrypt. no sender_chain");
        //     return Err(MyError::SessionError {
        //         code: 2052,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "no sender chain".to_string(),
        //     });
        // }

        // let their_ephemeral = encrypted.sender_ratchet_key;
        // let counter = encrypted.counter;
        // // let mut chain_key = ChainKey::default();
        // let mut chain_key;
        // if let Some(_receiver_chain) = session_state.get_receiver_chain(&their_ephemeral) {
        //     chain_key = session_state
        //         .get_receiver_chain_key(&their_ephemeral)
        //         .expect("decrypt");
        //     trace!(
        //         "pre_key_message_decrypt. chain_key:{:?}, their_ephemeral:{:?}",
        //         chain_key,
        //         their_ephemeral
        //     );
        // } else {
        //     let root_key = session_state.get_root_key();
        //     let our_ephemeral_opt = session_state.get_sender_ratchet_key_pair();
        //     if our_ephemeral_opt.is_none() {
        //         return Err(MyError::SessionError {
        //             code: 2053,
        //             name: "pre key message decrypt".to_string(),
        //             msg: "session state get_sender_ratchet_key_pair is none".to_string(),
        //         });
        //     }
        //     let our_ephemeral = our_ephemeral_opt.unwrap();
        //     let (receiver_root, receiver_chain) =
        //         root_key.create_chain(&their_ephemeral, &our_ephemeral);
        //     let our_new_key = KeyPair::generate();
        //     let (sender_root, sender_chain) =
        //         receiver_root.create_chain(&their_ephemeral, &our_new_key);

        //     session_state.set_root_key(sender_root);
        //     session_state.add_receiver_chain(their_ephemeral.clone(), receiver_chain.clone());
        //     session_state.set_previous_counter(
        //         std::cmp::max(
        //             session_state
        //                 .get_sender_chain_key()
        //                 .expect("decrypt2")
        //                 .index,
        //             1,
        //         ) - 1,
        //     );
        //     session_state.set_sender_chain(our_new_key.clone(), sender_chain);

        //     chain_key = receiver_chain;
        //     trace!(
        //         "pre_key_message_decrypt. chain_key2:{:?}, their_ephemeral:{:?}",
        //         chain_key,
        //         their_ephemeral
        //     );
        // }

        // let message_keys = Self::get_message_keys(
        //     &mut session_state,
        //     &their_ephemeral,
        //     &mut chain_key,
        //     counter,
        // )?;
        // trace!("decrypt message keys: {:?}", message_keys);

        // if session_state.get_remote_identity_key().is_none() {
        //     return Err(MyError::SessionError {
        //         code: 2055,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "remote identity key is none".to_string(),
        //     });
        // }

        // if session_state.get_local_identity_key().is_none() {
        //     return Err(MyError::SessionError {
        //         code: 2056,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "local identity key is none".to_string(),
        //     });
        // }

        // let verify_result = encrypted.verify_mac(
        //     &session_state.get_remote_identity_key().expect("decrypt3"),
        //     &session_state.get_local_identity_key().expect("decrypt4"),
        //     &message_keys.mac_key,
        // );
        // trace!("pre_key_message_decrypt. verify_result:{:?}", verify_result);
        // if verify_result.is_err() {
        //     return Err(MyError::SessionError {
        //         code: 2054,
        //         name: "pre key message decrypt".to_string(),
        //         msg: "verify mac error".to_string(),
        //     });
        // }

        // let mut body = encrypted.ciphertext;
        // let plain_text =
        //     aes256_cbc_pkcs7_decrypt(&message_keys.cipher_key, &message_keys.iv, &mut body)?;

        // session_state.clear_unknown_pre_key_message();
    }

    fn decrypt_with_state(
        &mut self,
        session_state: &mut SessionState,
        encrypted: SignalMessage,
    ) -> Result<Vec<u8>> {
        trace!("decrypt_with_state. session_state:{:?}", session_state);
        if !session_state.has_sender_chain() {
            trace!("decrypt_with_state. no sender_chain");
            return Err(MyError::SessionError {
                code: 2052,
                name: "decrypt_with_state".to_string(),
                msg: "no sender chain".to_string(),
            });
        }

        let their_ephemeral = encrypted.sender_ratchet_key;
        let counter = encrypted.counter;
        // let mut chain_key = ChainKey::default();
        let mut chain_key;
        if let Some(_receiver_chain) = session_state.get_receiver_chain(&their_ephemeral) {
            chain_key = session_state
                .get_receiver_chain_key(&their_ephemeral)
                .expect("decrypt");
            trace!(
                "decrypt_with_state. chain_key:{:?}, their_ephemeral:{:?}",
                chain_key,
                their_ephemeral
            );
        } else {
            let root_key = session_state.get_root_key();
            let our_ephemeral_opt = session_state.get_sender_ratchet_key_pair();
            if our_ephemeral_opt.is_none() {
                return Err(MyError::SessionError {
                    code: 2053,
                    name: "decrypt_with_state".to_string(),
                    msg: "session state get_sender_ratchet_key_pair is none".to_string(),
                });
            }
            let our_ephemeral = our_ephemeral_opt.unwrap();
            let (receiver_root, receiver_chain) =
                root_key.create_chain(&their_ephemeral, &our_ephemeral);
            let our_new_key = KeyPair::generate();
            let (sender_root, sender_chain) =
                receiver_root.create_chain(&their_ephemeral, &our_new_key);

            session_state.set_root_key(sender_root);
            session_state.add_receiver_chain(their_ephemeral.clone(), receiver_chain.clone());
            session_state.set_previous_counter(
                std::cmp::max(
                    session_state
                        .get_sender_chain_key()
                        .expect("decrypt2")
                        .index,
                    1,
                ) - 1,
            );
            session_state.set_sender_chain(our_new_key.clone(), sender_chain);

            chain_key = receiver_chain;
            trace!(
                "decrypt_with_state. chain_key2:{:?}, their_ephemeral:{:?}",
                chain_key,
                their_ephemeral
            );
        }

        let message_keys =
            Self::get_message_keys(session_state, &their_ephemeral, &mut chain_key, counter)?;
        trace!("decrypt message keys: {:?}", message_keys);

        if session_state.get_remote_identity_key().is_none() {
            return Err(MyError::SessionError {
                code: 2055,
                name: "decrypt_with_state".to_string(),
                msg: "remote identity key is none".to_string(),
            });
        }

        if session_state.get_local_identity_key().is_none() {
            return Err(MyError::SessionError {
                code: 2056,
                name: "decrypt_with_state".to_string(),
                msg: "local identity key is none".to_string(),
            });
        }

        let verify_result = encrypted.verify_mac(
            &session_state.get_remote_identity_key().expect("decrypt3"),
            &session_state.get_local_identity_key().expect("decrypt4"),
            &message_keys.mac_key,
        );
        trace!("decrypt_with_state. verify_result:{:?}", verify_result);
        if verify_result.is_err() {
            return Err(MyError::SessionError {
                code: 2054,
                name: "decrypt_with_state".to_string(),
                msg: "verify mac error".to_string(),
            });
        }

        let mut body = encrypted.ciphertext;
        let plain_text =
            aes256_cbc_pkcs7_decrypt(&message_keys.cipher_key, &message_keys.iv, &mut body)?;

        session_state.clear_unknown_pre_key_message();

        Ok(plain_text.to_vec())
    }

    pub fn decrypt(&mut self, encrypted: SignalMessage) -> Result<Vec<u8>> {
        // let has_opt = self.session_store.contains_session(&self.address)?;
        // if has_opt.is_none() {
        //     trace!("in rust decrypt. containSession fail");
        //     return Err(MyError::SessionError {
        //         code: 2060,
        //         name: "message decrypt".to_string(),
        //         msg: "call containSession fail".to_string(),
        //     });
        // }

        // if !has_opt.unwrap() {
        //     trace!("in rust decrypt. no session");
        //     return Err(MyError::SessionError {
        //         code: 2061,
        //         name: "message decrypt".to_string(),
        //         msg: "no session".to_string(),
        //     });
        // }

        trace!("in rust decrypt. start load session");
        let session_record_opt = self.session_store.load_session(&self.address)?;
        if session_record_opt.is_none() {
            return Err(MyError::SessionError {
                code: 2062,
                name: "message decrypt".to_string(),
                msg: "load session is none".to_string(),
            });
        }
        let mut session_record = session_record_opt.unwrap();
        if session_record == SessionRecord::default() {
            trace!("in rust decrypt. no session");
            return Err(MyError::SessionError {
                code: 2063,
                name: "message decrypt".to_string(),
                msg: "session recored is empty".to_string(),
            });
        }

        trace!("in rust decrypt. after load session: {:?}", session_record);
        let mut session_state = session_record.session_state.clone();

        let plain_text_ret = self.decrypt_with_state(&mut session_state, encrypted.clone());
        if plain_text_ret.is_err() {
            for (idx, state) in session_record.previous_states.clone().iter().enumerate() {
                trace!("decrypt. index:{}, state:{:?}", idx, state);
                session_state = state.clone();
                let ret = self.decrypt_with_state(&mut session_state, encrypted.clone());
                if ret.is_ok() {
                    self.identity_store.save_identity(
                        self.address.clone(),
                        session_state.get_remote_identity_key().unwrap(),
                    );
                    // session_record.session_state = session_state;
                    session_record.remove_previous_state(idx);
                    session_record.promote_state(session_state);
                    let _ = self
                        .session_store
                        .store_session(self.address.clone(), session_record);
                    return Ok(ret.unwrap().to_vec());
                }
            }
            return plain_text_ret;
        } else {
            self.identity_store.save_identity(
                self.address.clone(),
                session_state.get_remote_identity_key().unwrap(),
            );
            session_record.session_state = session_state;
            let _ = self
                .session_store
                .store_session(self.address.clone(), session_record)?;

            Ok(plain_text_ret.unwrap().to_vec())
        }
        // if !session_state.has_sender_chain() {
        //     trace!("in rust decrypt. no sender chain");
        //     return Err(MyError::SessionError {
        //         code: 2064,
        //         name: "message decrypt".to_string(),
        //         msg: "no sender chain".to_string(),
        //     });
        // }

        // let their_ephemeral = encrypted.sender_ratchet_key;
        // let counter = encrypted.counter;
        // // let mut chain_key = ChainKey::default();
        // let mut chain_key;
        // if let Some(_receiver_chain) = session_state.get_receiver_chain(&their_ephemeral) {
        //     trace!("in rust decrypt. no sender chain");
        //     chain_key = session_state
        //         .get_receiver_chain_key(&their_ephemeral)
        //         .expect("decrypt");
        // } else {
        //     println!("decrypt14");
        //     let root_key = session_state.get_root_key();
        //     let our_ephemeral_opt = session_state.get_sender_ratchet_key_pair();
        //     if our_ephemeral_opt.is_none() {
        //         return Err(MyError::SessionError {
        //             code: 2065,
        //             name: "message decrypt".to_string(),
        //             msg: "session state get_sender_ratchet_key_pair is none".to_string(),
        //         });
        //     }
        //     let our_ephemeral = our_ephemeral_opt.unwrap();
        //     let (receiver_root, receiver_chain) =
        //         root_key.create_chain(&their_ephemeral, &our_ephemeral);
        //     let our_new_key = KeyPair::generate();
        //     let (sender_root, sender_chain) =
        //         receiver_root.create_chain(&their_ephemeral, &our_new_key);

        //     session_state.set_root_key(sender_root);
        //     session_state.add_receiver_chain(their_ephemeral.clone(), receiver_chain.clone());
        //     session_state.set_previous_counter(
        //         std::cmp::max(
        //             session_state
        //                 .get_sender_chain_key()
        //                 .expect("decrypt2")
        //                 .index,
        //             1,
        //         ) - 1,
        //     );
        //     session_state.set_sender_chain(our_new_key.clone(), sender_chain);

        //     chain_key = receiver_chain;
        // }

        // trace!("decrypt get message keys before: {:02x?}, their_ephemeral:{:02x?}, chain_key:{:02x?}, counter:{}", session_state, their_ephemeral, chain_key, counter);
        // let message_keys = Self::get_message_keys(
        //     &mut session_state,
        //     &their_ephemeral,
        //     &mut chain_key,
        //     counter,
        // )?;
        // trace!("decrypt message keys: {:?}", message_keys);

        // if session_state.get_remote_identity_key().is_none() {
        //     return Err(MyError::SessionError {
        //         code: 2066,
        //         name: "message decrypt".to_string(),
        //         msg: "remote identity key is none".to_string(),
        //     });
        // }

        // if session_state.get_local_identity_key().is_none() {
        //     return Err(MyError::SessionError {
        //         code: 2066,
        //         name: "message decrypt".to_string(),
        //         msg: "local identity key is none".to_string(),
        //     });
        // }

        // let verify_result = encrypted.verify_mac(
        //     &session_state.get_remote_identity_key().expect("decrypt3"),
        //     &session_state.get_local_identity_key().expect("decrypt4"),
        //     &message_keys.mac_key,
        // );
        // if verify_result.is_err() {
        //     return Err(MyError::SessionError {
        //         code: 2065,
        //         name: "message decrypt".to_string(),
        //         msg: "verify mac error".to_string(),
        //     });
        // }

        // let mut body = encrypted.ciphertext;
        // let plain_text =
        //     aes256_cbc_pkcs7_decrypt(&message_keys.cipher_key, &message_keys.iv, &mut body)?;

        // session_state.clear_unknown_pre_key_message();

        // self.identity_store.save_identity(
        //     self.address.clone(),
        //     session_state.get_remote_identity_key().unwrap(),
        // );
        // session_record.session_state = session_state;
        // let _ = self
        //     .session_store
        //     .store_session(self.address.clone(), session_record)?;

        // Ok(plain_text.to_vec())
    }

    fn get_message_keys(
        session_state: &mut SessionState,
        their_ephemeral: &PublicKey,
        chain_key: &mut ChainKey,
        counter: u32,
    ) -> Result<MessageKeys> {
        // let mut message_keys = MessageKeys::default();
        let mut message_keys;
        if chain_key.index > counter {
            if session_state.has_message_keys(&their_ephemeral, counter) {
                message_keys = session_state
                    .remove_message_keys(&their_ephemeral, counter)
                    .expect("decrypt3");
                return Ok(message_keys);
            } else {
                // Received message with old counter
                debug!(
                    "Received message with old counter. index:{}, counter:{}",
                    chain_key.index, counter
                );
                // return Err(MyError::SessionError {
                //     code: 2070,
                //     name: "DuplicateMessageException".to_string(),
                //     msg: "receive message with old counter".to_string(),
                // });
                return Err(MyError::DuplicateMessageException);
            }
        }

        if counter > 2000 + chain_key.index {
            // Over 2000 messages into the future!
            trace!(
                "Over 2000 messages into the future! index:{}, counter:{}",
                chain_key.index,
                counter
            );
            return Err(MyError::SessionError {
                code: 2071,
                name: "get message keys".to_string(),
                msg: "over 2000 messages into the future".to_string(),
            });
        }

        while chain_key.index < counter {
            message_keys = chain_key.get_message_keys();
            session_state.set_message_keys(&their_ephemeral, &message_keys);
            *chain_key = chain_key.next();
        }

        session_state.set_receiver_chain_key(&their_ephemeral, chain_key.next());
        message_keys = chain_key.get_message_keys();
        Ok(message_keys)
    }

    pub fn has_sender_chain(&self) -> Result<bool> {
        let session_record_opt = self.session_store.load_session(&self.address)?;
        session_record_opt.map_or(Ok(false), |record| {
            Ok(record.get_session_state().has_sender_chain())
        })
    }
}

pub type Result<T> = std::result::Result<T, MyError>;

pub fn aes256_cbc_pkcs7_encrypt<'a>(
    key: &[u8],
    iv: &[u8],
    buffer: &'a mut [u8],
    len: usize,
) -> &'a [u8] {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, BlockModeIv, Cbc};

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    //let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let cipher = Aes256Cbc::new_varkey(key, iv).unwrap();

    // TODO: not unwrap!
    cipher.encrypt_pad(buffer, len).unwrap()
}

pub fn aes256_cbc_pkcs7_decrypt<'a>(
    key: &[u8],
    iv: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, BlockModeIv, Cbc};

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    //let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let cipher = Aes256Cbc::new_varkey(key, iv).unwrap();

    cipher
        .decrypt_pad(buffer)
        .map_err(|_| MyError::SessionError {
            code: 2080,
            name: "aes256 decrypt".to_string(),
            msg: "aes256_cbc_pkcs7_decrypt fail".to_string(),
        })
}
