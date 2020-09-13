use crate::address::{Address, SenderKeyName};
use crate::keys::*;
use curve_crypto::*;
//use crate::keys::IdentityKeyPair;
use crate::session_record::{SenderKeyRecord, SessionRecord};
//use anyhow::Result;
use crate::errors::MyError;
use std::collections::HashMap;

pub enum Direction {
    SENDING,
    RECEIVING,
}

pub trait SessionStore {
    fn load_session(&self, address: &Address) -> Result<Option<SessionRecord>, MyError>;
    fn store_session(&mut self, address: Address, session: SessionRecord) -> Result<(), MyError>;
    // fn contains_session(&self, address: &Address) -> Result<Option<bool>, MyError>;
    fn delete_session(&mut self, address: &Address);
    fn delete_all_sessions(&mut self);
}

#[derive(Default, Debug)]
pub struct MemorySessionStore {
    sessions: HashMap<Address, SessionRecord>,
}

impl SessionStore for MemorySessionStore {
    fn load_session(&self, address: &'_ Address) -> Result<Option<SessionRecord>, MyError> {
        if let Some(session) = self.sessions.get(address) {
            return Ok(Some(session.clone()));
        }

        Ok(None)
    }

    fn store_session(&mut self, address: Address, session: SessionRecord) -> Result<(), MyError> {
        self.sessions.insert(address, session);
        Ok(())
    }

    // fn contains_session(&self, address: &'_ Address) -> Result<Option<bool>, MyError> {
    //     if self.sessions.is_empty() {
    //         return Ok(Some(false));
    //     }

    //     if let Some(_) = self.sessions.get(address) {
    //         return Ok(Some(true));
    //     }

    //     Ok(Some(false))
    // }

    fn delete_session(&mut self, address: &'_ Address) {
        self.sessions.remove(address);
    }

    fn delete_all_sessions(&mut self) {
        self.sessions.clear()
    }
}

pub trait PreKeyStore {
    fn load_pre_key(&self, id: u32) -> Option<PreKey>;
    fn store_pre_key(&mut self, id: u32, pre_key: PreKey);
    fn contains_pre_key(&self, id: u32) -> bool;
    fn remove_pre_key(&mut self, id: u32);
}

#[derive(Default, Debug)]
pub struct MemoryPreKeyStore {
    pre_keys: HashMap<u32, PreKey>,
}

impl PreKeyStore for MemoryPreKeyStore {
    fn load_pre_key(&self, id: u32) -> Option<PreKey> {
        let option = self.pre_keys.get(&id);
        if let Some(key) = option {
            let pre_key = *key;
            return Some(pre_key);
        }
        None
    }

    fn store_pre_key(&mut self, id: u32, pre_key: PreKey) {
        self.pre_keys.insert(id, pre_key);
    }

    fn contains_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    fn remove_pre_key(&mut self, _id: u32) {
        unimplemented!()
    }
}

pub trait SignedPreKeyStore {
    fn load_signed_pre_key(&self, id: u32) -> Option<SignedPreKey>;
    fn store_signed_pre_key(&mut self, id: u32, signed_pre_key: SignedPreKey);
    fn contains_signed_pre_key(&self, id: u32) -> bool;
    fn remove_signed_pre_key(&mut self, id: u32);
}

#[derive(Default, Debug)]
pub struct MemorySignedPreKeyStore {
    signed_keys: HashMap<u32, SignedPreKey>,
}

impl SignedPreKeyStore for MemorySignedPreKeyStore {
    fn load_signed_pre_key(&self, id: u32) -> Option<SignedPreKey> {
        let option = self.signed_keys.get(&id);
        if let Some(key) = option {
            let signed_key = *key;
            return Some(signed_key);
        }
        None
    }

    fn store_signed_pre_key(&mut self, id: u32, signed_pre_key: SignedPreKey) {
        self.signed_keys.insert(id, signed_pre_key);
    }

    fn contains_signed_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    fn remove_signed_pre_key(&mut self, _id: u32) {
        unimplemented!()
    }
}

pub trait IdentityKeyStore {
    fn get_identity_key_pair(&self) -> Option<IdentityKeyPair>;
    fn get_local_registration_id(&self) -> u32;
    fn save_identity(&mut self, address: Address, identity: PublicKey) -> bool;
    fn get_identity_key(&self, address: &Address) -> Option<PublicKey>;
    fn is_trusted_identity(
        &self,
        address: &Address,
        identity_key: &PublicKey,
        direction: Direction,
    ) -> bool;
}

#[derive(Default, Debug)]
pub struct MemoryIdentityKeyStore {
    trusted_keys: HashMap<Address, PublicKey>,
    pub identity_pair: IdentityKeyPair,
    pub registration_id: u32,
}

impl IdentityKeyStore for MemoryIdentityKeyStore {
    fn get_identity_key_pair(&self) -> Option<IdentityKeyPair> {
        Some(self.identity_pair)
    }

    fn get_local_registration_id(&self) -> u32 {
        self.registration_id
    }

    fn save_identity(&mut self, address: Address, identity: PublicKey) -> bool {
        self.trusted_keys.insert(address, identity);
        true
    }

    fn get_identity_key(&self, address: &'_ Address) -> Option<PublicKey> {
        match self.trusted_keys.get(address) {
            None => None,
            Some(key) => Some(key.clone()),
        }
    }

    fn is_trusted_identity(
        &self,
        address: &'_ Address,
        identity_key: &PublicKey,
        _direction: Direction,
    ) -> bool {
        if !self.trusted_keys.contains_key(address) {
            return true;
        }

        let local = self.trusted_keys.get(address).unwrap();
        if local == identity_key {
            return true;
        }

        false
    }
}

pub trait Store: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}

pub trait SenderKeyStore {
    fn store_sender_key(&mut self, sender: SenderKeyName, record: SenderKeyRecord);
    fn load_sender_key(&self, sender: &SenderKeyName) -> Option<SenderKeyRecord>;
}

#[derive(Default, Debug)]
pub struct MemorySenderKeyStore {
    store: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl SenderKeyStore for MemorySenderKeyStore {
    fn store_sender_key(&mut self, sender: SenderKeyName, record: SenderKeyRecord) {
        self.store.insert(sender, record);
    }

    fn load_sender_key(&self, sender: &'_ SenderKeyName) -> Option<SenderKeyRecord> {
        match self.store.get(sender) {
            None => None,
            Some(record) => Some(record.clone()),
        }
    }
}
