use crate::errors::MyError;
use crate::session_state::SenderKeyState;
use crate::session_state::SessionState;
use curve_crypto::{KeyPair, PublicKey};
use prost::Message;
use std::io::Cursor;

const ARCHIVED_STATES_MAX_LENGTH: usize = 40;

#[derive(Debug, Clone, Default)]
pub struct SenderKeyRecord {
    pub sender_key_states: Vec<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord, prost::DecodeError> {
        match crate::storage_proto::SenderKeyRecordStructure::decode(&mut Cursor::new(buf)) {
            Err(e) => Err(e),
            Ok(states) => {
                let mut sender_key_states = Vec::new();
                for state in states.sender_key_states {
                    let sender_state = SenderKeyState::new(state);
                    sender_key_states.push(sender_state);
                }

                Ok(SenderKeyRecord { sender_key_states })
            }
        }
    }

    pub fn get_sender_key_state(&self) -> Option<SenderKeyState> {
        match self.sender_key_states.get(0) {
            None => None,
            Some(s) => Some(s.clone()),
        }
    }

    pub fn get_sender_key_state_by_id(&self, id: u32) -> Option<SenderKeyState> {
        for state in &self.sender_key_states {
            if state.get_key_id() == id {
                return Some(state.clone());
            }
        }

        None
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key: PublicKey,
    ) {
        let state = SenderKeyState::build(id, iteration, chain_key, signature_key, None);
        self.sender_key_states.insert(0, state);
        if self.sender_key_states.len() > ARCHIVED_STATES_MAX_LENGTH {
            self.sender_key_states.pop();
        }
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key: KeyPair,
    ) {
        let state = SenderKeyState::build(
            id,
            iteration,
            chain_key,
            signature_key.public,
            Some(signature_key.private),
        );
        self.sender_key_states.clear();
        self.sender_key_states.push(state);
    }

    pub fn reset_sender_key_state(&mut self, state: SenderKeyState) {
        self.sender_key_states.clear();
        self.sender_key_states.push(state);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut structures: Vec<crate::storage_proto::SenderKeyStateStructure> = Vec::new();
        for state in &self.sender_key_states {
            structures.push(state.get_structure().clone());
        }

        let mut record = crate::storage_proto::SenderKeyRecordStructure::default();
        record.sender_key_states = structures;

        let mut buf = Vec::new();
        buf.reserve(record.encoded_len());
        record.encode(&mut buf).unwrap();
        buf
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionRecord {
    pub session_state: SessionState,
    pub previous_states: Vec<SessionState>,
    pub fresh: bool,
}

impl Default for SessionRecord {
    fn default() -> Self {
        Self {
            session_state: SessionState::default(),
            previous_states: vec![],
            fresh: true,
        }
    }
}

impl SessionRecord {
    pub fn session_state(mut self, state: SessionState) -> SessionRecord {
        self.session_state = state;
        self
    }

    pub fn fresh(mut self, fresh: bool) -> SessionRecord {
        self.fresh = fresh;
        self
    }

    pub fn deserialize(buf: &[u8]) -> Result<SessionRecord, MyError> {
        match crate::storage_proto::RecordStructure::decode(&mut Cursor::new(buf)) {
            Err(e) => {
                error!("deserialize SessionRecord fail. buf:{:02x?}", buf);
                Err(MyError::PbDecodeError {
                    code: 1000,
                    name: "RecordStructure".to_string(),
                    msg: format!("{}", e),
                })
            }
            Ok(record) => {
                debug!("deserialize SessionRecord success. record: {:?}", record);
                record.current_session.clone().map_or(
                    Err(MyError::PbDecodeError {
                        code: 1000,
                        name: "RecordStructure".to_string(),
                        msg: "current_session is None".to_string(),
                    }),
                    |session| {
                        let session_state = SessionState::new(session.clone());
                        let mut previous_states: Vec<SessionState> = Vec::new();
                        for previous_structure in record.previous_sessions {
                            previous_states.push(SessionState::new(previous_structure));
                        }

                        let session_record = SessionRecord {
                            session_state,
                            fresh: false,
                            previous_states,
                        };

                        Ok(session_record)
                    },
                )
            }
        }
    }

    pub fn has_session_state(&self, alice_base_key: &[u8]) -> bool {
        let mut state_base_key = self.session_state.get_alice_base_key().to_vec();
        let mut message_base_key = alice_base_key.to_vec();

        if state_base_key.len() == 33 {
            let _ = state_base_key.remove(0);
        }

        if message_base_key.len() == 33 {
            let _ = message_base_key.remove(0);
        }

        if state_base_key == message_base_key {
            return true;
        }

        for state in &self.previous_states {
            if state.get_alice_base_key() == alice_base_key {
                return true;
            }
        }

        false
    }

    pub fn get_session_state(self) -> SessionState {
        self.session_state
    }

    pub fn get_previous_states(self) -> Vec<SessionState> {
        self.previous_states
    }

    pub fn remove_previous_states(&mut self) {
        self.previous_states.clear();
    }

    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    pub fn promote_state(&mut self, promoted_state: SessionState) {
        self.previous_states.insert(0, self.session_state.clone());
        self.session_state = promoted_state;
        if self.previous_states.len() > ARCHIVED_STATES_MAX_LENGTH {
            self.previous_states.pop();
        }
    }

    pub fn remove_previous_state(&mut self, idx: usize) {
        self.previous_states.remove(idx);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut previous_structures: Vec<crate::storage_proto::SessionStructure> = Vec::new();
        for previous_state in self.previous_states.clone() {
            previous_structures.push(previous_state.get_structure().clone());
        }

        let mut record = crate::storage_proto::RecordStructure::default();
        record.current_session = Some(self.session_state.get_structure().clone());
        record.previous_sessions = previous_structures;

        let mut buf = Vec::new();
        buf.reserve(record.encoded_len());
        record.encode(&mut buf).unwrap();
        buf
    }
}
