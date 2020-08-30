//extern crate libc;
#[macro_use]
extern crate log;
extern crate simplelog;
use curve_crypto::*;
use rand_core::OsRng;
use rust::errors::MyError;
use rust::message::CiphertextMessage;
use simplelog::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uchar;
use std::os::raw::c_uint;
use std::os::raw::c_ulonglong;
use std::ptr;
use std::slice;
use std::str::FromStr;

extern crate core;
extern crate libc;
extern crate rust;

extern "Rust" {
    pub fn c_load_session(address: *const Address) -> *const DataWrap;
    pub fn c_store_session(address: *const Address, session: DataWrap) -> c_int;
    // pub fn c_contain_session(address: *const Address) -> bool;
    pub fn c_get_identity_keypair() -> *const IdentityKeyPair;
    pub fn c_get_local_registration_id() -> c_uint;
    pub fn c_save_identity(address: *const Address, public_key: [c_uchar; 32]) -> c_int;
    pub fn c_get_identity(address: *const Address) -> [c_uchar; 32];
    pub fn c_is_trusted_identity(address: *const Address, public_key: [c_uchar; 32]) -> bool;
    pub fn c_load_signed_pre_key(id: c_uint) -> *const SignedPreKey;
    pub fn c_load_pre_key(id: c_uint) -> *const PreKey;
    pub fn c_remove_pre_key(id: c_uint) -> bool;
    pub fn c_store_sender_key(
        group_id: *const c_char,
        address: *const Address,
        session: DataWrap,
    ) -> c_int;
    pub fn c_load_sender_key(group_id: *const c_char, address: *const Address) -> *const DataWrap;
}

#[repr(C)]
pub struct DataWrap {
    pub data: *const c_char,
    pub length: c_uint,
}

#[repr(C)]
#[derive(Debug)]
pub struct MessageBuf {
    pub data: *const c_char,
    pub length: c_uint,
    pub message_type: c_uint,
}

#[repr(C)]
pub struct CSenderKeyStore;

impl rust::store::SenderKeyStore for CSenderKeyStore {
    fn store_sender_key(
        &mut self,
        sender: rust::address::SenderKeyName,
        record: rust::session_record::SenderKeyRecord,
    ) {
        let c_address = Address {
            name: CString::new(sender.sender.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: sender.sender.name.len() as c_uint,
            device_id: sender.sender.device_id as i32,
        };
        let group_id =
            CString::new(sender.group_id.clone()).expect("CString::new(group_id) failed.");
        debug!(
            "store_sender_key. group:{:02x?}",
            group_id.clone().into_bytes_with_nul()
        );
        //        let group_id = unsafe {
        //            CStr::from_bytes_with_nul_unchecked(sender.group_id.as_bytes()).as_ptr()
        //        };

        let buf = record.serialize();
        let length = buf.len() as u32;
        debug!("store_sender_key. buf:{:?}, len:{}", buf, length);
        unsafe {
            let string = CString::from_vec_unchecked(buf);
            debug!("store_sender_key. cstring:{:?}", string);
            let temp = DataWrap {
                data: string.into_raw(),
                length,
            };

            let result = c_store_sender_key(group_id.into_raw(), &c_address, temp);
            debug!("store_sender_key result: {}", result);
        }
    }

    fn load_sender_key(
        &self,
        sender: &'_ rust::address::SenderKeyName,
    ) -> Option<rust::session_record::SenderKeyRecord> {
        let c_address = Address {
            name: CString::new(sender.sender.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: sender.sender.name.len() as c_uint,
            device_id: sender.sender.device_id as i32,
        };
        let group_id =
            CString::new(sender.group_id.clone()).expect("CString::new(group_id) failed.");
        debug!(
            "load_sender_key. group:{:02x?}",
            group_id.clone().into_bytes_with_nul()
        );
        //        let group_id = unsafe {
        //            CStr::from_bytes_with_nul_unchecked(sender.group_id.as_bytes())
        //        };
        //        println!("load_sender_key. group:{:02x?}", group_id.to_bytes_with_nul());

        let key = unsafe {
            debug!("c_load_sender_key1. c_address: {:?}", c_address);
            c_load_sender_key(group_id.into_raw(), &c_address)
        };
        if key.is_null() {
            error!("c_load_sender_key1 point is null");
            return None;
        }

        let c_session = unsafe { &*key };
        let data: &[u8] = unsafe {
            slice::from_raw_parts(c_session.data as *const c_uchar, c_session.length as usize)
        };

        debug!("c_load_sender_key1 data: {:02x?}", data);
        let result = rust::session_record::SenderKeyRecord::deserialize(data);
        match result {
            Err(e) => {
                error!("c_load_sender_key deserialize fail. error:{:?}", e);
                None
            }
            Ok(record) => Some(record),
        }
    }
}

#[repr(C)]
pub struct CSessionStore;

impl rust::store::SessionStore for CSessionStore {
    fn load_session(
        &self,
        address: &'_ rust::address::Address,
    ) -> Result<Option<rust::session_record::SessionRecord>, MyError> {
        let c_address = Address {
            //name: address.name.as_bytes().as_ptr(),
            name: CString::new(address.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: address.name.len() as c_uint,
            device_id: address.device_id as i32,
        };
        debug!("c_load_session. address: {:?}", c_address);
        //let session = unsafe { c_load_session(&c_address) };
        debug!("c_load_session. {:p}", &c_load_session);
        let session = unsafe { c_load_session(&c_address) };
        if session.is_null() {
            return Ok(Some(rust::session_record::SessionRecord::default()));
        }
        unsafe {
            debug!("c_load_session.... {:p}", &session);
            let c_session = &*session;
            //debug!("c_load_session after. session: {:?}", c_session);
            let data: &[u8] =
                slice::from_raw_parts(c_session.data as *const c_uchar, c_session.length as usize);
            //            let data = CStr::from_ptr((*c_session).data);
            //            let data = CString::from_raw((*c_session).data);
            debug!("c_load_session after. session_string: {:x?}", data);
            //            let data = slice::from_raw_parts((*c_session).data, (*c_session).length as usize);
            let record = rust::session_record::SessionRecord::deserialize(data)?;
            Ok(Some(record))
        }
    }

    fn store_session(
        &mut self,
        address: rust::address::Address,
        session: rust::session_record::SessionRecord,
    ) -> Result<(), MyError> {
        let c_address = Address {
            //name: address.name.as_bytes().as_ptr(),
            name: CString::new(address.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: address.name.len() as c_uint,
            device_id: address.device_id as i32,
        };

        let buf = session.serialize();
        let length = buf.len() as u32;
        debug!("store_session. buf:{:?}, len:{}", buf, length);
        unsafe {
            let string = CString::from_vec_unchecked(buf);
            debug!("store_session. cstring:{:?}", string);
            let temp = DataWrap {
                data: string.into_raw(),
                length,
            };

            let result = c_store_session(&c_address, temp);
            debug!("session store result: {}", result);
            if result != 0 {
                return Err(MyError::SessionError {
                    code: 3000,
                    name: "call c store session".to_string(),
                    msg: "c store session fail".to_string(),
                });
            }
            Ok(())
        }
    }

    // fn contains_session(
    //     &self,
    //     address: &'_ rust::address::Address,
    // ) -> Result<Option<bool>, MyError> {
    //     debug!("in rust address: {:?}", address);
    //     let c_address = Address {
    //         //name: address.name.as_bytes().as_ptr(),
    //         name: CString::new(address.name.clone())
    //             .expect("CString::new failed")
    //             .into_raw(),
    //         name_len: address.name.len() as c_uint,
    //         device_id: address.device_id as i32,
    //     };
    //     unsafe {
    //         let has = c_contain_session(&c_address);
    //         debug!("in rust call c fn: has:{}", has);
    //         return Ok(Some(has));
    //     }
    // }

    // no use
    fn delete_session(&mut self, _address: &'_ rust::address::Address) {
        unimplemented!()
    }

    // no use
    fn delete_all_sessions(&mut self) {
        debug!("delete_all_session");
    }
}

pub struct CIdentityStore;

impl rust::store::IdentityKeyStore for CIdentityStore {
    fn get_identity_key_pair(&self) -> rust::keys::IdentityKeyPair {
        unsafe {
            let key_pair = &*c_get_identity_keypair();
            rust::keys::IdentityKeyPair {
                public: key_pair.public_key.into(),
                private: key_pair.private_key.into(),
            }
        }
    }

    fn get_local_registration_id(&self) -> u32 {
        unsafe { c_get_local_registration_id() }
    }

    fn save_identity(&mut self, address: rust::address::Address, identity: PublicKey) -> bool {
        let c_address = Address {
            //name: address.name.as_bytes().as_ptr(),
            name: CString::new(address.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: address.name.len() as c_uint,
            device_id: address.device_id as i32,
        };
        // let data = EcPublicKey {
        //     data: identity.to_bytes(),
        // };
        // debug!("save_identity. key: {:x?}", data);
        unsafe {
            c_save_identity(&c_address, identity.to_bytes());
        }
        true
    }

    fn get_identity_key(&self, address: &'_ rust::address::Address) -> Option<PublicKey> {
        let c_address = Address {
            //name: address.name.as_bytes().as_ptr(),
            name: CString::new(address.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: address.name.len() as c_uint,
            device_id: address.device_id as i32,
        };
        unsafe {
            let identity = c_get_identity(&c_address);
            debug!(
                "c_get_identity. address:{:?}, key: {:x?}",
                c_address, identity
            );
            Some(PublicKey::from(identity))
        }
    }

    fn is_trusted_identity(
        &self,
        address: &'_ rust::address::Address,
        identity_key: &'_ PublicKey,
        _direction: rust::store::Direction,
    ) -> bool {
        let c_address = Address {
            //name: address.name.as_bytes().as_ptr(),
            name: CString::new(address.name.clone())
                .expect("CString::new failed")
                .into_raw(),
            name_len: address.name.len() as c_uint,
            device_id: address.device_id as i32,
        };
        // let data = EcPublicKey {
        //     data: identity_key.to_bytes(),
        // };
        unsafe { c_is_trusted_identity(&c_address, identity_key.to_bytes()) }
    }
}

pub struct CSignedKeyStore;
impl rust::store::SignedPreKeyStore for CSignedKeyStore {
    fn load_signed_pre_key(&self, id: u32) -> Option<rust::keys::SignedPreKey> {
        unsafe {
            let key = &*c_load_signed_pre_key(id);
            let key_pair = KeyPair {
                private: key.private_key.into(),
                public: key.public_key.into(),
            };
            let signature = curve_crypto::Signature::from_bytes(&key.signature).unwrap();
            let rust_key = rust::keys::SignedPreKey {
                id: key.key_id,
                keypair: key_pair,
                signature,
                timestamp: key.timestamp,
            };
            Some(rust_key)
        }
    }

    // no use
    fn store_signed_pre_key(&mut self, _id: u32, _signed_pre_key: rust::keys::SignedPreKey) {
        unimplemented!()
    }

    // no use
    fn contains_signed_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    // no use
    fn remove_signed_pre_key(&mut self, _id: u32) {
        unimplemented!()
    }
}

pub struct CPreKeyStore;
impl rust::store::PreKeyStore for CPreKeyStore {
    fn load_pre_key(&self, id: u32) -> Option<rust::keys::PreKey> {
        unsafe {
            let key = &*c_load_pre_key(id);
            let key_pair = KeyPair {
                private: key.private_key.into(),
                public: key.public_key.into(),
            };
            let rust_key = rust::keys::PreKey {
                id: key.key_id,
                keypair: key_pair,
            };
            Some(rust_key)
        }
    }

    // no use
    fn store_pre_key(&mut self, _id: u32, _pre_key: rust::keys::PreKey) {
        unimplemented!()
    }

    // no use
    fn contains_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    // no use
    fn remove_pre_key(&mut self, id: u32) {
        unsafe {
            let ret = c_remove_pre_key(id);
            println!("c_remove_pre_key result:{}", ret);
        }
    }
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct EcKeyPair {
    pub public_key: [c_uchar; 32],
    pub private_key: [c_uchar; 32],
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct EcPublicKey {
    pub data: [c_uchar; 32],
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct EcPrivateKey {
    pub data: [c_uchar; 32],
}

//#[repr(C)]
//#[derive(Debug, Default)]
//pub struct IdentityKeyPair {
//    pub public_key: [c_uchar; 32],
//    pub private_key: [c_uchar; 32],
//}
type IdentityKeyPair = EcKeyPair;

#[repr(C)]
pub struct SignedPreKey {
    pub public_key: [c_uchar; 32],
    pub private_key: [c_uchar; 32],
    pub signature: [c_uchar; 64],
    pub key_id: c_uint,
    pub timestamp: c_ulonglong,
}

#[repr(C)]
pub struct PreKey {
    pub public_key: [c_uchar; 32],
    pub private_key: [c_uchar; 32],
    pub key_id: c_uint,
}

impl PreKey {
    pub fn new(key: EcKeyPair, key_id: u32) -> Self {
        Self {
            public_key: key.public_key,
            private_key: key.private_key,
            key_id,
        }
    }
}

#[repr(C)]
pub struct PreKeyNode {
    pub element: *mut PreKey,
    pub next: *mut Self,
}

#[repr(C)]
#[derive(Clone)]
pub struct Signature {
    pub data: [c_uchar; 64],
}

#[repr(C)]
#[derive(Debug)]
pub struct SharedKey {
    pub data: [c_uchar; 32],
}

// #[repr(C)]
// #[derive(Clone)]
// pub struct PreKeyBundle {
//     pub registration_id: u32,
//     pub device_id: u32,
//     pub pre_key: [c_uchar; 32],
//     pub pre_key_id: u32,
//     pub signed_pre_key: [c_uchar; 32],
//     pub signed_pre_key_id: u32,
//     pub signature: [c_uchar; 64],
//     pub identity_key: [c_uchar; 32],
// }

#[repr(C)]
#[derive(Debug)]
pub struct Address {
    pub name: *mut c_char,
    pub name_len: c_uint,
    pub device_id: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn generate_address(
    address: *mut *mut Address,
    name: *mut c_char,
    name_len: c_uint,
    id: c_int,
) -> c_int {
    let a = Address {
        name,
        name_len,
        device_id: id,
    };
    let _ = address.replace(Box::into_raw(Box::new(a)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn free_address(address: *const Address) {
    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    let name = String::from_utf8_unchecked(name1);
    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    debug!("address: {:?}", rust_address);
}

#[no_mangle]
pub unsafe extern "C" fn generate_buf(
    buf: *mut *mut DataWrap,
    data: *const c_char,
    length: c_uint,
) -> c_int {
    let a = DataWrap { data, length };

    let _ = buf.replace(Box::into_raw(Box::new(a)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn generate_message_buf(
    buf: *mut *mut MessageBuf,
    data: *const c_char,
    length: c_uint,
    message_type: c_uint,
) -> c_int {
    let a = MessageBuf {
        data,
        length,
        message_type,
    };
    let _ = buf.replace(Box::into_raw(Box::new(a)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn key_helper_generate_ec_key_pair(key_pair: *mut *mut EcKeyPair) -> c_int {
    let key = KeyPair::generate();
    let mut pair = EcKeyPair::default();
    pair.public_key = key.public.to_bytes();
    pair.private_key = key.private.to_bytes();
    trace!("public_key:{:02x?}", pair.public_key);
    trace!("private_key:{:02x?}", pair.private_key);
    let _ = key_pair.replace(Box::into_raw(Box::new(pair)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn key_helper_generate_identity_key_pair(
    key_pair: *mut *mut IdentityKeyPair,
) -> c_int {
    let key = rust::keys::IdentityKeyPair::new(&mut OsRng);
    let mut pair = IdentityKeyPair::default();
    pair.private_key = key.private.to_bytes();
    pair.public_key = key.public.to_bytes();
    let _ = key_pair.replace(Box::into_raw(Box::new(pair)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn key_helper_generate_signed_pre_key(
    key_pair: *mut *mut SignedPreKey,
    identity_key_pair: *const IdentityKeyPair,
    key_id: c_uint,
) -> c_int {
    let key = &*identity_key_pair;
    let mut ik = rust::keys::IdentityKeyPair::default();
    ik.public = key.public_key.into();
    ik.private = key.private_key.into();
    let signed_key = rust::keys::SignedPreKey::new(&ik, key_id);
    let pair = SignedPreKey {
        public_key: signed_key.keypair.public.to_bytes(),
        private_key: signed_key.keypair.private.to_bytes(),
        key_id,
        signature: signed_key.signature.to_bytes(),
        timestamp: signed_key.timestamp,
    };
    let _ = key_pair.replace(Box::into_raw(Box::new(pair)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn key_helper_generate_pre_keys(
    head: *mut *mut PreKeyNode,
    start: c_uint,
    count: c_uint,
) -> c_int {
    *head = ptr::null_mut();

    let keys = rust::keys::PreKey::new_list(start, count);
    for key in keys {
        let pre_key = PreKey {
            private_key: key.keypair.private.to_bytes(),
            public_key: key.keypair.public.to_bytes(),
            key_id: key.id,
        };

        let node = PreKeyNode {
            element: Box::into_raw(Box::new(pre_key)),
            next: *head,
        };

        let _ = head.replace(Box::into_raw(Box::new(node)));
    }

    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn curve_calculate_agreement(
    shared_key_data: *mut *mut SharedKey,
    public_key: *const [c_uchar; 32],
    private_key: *const [c_uchar; 32],
) -> c_int {
    if public_key.is_null() || private_key.is_null() {
        return -1 as c_int;
    }

    let secret = PrivateKey::from(*private_key);
    trace!("private_key:{:02x?}", *private_key);
    trace!("public_key:{:02x?}", *public_key);
    let shared_key = secret.dh(&PublicKey::from(*public_key));
    debug!("shared key:{:02x?}", shared_key);
    let shared = SharedKey {
        data: shared_key.as_bytes().clone(),
    };

    let _ = shared_key_data.replace(Box::into_raw(Box::new(shared)));
    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn curve_calculate_signature(
    signature: *mut *mut Signature,
    message: *const c_uchar,
    mlen: c_uint,
    identity_private_key: *const [c_uchar; 32],
) -> c_int {
    if message.is_null() {
        return -1 as c_int;
    }

    let data = slice::from_raw_parts(message, mlen as usize);
    trace!("private_key:{:02x?}", *identity_private_key);
    let identity_private_key = PrivateKey::from(*identity_private_key);
    let rust_signature = identity_private_key.sign(data);
    let sign = Signature {
        data: rust_signature.to_bytes(),
    };
    let _ = signature.replace(Box::into_raw(Box::new(sign)));

    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn curve_verify_signature(
    public_key: *const [c_uchar; 32],
    message: *const c_uchar,
    mlen: c_uint,
    signature: *const [c_uchar; 64],
) -> c_int {
    if message.is_null() {
        return -4 as c_int;
    }

    let data = slice::from_raw_parts(message, mlen as usize);
    let identity_public_key = PublicKey::from(*public_key);
    // let sig1: &[u8] = &(*signature).data;
    let sig2 = curve_crypto::Signature::from_bytes(&*signature);
    if let Ok(sign_ret) = sig2 {
        let result = identity_public_key.verify(data, &sign_ret);
        if let Err(_e) = result {
            return -1 as c_int;
        }
    } else {
        return -3 as c_int;
    }

    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn process_with_key_bundle(
    address: *const Address,
    registration_id: c_uint,
    device_id: c_uint,
    pre_key: *const [c_uchar; 32],
    pre_key_id: c_uint,
    signed_pre_key: *const [c_uchar; 32],
    signed_pre_key_id: c_uint,
    signature: *const [c_uchar; 64],
    identity_key: *const [c_uchar; 32],
    signed_data: *const c_char,
    signed_data_len: c_uint,
) -> c_int {
    //    let name1: Vec<u8> = slice::from_raw_parts((*address).name, (*address).name_len as usize).to_vec();
    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    let name = String::from_utf8_unchecked(name1);
    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    debug!("address: {:?}", rust_address);
    let mut session_store = CSessionStore {};
    let mut pre_key_store = CPreKeyStore {};
    let mut signed_key_store = CSignedKeyStore {};
    let mut identity_store = CIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        rust_address,
    );
    let mut rust_pre_key = PublicKey::default();
    if pre_key_id > 0 {
        rust_pre_key = PublicKey::from(*pre_key);
    }
    let rust_signed_key = PublicKey::from(*signed_pre_key);
    let rust_signature_ret = curve_crypto::Signature::from_bytes(&*signature);
    if rust_signature_ret.is_err() {
        return -2 as c_int;
    }
    let rust_signature = rust_signature_ret.unwrap();
    let rust_identity = PublicKey::from(*identity_key);
    let signed_data =
        slice::from_raw_parts(signed_data as *const c_uchar, signed_data_len as usize).to_vec();
    let key_bundle = rust::keys::PreKeyBundle {
        registration_id,
        device_id,
        pre_key: rust_pre_key,
        pre_key_id,
        signed_pre_key: rust_signed_key,
        signed_data,
        signed_pre_key_id,
        signature: rust_signature,
        identity_key: rust_identity,
    };
    let result = session.process_with_key_bundle(key_bundle);
    if let Err(_e) = result {
        return -1 as c_int;
    }

    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn session_cipher_encrypt(
    encrypted_message: *mut *mut MessageBuf,
    address: *const Address,
    plain_text: *const c_char,
    text_len: c_uint,
) -> c_int {
    //    let name1: Vec<u8> = slice::from_raw_parts((*address).name, (*address).name_len as usize).to_vec();
    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    let name = String::from_utf8_unchecked(name1);
    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    debug!("address: {:?}", rust_address);
    let mut session_store = CSessionStore {};
    let mut pre_key_store = CPreKeyStore {};
    let mut signed_key_store = CSignedKeyStore {};
    let mut identity_store = CIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        rust_address,
    );
    let cstr = CStr::from_ptr(plain_text);
    debug!("session_cipher_encrypt. cstr: {:?}", cstr);
    //    let text_old = cstr.to_str().expect("CStr from_ptr error");
    //    println!("session_cipher_encrypt. text_old: {:?}", text_old);
    let text = slice::from_raw_parts(plain_text as *const c_uchar, text_len as usize).to_vec();
    //    let v = &[0u8, 10];
    debug!("session_cipher_encrypt. text: {:?}", text);
    let encrypted_ret = session.encrypt(text);
    match encrypted_ret {
        Err(e) => match e {
            rust::errors::MyError::SessionError { code, name, msg } => {
                debug!(
                    "session_cipher_encrypt fail. code:{}, name:{}, msg: {}",
                    code, name, msg
                );
                return code as c_int;
            }
            rust::errors::MyError::NoPreKeyException => -2 as c_int,
            rust::errors::MyError::NoSignedKeyException => -3 as c_int,
            _ => -1 as c_int,
        },
        Ok(encrypted) => {
            let vec = encrypted.serialize();
            debug!("session_cipher_encrypt. encrypted: {:?}", vec);
            let length = vec.len() as u32;
            let result = CString::from_vec_unchecked(vec);
            let message_type = encrypted.get_type() as u32;
            let out = MessageBuf {
                data: result.into_raw(),
                length,
                message_type,
            };

            let _ = encrypted_message.replace(Box::into_raw(Box::new(out)));
            0 as c_int
        }
    }
    // if encrypted_ret.is_err() {
    //     return -1 as c_int;
    // }
    // let encrypted = encrypted_ret.unwrap();
    // let vec = encrypted.serialize();
    // debug!("session_cipher_encrypt. encrypted: {:?}", vec);
    // let length = vec.len() as u32;
    // let result = CString::from_vec_unchecked(vec);
    // let message_type = encrypted.get_type() as u32;

    // let out = MessageBuf {
    //     data: result.into_raw(),
    //     length,
    //     message_type,
    // };

    // let _ = encrypted_message.replace(Box::into_raw(Box::new(out)));

    // 0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn session_cipher_decrypt(
    out: *mut *mut DataWrap,
    encrypted_message: *const MessageBuf,
    address: *const Address,
) -> c_int {
    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    let name = String::from_utf8_unchecked(name1);
    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    debug!("address: {:?}", rust_address);
    let message_buf = &*encrypted_message;
    let mut session_store = CSessionStore {};
    let mut pre_key_store = CPreKeyStore {};
    let mut signed_key_store = CSignedKeyStore {};
    let mut identity_store = CIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        rust_address,
    );
    //let serialized = CString::from_raw(message_buf.data);
    let serialized: &[u8] = slice::from_raw_parts(
        message_buf.data as *const c_uchar,
        message_buf.length as usize,
    );
    if message_buf.message_type == 3 {
        let pre_key_message = rust::message::PreKeySignalMessage::deserialize(serialized);
        match pre_key_message {
            Err(_e) => return -1 as c_int,
            Ok(message) => {
                let result = session.pre_key_message_decrypt(message);
                match result {
                    Err(e) => match e {
                        rust::errors::MyError::SessionError { code, name, msg } => {
                            debug!(
                                "session_cipher_decrypt fail. code:{}, name:{}, msg: {}",
                                code, name, msg
                            );
                            return code as c_int;
                        }
                        rust::errors::MyError::NoPreKeyException => return -30 as c_int,
                        rust::errors::MyError::NoSignedKeyException => return -40 as c_int,
                        _ => return -20 as c_int,
                    },
                    // Err(_e) => return -2 as c_int,
                    Ok(text) => {
                        let length = text.len() as u32;
                        let string = CString::from_vec_unchecked(text);
                        let tmp = DataWrap {
                            data: string.into_raw(),
                            length,
                        };
                        out.replace(Box::into_raw(Box::new(tmp)));
                        return 0 as c_int;
                    }
                }
            }
        }
    }

    if message_buf.message_type == 2 {
        let signal_message = rust::message::SignalMessage::deserialize(serialized);
        match signal_message {
            Err(_e) => return -3 as c_int,
            Ok(message) => {
                let result = session.decrypt(message);
                match result {
                    Err(_e) => return -4 as c_int,
                    Ok(text) => {
                        let length = text.len() as u32;

                        let string = CString::from_vec_unchecked(text);
                        let tmp = DataWrap {
                            data: string.into_raw(),
                            length,
                        };
                        out.replace(Box::into_raw(Box::new(tmp)));
                        return 0 as c_int;
                    }
                }
            }
        }
    }

    -10 as c_int
}

#[no_mangle]
pub extern "C" fn group_create_distribution_message(
    distribution_message: *mut *mut MessageBuf,
    group_id: *const c_char,
    group_len: c_uint,
    address: *const Address,
) -> c_int {
    if group_id.is_null() {
        error!("group_id is null");
        return -1 as c_int;
    }

    if address.is_null() {
        error!("address is null");
        return -2 as c_int;
    }

    let c_address = unsafe { &*address };
    if c_address.name.is_null() {
        error!("address name is null");
        return -3 as c_int;
    }

    let mut sender_key_store = CSenderKeyStore;
    let name1 = unsafe { CStr::from_ptr((*address).name).to_bytes().to_vec() };
    let name = unsafe { String::from_utf8_unchecked(name1) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);

    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};
    let parts = unsafe { slice::from_raw_parts(group_id as *const c_uchar, group_len as usize) };
    let group = unsafe { String::from_utf8_unchecked(parts.to_vec()) };
    //    let group1 = unsafe {CStr::from_ptr(group_id).to_bytes().to_vec()};

    let sender = rust::address::SenderKeyName {
        group_id: group,
        sender: rust_address,
    };

    debug!("sender:{:?}", sender);

    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let message_opt = session_builder.create(&sender);
    if message_opt.is_err() {
        error!("create distribution message error");
        return -4 as c_int;
    }

    let message = message_opt.unwrap();

    let vec = message.serialize();
    debug!("create_distribution_message. encrypted: {:?}", vec);
    let length = vec.len() as u32;
    let result = unsafe { CString::from_vec_unchecked(vec) };
    debug!(
        "create_distribution_message. CString::from_vec_unchecked:{:?}, length:{}",
        result, length
    );
    let message_type = message.get_type() as u32;

    let out = MessageBuf {
        data: result.into_raw(),
        length,
        message_type,
    };

    debug!("create_distribution_message. out:{:?}", out);

    let _ = unsafe { distribution_message.replace(Box::into_raw(Box::new(out))) };

    0 as c_int
}

#[no_mangle]
pub extern "C" fn group_get_distribution_message(
    distribution_message: *mut *mut MessageBuf,
    group_id: *const c_char,
    group_len: c_uint,
    address: *const Address,
) -> c_int {
    if group_id.is_null() {
        error!("group_id is null");
        return -1 as c_int;
    }

    if address.is_null() {
        error!("address is null");
        return -2 as c_int;
    }

    let c_address = unsafe { &*address };
    if c_address.name.is_null() {
        error!("address name is null");
        return -3 as c_int;
    }

    let mut sender_key_store = CSenderKeyStore;
    let name1 = unsafe { CStr::from_ptr((*address).name).to_bytes().to_vec() };
    let name = unsafe { String::from_utf8_unchecked(name1) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);

    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};
    let parts = unsafe { slice::from_raw_parts(group_id as *const c_uchar, group_len as usize) };
    let group = unsafe { String::from_utf8_unchecked(parts.to_vec()) };
    //    let group1 = unsafe {CStr::from_ptr(group_id).to_bytes().to_vec()};

    let sender = rust::address::SenderKeyName {
        group_id: group,
        sender: rust_address,
    };

    debug!("sender:{:?}", sender);

    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let message_opt = session_builder.get_distribution_message(&sender);
    if message_opt.is_err() {
        error!("get distribution message error");
        return -4 as c_int;
    }

    let message = message_opt.unwrap();

    let vec = message.serialize();
    debug!("get_distribution_message. encrypted: {:?}", vec);
    let length = vec.len() as u32;
    let result = unsafe { CString::from_vec_unchecked(vec) };
    debug!(
        "get_distribution_message. CString::from_vec_unchecked:{:?}, length:{}",
        result, length
    );
    let message_type = message.get_type() as u32;

    let out = MessageBuf {
        data: result.into_raw(),
        length,
        message_type,
    };

    debug!("get_distribution_message. out:{:?}", out);

    let _ = unsafe { distribution_message.replace(Box::into_raw(Box::new(out))) };

    0 as c_int
}

#[no_mangle]
pub extern "C" fn group_process_distribution_message(
    distribution_message: *const MessageBuf,
    group_id: *const c_char,
    group_len: c_uint,
    address: *const Address,
) -> c_int {
    let mut sender_key_store = CSenderKeyStore;
    if group_id.is_null() {
        return -2 as c_int;
    }

    if address.is_null() {
        return -3 as c_int;
    }

    let c_address = unsafe { &*address };
    if c_address.name.is_null() {
        error!("address name is null");
        return -3 as c_int;
    }

    let name1 = unsafe { CStr::from_ptr((*address).name).to_bytes().to_vec() };
    let name = unsafe { String::from_utf8_unchecked(name1) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);
    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};
    let parts = unsafe { slice::from_raw_parts(group_id as *const c_uchar, group_len as usize) };
    let group = unsafe { String::from_utf8_unchecked(parts.to_vec()) };

    //    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    //    let name = String::from_utf8_unchecked(name1);
    //    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    //    let group1 = CStr::from_ptr(group_id).to_bytes().to_vec();
    //    let group = String::from_utf8_unchecked(group1);

    let sender = rust::address::SenderKeyName {
        group_id: group,
        sender: rust_address,
    };

    debug!("sender:{:?}", sender);

    let serialized: &[u8] = unsafe {
        slice::from_raw_parts(
            (*distribution_message).data as *const c_uchar,
            (*distribution_message).length as usize,
        )
    };
    debug!(
        "group_process_distribution_message. serialized bytes: {:?}",
        serialized
    );
    let key_distribution_message =
        rust::message::SenderKeyDistributionMessage::deserialize(serialized);
    if key_distribution_message.is_err() {
        return -10 as c_int;
    }

    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    session_builder.process(&sender, key_distribution_message.unwrap());

    0 as c_int
}

#[no_mangle]
pub unsafe extern "C" fn build_session(
    session: *mut *mut rust::session_builder::SessionBuilder,
    session_store: *mut dyn rust::store::SessionStore,
    identity_store: *mut dyn rust::store::IdentityKeyStore,
    signed_key_store: *mut dyn rust::store::SignedPreKeyStore,
    pre_key_store: *mut dyn rust::store::PreKeyStore,
    address: *const Address,
) -> c_int {
    //    let name1: Vec<u8> = slice::from_raw_parts((*address).name, (*address).name_len as usize).to_vec();
    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    let name = String::from_utf8_unchecked(name1);
    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    let session_build = rust::session_builder::SessionBuilder::new(
        &mut *session_store,
        &mut *pre_key_store,
        &mut *signed_key_store,
        &mut *identity_store,
        rust_address,
    );
    let _ = session.replace(Box::into_raw(Box::new(session_build)));

    0 as c_int
}

#[no_mangle]
pub extern "C" fn group_cipher_encode(
    encrypted_message: *mut *mut MessageBuf,
    group_id: *const c_char,
    group_len: c_uint,
    address: *const Address,
    plain_text: *const c_char,
    text_len: c_uint,
) -> c_int {
    let mut sender_key_store = CSenderKeyStore;
    if group_id.is_null() {
        return -2 as c_int;
    }

    if address.is_null() {
        return -3 as c_int;
    }

    let c_address = unsafe { &*address };
    if c_address.name.is_null() {
        error!("address name is null");
        return -3 as c_int;
    }
    //    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    //    let name = String::from_utf8_unchecked(name1);
    //    let rust_address = rust::address::Address::new(name, (*address).device_id as u64);
    //    let group1 = CStr::from_ptr(group_id).to_bytes().to_vec();
    //    let group = String::from_utf8_unchecked(group1);
    let name1 = unsafe { CStr::from_ptr((*address).name).to_bytes().to_vec() };
    let name = unsafe { String::from_utf8_unchecked(name1) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);
    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};
    let parts = unsafe { slice::from_raw_parts(group_id as *const c_uchar, group_len as usize) };
    let group = unsafe { String::from_utf8_unchecked(parts.to_vec()) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    //    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);
    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};

    let sender = rust::address::SenderKeyName {
        group_id: group,
        sender: rust_address,
    };
    debug!("sender:{:?}", sender);

    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let text =
        unsafe { slice::from_raw_parts(plain_text as *const c_uchar, text_len as usize).to_vec() };
    debug!("group_cipher_encrypt. text: {:02x?}", text);
    let encrypted = session_builder.encrypt(text);
    match encrypted {
        Err(_) => -1 as c_int,
        Ok(buf) => {
            let length = buf.len() as u32;
            let result = unsafe { CString::from_vec_unchecked(buf) };
            let message_type = 4 as u32;

            let out = MessageBuf {
                data: result.into_raw(),
                length,
                message_type,
            };

            let _ = unsafe { encrypted_message.replace(Box::into_raw(Box::new(out))) };
            0 as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn group_cipher_decode(
    decrypted_message: *mut *mut MessageBuf,
    group_id: *mut c_char,
    group_len: c_uint,
    address: *const Address,
    cipher_text: *const c_char,
    text_len: c_uint,
) -> c_int {
    let mut sender_key_store = CSenderKeyStore;
    if group_id.is_null() {
        return -2 as c_int;
    }

    if address.is_null() {
        return -3 as c_int;
    }

    let c_address = unsafe { &*address };
    if c_address.name.is_null() {
        error!("address name is null");
        return -3 as c_int;
    }

    let name1 = unsafe { CStr::from_ptr((*address).name).to_bytes().to_vec() };
    let name = unsafe { String::from_utf8_unchecked(name1) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};
    let rust_address = rust::address::Address::new(name, c_address.device_id as u64);
    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};
    let parts = unsafe { slice::from_raw_parts(group_id as *const c_uchar, group_len as usize) };
    let group = unsafe { String::from_utf8_unchecked(parts.to_vec()) };
    //    let name = unsafe {String::from_raw_parts(c_address.name as *mut c_uchar, c_address.name_len as usize, c_address.name_len as usize)};

    //    let name1 = CStr::from_ptr((*address).name).to_bytes().to_vec();
    //    let name = String::from_utf8_unchecked(name1);
    //    let group1 = CStr::from_ptr(group_id).to_bytes().to_vec();
    //    let group = String::from_utf8_unchecked(group1);
    //    let group= unsafe {String::from_raw_parts(group_id as *mut c_uchar,group_len as usize, group_len as usize)};

    let sender = rust::address::SenderKeyName {
        group_id: group,
        sender: rust_address,
    };
    debug!("sender:{:?}", sender);

    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let text =
        unsafe { slice::from_raw_parts(cipher_text as *const c_uchar, text_len as usize).to_vec() };
    debug!(
        "group_cipher_decrypt. text: {:02x?}, len:{}",
        text, text_len
    );
    let decrypted = session_builder.decrypt(text);
    match decrypted {
        Err(_e) => -1 as c_int,
        Ok(buf) => {
            let length = buf.len() as u32;
            let result = unsafe { CString::from_vec_unchecked(buf) };
            let message_type = 4 as u32;

            let out = MessageBuf {
                data: result.into_raw(),
                length,
                message_type,
            };

            let _ = unsafe { decrypted_message.replace(Box::into_raw(Box::new(out))) };
            0 as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn initE2eeSdkLogger(level: *const c_char) -> c_int {
    if level.is_null() {
        return -1 as c_int;
    }

    let level_ret = unsafe { CStr::from_ptr(level).to_str() };
    match level_ret {
        Err(_) => return -2 as c_int,
        Ok(s) => {
            let l = LevelFilter::from_str(s).unwrap_or(LevelFilter::Off);
            let config = ConfigBuilder::new()
                .set_time_format_str("%F %T%z")
                .set_time_to_local(true)
                .build();
            let result = SimpleLogger::init(l, config);
            if result.is_err() {
                return -3 as c_int;
            }
            return 0 as c_int;
        }
    }
}
