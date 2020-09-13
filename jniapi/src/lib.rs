#![cfg(target_os = "android")]
#![allow(non_snake_case)]
#[macro_use]
extern crate log;
extern crate android_logger;

use jni::JNIEnv;
//use jni::Result;
use android_logger::Config;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::*;
use jni::{JavaVM, NativeMethod};
use lazy_static::lazy_static;
use log::Level;
use rand_core::OsRng;
use rust::errors::MyError;
use std::os::raw::c_void;
use std::str::FromStr;
use std::sync::Mutex;

const JAVA_PACKAGE: &str = "com/blue/baselib/ikey/";
// const JAVA_PACKAGE: &str = "ai/totok/e2ee/";

// 添加一个全局变量来缓存回调对象
lazy_static! {
    // jvm
    static ref JVM_GLOBAL: Mutex<Option<JavaVM>> = Mutex::new(None);
    //callback
    static ref JNI_CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);
}

/// Expose the JNI interface for android below
macro_rules! jni_method {
    ( $method:tt, $signature:expr ) => {{
        jni::NativeMethod {
            name: jni::strings::JNIString::from(stringify!($method)),
            sig: jni::strings::JNIString::from($signature),
            fn_ptr: $method as *mut c_void,
        }
    }};
}

pub unsafe fn newKeyPair(env: JNIEnv, _: JClass) -> jobject {
    let pair = curve_crypto::KeyPair::generate();

    let ja_public_key = env.byte_array_from_slice(pair.public.as_bytes()).unwrap();
    let ja_private_key = env.byte_array_from_slice(pair.private.as_bytes()).unwrap();

    let jo_public_key = env
        .new_object(
            format!("{}EcPublicKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_public_key))],
        )
        .unwrap();
    let jo_private_key = env
        .new_object(
            format!("{}EcPrivateKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_private_key))],
        )
        .unwrap();
    let jo_key_pair = env
        .new_object(
            format!("{}KeyPair", JAVA_PACKAGE),
            format!(
                "(L{}EcPublicKey;L{}EcPrivateKey;)V",
                JAVA_PACKAGE, JAVA_PACKAGE
            ),
            &[
                JValue::Object(jo_public_key),
                JValue::Object(jo_private_key),
            ],
        )
        .unwrap();

    jo_key_pair.into_inner()
}

pub unsafe fn newIdentityKey(env: JNIEnv, _: JClass) -> jobject {
    let pair = rust::keys::IdentityKeyPair::new(&mut OsRng);

    let ja_public_key = env.byte_array_from_slice(pair.public.as_bytes()).unwrap();
    let ja_private_key = env.byte_array_from_slice(pair.private.as_bytes()).unwrap();

    let jo_public_key = env
        .new_object(
            format!("{}EcPublicKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_public_key))],
        )
        .unwrap();
    let jo_private_key = env
        .new_object(
            format!("{}EcPrivateKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_private_key))],
        )
        .unwrap();
    let jo_key_pair = env
        .new_object(
            format!("{}IdentityKeyPair", JAVA_PACKAGE),
            format!(
                "(L{}EcPublicKey;L{}EcPrivateKey;)V",
                JAVA_PACKAGE, JAVA_PACKAGE
            ),
            &[
                JValue::Object(jo_public_key),
                JValue::Object(jo_private_key),
            ],
        )
        .unwrap();

    jo_key_pair.into_inner()
}

pub unsafe fn newSignedPreKey(env: JNIEnv, _: JClass, ik: JObject, key_id: jint) -> jobject {
    let jv_public_key = env
        .get_field(ik, "publicKey", format!("L{}EcPublicKey;", JAVA_PACKAGE))
        .unwrap();
    let jo_public_key = jv_public_key.l().unwrap();
    let ja_public_key = env
        .get_field(jo_public_key, "publicKey", "[B")
        .unwrap()
        .l()
        .unwrap()
        .into_inner() as jbyteArray;
    let public_key = env.convert_byte_array(ja_public_key).unwrap();

    let jv_private_key = env
        .get_field(ik, "privateKey", format!("L{}EcPrivateKey;", JAVA_PACKAGE))
        .unwrap();
    let jo_private_key = jv_private_key.l().unwrap();
    let ja_private_key = env
        .get_field(jo_private_key, "privateKey", "[B")
        .unwrap()
        .l()
        .unwrap()
        .into_inner() as jbyteArray;
    let private_key = env.convert_byte_array(ja_private_key).unwrap();

    let identity_key_pair = rust::keys::IdentityKeyPair::pair(
        private_key.as_slice().into(),
        public_key.as_slice().into(),
    );

    let pair = rust::keys::SignedPreKey::new(&identity_key_pair, key_id as u32);

    debug!("new signed key {:?}", pair);

    let ja_public_key = env
        .byte_array_from_slice(pair.keypair.public.as_bytes())
        .unwrap();
    let ja_private_key = env
        .byte_array_from_slice(pair.keypair.private.as_bytes())
        .unwrap();

    let jo_public_key = env
        .new_object(
            format!("{}EcPublicKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_public_key))],
        )
        .unwrap();
    let jo_private_key = env
        .new_object(
            format!("{}EcPrivateKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_private_key))],
        )
        .unwrap();
    let ja_signature = env
        .byte_array_from_slice(&pair.signature.to_bytes())
        .unwrap()
        .into();
    let ts = JValue::Long(pair.timestamp as jlong);
    debug!("ts: {:?}", ts.j());

    let jo_key_pair = env.new_object(
        format!("{}SignedPreKey", JAVA_PACKAGE),
        format!(
            "(IL{}EcPrivateKey;L{}EcPublicKey;[BJ)V",
            JAVA_PACKAGE, JAVA_PACKAGE
        ),
        &[
            JValue::Int(key_id),
            JValue::Object(jo_private_key),
            JValue::Object(jo_public_key),
            JValue::Object(ja_signature),
            ts,
        ],
    );

    jo_key_pair.unwrap().into_inner()
}

pub fn initLogger(env: JNIEnv, _: JClass, level: JString) {
    let mut level_string: String = "error".to_string();
    let l = env.get_string(level);
    if l.is_ok() {
        level_string = l.unwrap().into();
    }

    android_logger::init_once(
        Config::default()
            .with_min_level(Level::from_str(level_string.as_str()).unwrap_or(Level::Error))
            .with_tag("e2eesdk"),
    );
}

pub unsafe fn newPreKey(env: JNIEnv, _: JClass, key_id: jint) -> jobject {
    let pair = rust::keys::PreKey::new(key_id as u32);
    debug!("{:?}", pair);

    let ja_public_key = env
        .byte_array_from_slice(pair.keypair.public.as_bytes())
        .unwrap();
    let ja_private_key = env
        .byte_array_from_slice(pair.keypair.private.as_bytes())
        .unwrap();

    let jo_public_key = env
        .new_object(
            format!("{}EcPublicKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_public_key))],
        )
        .unwrap();
    let jo_private_key = env
        .new_object(
            format!("{}EcPrivateKey", JAVA_PACKAGE),
            "([B)V",
            &[JValue::Object(JObject::from(ja_private_key))],
        )
        .unwrap();
    let jo_key_pair = env
        .new_object(
            format!("{}PreKeyRecord", JAVA_PACKAGE),
            format!(
                "(IL{}EcPrivateKey;L{}EcPublicKey;)V",
                JAVA_PACKAGE, JAVA_PACKAGE
            ),
            &[
                JValue::Int(key_id),
                JValue::Object(jo_private_key),
                JValue::Object(jo_public_key),
            ],
        )
        .unwrap();

    jo_key_pair.into_inner()
}

pub fn newPreKeys(env: JNIEnv, _: JClass, start: jint, count: jint) -> jobject {
    let keys = rust::keys::PreKey::new_list(start as u32, count as u32);

    let j_ArrayList = env.new_object("java/util/ArrayList", "()V", &[]).unwrap();

    for key in keys {
        let ja_public_key = env
            .byte_array_from_slice(key.keypair.public.as_bytes())
            .unwrap();
        let ja_private_key = env
            .byte_array_from_slice(key.keypair.private.as_bytes())
            .unwrap();

        let jo_public_key = env
            .new_object(
                format!("{}EcPublicKey", JAVA_PACKAGE),
                "([B)V",
                &[JValue::Object(JObject::from(ja_public_key))],
            )
            .unwrap();
        let jo_private_key = env
            .new_object(
                format!("{}EcPrivateKey", JAVA_PACKAGE),
                "([B)V",
                &[JValue::Object(JObject::from(ja_private_key))],
            )
            .unwrap();
        let jo_key_pair = env
            .new_object(
                format!("{}PreKeyRecord", JAVA_PACKAGE),
                format!(
                    "(IL{}EcPrivateKey;L{}EcPublicKey;)V",
                    JAVA_PACKAGE, JAVA_PACKAGE
                ),
                &[
                    JValue::Int(key.id as i32),
                    JValue::Object(jo_private_key),
                    JValue::Object(jo_public_key),
                ],
            )
            .unwrap();
        let _ = env.call_method(
            j_ArrayList,
            "add",
            "(Ljava/lang/Object;)Z",
            &[JValue::Object(jo_key_pair)],
        );
    }

    j_ArrayList.into_inner()
}

pub fn curveAgreement(
    env: JNIEnv,
    _: JClass,
    our_private: jbyteArray,
    their_public: jbyteArray,
) -> jbyteArray {
    let vec_our_private = env.convert_byte_array(our_private).unwrap();
    let vec_their_public = env.convert_byte_array(their_public).unwrap();

    let private_key = curve_crypto::PrivateKey::from(vec_our_private.as_slice());
    let public_key = curve_crypto::PublicKey::from(vec_their_public.as_slice());

    let secret = private_key.dh(&public_key);

    env.byte_array_from_slice(secret.as_bytes()).unwrap()
}

pub fn curveCalculateSignature(
    env: JNIEnv,
    _: JClass,
    our_private: jbyteArray,
    data: jbyteArray,
) -> jbyteArray {
    let vec_our_private = env.convert_byte_array(our_private).unwrap();
    let vec_data = env.convert_byte_array(data).unwrap();

    let private_key = curve_crypto::PrivateKey::from(vec_our_private.as_slice());

    let signature = private_key.sign(vec_data.as_slice());

    env.byte_array_from_slice(&signature.to_bytes()).unwrap()
}

pub fn curveVerifySignature(
    env: JNIEnv,
    _: JClass,
    their_public: jbyteArray,
    data: jbyteArray,
    signature: jbyteArray,
) -> jboolean {
    let vec_their_public = env.convert_byte_array(their_public).unwrap();
    let public_key = curve_crypto::PublicKey::from(vec_their_public.as_slice());

    let vec_signature = env.convert_byte_array(signature).unwrap();
    let vec_data = env.convert_byte_array(data).unwrap();
    let rust_signature = curve_crypto::Signature::from_bytes(vec_signature.as_slice()).unwrap();

    let result = public_key.verify(vec_data.as_slice(), &rust_signature);
    if result.is_err() {
        return 0;
    }

    1
}

pub fn processWithKeyBundle(
    env: JNIEnv,
    _: JClass,
    name: JString,
    device_id: i32,
    device_name: JString,
    bob_register_id: i32,
    bob_pre_key: jbyteArray,
    bob_pre_key_id: i32,
    bob_signed_key: jbyteArray,
    bob_signed_key_id: i32,
    signature: jbyteArray,
    signed_data: jbyteArray,
    bob_identity: jbyteArray,
) {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("processWithKeyBundle. name input error");
        let _ = env.throw("processWithKeyBundle. name input error");
        return;
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("processWithKeyBundle. device_name input error");
        let _ = env.throw("processWithKeyBundle. device_name input error");
        return;
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);

    let mut pre_key = curve_crypto::PublicKey::default();
    let bob_pre_key_id = bob_pre_key_id as u32;
    debug!("processWithKeyBundle. bob_pre_key_id:{}", bob_pre_key_id);
    if bob_pre_key_id > 0 {
        let bob_pre_key = env.convert_byte_array(bob_pre_key).unwrap();
        debug!("processWithKeyBundle. bob_pre_key:{:?}", bob_pre_key);
        if bob_pre_key.len() != 32 {
            debug!(
                "pre key length error. found: {}, expected 32, bytes:{:?}",
                bob_pre_key.len(),
                bob_pre_key
            );
            let _ = env.throw(format!(
                "pre key length error. found: {}, expected 32",
                bob_pre_key.len()
            ));
            return;
        }
        pre_key = bob_pre_key.as_slice().into();
    }

    let bob_signed_key = env.convert_byte_array(bob_signed_key).unwrap();
    debug!("processWithKeyBundle. bob_signed_key:{:?}", bob_signed_key);
    if bob_signed_key.len() != 32 {
        debug!(
            "signed key length error. found: {}, expected 32, bytes:{:?}",
            bob_signed_key.len(),
            bob_signed_key
        );
        let _ = env.throw(format!(
            "signed key length error. found: {}, expected 32",
            bob_signed_key.len()
        ));
        return;
    }

    let signed_key = curve_crypto::PublicKey::from(bob_signed_key.as_slice());
    let signed_pre_key_id = bob_signed_key_id as u32;

    let signature_vec = env.convert_byte_array(signature).unwrap();
    debug!("processWithKeyBundle. signature:{:?}", signature_vec);
    let signature_opt = curve_crypto::Signature::from_bytes(signature_vec.as_slice());
    if signature_opt.is_err() {
        debug!("signature bytes parse error. bytes: {:?}", signature_vec);
        let _ = env.throw("signature bytes parse error");
        return;
    }

    let signature = signature_opt.unwrap();

    let data = env.convert_byte_array(signed_data).unwrap();
    debug!("processWithKeyBundle. sign data:{:?}", data);

    let identity_vec = env.convert_byte_array(bob_identity).unwrap();
    debug!("processWithKeyBundle. identity:{:?}", identity_vec);
    if identity_vec.len() != 32 {
        debug!(
            "identity key length error. found: {}, expected 32, bytes:{:?}",
            identity_vec.len(),
            identity_vec
        );
        let _ = env.throw(format!(
            "identity key length error. found: {}, expected 32",
            identity_vec.len()
        ));
        return;
    }
    let identity_key = identity_vec.as_slice().into();

    let key_bundle = PreKeyBundle {
        registration_id: bob_register_id as u32,
        device_id: device_id as u32,
        pre_key,
        pre_key_id: bob_pre_key_id,
        signed_pre_key: signed_key,
        signed_data: data,
        signed_pre_key_id,
        signature,
        identity_key,
    };

    debug!("preKeyBundle:{:?}", key_bundle);

    let mut session_store = JavaSessionStore {};
    let mut pre_key_store = JavaPreKeyStore {};
    let mut signed_key_store = JavaSignedKeyStore {};
    let mut identity_store = JavaIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        address.clone(),
    );

    debug!("process_with_key_bundle. builder session");
    let result = session.process_with_key_bundle(key_bundle);
    debug!(
        "process_with_key_bundle. builder session result: {:?}",
        result
    );
    if let Err(e) = result {
        match e {
            rust::errors::MyError::NoSignedKeyException => {
                let _ = env.throw_new(
                    format!("{}NoSignedKeyException", JAVA_PACKAGE),
                    "no signed key",
                );
            }
            _ => {
                let _ = env.throw(format!("process_with_key_bundle error: {:?}", e));
            }
        }
        return;
    }

    let record = session.session_store.load_session(&address);
    info!("record: {:?}", record);
}

pub fn cipherEncrypt(
    env: JNIEnv,
    _: JClass,
    name: JString,
    device_id: i32,
    device_name: JString,
    plain_text: jbyteArray,
) -> jobject {
    let jo_message_null = env
        .new_object(
            format!("{}CipherMessage", JAVA_PACKAGE),
            "([BI)V",
            &[JValue::Object(JObject::from(plain_text)), JValue::Int(0)],
        )
        .unwrap();
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        trace!("e2ee-encrypt. name input error");
        let _ = env.throw("e2ee-encrypt. name input error");
        return jo_message_null.into_inner();
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return jo_message_null.into_inner();
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);

    let text = env.convert_byte_array(plain_text).unwrap();

    let mut session_store = JavaSessionStore {};
    let mut pre_key_store = JavaPreKeyStore {};
    let mut signed_key_store = JavaSignedKeyStore {};
    let mut identity_store = JavaIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        address,
    );

    let encrypted_ret = session.encrypt(text);
    if encrypted_ret.is_err() {
        trace!("e2ee-encrypt. name input error");
        let _ = env.throw("e2ee-encrypt error");
        return jo_message_null.into_inner();
    }
    let encrypted = encrypted_ret.unwrap();
    let vec = encrypted.serialize();
    let message_type = encrypted.get_type() as i32;
    trace!(
        "e2ee-encrypt. serialize: {:02x?}, type: {}",
        vec,
        message_type
    );

    let ja_data = env.byte_array_from_slice(vec.as_slice()).unwrap();

    let jo_message = env
        .new_object(
            format!("{}CipherMessage", JAVA_PACKAGE),
            "([BI)V",
            &[
                JValue::Object(JObject::from(ja_data)),
                JValue::Int(message_type),
            ],
        )
        .unwrap();

    jo_message.into_inner()
}

pub fn cipherDecrypt(
    env: JNIEnv,
    _: JClass,
    name: JString,
    device_id: i32,
    device_name: JString,
    cipher_text: jbyteArray,
    message_type: i32,
) -> jbyteArray {
    //let name: String = env.get_string(name).unwrap().into();
    trace!("cipherDecrypt begin");
    let name_ret = env.get_string(name);
    trace!("cipherDecrypt 1");
    if name_ret.is_err() {
        trace!("cipherDecrypt. name input error");
        let _ = env.throw("cipherDecrypt. name input error");
        return cipher_text;
    }
    let name = name_ret.unwrap().into();
    trace!("cipherDecrypt 2 name:{:?}", name);
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return cipher_text;
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    trace!("cipherDecrypt 3 address: {:?}", address);

    let text = env.convert_byte_array(cipher_text).unwrap();
    trace!(
        "cipherDecrypt 4 convert byte array(cipher_text): {:?}",
        text
    );

    let mut session_store = JavaSessionStore {};
    let mut pre_key_store = JavaPreKeyStore {};
    let mut signed_key_store = JavaSignedKeyStore {};
    let mut identity_store = JavaIdentityStore {};
    let mut session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        address,
    );
    trace!("cipherDecrypt 5 new session");

    if message_type == 3 {
        let pre_key_message = rust::message::PreKeySignalMessage::deserialize(text.as_slice());
        trace!(
            "cipherDecrypt 6. PreKeySignalMessage::deserialize: {:?}",
            pre_key_message
        );
        match pre_key_message {
            Err(e) => {
                trace!(
                    "cipherDecrypt 7. PreKeySignalMessage::deserialize error: {:?}",
                    e
                );

                let _ = env.throw(format!("PreKeySignalMessage decrypt error: {:?}", e));
                return cipher_text;
            }
            Ok(message) => {
                trace!(
                    "cipherDecrypt 9. PreKeySignalMessage::deserialize Ok: {:?}",
                    message
                );
                let result = session.pre_key_message_decrypt(message);
                trace!("cipherDecrypt 10. pre_key_message_decrypt: {:?}", result);
                match result {
                    Err(e) => {
                        trace!("cipherDecrypt 11. pre_key_message_decrypt error: {:?}", e);
                        match e {
                            rust::errors::MyError::DuplicateMessageException => {
                                let _ = env.throw_new(
                                    format!("{}DuplicateMessageException", JAVA_PACKAGE),
                                    "receive message with old counter",
                                );
                            }
                            rust::errors::MyError::NoPreKeyException => {
                                let _ = env.throw_new(
                                    format!("{}NoPreKeyException", JAVA_PACKAGE),
                                    "no pre key found",
                                );
                            }
                            rust::errors::MyError::NoSignedKeyException => {
                                let _ = env.throw_new(
                                    format!("{}NoSignedKeyException", JAVA_PACKAGE),
                                    "no signed key found",
                                );
                            }
                            _ => {
                                let _ = env
                                    .throw(format!("PreKeySignalMessage decrypt error: {:?}", e));
                            }
                        }
                        // let result =
                        //     env.throw(format!("PreKeySignalMessage decrypt error: {:?}", e));
                        return cipher_text;
                    }
                    Ok(text) => {
                        trace!("cipherDecrypt 12. pre_key_message_decrypt text: {:?}", text);
                        let ja_plain_text = env.byte_array_from_slice(text.as_slice()).unwrap();
                        trace!("cipherDecrypt 13. pre_key_message_decrypt text2");
                        return ja_plain_text;
                    }
                }
            }
        }
    }

    if message_type == 2 {
        let signal_message = rust::message::SignalMessage::deserialize(text.as_slice());
        trace!(
            "cipherDecrypt 14. SignalMessage::deserialize: {:?}",
            signal_message
        );
        match signal_message {
            Err(e) => {
                trace!("cipherDecrypt 15 SignalMessage decode error!: {:?}", e);

                let _ = env.throw(format!("SignalMessage decrypt error: {:?}", e));
                return cipher_text;
            }
            Ok(message) => {
                trace!(
                    "cipherDecrypt 17. SignalMessage::deserialize Ok: {:?}",
                    message
                );
                let result = session.decrypt(message);
                trace!("cipherDecrypt 18. SignalMessage decrypt: {:?}", result);
                match result {
                    Err(e) => {
                        trace!("cipherDecrypt 19. SignalMessage decode error: {:?}", e);
                        match e {
                            rust::errors::MyError::DuplicateMessageException => {
                                let _ = env.throw_new(
                                    format!("{}DuplicateMessageException", JAVA_PACKAGE),
                                    "receive message with old counter",
                                );
                            }
                            _ => {
                                let _ = env.throw(format!("SignalMessage decrypt error: {:?}", e));
                            }
                        }
                        return cipher_text;
                    }
                    Ok(text) => {
                        trace!("cipherDecrypt 21. SignalMessage decrypt text: {:?}", text);
                        let ja_plain_text = env.byte_array_from_slice(text.as_slice()).unwrap();
                        trace!("cipherDecrypt 22. SignalMessage decrypt text2");
                        return ja_plain_text;
                    }
                }
            }
        }
    }

    trace!("cipherDecrypt. last line");
    let _ = env.throw("invalid message type");
    return cipher_text;
}

use rust::message::CiphertextMessage;
pub fn createDistributionMessage(
    env: JNIEnv,
    _: JClass,
    group: JString,
    name: JString,
    device_id: i32,
    device_name: JString,
) -> jbyteArray {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("createDistributionMessage. name input error");
        let _ = env.throw("createDistributionMessage. name input error");
        return env.new_byte_array(1).unwrap();
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return env.new_byte_array(1).unwrap();
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    let group_ret = env.get_string(group);
    if group_ret.is_err() {
        debug!("createDistributionMessage. group input error");
        let _ = env.throw("createDistributionMessage. group input error");
        return env.new_byte_array(1).unwrap();
    }
    let group = group_ret.unwrap().into();
    let sender = SenderKeyName {
        sender: address,
        group_id: group,
    };

    let mut sender_key_store = JavaSenderKeyStore;
    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let message_ret = session_builder.create(&sender);

    match message_ret {
        Err(_e) => {
            let _ = env.throw("create distribution message error");
            return env.new_byte_array(1).unwrap();
        }
        Ok(message) => {
            let vec = message.serialize();
            debug!("createDistributionMessage. message: {:?}", vec);

            env.byte_array_from_slice(vec.as_slice()).unwrap()
        }
    }
}

pub fn getDistributionMessage(
    env: JNIEnv,
    _: JClass,
    group: JString,
    name: JString,
    device_id: i32,
    device_name: JString,
) -> jbyteArray {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("getDistributionMessage. name input error");
        let _ = env.throw("getDistributionMessage. name input error");
        return env.new_byte_array(1).unwrap();
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return env.new_byte_array(1).unwrap();
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    let group_ret = env.get_string(group);
    if group_ret.is_err() {
        debug!("getDistributionMessage. group input error");
        let _ = env.throw("getDistributionMessage. group input error");
        return env.new_byte_array(1).unwrap();
    }
    let group = group_ret.unwrap().into();
    let sender = SenderKeyName {
        sender: address,
        group_id: group,
    };

    let mut sender_key_store = JavaSenderKeyStore;
    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let message_ret = session_builder.get_distribution_message(&sender);

    match message_ret {
        Err(_e) => {
            let _ = env.throw("get distribution message error");
            return env.new_byte_array(1).unwrap();
        }
        Ok(message) => {
            let vec = message.serialize();
            debug!("getDistributionMessage. message: {:?}", vec);

            env.byte_array_from_slice(vec.as_slice()).unwrap()
        }
    }
}

pub fn processDistributionMessage(
    env: JNIEnv,
    _: JClass,
    group: JString,
    name: JString,
    device_id: i32,
    device_name: JString,
    distribution_message: jbyteArray,
) -> jboolean {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("processDistributionMessage. name input error");
        let _ = env.throw("processDistributionMessage. name input error");
        return 0;
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return 0;
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    let group_ret = env.get_string(group);
    if group_ret.is_err() {
        debug!("processDistributionMessage. group input error");
        let _ = env.throw("processDistributionMessage. group input error");
        return 0;
    }
    let group = group_ret.unwrap().into();
    let sender = SenderKeyName {
        sender: address,
        group_id: group,
    };

    let serialized = env.convert_byte_array(distribution_message).unwrap();
    let key_distribution_message =
        rust::message::SenderKeyDistributionMessage::deserialize(serialized.as_slice());
    if key_distribution_message.is_err() {
        return 0;
    }

    let mut sender_key_store = JavaSenderKeyStore;
    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    session_builder.process(&sender, key_distribution_message.unwrap());

    1
}

pub fn groupEncrypt(
    env: JNIEnv,
    _: JClass,
    group: JString,
    name: JString,
    device_id: i32,
    device_name: JString,
    plain_text: jbyteArray,
) -> jbyteArray {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("groupEncrypt. name input error");
        let _ = env.throw("groupEncrypt. name input error");
        return plain_text;
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return plain_text;
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    let group_ret = env.get_string(group);
    if group_ret.is_err() {
        debug!("groupEncrypt. group input error");
        let _ = env.throw("groupEncrypt. group input error");
        return plain_text;
    }
    let group = group_ret.unwrap().into();
    let sender = SenderKeyName {
        sender: address,
        group_id: group,
    };

    let text = env.convert_byte_array(plain_text).unwrap();

    let mut sender_key_store = JavaSenderKeyStore;
    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let encrypted = session_builder.encrypt(text);
    debug!("groupEncrypt. message: {:?}", encrypted);
    match encrypted {
        Err(e) => {
            debug!("groupEncrypt fail: {:?}", e);
            let _ = env.throw("groupEncrypt fail");
            return plain_text;
        }
        Ok(buf) => {
            return env.byte_array_from_slice(buf.as_slice()).unwrap();
        }
    }
}

pub fn groupDecrypt(
    env: JNIEnv,
    _: JClass,
    group: JString,
    name: JString,
    device_id: i32,
    device_name: JString,
    cipher_text: jbyteArray,
) -> jbyteArray {
    let name_ret = env.get_string(name);
    if name_ret.is_err() {
        debug!("groupDecrypt. name input error");
        let _ = env.throw("groupDecrypt. name input error");
        return cipher_text;
    }
    let name = name_ret.unwrap().into();
    let device_name_ret = env.get_string(device_name);
    if device_name_ret.is_err() {
        debug!("device_name input error");
        let _ = env.throw("device_name input error");
        return cipher_text;
    }
    let device_name = device_name_ret.unwrap().into();
    let address = Address::new(name, device_id as u64, device_name);
    //    let group: String = env.get_string(group).unwrap().into();
    let group_ret = env.get_string(group);
    if group_ret.is_err() {
        debug!("groupDecrypt. group input error");
        let _ = env.throw("groupDecrypt. group input error");
        return cipher_text;
    }
    let group = group_ret.unwrap().into();

    let sender = SenderKeyName {
        sender: address,
        group_id: group,
    };

    let text_ret = env.convert_byte_array(cipher_text);
    if text_ret.is_err() {
        debug!("groupDecrypt fail. cipher test is error");
        let _ = env.throw("groupDecrypt fail");
        return cipher_text;
    }
    let text = text_ret.unwrap();

    let mut sender_key_store = JavaSenderKeyStore;
    let mut session_builder =
        rust::session_builder::GroupSessionBuilder::new(&mut sender_key_store, sender.clone());
    let decrypted = session_builder.decrypt(text);
    debug!("groupDecrypt. message: {:?}", decrypted);
    match decrypted {
        Err(e) => {
            debug!("groupDecrypt fail: {:?}", e);
            let _ = env.throw("groupDecrypt fail");
            return cipher_text;
        }
        Ok(buf) => {
            return env.byte_array_from_slice(buf.as_slice()).unwrap();
        }
    }
}

#[no_mangle]
unsafe fn JNI_OnLoad(jvm: JavaVM, _reserved: *mut c_void) -> jint {
    info!("Load JNI...");

    let class_name: String = format!("{}RustKeyHelper", JAVA_PACKAGE);
    let jni_methods = [
        jni_method!(
            initStoreInterface,
            format!("(L{}StoreInterface;)V", JAVA_PACKAGE)
        ),
        jni_method!(newKeyPair, format!("()L{}KeyPair;", JAVA_PACKAGE)),
        jni_method!(
            newIdentityKey,
            format!("()L{}IdentityKeyPair;", JAVA_PACKAGE)
        ),
        jni_method!(
            newSignedPreKey,
            format!(
                "(L{}IdentityKeyPair;I)L{}SignedPreKey;",
                JAVA_PACKAGE, JAVA_PACKAGE
            )
        ),
        jni_method!(initLogger, "(Ljava/lang/String;)V"),
        jni_method!(newPreKey, format!("(I)L{}PreKeyRecord;", JAVA_PACKAGE)),
        jni_method!(newPreKeys, "(II)Ljava/util/List;"),
        jni_method!(curveAgreement, "([B[B)[B"),
        jni_method!(curveCalculateSignature, "([B[B)[B"),
        jni_method!(curveVerifySignature, "([B[B[B)Z"),
        jni_method!(newAddress, "(Ljava/lang/String;ILjava/lang/String;)J"),
        jni_method!(
            processWithKeyBundle,
            "(Ljava/lang/String;ILjava/lang/String;I[BI[BI[B[B[B)V"
        ),
        jni_method!(
            cipherEncrypt,
            format!(
                "(Ljava/lang/String;ILjava/lang/String;[B)L{}CipherMessage;",
                JAVA_PACKAGE
            )
        ),
        jni_method!(
            cipherDecrypt,
            "(Ljava/lang/String;ILjava/lang/String;[BI)[B"
        ),
        jni_method!(
            createDistributionMessage,
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)[B"
        ),
        jni_method!(
            getDistributionMessage,
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)[B"
        ),
        jni_method!(
            processDistributionMessage,
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[B)Z"
        ),
        jni_method!(
            groupEncrypt,
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[B)[B"
        ),
        jni_method!(
            groupDecrypt,
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[B)[B"
        ),
        jni_method!(hasSenderChain, "(Ljava/lang/String;ILjava/lang/String;)Z"),
    ];

    let ok = register_natives(&jvm, &class_name, jni_methods.as_ref());

    let mut ptr_jvm = JVM_GLOBAL.lock().unwrap();
    *ptr_jvm = Some(jvm);

    ok
}

pub fn initStoreInterface(env: JNIEnv, _obj: jobject, callback: jobject) {
    // 创建一个全局引用,
    let callback = env.new_global_ref(JObject::from(callback)).unwrap();

    // 添加到全局缓存
    let mut ptr_fn = JNI_CALLBACK.lock().unwrap();
    *ptr_fn = Some(callback);
}

/// # 封装jvm调用
fn call_jvm<F>(callback: &Mutex<Option<GlobalRef>>, run: F)
where
    F: Fn(JObject, &JNIEnv) + Send + 'static,
{
    let ptr_jvm = JVM_GLOBAL.lock().unwrap();
    trace!("e2ee-encrypt call_jvm 1");
    if (*ptr_jvm).is_none() {
        return;
    }
    trace!("e2ee-encrypt call_jvm 2");
    let ptr_fn = callback.lock().unwrap();
    if (*ptr_fn).is_none() {
        return;
    }
    trace!("e2ee-encrypt call_jvm 3");
    let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

    match jvm.attach_current_thread_permanently() {
        Ok(env) => {
            trace!("e2ee-encrypt call_jvm 4");
            let obj = (*ptr_fn).as_ref().unwrap().as_obj();
            let _ = run(obj, &env);

            trace!("e2ee-encrypt call_jvm 5");
            // 检查回调是否发生异常, 如果有异常发生,则打印并清空
            if let Ok(true) = env.exception_check() {
                trace!("e2ee-encrypt call_jvm 6");
                let _ = env.exception_describe();
                let _ = env.exception_clear();
                // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
            }
        }
        Err(e) => {
            trace!("e2ee-encrypt call_jvm 7");
            debug!("jvm attach_current_thread failed: {:?}", e);
        }
    }
}

unsafe fn register_natives(jvm: &JavaVM, class_name: &str, methods: &[NativeMethod]) -> jint {
    let env: JNIEnv = jvm.get_env().unwrap();
    let jni_version = env.get_version().unwrap();
    let version: jint = jni_version.into();

    info!("JNI Version : {:#?} ", jni_version);

    let clazz = match env.find_class(class_name) {
        Ok(clazz) => clazz,
        Err(e) => {
            error!("java class not found : {:?}", e);
            return JNI_ERR;
        }
    };
    let result = env.register_native_methods(clazz, &methods);

    if result.is_ok() {
        info!("register_natives : succeed");
        version
    } else {
        error!("register_natives : failed ");
        JNI_ERR
    }
}

pub fn newAddress(
    env: JNIEnv,
    _: JClass,
    name: JString,
    device_id: jint,
    device_name: JString,
) -> jlong {
    let name: String = env
        .get_string(name)
        .expect("Couldn't get java name!")
        .into();

    let device_name: String = env
        .get_string(device_name)
        .expect("Couldn't get java device_name!")
        .into();
    let address = rust::address::Address::new(name, device_id as u64, device_name);
    Box::into_raw(Box::new(address)) as jlong
}

pub fn hasSenderChain(
    env: JNIEnv,
    _: JClass,
    name: JString,
    device_id: i32,
    device_name: JString,
) -> jboolean {
    let name: String = env
        .get_string(name)
        .expect("Couldn't get java name!")
        .into();

    let device_name: String = env
        .get_string(device_name)
        .expect("Couldn't get java name!")
        .into();
    let address = rust::address::Address::new(name, device_id as u64, device_name);

    let mut session_store = JavaSessionStore {};
    let mut pre_key_store = JavaPreKeyStore {};
    let mut signed_key_store = JavaSignedKeyStore {};
    let mut identity_store = JavaIdentityStore {};
    let session = rust::session_builder::SessionBuilder::new(
        &mut session_store,
        &mut pre_key_store,
        &mut signed_key_store,
        &mut identity_store,
        address,
    );

    let ret = session.has_sender_chain();
    if ret.is_err() {
        return 0;
    }

    let has = ret.unwrap();

    has as jboolean
}

use rust::address::*;
use rust::session_record::*;
struct JavaSessionStore;
impl rust::store::SessionStore for JavaSessionStore {
    fn load_session(&self, address: &Address) -> Result<Option<SessionRecord>, MyError> {
        trace!("call java loadSession begin. address: {:?}", address);
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return Err(MyError::SessionError {
                code: 9000,
                name: "load_session".to_string(),
                msg: "jvm is none".to_string(),
            });
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return Err(MyError::SessionError {
                code: 9001,
                name: "load_session".to_string(),
                msg: "callback is none".to_string(),
            });
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
                let jo_device_name =
                    JValue::Object(env.new_string(address.device_name.clone()).unwrap().into());
                let args: [JValue; 3] = [
                    jo_name,
                    JValue::Int(address.device_id as i32),
                    jo_device_name,
                ];
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let call_result = env.call_method(
                    obj,
                    "loadSession",
                    "(Ljava/lang/String;ILjava/lang/String;)[B",
                    &args,
                );

                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    trace!("call java loadSession exception!!!");
                    return Err(MyError::SessionError {
                        code: 9002,
                        name: "load_session".to_string(),
                        msg: "call java loadSession exception".to_string(),
                    });
                }
                debug!(
                    "call java loadSession. address: {:?}, result:{:?}",
                    address, call_result
                );
                match call_result {
                    Ok(jvalue) => {
                        debug!("call java loadSession 1");
                        let out = jvalue.l().unwrap().into_inner() as jbyteArray;
                        if out.is_null() {
                            debug!("call java loadSession 3");
                            return Ok(None);
                        }
                        debug!("call java loadSession 2");
                        let session = env.convert_byte_array(out);
                        debug!("call java loadSession. session:{:02x?}", session);
                        let record = SessionRecord::deserialize(session.unwrap().as_slice())?;
                        Ok(Some(record))
                    }
                    Err(_e) => {
                        error!("call java loadSession fail");
                        return Err(MyError::SessionError {
                            code: 9003,
                            name: "load_session".to_string(),
                            msg: "call java loadSession fail".to_string(),
                        });
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return Err(MyError::SessionError {
                    code: 9004,
                    name: "load_session".to_string(),
                    msg: "get env fail".to_string(),
                });
            }
        }

        //        call_jvm(&JNI_CALLBACK, move |obj: JObject, env: &JNIEnv| {
        //            let args: [JValue; 1] = [JValue::from(raw)];
        //            match env.call_method(obj, "loadSession", "(J)[B", &args) {
        //                Ok(jvalue) => {
        //                    let out = jvalue.l().unwrap().into_inner() as jbyteArray;
        //                    session = env.convert_byte_array(out).unwrap();
        //                    debug!("callback succeed: {:?}", session);
        //                }
        //                Err(e) => {
        //                    error!("callback failed : {:?}", e);
        //                }
        //            }
        //        });
        //
        //        SessionRecord::deserialize(session.as_slice()).expect("SessionRecord deserialize fail")
    }

    fn store_session(&mut self, address: Address, session: SessionRecord) -> Result<(), MyError> {
        trace!("e2ee-encrypt. start store session. address:{:?}", address);
        let vec = session.serialize();
        trace!("e2ee-encrypt. session serialize: {:?}", vec);
        //let raw = Box::into_raw(Box::new(address.clone())) as jlong;
        call_jvm(&JNI_CALLBACK, move |obj: JObject, env: &JNIEnv| {
            let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
            let jo_device_name =
                JValue::Object(env.new_string(address.device_name.clone()).unwrap().into());
            let ja_session = env.byte_array_from_slice(vec.as_slice()).unwrap().into();
            let args: [JValue; 4] = [
                jo_name,
                JValue::Int(address.device_id as i32),
                jo_device_name,
                JValue::Object(ja_session),
            ];
            let result = env.call_method(
                obj,
                "storeSession",
                "(Ljava/lang/String;ILjava/lang/String;[B)V",
                &args,
            );
            trace!("e2ee-encrypt. call java storeSession result: {:?}", result);

            if result.is_err() {
                trace!("e2ee-encrypt. store session fail!");
            }
        });

        Ok(())
    }

    // fn contains_session(&self, address: &'_ Address) -> Result<Option<bool>, MyError> {
    //     //let raw = Box::into_raw(Box::new(address.clone())) as jlong;
    //     trace!("call java containSession begin");
    //     let ptr_jvm = JVM_GLOBAL.lock().unwrap();
    //     if (*ptr_jvm).is_none() {
    //         error!("jvm is none");
    //         return Err(MyError::SessionError {
    //             code: 9010,
    //             name: "contains_session".to_string(),
    //             msg: "jvm is none".to_string(),
    //         });
    //     }

    //     let ptr_fn = JNI_CALLBACK.lock().unwrap();
    //     if (*ptr_fn).is_none() {
    //         error!("get callback is none");
    //         return Err(MyError::SessionError {
    //             code: 9011,
    //             name: "contains_session".to_string(),
    //             msg: "callback is none".to_string(),
    //         });
    //     }

    //     let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

    //     let env_result = jvm.attach_current_thread_permanently();
    //     match env_result {
    //         Ok(env) => {
    //             let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
    //             let args: [JValue; 2] = [jo_name, JValue::Int(address.device_id as i32)];
    //             let obj = (*ptr_fn).as_ref().unwrap().as_obj();
    //             let call_result =
    //                 env.call_method(obj, "containSession", "(Ljava/lang/String;I)Z", &args);
    //             if let Ok(true) = env.exception_check() {
    //                 let _ = env.exception_describe();
    //                 let _ = env.exception_clear();
    //                 // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
    //                 trace!("call java containSession exception");
    //                 return Err(MyError::SessionError {
    //                     code: 9012,
    //                     name: "contains_session".to_string(),
    //                     msg: "call java containSession exception".to_string(),
    //                 });
    //             }
    //             match call_result {
    //                 Ok(jvalue) => {
    //                     return Ok(Some(
    //                         jvalue.z().expect("unwrap java containSession result fail"),
    //                     ));
    //                 }
    //                 Err(_e) => {
    //                     error!("call java containSession fail");
    //                     return Err(MyError::SessionError {
    //                         code: 9013,
    //                         name: "contains_session".to_string(),
    //                         msg: "call java containSession fail".to_string(),
    //                     });
    //                 }
    //             }
    //         }
    //         Err(_e) => {
    //             error!("get env fail");
    //             return Err(MyError::SessionError {
    //                 code: 9014,
    //                 name: "contains_session".to_string(),
    //                 msg: "get env fail".to_string(),
    //             });
    //         }
    //     }

    //     //        call_jvm(&JNI_CALLBACK, move |obj: JObject, env: &JNIEnv| {
    //     //            let args: [JValue; 1] = [JValue::from(raw)];
    //     //            let result = env.call_method(obj, "containSession", "(J)Z", &args);
    //     //
    //     //            match result {
    //     //                Ok(jvalue) => {
    //     //                    has = jvalue.z().unwrap();
    //     //                },
    //     //                Err(e) => {
    //     //                    error!("call java containSession fail!");
    //     //                }
    //     //            }
    //     //
    //     //        });
    //     //
    //     //        has
    // }

    fn delete_session(&mut self, _address: &'_ Address) {
        unimplemented!()
    }

    fn delete_all_sessions(&mut self) {
        unimplemented!()
    }
}

use rust::keys::*;
use rust::store::Direction;
struct JavaIdentityStore;

impl rust::store::IdentityKeyStore for JavaIdentityStore {
    fn get_identity_key_pair(&self) -> Option<IdentityKeyPair> {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return None;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return None;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let call_result = env.call_method(
                    obj,
                    "getIdentityKeyPair",
                    format!("()L{}IdentityKeyPair;", JAVA_PACKAGE),
                    &[],
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java getIdentityKeyPair exception");
                    return None;
                }
                debug!("call java getIdentityKeyPair: {:?}", call_result);
                match call_result {
                    Ok(jvalue) => {
                        let ik = jvalue.l().unwrap();
                        if ik.is_null() {
                            return None;
                        }
                        let jv_public_key = env
                            .get_field(ik, "publicKey", format!("L{}EcPublicKey;", JAVA_PACKAGE))
                            .unwrap();
                        let jo_public_key = jv_public_key.l().unwrap();
                        if jo_public_key.is_null() {
                            return None;
                        }
                        let ja_public_key = env
                            .get_field(jo_public_key, "publicKey", "[B")
                            .unwrap()
                            .l()
                            .unwrap()
                            .into_inner() as jbyteArray;
                        let public_key = env.convert_byte_array(ja_public_key).unwrap();

                        let jv_private_key = env
                            .get_field(ik, "privateKey", format!("L{}EcPrivateKey;", JAVA_PACKAGE))
                            .unwrap();
                        let jo_private_key = jv_private_key.l().unwrap();
                        if jo_public_key.is_null() {
                            return None;
                        }
                        let ja_private_key =
                            env.get_field(jo_private_key, "privateKey", "[B")
                                .unwrap()
                                .l()
                                .unwrap()
                                .into_inner() as jbyteArray;
                        let private_key = env.convert_byte_array(ja_private_key).unwrap();

                        let identity_key_pair = rust::keys::IdentityKeyPair::pair(
                            private_key.as_slice().into(),
                            public_key.as_slice().into(),
                        );
                        return Some(identity_key_pair);
                    }
                    Err(_e) => {
                        error!("call java getIdentityKeyPair fail");
                        return None;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return None;
            }
        }
    }

    fn get_local_registration_id(&self) -> u32 {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return 0;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return 0;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let call_result = env.call_method(obj, "getLocalRegistrationId", "()I", &[]);
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java getLocalRegistrationId exception");
                    return 0;
                }
                debug!("call java getLocalRegistrationId: {:?}", call_result);
                match call_result {
                    Ok(jvalue) => {
                        return jvalue.i().unwrap() as u32;
                    }
                    Err(_e) => {
                        error!("call java getLocalRegistrationId fail");
                        return 0;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return 0;
            }
        }
    }

    fn save_identity(&mut self, address: Address, identity: curve_crypto::PublicKey) -> bool {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return false;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return false;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
                let jo_device_name =
                    JValue::Object(env.new_string(address.device_name.clone()).unwrap().into());
                let jo_public = JValue::Object(
                    env.byte_array_from_slice(identity.as_bytes())
                        .unwrap()
                        .into(),
                );
                let args: [JValue; 4] = [
                    jo_name,
                    JValue::Int(address.device_id as i32),
                    jo_device_name,
                    jo_public,
                ];
                let call_result = env.call_method(
                    obj,
                    "saveIdentity",
                    "(Ljava/lang/String;ILjava/lang/String;[B)Z",
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java saveIdentity exception");
                    return false;
                }
                debug!("call java saveIdentity: {:?}", call_result);
                match call_result {
                    Ok(jvalue) => {
                        return jvalue.z().unwrap();
                    }
                    Err(_e) => {
                        error!("call java saveIdentity fail");
                        return false;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return false;
            }
        }
    }

    fn get_identity_key(&self, address: &'_ Address) -> Option<curve_crypto::PublicKey> {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return None;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return None;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
                let jo_device_name =
                    JValue::Object(env.new_string(address.device_name.clone()).unwrap().into());
                let args: [JValue; 3] = [
                    jo_name,
                    JValue::Int(address.device_id as i32),
                    jo_device_name,
                ];
                let call_result = env.call_method(
                    obj,
                    "getIdentity",
                    "(Ljava/lang/String;ILjava/lang/String;)[B",
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java getIdentity exception");
                    return None;
                }
                match call_result {
                    Ok(jvalue) => {
                        let result = jvalue.l();
                        match result {
                            Ok(jo) => {
                                if jo.is_null() {
                                    trace!("call java getIdentity is null");
                                    return None;
                                }
                                let vec = env
                                    .convert_byte_array(jo.into_inner() as jbyteArray)
                                    .unwrap();
                                return Some(curve_crypto::PublicKey::from(vec.as_slice()));
                            }
                            Err(_e) => {
                                return None;
                            }
                        }
                    }
                    Err(_e) => {
                        error!("call java getIdentity fail");
                        return None;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return None;
            }
        }
    }

    fn is_trusted_identity(
        &self,
        address: &'_ Address,
        identity_key: &'_ curve_crypto::PublicKey,
        _direction: Direction,
    ) -> bool {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return false;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return false;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let jo_name = JValue::Object(env.new_string(address.name.clone()).unwrap().into());
                let jo_device_name =
                    JValue::Object(env.new_string(address.device_name.clone()).unwrap().into());
                let jo_public = JValue::Object(
                    env.byte_array_from_slice(identity_key.as_bytes())
                        .unwrap()
                        .into(),
                );
                let args: [JValue; 4] = [
                    jo_name,
                    JValue::Int(address.device_id as i32),
                    jo_device_name,
                    jo_public,
                ];
                let call_result = env.call_method(
                    obj,
                    "isTrustedIdentity",
                    "(Ljava/lang/String;ILjava/lang/String;[B)Z",
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java isTrustedIdentity exception");
                    return false;
                }
                debug!(
                    "call java isTrustedIdentity: {:?}, identity_public:{:02x?}",
                    call_result, identity_key
                );
                match call_result {
                    Ok(jvalue) => {
                        return jvalue.z().unwrap();
                    }
                    Err(_e) => {
                        error!("call java isTrustedIdentity fail");
                        return false;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return false;
            }
        }
    }
}

struct JavaSignedKeyStore;
impl rust::store::SignedPreKeyStore for JavaSignedKeyStore {
    fn load_signed_pre_key(&self, id: u32) -> Option<SignedPreKey> {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return None;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return None;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let args: [JValue; 1] = [JValue::Int(id as i32)];
                let call_result = env.call_method(
                    obj,
                    "loadSignedPreKey",
                    format!("(I)L{}SignedPreKey;", JAVA_PACKAGE),
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java loadSignedPreKey exception");
                    return None;
                }
                debug!("call java loadSignedPreKey: {:?}, id:{}", call_result, id);
                match call_result {
                    Ok(jvalue) => {
                        let result = jvalue.l();
                        match result {
                            Ok(jo) => {
                                if jo.is_null() {
                                    trace!("call java loadSignedPreKey result is null");
                                    return None;
                                }
                                let jv_public_key = env
                                    .get_field(
                                        jo,
                                        "publicKey",
                                        format!("L{}EcPublicKey;", JAVA_PACKAGE),
                                    )
                                    .unwrap();
                                let jo_public_key = jv_public_key.l().unwrap();
                                let ja_public_key = env
                                    .get_field(jo_public_key, "publicKey", "[B")
                                    .unwrap()
                                    .l()
                                    .unwrap()
                                    .into_inner()
                                    as jbyteArray;
                                let public_key = env.convert_byte_array(ja_public_key).unwrap();

                                let jv_private_key = env
                                    .get_field(
                                        jo,
                                        "privateKey",
                                        format!("L{}EcPrivateKey;", JAVA_PACKAGE),
                                    )
                                    .unwrap();
                                let jo_private_key = jv_private_key.l().unwrap();
                                let ja_private_key = env
                                    .get_field(jo_private_key, "privateKey", "[B")
                                    .unwrap()
                                    .l()
                                    .unwrap()
                                    .into_inner()
                                    as jbyteArray;
                                let private_key = env.convert_byte_array(ja_private_key).unwrap();

                                let ja_signature = env
                                    .get_field(jo, "signature", "[B")
                                    .unwrap()
                                    .l()
                                    .unwrap()
                                    .into_inner()
                                    as jbyteArray;
                                let signature = curve_crypto::Signature::from_bytes(
                                    env.convert_byte_array(ja_signature).unwrap().as_slice(),
                                )
                                .unwrap();

                                let timestamp =
                                    env.get_field(jo, "timestamp", "J").unwrap().j().unwrap()
                                        as u64;

                                let sk = SignedPreKey {
                                    id,
                                    keypair: curve_crypto::KeyPair::pair(
                                        private_key.as_slice().into(),
                                        public_key.as_slice().into(),
                                    ),
                                    signature,
                                    timestamp,
                                };
                                return Some(sk);
                            }
                            Err(_e) => {
                                return None;
                            }
                        }
                    }
                    Err(_e) => {
                        error!("call java loadSignedPreKey fail");
                        return None;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return None;
            }
        }
    }

    fn store_signed_pre_key(&mut self, _id: u32, _signed_pre_key: SignedPreKey) {
        unimplemented!()
    }

    fn contains_signed_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    fn remove_signed_pre_key(&mut self, _id: u32) {
        unimplemented!()
    }
}

pub struct JavaPreKeyStore;
impl rust::store::PreKeyStore for JavaPreKeyStore {
    fn load_pre_key(&self, id: u32) -> Option<PreKey> {
        let ptr_jvm = JVM_GLOBAL.lock().unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return None;
        }

        let ptr_fn = JNI_CALLBACK.lock().unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return None;
        }

        let jvm: &JavaVM = (*ptr_jvm).as_ref().unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let args: [JValue; 1] = [JValue::Int(id as i32)];
                let call_result = env.call_method(
                    obj,
                    "loadPreKey",
                    format!("(I)L{}PreKeyRecord;", JAVA_PACKAGE),
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java loadPreKey exception");
                    return None;
                }
                match call_result {
                    Ok(jvalue) => {
                        let result = jvalue.l();
                        match result {
                            Ok(jo) => {
                                if jo.is_null() {
                                    trace!("call java loadPreKey result is null");
                                    return None;
                                }
                                let jv_public_key = env
                                    .get_field(
                                        jo,
                                        "publicKey",
                                        format!("L{}EcPublicKey;", JAVA_PACKAGE),
                                    )
                                    .unwrap();
                                let jo_public_key = jv_public_key.l().unwrap();
                                let ja_public_key = env
                                    .get_field(jo_public_key, "publicKey", "[B")
                                    .unwrap()
                                    .l()
                                    .unwrap()
                                    .into_inner()
                                    as jbyteArray;
                                let public_key = env.convert_byte_array(ja_public_key).unwrap();

                                let jv_private_key = env
                                    .get_field(
                                        jo,
                                        "privateKey",
                                        format!("L{}EcPrivateKey;", JAVA_PACKAGE),
                                    )
                                    .unwrap();
                                let jo_private_key = jv_private_key.l().unwrap();
                                let ja_private_key = env
                                    .get_field(jo_private_key, "privateKey", "[B")
                                    .unwrap()
                                    .l()
                                    .unwrap()
                                    .into_inner()
                                    as jbyteArray;
                                let private_key = env.convert_byte_array(ja_private_key).unwrap();

                                let sk = PreKey {
                                    id,
                                    keypair: curve_crypto::KeyPair::pair(
                                        private_key.as_slice().into(),
                                        public_key.as_slice().into(),
                                    ),
                                };
                                return Some(sk);
                            }
                            Err(_e) => {
                                return None;
                            }
                        }
                    }
                    Err(_e) => {
                        error!("call java loadPreKey fail");
                        return None;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return None;
            }
        }
    }

    fn store_pre_key(&mut self, _id: u32, _pre_key: PreKey) {
        unimplemented!()
    }

    fn contains_pre_key(&self, _id: u32) -> bool {
        unimplemented!()
    }

    fn remove_pre_key(&mut self, id: u32) {
        call_jvm(&JNI_CALLBACK, move |obj: JObject, env: &JNIEnv| {
            let args: [JValue; 1] = [JValue::Int(id as i32)];
            let result = env.call_method(obj, "removePreKey", "(I)Z", &args);
            trace!("call java removePreKey result: {:?}", result);

            if result.is_err() {
                trace!("removePreKey fail!");
            }
        });
    }
}

pub struct JavaSenderKeyStore;

impl rust::store::SenderKeyStore for JavaSenderKeyStore {
    fn store_sender_key(&mut self, sender: SenderKeyName, record: SenderKeyRecord) {
        let vec = record.serialize();
        //let raw = Box::into_raw(Box::new(address.clone())) as jlong;
        call_jvm(&JNI_CALLBACK, move |obj: JObject, env: &JNIEnv| {
            let jo_name =
                JValue::Object(env.new_string(sender.sender.name.clone()).unwrap().into());
            let jo_device_name = JValue::Object(
                env.new_string(sender.sender.device_name.clone())
                    .unwrap()
                    .into(),
            );
            let jo_group = JValue::Object(env.new_string(sender.group_id.clone()).unwrap().into());
            let ja_session = env.byte_array_from_slice(vec.as_slice()).unwrap().into();
            let args: [JValue; 5] = [
                jo_name,
                jo_group,
                JValue::Int(sender.sender.device_id as i32),
                jo_device_name,
                JValue::Object(ja_session),
            ];
            let result = env.call_method(
                obj,
                "storeSenderKey",
                "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[B)V",
                &args,
            );
            debug!("call java storeSenderKey: {:?}", result);

            if result.is_err() {
                error!("store session fail!");
            }
        });
    }

    fn load_sender_key(&self, sender: &'_ SenderKeyName) -> Option<SenderKeyRecord> {
        let ptr_jvm = JVM_GLOBAL.lock();
        if ptr_jvm.is_err() {
            error!("jvm is error");
            return None;
        }
        let ptr_jvm = ptr_jvm.unwrap();
        if (*ptr_jvm).is_none() {
            error!("jvm is none");
            return None;
        }

        let ptr_fn = JNI_CALLBACK.lock();
        if ptr_fn.is_err() {
            error!("get callback is error");
            return None;
        }
        let ptr_fn = ptr_fn.unwrap();
        if (*ptr_fn).is_none() {
            error!("get callback is none");
            return None;
        }

        let jvm_opt = (&ptr_jvm).as_ref();
        if jvm_opt.is_none() {
            error!("get jvm is none");
            return None;
        }
        let jvm: &JavaVM = jvm_opt.unwrap();

        let env_result = jvm.attach_current_thread_permanently();
        match env_result {
            Ok(env) => {
                let jo_name =
                    JValue::Object(env.new_string(sender.sender.name.clone()).unwrap().into());
                let jo_device_name = JValue::Object(
                    env.new_string(sender.sender.device_name.clone())
                        .unwrap()
                        .into(),
                );
                let jo_group =
                    JValue::Object(env.new_string(sender.group_id.clone()).unwrap().into());
                let args: [JValue; 4] = [
                    jo_name,
                    jo_group,
                    JValue::Int(sender.sender.device_id as i32),
                    jo_device_name,
                ];
                let obj = (*ptr_fn).as_ref().unwrap().as_obj();
                let call_result = env.call_method(
                    obj,
                    "getSenderKey",
                    "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)[B",
                    &args,
                );
                if let Ok(true) = env.exception_check() {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                    // let _ = env.throw_new("java/lang/Exception", "JNI抛出的异常！");
                    trace!("call java getSenderKey exception");
                    return None;
                }
                debug!("call java getSenderKey: {:?}", call_result);
                match call_result {
                    Ok(jvalue) => {
                        debug!("call java getSenderKey 1");
                        let out = jvalue.l().unwrap().into_inner() as jbyteArray;
                        if out.is_null() {
                            debug!("call java getSenderKey 3");
                            return None;
                        }
                        debug!("call java getSenderKey 2");
                        let session = env.convert_byte_array(out);
                        debug!("call java getSenderKey. session:{:02x?}", session);
                        Some(
                            SenderKeyRecord::deserialize(session.unwrap().as_slice())
                                .expect("SessionRecord deserialize fail"),
                        )
                    }
                    Err(_e) => {
                        error!("call java getSenderKey fail");
                        return None;
                    }
                }
            }
            Err(_e) => {
                error!("get env fail");
                return None;
            }
        }
    }
}
