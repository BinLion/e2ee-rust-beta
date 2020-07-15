use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum KeysError {
    #[error("Can not find edwards point")]
    NoEdwards,

    #[error("signature verify error")]
    SignatureError,

    #[error("{0:?} bytes length error, expected {1}, found {2}")]
    BytesLengthError(String, usize, usize),
}
