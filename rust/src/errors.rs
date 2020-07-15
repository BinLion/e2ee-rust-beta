use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum MyError {
    #[error("Can not find edwards point")]
    NoEdwards,

    #[error("signature verify error")]
    SignatureError,

    #[error("{0:?} bytes length error, expected {1}, found {2}")]
    BytesLengthError(String, usize, usize),

    #[error("protocalbuf decode error")]
    PbDecodeError {
        code: isize,
        name: String,
        msg: String,
    },

    #[error("Session error")]
    SessionError {
        code: isize,
        name: String,
        msg: String,
    },
}
