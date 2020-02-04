extern crate failure;

use failure::Fail;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum SigServerError {
    #[fail(
        display = "Failed to parse {:?} as base64 with error: {:?}",
        string, error
    )]
    InvalidBase64 { string: String, error: String },
    #[fail(display = "Secret key invalid: {:?}", key)]
    InvalidSecretKey { key: String },
    #[fail(display = "Public key invalid: {:?}", key)]
    InvalidPublicKey { key: String },
    #[fail(display = "Could not find config file: {:?}", file)]
    MissingConfigFile { file: String },
    #[fail(display = "Either port number is missing in config file or is a invalid")]
    MissingPortInConfig,
    #[fail(display = "Could not find private key in config file")]
    MissingPrivateKeyInConfig,
    #[fail(display = "Could not find public key in config file")]
    MissingPublicKeyInConfig,
}
