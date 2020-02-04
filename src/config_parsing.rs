use crate::crypto::{public_key_from_base64, secret_key_from_base64};
use crate::errors::SigServerError;
use config::{Config, File};
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
use zeroize::Zeroize;

/// Return the port number, public key and private key as ExpandedSecretKey.
/// Keeping port as string since no operation needs to be done on it
pub fn load_from_config_file(
    config_path: &str,
) -> Result<(String, String, PublicKey, ExpandedSecretKey), SigServerError> {
    let mut cfg = Config::new();
    cfg.merge(File::with_name(config_path))
        .map_err(|_| SigServerError::MissingConfigFile {
            file: config_path.to_string(),
        })?;

    // TODO: More elaborate checks whether port is not used by other services like SSH, SMTP, etc
    let port: u16 = cfg
        .get("deployment.port")
        .map_err(|_| SigServerError::MissingPortInConfig)?;

    // Take ownership secret key memory
    let mut sk_b64 = cfg
        .get_str("private_keys.private_key")
        .map_err(|_| SigServerError::MissingPrivateKeyInConfig)?;
    // Check that secret key can be created and clear the secret key string
    let sk = secret_key_from_base64(&sk_b64).map_err(|e| {
        // Zero the base64 string even if could not create the secret key
        sk_b64.zeroize();
        e
    })?;

    // Zero the base64 string
    sk_b64.zeroize();

    let pk_b64 = cfg
        .get_str("public_keys.public_key")
        .map_err(|_| SigServerError::MissingPublicKeyInConfig)?;

    // Check that public key can be created
    let pk = public_key_from_base64(&pk_b64)?;

    Ok((port.to_string(), pk_b64, pk, sk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_file() {
        // The test runner (CI/developer) should ensure the config file with appropriate entries exists
        // before running the test
        let config_file_path = "./Config.toml";
        let (_, _, _, _): (String, String, PublicKey, ExpandedSecretKey) =
            load_from_config_file(config_file_path).unwrap();
    }
}
