use crate::errors::SigServerError;
use crate::util::base64_str_to_bytes;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature};
use zeroize::Zeroize;

/// Parse a base64 string as a secret key (byte representation of SecretKey) and then convert the
/// secret key to an ExpandedSecretKey. This is done since signing would require converting a SecretKey
/// to an ExpandedSecretKey. It might look wasteful to do 2 conversions, i.e. from bytes -> SecretKey
/// and then SecretKey -> ExpandedSecretKey but this is fine as its only done once. It has the benefit
/// of keeping the secret key string living outside this app (in secret data stores like Vault) small
/// as size of ExpandedSecretKey > size of SecretKey
pub fn secret_key_from_base64(b64_sk: &str) -> Result<ExpandedSecretKey, SigServerError> {
    let mut sk_bytes = base64_str_to_bytes(b64_sk)?;

    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| {
        // Zero the byte array even if could nto create the secret key
        sk_bytes.zeroize();
        SigServerError::InvalidSecretKey {
            key: b64_sk.to_string(),
        }
    })?;

    // Zero the byte array
    sk_bytes.zeroize();

    let exp_sk = ExpandedSecretKey::from(&sk);

    // sk will be cleared since SecretKey clears on drop
    Ok(exp_sk)
}

/// Parse a base64 string as a public key
pub fn public_key_from_base64(b64_pk: &str) -> Result<PublicKey, SigServerError> {
    PublicKey::from_bytes(&base64_str_to_bytes(b64_pk)?).map_err(|_| {
        SigServerError::InvalidPublicKey {
            key: b64_pk.to_string(),
        }
    })
}

/// Sign a byte slice using the ExpandedSecretKey.
pub fn sign(message: &[u8], secret_key: &ExpandedSecretKey, public_key: &PublicKey) -> Signature {
    secret_key.sign(message, public_key)
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;

    #[test]
    fn test_base64_secret_key_to_bytes() {
        // short key
        assert!(secret_key_from_base64("YWJj").is_err());

        // long key
        assert!(secret_key_from_base64("YWJjZGVmZ2hpb2thYmNkZWZnaGlva2FiY2RlZmdoaW9rYWJjZGVmZ2hpb2thYmNkZWZnaGlva2FiY2RlZmdoaW9rYWJjZGVmZ2hpb2thYmNkZWZnaGlva2FiY2RlZmdoaW9r").is_err());

        // invalid base64
        assert!(secret_key_from_base64(
            "f55af4d6e48e35e9fab21a9d78b27dc8dfbe7b3f3cf0a9f71b7e4fab19bf55"
        )
        .is_err());

        // valid key
        assert!(secret_key_from_base64("pIwwiWYMzK1vd/aPWQWYW254d6RaqVY1M3ocUiFxKY8=").is_ok());
    }

    #[test]
    fn test_base64_public_key_to_bytes() {
        // short key
        assert!(public_key_from_base64("MTIzNDU2Nzg5MA==").is_err());

        // long key
        assert!(public_key_from_base64(
            "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
        )
        .is_err());

        // invalid base64
        assert!(public_key_from_base64(
            "f55af4d6e48e35e9fab21a9d78b27dc8dfbe7b3f3cf0a9f71b7e4fab19bf55"
        )
        .is_err());

        // secret key
        assert!(public_key_from_base64("pIwwiWYMzK1vd/aPWQWYW254d6RaqVY1M3ocUiFxKY8=").is_err());

        // valid key
        assert!(public_key_from_base64("TaxyY3G2A3pw7t2YSNtp88rRMV2G2GAasfldraakCZ8=").is_ok());
    }

    #[test]
    fn test_sign() {
        // Following is a valid ed25519 keypair
        let sk_1_b64 = "pIwwiWYMzK1vd/aPWQWYW254d6RaqVY1M3ocUiFxKY8=";
        let pk_1_b64 = "TaxyY3G2A3pw7t2YSNtp88rRMV2G2GAasfldraakCZ8=";

        let sk_1 = secret_key_from_base64(sk_1_b64).unwrap();
        let pk_1 = public_key_from_base64(pk_1_b64).unwrap();

        let msg_1 = "test msg".as_bytes();
        let sig_1 = sign(msg_1, &sk_1, &pk_1);
        assert!(pk_1.verify(msg_1, &sig_1).is_ok());

        let msg_2 = "another test msg".as_bytes();
        let sig_2 = sign(msg_2, &sk_1, &pk_1);
        assert!(pk_1.verify(msg_2, &sig_2).is_ok());

        // Invalid message, signature tuple
        assert!(pk_1.verify(msg_1, &sig_2).is_err());
        assert!(pk_1.verify(msg_2, &sig_1).is_err());

        // Following is a valid ed25519 keypair
        let sk_2_b64 = "DGSLrt8h/EGNgeDuTD6N6e1TWmgtPmfE7ZreJxMIxZg=";
        let pk_2_b64 = "F/Ot9XtGzDjITzKMW6NhwCpK6wsAJMl5oz1OD0gMFxo=";
        let sk_2 = secret_key_from_base64(sk_2_b64).unwrap();
        let pk_2 = public_key_from_base64(pk_2_b64).unwrap();

        let sig_3 = sign(msg_1, &sk_2, &pk_2);
        assert!(pk_2.verify(msg_1, &sig_3).is_ok());

        // Valid message, signature tuple but invalid public key
        assert!(pk_1.verify(msg_1, &sig_3).is_err());
    }
}
