use crate::errors::SigServerError;
use base64;
use std::error::Error;
use rayon::prelude::*;

/// Convert given base64 string to bytes.
pub fn base64_str_to_bytes(b64_str: &str) -> Result<Vec<u8>, SigServerError> {
    base64::decode(b64_str).map_err(|e| SigServerError::InvalidBase64 {
        string: b64_str.to_string(),
        error: e.description().to_string(),
    })
}

/// Bytes to base64 string
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

/// Serialize txns as base64 strings, in parallel.
/// Test shows that this runs slower compared to sequential serialization.
pub fn serialize_txns_in_parallel(txns: &[Vec<u8>]) -> Vec<String> {
    txns
        .par_iter()
        .map(|txn| bytes_to_base64(txn))
        .collect::<Vec<String>>()
}

/// Serialize txns as base64 strings
pub fn serialize_txns(txns: &[Vec<u8>]) -> Vec<String> {
    txns
        .iter()
        .map(|txn| bytes_to_base64(txn))
        .collect::<Vec<String>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use std::time::Instant;

    #[test]
    fn test_parse_base64() {
        // non base64 char
        assert!(base64_str_to_bytes("o").is_err());
        assert!(base64_str_to_bytes("ao").is_err());

        // bad length
        assert!(base64_str_to_bytes("a").is_err());
        // bad byte
        assert!(base64_str_to_bytes("a=").is_err());

        assert_eq!(base64_str_to_bytes("abcd").unwrap(), vec![105, 183, 29]);
        assert_eq!(base64_str_to_bytes("GA").unwrap(), vec![24]);
    }

    #[test]
    fn test_to_base64() {
        assert_eq!(bytes_to_base64(&vec![105, 183, 29]), String::from("abcd"));
    }

    #[test]
    fn test_compare_txn_serialization_time() {
        // Compare transaction serialization in parallel vs sequential
        // XXX: The test shows that its better to serialize sequentially when run in release mode (`cargo test --release -- --nocapture test_compare_txn_serialization_time`)
        // but better to do parallel when run in debug mode. Find out why?
        let count = 100;
        let mut txns = vec![];
        let txn_size = 200;
        for _ in 0..count {
            let txn_bytes: Vec<u8> = (0..txn_size).map(|_| { rand::random::<u8>() }).collect();
            txns.push(txn_bytes);
        }

        let start = Instant::now();
        let s2 = serialize_txns_in_parallel(&txns);
        println!(
            "Serialization time for {} txns in parallel takes {:?}",
            count,
            start.elapsed()
        );

        let start = Instant::now();
        let s1 = serialize_txns(&txns);
        println!(
            "Serialization time for {} txns sequentially takes {:?}",
            count,
            start.elapsed()
        );

        assert_eq!(s1, s2);
    }
}
