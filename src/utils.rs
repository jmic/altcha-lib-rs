use crate::algorithm::AltchaAlgorithm;
use hmac::digest::Digest;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
pub type ParamsMapType = HashMap<String, String>;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut values: Vec<u8> = vec![0; len];
    let mut rng = rand::thread_rng();
    rng.fill(values.as_mut_slice());
    values
}

pub fn random_int(max: u64) -> u64 {
    let mut rng = rand::thread_rng();
    let dist = rand::distributions::Uniform::new_inclusive(0, max);
    rng.sample(&dist)
}

pub fn hash_function(altcha_algorithm: &AltchaAlgorithm, data: &str) -> String {
    match altcha_algorithm {
        AltchaAlgorithm::Sha1 => {
            let hash = Sha1::digest(data);
            base16ct::lower::encode_string(&hash)
        }
        AltchaAlgorithm::Sha256 => {
            let hash = Sha256::digest(data);
            base16ct::lower::encode_string(&hash)
        }
        AltchaAlgorithm::Sha512 => {
            let hash = Sha512::digest(data);
            base16ct::lower::encode_string(&hash)
        }
    }
}

pub fn hmac_function(altcha_algorithm: &AltchaAlgorithm, data: &str, key: &str) -> String {
    match altcha_algorithm {
        AltchaAlgorithm::Sha1 => {
            let mut mac =
                HmacSha1::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            let res = mac.finalize();
            base16ct::lower::encode_string(&res.into_bytes())
        }
        AltchaAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            let res = mac.finalize();
            base16ct::lower::encode_string(&res.into_bytes())
        }
        AltchaAlgorithm::Sha512 => {
            let mut mac =
                HmacSha512::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            let res = mac.finalize();
            base16ct::lower::encode_string(&res.into_bytes())
        }
    }
}

pub fn extract_salt_params(salt: &str) -> (String, ParamsMapType) {
    let mut salt_params = ParamsMapType::new();
    if !salt.contains("?") {
        return (salt.to_string(), salt_params);
    }
    let (salt, salt_query) = salt.split_once("?").unwrap();
    for parts in salt_query.split("&") {
        let Some((key, value)) = parts.split_once("=") else {
            continue;
        };
        salt_params.insert(key.to_string(), value.to_string());
    }
    (salt.to_string(), salt_params)
}

pub fn generate_url_from_salt_params(params: &ParamsMapType) -> String {
    params
        .into_iter()
        .map(|(key, value)| key.to_owned() + "=" + value)
        .reduce(|acc, e| acc + "&" + e.as_str())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_salt_params() {
        let (salt, map) = extract_salt_params("mjsSEFiofesw432==?bla=test&jo=foo");
        let mut expectation = ParamsMapType::new();
        expectation.insert("bla".to_string(), "test".to_string());
        expectation.insert("jo".to_string(), "foo".to_string());
        assert_eq!(map, expectation);
        assert_eq!(salt, "mjsSEFiofesw432==");
    }

    #[test]
    fn test_generate_url_from_salt_params() {
        let expectation_a = "bla=test&jo=foo".to_string();
        let expectation_b = "jo=foo&bla=test".to_string();
        let mut input = ParamsMapType::new();
        input.insert("bla".to_string(), "test".to_string());
        input.insert("jo".to_string(), "foo".to_string());
        let res = generate_url_from_salt_params(&input);
        assert!(res == expectation_a || res == expectation_b);
    }
}
