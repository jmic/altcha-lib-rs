use crate::algorithm::AltchaAlgorithm;
use hmac::digest::{Digest, KeyInit};
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
    rng.sample(dist)
}

pub fn hash_function(altcha_algorithm: &AltchaAlgorithm, data: &str) -> String {
    match altcha_algorithm {
        AltchaAlgorithm::Sha1 => hash_str_to_hex::<Sha1>(data),
        AltchaAlgorithm::Sha256 => hash_str_to_hex::<Sha256>(data),
        AltchaAlgorithm::Sha512 => hash_str_to_hex::<Sha512>(data),
    }
}

fn hash_str_to_hex<Hash: Digest>(data: &str) -> String {
    let hash = Hash::digest(data);
    base16ct::lower::encode_string(&hash)
}

pub fn hmac_function(altcha_algorithm: &AltchaAlgorithm, data: &str, key: &str) -> String {
    match altcha_algorithm {
        AltchaAlgorithm::Sha1 => hmac_from_slice_to_hex_str::<HmacSha1>(data, key),
        AltchaAlgorithm::Sha256 => hmac_from_slice_to_hex_str::<HmacSha256>(data, key),
        AltchaAlgorithm::Sha512 => hmac_from_slice_to_hex_str::<HmacSha512>(data, key),
    }
}

fn hmac_from_slice_to_hex_str<HmacType: KeyInit + Mac>(data: &str, key: &str) -> String {
    let mut mac = <HmacType as hmac::Mac>::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let res = mac.finalize();
    base16ct::lower::encode_string(&res.into_bytes())
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
        .iter()
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
