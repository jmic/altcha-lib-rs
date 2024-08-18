use chrono::{DateTime, Utc};
use base16ct;
use serde::{Deserialize, Serialize};
use algorithm::AltchaAlgorithm;
use error::Error;
use utils::ParamsMapType;

mod algorithm;
mod error;
mod utils;

pub const DEFAULT_MAX_NUMBER: u64 = 1000000;
pub const DEFAULT_SALT_LENGTH: usize = 12;
pub const DEFAULT_ALGORITHM: AltchaAlgorithm = AltchaAlgorithm::Sha256;

#[derive(Debug, Clone, Default)]
pub struct ChallengeOptions<'a> {
    algorithm: Option<AltchaAlgorithm>,
    max_number: Option<u64>,
    salt_length: Option<usize>,
    hmac_key: &'a str,
    salt: Option<String>,
    number: Option<u64>,
    expires: Option<DateTime<Utc>>,
    params: Option<ParamsMapType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Challenge {
    algorithm: AltchaAlgorithm,
    challenge: String,
    maxnumber: u64,
    salt: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Payload {
    algorithm: AltchaAlgorithm,
    challenge: String,
    number: u64,
    salt: String,
    signature: String,
}

pub fn create_challenge(options: ChallengeOptions) -> Result<Challenge, Error> {
    let algorithm = options.algorithm.unwrap_or(DEFAULT_ALGORITHM);
    let max_number = options.max_number.unwrap_or(DEFAULT_MAX_NUMBER);
    let salt_length = options.salt_length.unwrap_or(DEFAULT_SALT_LENGTH);

    let salt = options.salt.unwrap_or_else(|| base16ct::lower::encode_string(utils::random_bytes(salt_length).as_slice()));

    if options.number.is_some_and(|number| number > max_number) {
        return Err(Error::WrongChallengeInput(format!("number exides max_number {} > {}", options.number.unwrap(), max_number)));
    }
    let number = options.number.unwrap_or_else(|| utils::random_int(max_number));

    let (mut salt, mut salt_params) = utils::extract_salt_params(salt.as_str());

    if let Some(expire_value) = options.expires{
        salt_params.insert(String::from(EXPIRES_PRAM), expire_value.timestamp().to_string());
    }
    if let Some(params) = options.params {
        salt_params.extend(params);
    }

    if !salt_params.is_empty() {
        salt += format!("?{}", utils::generate_url_from_salt_params(&salt_params)).as_str();
    }

    let salt_with_number = salt.clone() + number.to_string().as_str();
    let challenge = utils::hash_function(&algorithm, salt_with_number.as_str());
    let signature = utils::hmac_function(&algorithm, &challenge, options.hmac_key);

    Ok(Challenge{ algorithm, challenge, maxnumber: max_number, salt, signature })
}
#[cfg(feature = "json")]
pub fn create_json_challenge(options: ChallengeOptions) -> Result<String, Error> {
    let challenge = create_challenge(options)?;
    Ok(serde_json::to_string(&challenge)?)
}
#[cfg(feature = "json")]
pub fn verify_json_solution(payload: &str, hmac_key: &str, check_expire: bool) -> Result<(), Error> {
    let payload_decoded: Payload = serde_json::from_str(payload)?;
    verify_solution(payload_decoded, hmac_key, check_expire)
}

pub fn verify_solution(payload: Payload, hmac_key: &str, check_expire: bool) -> Result<(), Error> {
    let (_, salt_params) = utils::extract_salt_params(&payload.salt);

    if check_expire {
        if let Some(expire_str) = salt_params.get(&String::from(EXPIRES_PRAM)) {
            let expire_timestamp: i64 = expire_str.parse()?;
            let Some(expire) = DateTime::from_timestamp(expire_timestamp, 0) else {
                return Err(Error::ParseExpire(format!("Failed to parse timestamp {}", expire_timestamp)))
            };
            let now_time: DateTime<Utc> = Utc::now();
            if expire < now_time{
                return Err(Error::VerificationFailedExpired(format!("expired {}", expire - now_time)))
            }
        }
    }

    let options = ChallengeOptions {
        algorithm: Some(payload.algorithm),
        max_number: None,
        salt_length: None,
        hmac_key,
        salt: Some(payload.salt.clone()),
        number: Some(payload.number),
        expires: None,
        params: None,
    };
    let expected_challenge = create_challenge(options)?;
    if expected_challenge.challenge != payload.challenge {
        return Err(Error::VerificationMismatchChallenge(format!("mismatch expected challenge {} != {}", expected_challenge.challenge, payload.challenge)))
    }
    if expected_challenge.signature != payload.signature {
        return Err(Error::VerificationMismatchSignature(format!("mismatch expected signature {} != {}", expected_challenge.signature, payload.signature)))
    }
    Ok(())
}

pub fn solve_challenge(challenge: &str, salt: &str, algorithm: Option<AltchaAlgorithm>, max_number: Option<u64>, start: u64) -> Result<u64, Error> {
    let selected_algorithm = algorithm.unwrap_or(DEFAULT_ALGORITHM);
    let selected_max_number = max_number.unwrap_or(DEFAULT_MAX_NUMBER);

    for n in start..selected_max_number + 1 {
        let current_try = String::from(salt) + n.to_string().as_str();
        let hash_hex_value = utils::hash_function(&selected_algorithm, current_try.as_str());
        if hash_hex_value.eq(challenge) {
            return Ok(n);
        }
    }
    Err(Error::SolveChallengeMaxNumberReached(format!("maximum iterations reached {}", selected_max_number)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "json")]
    fn test_verify_solution() {
        let data = r#"
        {
            "algorithm": "SHA-512",
            "challenge": "ca6dc405dbe2c4c35849eaf434cafa852eacd27e70494220ecef849bb4545b670ed3e6adecc27d95768c1d4985753307ed29ee0188800d7eb37ce76bbf0343cb",
            "number": 1000,
            "salt": "blablabla",
            "signature": "b2e4f529389c32c3960438ab12409f298014e580b0c75a5ed6664c7a19e5ff1607ee2690c25f7977bbde126d677f0e18cfbb8487a7f4f06ab199fd27bfd26af1"
        }"#.to_string();
        verify_json_solution(&data, &"blabla".to_string(), true).expect("should be ok");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_challenge() {
        let challenge = create_challenge(ChallengeOptions{algorithm: None, max_number: None, number: None, salt: None, hmac_key: "my_key", params: None, expires: Some(Utc::now()+chrono::TimeDelta::minutes(1)), salt_length: None}).expect("should be ok");
        let res = solve_challenge(&challenge.challenge, &challenge.salt, None, None, 0).expect("need to be solved");
        let payload = Payload {algorithm: challenge.algorithm, challenge: challenge.challenge, number: res, salt: challenge.salt, signature: challenge.signature };
        let string_payload = serde_json::to_string(&payload).unwrap();
        verify_json_solution(&string_payload, "my_key", true).expect("should be ok");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_create_json_challenge() {
        let challenge_json = create_json_challenge(ChallengeOptions{
            algorithm: Some(AltchaAlgorithm::Sha1),
            max_number: Some(100000),
            number: Some(22222),
            salt: Some(String::from("blabla")),
            hmac_key: "my_key",
            expires: Some(DateTime::from_timestamp(1715526540, 0).unwrap()),
            ..Default::default()
        }).expect("should be ok");
        assert_eq!(challenge_json, r#"{"algorithm":"SHA-1","challenge":"864412db92050e02c89e7e623c773491e8495990","maxnumber":100000,"salt":"blabla?expires=1715526540","signature":"2e66edb70874996e94430c62ac6e2815a092718d"}"#);
    }

    #[test]
    fn test_create_challenge_wrong_input() {
        let challenge = create_challenge(ChallengeOptions{
            max_number: Some(222),
            number: Some(100000),
            hmac_key: "my_key",
            ..Default::default()
        });
        assert!(challenge.is_err());
    }

}

const EXPIRES_PRAM: &str = "expires";