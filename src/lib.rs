//! Community implementation of the Altcha library in Rust for your own server applications to create and validate challenges and responses.
//!
//! For more details about Altcha see <https://altcha.org/docs>

// Copyright 2024 jmic
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::{DateTime, Utc};
use base16ct;
use serde::{Deserialize, Serialize};
use algorithm::AltchaAlgorithm;
use error::Error;
use utils::ParamsMapType;

/// Algorithm options for the challenge
pub mod algorithm;
/// Errors
pub mod error;
mod utils;

pub const DEFAULT_MAX_NUMBER: u64 = 1000000;
pub const DEFAULT_SALT_LENGTH: usize = 12;
pub const DEFAULT_ALGORITHM: AltchaAlgorithm = AltchaAlgorithm::Sha256;

/// ChallengeOptions defines the options for creating a challenge
#[derive(Debug, Clone, Default)]
pub struct ChallengeOptions<'a> {
    pub algorithm: Option<AltchaAlgorithm>,
    pub max_number: Option<u64>,
    pub salt_length: Option<usize>,
    pub hmac_key: &'a str,
    pub salt: Option<String>,
    pub number: Option<u64>,
    pub expires: Option<DateTime<Utc>>,
    pub params: Option<ParamsMapType>,
}

/// Challenge defines the challenge send to the client
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Challenge {
    pub algorithm: AltchaAlgorithm,
    pub challenge: String,
    pub maxnumber: u64,
    pub salt: String,
    pub signature: String,
}

/// Payload defines the response from the client
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Payload {
    pub algorithm: AltchaAlgorithm,
    pub challenge: String,
    pub number: u64,
    pub salt: String,
    pub signature: String,
    pub took: Option<u32>,
}

/// Creates a challenge for the client to solve.
///
/// # Arguments
///
/// * `options`: ChallengeOptions defines the options for creating a challenge
///
/// returns: Result<Challenge, Error> The new challenge or error.
///
/// # Examples
///
/// ```
/// use std::default;
/// use chrono::Utc;
/// use altcha_lib_rs::{create_challenge, ChallengeOptions};
/// let challenge = create_challenge(
///     ChallengeOptions{
///         hmac_key: "super-secret",
///         expires: Some(Utc::now()+chrono::TimeDelta::minutes(1)),
///         ..Default::default()
///  });
/// ```
pub fn create_challenge(options: ChallengeOptions) -> Result<Challenge, Error> {
    let algorithm = options.algorithm.unwrap_or(DEFAULT_ALGORITHM);
    let max_number = options.max_number.unwrap_or(DEFAULT_MAX_NUMBER);
    let salt_length = options.salt_length.unwrap_or(DEFAULT_SALT_LENGTH);

    let salt = options.salt.unwrap_or_else(|| base16ct::lower::encode_string(utils::random_bytes(salt_length).as_slice()));

    if options.number.is_some_and(|number| number > max_number) {
        return Err(Error::WrongChallengeInput(format!("number exceeds max_number {} > {}", options.number.unwrap(), max_number)));
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
/// Creates a challenge for the client to solve as a string containing a json.
/// `features = ["json"]` must be enabled.
///
/// # Arguments
///
/// * `options`: ChallengeOptions defines the options for creating a challenge
///
/// returns: Result<String, Error> The new challenge formated as JSON string or error.
///
/// # Examples
///
/// ```
/// use std::default;
/// use chrono::Utc;
/// use altcha_lib_rs::{create_challenge, create_json_challenge, ChallengeOptions};
/// let challenge = create_json_challenge(
///     ChallengeOptions{
///         hmac_key: "super-secret",
///         expires: Some(Utc::now()+chrono::TimeDelta::minutes(1)),
///         ..Default::default()
///  });
/// ```
#[cfg(feature = "json")]
pub fn create_json_challenge(options: ChallengeOptions) -> Result<String, Error> {
    let challenge = create_challenge(options)?;
    Ok(serde_json::to_string(&challenge)?)
}
/// Verifies the json formated solution provided by the client.
/// `features = ["json"]` must be enabled.
///
/// # Arguments
///
/// * `payload`: The json formated payload to verify.
/// * `hmac_key`: The HMAC key used for verification.
/// * `check_expire`: Whether to check if the challenge has expired.
///
/// returns: Result<(), Error> Whether the solution is valid.
///
/// # Examples
///
/// ```
/// use altcha_lib_rs::verify_json_solution;
/// let payload_str = r#"{
///     "algorithm":"SHA-256","challenge":"aa9c8ec8057413dd8220e21e15ab54b095fb3c840601d44c39bece8d9df34529"
///     ,"number":971813,"salt":"3065d108b2314f5ecc7e1207",
///     "signature":"d6c436288f1979f298f6532cea31db9e84e6338f4f58a9e00cb4105abbd11397","took":9417
/// }"#.to_string();
/// let res =  verify_json_solution(&payload_str, &"super-secret".to_string(), true);
/// ```
#[cfg(feature = "json")]
pub fn verify_json_solution(payload: &str, hmac_key: &str, check_expire: bool) -> Result<(), Error> {
    let payload_decoded: Payload = serde_json::from_str(payload)?;
    verify_solution(&payload_decoded, hmac_key, check_expire)
}

/// Verifies the solution provided by the client.
///
/// # Arguments
///
/// * `payload`: The payload to verify.
/// * `hmac_key`: The HMAC key used for verification.
/// * `check_expire`: Whether to check if the challenge has expired.
///
/// returns: Result<(), Error> Whether the solution is valid.
pub fn verify_solution(payload: &Payload, hmac_key: &str, check_expire: bool) -> Result<(), Error> {
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
        algorithm: Some(payload.algorithm.clone()),
        max_number: None,
        salt_length: None,
        hmac_key,
        salt: Some(payload.salt.clone()),
        number: Some(payload.number.clone()),
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

/// Solves a challenge by brute force.
/// Used for testing.
///
/// # Arguments
///
/// * `challenge`: The challenge to solve.
/// * `salt`: The salt used in the challenge.
/// * `algorithm`: The hash algorithm used. Optional.
/// * `max_number`: The maximum number to try. Optional.
/// * `start`: The starting number.
///
/// returns: Result<u64, Error> The solution or error.
///
/// # Examples
///
/// ```
///  use chrono::Utc;
///  use altcha_lib_rs::{create_challenge, solve_challenge, ChallengeOptions};
///  let challenge = create_challenge(
///     ChallengeOptions{
///         hmac_key: "super-secret",
///         expires: Some(Utc::now()+chrono::TimeDelta::minutes(1)),
///         ..Default::default()
///  })?;
///  let res = solve_challenge(&challenge.challenge, &challenge.salt,
///     Some(challenge.algorithm), Some(challenge.maxnumber), 0);
/// ```
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
        {"algorithm":"SHA-256","challenge":"aa9c8ec8057413dd8220e21e15ab54b095fb3c840601d44c39bece8d9df34529","number":971813,"salt":"3065d108b2314f5ecc7e1207","signature":"d6c436288f1979f298f6532cea31db9e84e6338f4f58a9e00cb4105abbd11397","took":9417}"#.to_string();
        verify_json_solution(&data, &"super-secret".to_string(), true).expect("should be ok");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_challenge() {
        let challenge = create_challenge(ChallengeOptions{algorithm: None, max_number: None, number: None, salt: None, hmac_key: "super-secret", params: None, expires: Some(Utc::now()+chrono::TimeDelta::minutes(1)), salt_length: None}).expect("should be ok");
        let res = solve_challenge(&challenge.challenge, &challenge.salt, None, None, 0).expect("need to be solved");
        let payload = Payload {algorithm: challenge.algorithm, challenge: challenge.challenge, number: res, salt: challenge.salt, signature: challenge.signature, took: None };
        let string_payload = serde_json::to_string(&payload).unwrap();
        verify_json_solution(&string_payload, "super-secret", true).expect("should be ok");
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