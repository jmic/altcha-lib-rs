use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;

/// Algorithm options for the challenge
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum AltchaAlgorithm {
    #[serde(rename = "SHA-1")]
    Sha1,
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-512")]
    Sha512,
}

impl FromStr for AltchaAlgorithm {
    type Err = ();
    fn from_str(input: &str) -> Result<AltchaAlgorithm, Self::Err> {
        match input {
            "SHA-1" => Ok(AltchaAlgorithm::Sha1),
            "SHA-256" => Ok(AltchaAlgorithm::Sha256),
            "SHA-512" => Ok(AltchaAlgorithm::Sha512),
            _ => Err(()),
        }
    }
}

impl Display for AltchaAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            AltchaAlgorithm::Sha1 => "SHA-1",
            AltchaAlgorithm::Sha256 => "SHA-256",
            AltchaAlgorithm::Sha512 => "SHA-512",
        };
        write!(f, "{}", str)
    }
}
