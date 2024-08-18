#[derive(Debug)]
pub enum Error {
    ParseJson(serde_json::Error),
    ParseInteger(std::num::ParseIntError),
    ParseExpire(String),
    VerificationFailedExpired(String),
    VerificationMismatchChallenge(String),
    VerificationMismatchSignature(String),
    SolveChallengeMaxNumberReached(String),
    WrongChallengeInput(String),
    General(String)
}

impl From<serde_json::Error> for Error {
    fn from(other: serde_json::Error) -> Self {
        Self::ParseJson(other)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(other: std::num::ParseIntError) -> Self {
        Self::ParseInteger(other)
    }
}