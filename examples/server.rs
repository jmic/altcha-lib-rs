use actix_web::{body, get, http, post, web, App, HttpResponse, HttpServer, ResponseError};
use altcha_lib_rs::{error, Challenge, ChallengeOptions};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::{Display, Formatter};

const SECRET_KEY: &str = "super-secret";

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all(serialize = "camelCase"))]
struct ErrorResponse {
    error: String,
    #[serde(serialize_with = "status_code_into_u16")]
    status_code: http::StatusCode,
}

fn status_code_into_u16<S>(status_code: &http::StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u16(status_code.as_u16())
}

#[derive(Debug, Clone, Deserialize)]
struct SubmitRequest {
    altcha: String,
}

#[derive(Debug, Clone, Serialize)]
struct VerifiedResponse {
    verified: bool,
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl ResponseError for ErrorResponse {
    fn status_code(&self) -> http::StatusCode {
        self.status_code
    }
    fn error_response(&self) -> HttpResponse<body::BoxBody> {
        HttpResponse::build(self.status_code()).json(&self)
    }
}

impl From<error::Error> for ErrorResponse {
    fn from(other: error::Error) -> Self {
        match other {
            error::Error::WrongChallengeInput(e) => Self {
                error: format!("Failed to create challenge: {:?}", e),
                status_code: http::StatusCode::INTERNAL_SERVER_ERROR,
            },
            error::Error::VerificationMismatchSignature(e) => Self {
                error: format!("Verification mismatch signature {:?}", e),
                status_code: http::StatusCode::BAD_REQUEST,
            },
            error::Error::VerificationMismatchChallenge(e) => Self {
                error: format!("Verification mismatch challenge {:?}", e),
                status_code: http::StatusCode::BAD_REQUEST,
            },
            error::Error::VerificationFailedExpired(e) => Self {
                error: format!("Verification expired {:?}", e),
                status_code: http::StatusCode::BAD_REQUEST,
            },
            _ => Self {
                error: format!("{:?}", other),
                status_code: http::StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }
}

impl From<base64::DecodeError> for ErrorResponse {
    fn from(other: base64::DecodeError) -> Self {
        Self {
            error: format!("base64 decode error {:?}", other),
            status_code: http::StatusCode::BAD_REQUEST,
        }
    }
}

impl From<std::str::Utf8Error> for ErrorResponse {
    fn from(other: std::str::Utf8Error) -> Self {
        Self {
            error: format!("utf8 conversion error {:?}", other),
            status_code: http::StatusCode::BAD_REQUEST,
        }
    }
}

#[get("/altcha")]
async fn get_challenge() -> actix_web::Result<web::Json<Challenge>, ErrorResponse> {
    let res = altcha_lib_rs::create_challenge(ChallengeOptions {
        hmac_key: SECRET_KEY,
        expires: Some(Utc::now() + chrono::TimeDelta::minutes(5)),
        number: Some(22222),
        max_number: Some(100),
        ..Default::default()
    })?;
    Ok(web::Json(res))
}

#[post("/submit")]
async fn verify(
    req: web::Form<SubmitRequest>,
) -> actix_web::Result<web::Json<VerifiedResponse>, ErrorResponse> {
    let decoded_payload = BASE64_STANDARD.decode(&req.altcha)?;
    let string_payload = std::str::from_utf8(decoded_payload.as_slice())?;
    altcha_lib_rs::verify_json_solution(string_payload, SECRET_KEY, true)?;
    Ok(web::Json(VerifiedResponse { verified: true }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(get_challenge).service(verify))
        .bind(("127.0.0.1", 3000))?
        .run()
        .await
}
