# Community ALTCHA Rust Library &emsp; [![Build & test](https://github.com/jmic/altcha-lib-rs/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/jmic/altcha-lib-rs/actions/workflows/build-and-test.yml)

**Community implementation of the ALTCHA library in Rust for your
own server applications to create and validate challenges and responses.**

For more information about ALTCHA <https://altcha.org/docs>

---

## Features
- Compatible with the ALTCHA client-side widget
- Generates and validates self-hosted challenges
- Expiring challenges option

**Not part of this library:** 
- Methods to call ALTCHA's spam filter API
- machine-to-machine ALTCHA
- Store previously verified challenges to prevent replay attack prevention   

## Setup

```toml
[dependencies]
altcha-lib-rs = { version = "0", features = ["json"] }
```

## Example
    
```rust
use altcha_lib_rs::{create_challenge, verify_json_solution, 
                    Payload, Challenge, ChallengeOptions};

fn main() {
    // create a challenge
    let challenge = create_challenge(ChallengeOptions {
        hmac_key: "super-secret",
        expires: Some(Utc::now() + chrono::TimeDelta::minutes(1)),
        ..Default::default()
    }).expect("should be ok");

    // transmit the challenge to the client and let the client solve it
    let res = solve_challenge(&challenge.challenge, &challenge.salt, None, None, 0)
        .expect("need to be solved");
    // pack the solution into a json string
    let payload = Payload {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number: res,
        salt: challenge.salt,
        signature: challenge.signature,
        took: None,
    };
    let string_payload = serde_json::to_string(&payload).unwrap();

    // receive the solution from the client and verify it
    verify_json_solution(&string_payload, "super-secret", true).expect("should be verified");
}
```

### See [example server](https://github.com/jmic/altcha-lib-rs/blob/main/examples/server.rs)