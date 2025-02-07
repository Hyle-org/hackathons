use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use oidc_provider::{JwkPublicKey, OpenIdContext};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: u64,
    pub aud: String,
    pub iss: String,
}

fn split_jwt(token: &str) -> Result<(&str, &str, &str), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT structure".to_string());
    }
    Ok((parts[0], parts[1], parts[2]))
}

fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(input)
        .map_err(|_| "Base64 decoding failed".to_string())
}

pub fn construct_rsa_pub_key(jwk_pub_key: &JwkPublicKey) -> Result<RsaPublicKey, String> {
    let n_bytes = decode_b64(&jwk_pub_key.n)?;
    let e_bytes = decode_b64(&jwk_pub_key.e)?;

    let rsa_pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n_bytes),
        rsa::BigUint::from_bytes_be(&e_bytes),
    )
    .map_err(|_| "Failed to construct RSA public key")?;

    Ok(rsa_pub_key)
}

pub fn verify_jwt_signature(
    token: &str,
    jwk_pub_key: &JwkPublicKey,
    context: &OpenIdContext,
) -> Result<Claims, String> {
    let rsa_pub_key = construct_rsa_pub_key(jwk_pub_key)
        .map_err(|_| "Failed to construct RSA public key".to_string())?;

    let (header_b64, payload_b64, signature_b64) = split_jwt(token)?;

    // Decode Base64 values
    let signature = decode_b64(signature_b64)?;
    let header_payload = format!("{}.{}", header_b64, payload_b64);

    // Compute SHA256 hash of `header.payload`
    let mut hasher = Sha256::new();
    hasher.update(header_payload.as_bytes());
    let hashed_msg = hasher.finalize();

    // Verify RSA signature
    rsa_pub_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &hashed_msg, &signature)
        .map_err(|_| "JWT signature verification failed".to_string())?;

    // Decode & parse claims
    let payload_bytes = decode_b64(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "Failed to parse JWT claims".to_string())?;

    // Ensure audience (`aud`) matches expected value
    if !claims.aud.contains(&context.audience) {
        return Err(format!(
            "Invalid Audience: expected `{}`, got `{}`",
            context.audience, claims.aud
        ));
    }

    // Ensure issuer (`iss`) matches expected value
    if claims.iss != context.issuer {
        return Err(format!(
            "Invalid Issuer: expected `{}`, got `{}`",
            context.issuer, claims.iss
        ));
    }

    Ok(claims)
}
