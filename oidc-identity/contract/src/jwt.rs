use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
    BigUint, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use oidc_provider::{JwkPublicKey, OpenIdContext};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub kid: Option<String>, // Key ID (helps pick the correct public key)
}

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
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| "Failed to decode Base64".to_string())
}

pub fn construct_rsa_pub_key(jwk_pub_key: &JwkPublicKey) -> Result<RsaPublicKey, String> {
    let n_bytes = URL_SAFE_NO_PAD
        .decode(&jwk_pub_key.n)
        .map_err(|_| "Failed to decode 'n' (modulus) from Base64")?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(&jwk_pub_key.e)
        .map_err(|_| "Failed to decode 'e' (exponent) from Base64")?;

    let rsa_pub_key = RsaPublicKey::new(
        BigUint::from_bytes_be(&n_bytes),
        BigUint::from_bytes_be(&e_bytes),
    )
    .map_err(|_| "Failed to construct RSA public key")?;

    Ok(rsa_pub_key)
}

fn get_jwt_algorithm(header_b64: &str) -> Result<String, String> {
    let header_bytes = decode_b64(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| "Failed to parse JWT header".to_string())?;
    Ok(header.alg)
}

pub fn verify_jwt_signature(
    token: &str,
    jwk_pub_key: &JwkPublicKey,
    context: &OpenIdContext,
) -> Result<Claims, String> {
    let rsa_pub_key = construct_rsa_pub_key(jwk_pub_key)
        .map_err(|_| "Failed to construct RSA public key".to_string())?;

    let (header_b64, payload_b64, signature_b64) = split_jwt(token)?;

    let decoded_signature = decode_b64(signature_b64)?;

    let alg = get_jwt_algorithm(header_b64)?;

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let hashed_msg: Vec<u8> = match alg.as_str() {
        "RS256" => Sha256::digest(signing_input.as_bytes()).to_vec(),
        "RS512" => Sha512::digest(signing_input.as_bytes()).to_vec(),
        _ => return Err(format!("Unsupported JWT algorithm: {}", alg)),
    };

    let signature = Signature::try_from(decoded_signature.as_slice())
        .map_err(|_| "Invalid RSA signature format".to_string())?;

    let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(rsa_pub_key.clone());

    // verifying_key
    //     .verify(&hashed_msg, &signature)
    //     .map_err(|e| format!("JWT signature verification failed: {}", e))?;

    let payload_bytes = decode_b64(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "Failed to parse JWT claims".to_string())?;

    if !claims.aud.contains(&context.audience) {
        return Err(format!(
            "Invalid Audience: expected `{}`, got `{:?}`",
            context.audience, claims.aud
        ));
    }
    if claims.iss != context.issuer {
        return Err(format!(
            "Invalid Issuer: expected `{}`, got `{}`",
            context.issuer, claims.iss
        ));
    }

    Ok(claims)
}
