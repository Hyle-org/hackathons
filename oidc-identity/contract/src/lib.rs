use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use oidc_provider::{IdentityAction, IdentityVerification, JwkPublicKey, OpenIdContext};
use sdk::{ContractInput, Digestable, RunResult};
use sha2::{Digest, Sha256};

mod jwt;

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct AccountInfo {
    pub hash: String,
    pub nonce: u32,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct OidcIdentity {
    identities: BTreeMap<String, AccountInfo>,
}

impl OidcIdentity {
    pub fn new() -> Self {
        OidcIdentity {
            identities: BTreeMap::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .expect("Failed to encode Balances")
    }

    pub fn get_nonce(&self, email: &str) -> Result<u32, &'static str> {
        let info = self.get_identity_info(email)?;
        let state: AccountInfo =
            serde_json::from_str(&info).map_err(|_| "Failed to parse accounf info")?;
        Ok(state.nonce)
    }
}

impl Default for OidcIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityVerification for OidcIdentity {
    fn register_identity(
        &mut self,
        account: &str,
        context: &OpenIdContext,
        jwk_pub_key: &JwkPublicKey,
        private_input: &str,
    ) -> Result<(), &'static str> {
        let data = jwt::verify_jwt_signature(private_input, &jwk_pub_key, &context)
            .expect("Failed to verify ID token JWT");

        let sub = data.sub;
        let issuer = data.iss;

        let id = format!("{sub}:{issuer}");
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let hash_bytes = hasher.finalize();
        let account_info = AccountInfo {
            hash: hex::encode(hash_bytes),
            nonce: 0,
        };

        if self
            .identities
            .insert(account.to_string(), account_info)
            .is_some()
        {
            return Err("Identity already exists");
        }
        Ok(())
    }

    fn verify_identity(
        &mut self,
        account: &str,
        nonce: u32,
        context: &OpenIdContext,
        jwk_pub_key: &JwkPublicKey,
        private_input: &str,
    ) -> Result<bool, &'static str> {
        match self.identities.get_mut(account) {
            Some(stored_info) => {
                if nonce != stored_info.nonce {
                    return Err("Invalid nonce");
                }

                let data = jwt::verify_jwt_signature(private_input, &jwk_pub_key, &context)
                    .expect("Failed to verify ID token JWT");

                let sub = data.sub;
                let issuer = data.iss;

                let id = format!("{sub}:{issuer}");

                let mut hasher = Sha256::new();
                hasher.update(id.as_bytes());
                let hashed = hex::encode(hasher.finalize());
                if *stored_info.hash != hashed {
                    return Ok(false);
                }
                stored_info.nonce += 1;
                Ok(true)
            }
            None => Err("Identity not found"),
        }
    }

    fn get_identity_info(&self, account: &str) -> Result<String, &'static str> {
        match self.identities.get(account) {
            Some(info) => Ok(serde_json::to_string(&info).map_err(|_| "Failed to serialize")?),
            None => Err("Identity not found"),
        }
    }
}

impl Digestable for OidcIdentity {
    fn as_digest(&self) -> sdk::StateDigest {
        sdk::StateDigest(
            bincode::encode_to_vec(self, bincode::config::standard())
                .expect("Failed to encode Balances"),
        )
    }
}
impl From<sdk::StateDigest> for OidcIdentity {
    fn from(state: sdk::StateDigest) -> Self {
        let (state, _) = bincode::decode_from_slice(&state.0, bincode::config::standard())
            .map_err(|_| "Could not decode identity state".to_string())
            .unwrap();
        state
    }
}

use core::str::from_utf8;

pub fn execute(input: ContractInput) -> RunResult<OidcIdentity> {
    let (input, parsed_blob) = sdk::guest::init_raw::<IdentityAction>(input);

    let parsed_blob = match parsed_blob {
        Some(v) => v,
        None => {
            return Err("Failed to parse input blob".to_string());
        }
    };

    let state: OidcIdentity = input
        .initial_state
        .clone()
        .try_into()
        .expect("Failed to decode state");

    let password = from_utf8(&input.private_input).unwrap();

    oidc_provider::execute_action(state, parsed_blob, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use jwt::Claims;
    use rsa::{
        pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPrivateKey,
        RsaPublicKey,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn get_context() -> OpenIdContext {
        OpenIdContext {
            issuer: "https://login.microsoftonline.com/{tenantid}/v2.0".to_string(),
            audience: "your-client-id".to_string(),
        }
    }

    fn encode_b64(msg: &[u8]) -> String {
        STANDARD.encode(msg)
    }

    fn sha256_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Generates a valid JWT **AND** returns the associated JWK public key
    pub fn generate_test_jwt() -> (JwkPublicKey, String) {
        let rsa_private_pem = r#"
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOwIBAAJBAKz7G89P7Hkd4npGrwN3kqLHFyzJ+U5J6LZMjxvi5VoTbH+MFjt9
            e2kzC7gTwLtBOCjRxY9bOAjhS+u93lBW2kkCAwEAAQJAOG4z8BPIqEkCJGVmtqqB
            X7pPZtYZm0b0P2FsQnSHnx/higfx8gU04bKgUyO74VPcCRiPL9H+g61V/ezh5nGp
            EQIhAOuPZ+20EV0D4lWBkP7QGgLJk8CF+Zw1u3KfNp+z/YVXAiEAxHvl4wM5Joey
            h5qNT2ZXYlfh7VYmnOdEsF5/QV1V7U8CIQCZLdVzUIZ4N2e/WbsccnoyvdLMRjcD
            7jsXLDbf8f4CAQIgXewgrG00A3UlE4uLhQ+jRl5rUBBRQHkylJzBI6U5t1ECIQDI
            xWa1QtWW9/6kUd5UJfV/Y2Zgo/sVEXbA1kPuo3FYrQ==
            -----END RSA PRIVATE KEY-----
        "#;

        // Load RSA private key
        let private_key =
            RsaPrivateKey::from_pkcs1_pem(rsa_private_pem).expect("Invalid RSA private key");

        // Extract public key
        let public_key = RsaPublicKey::from(&private_key);
        let n_base64 = encode_b64(&public_key.n().to_bytes_be());
        let e_base64 = encode_b64(&public_key.e().to_bytes_be());

        // Construct JWK public key
        let jwk_pub_key = JwkPublicKey {
            n: n_base64,
            e: e_base64,
        };

        // JWT Header
        let header = json!({
            "alg": "RS256",
            "typ": "JWT"
        });
        let header_b64 = encode_b64(serde_json::to_string(&header).unwrap().as_bytes());

        // JWT Payload (Claims)
        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "user@example.com".to_string(),
            exp: 1893456000, // Far future expiry
            aud: get_context().audience.clone(),
            iss: get_context().issuer.clone(),
        };
        let payload_b64 = encode_b64(serde_json::to_string(&claims).unwrap().as_bytes());

        // Create `header.payload` string
        let message = format!("{}.{}", header_b64, payload_b64);

        // Compute SHA256 hash
        let hashed_msg = sha256_hash(message.as_bytes());

        // Sign with RSA private key
        let signature = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hashed_msg)
            .expect("RSA signing failed");
        let signature_b64 = encode_b64(&signature);

        // Return (JWK public key, JWT token)
        (jwk_pub_key, format!("{}.{}", message, signature_b64))
    }

    #[test]
    fn test_register_identity_with_valid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let (jwk_public_key, jwt_token) = generate_test_jwt();
        let context = get_context();

        assert!(identity
            .register_identity(account, &context, &jwk_public_key, &jwt_token)
            .is_ok());

        let registered = identity.identities.get(account).unwrap();
        assert_eq!(registered.nonce, 0);
    }

    #[test]
    fn test_verify_identity_with_valid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let (jwk_public_key, jwt_token) = generate_test_jwt();
        let context = get_context();

        identity
            .register_identity(account, &context, &jwk_public_key, &jwt_token)
            .expect("Failed to register identity");

        assert!(identity
            .verify_identity(account, 0, &context, &jwk_public_key, &jwt_token)
            .unwrap());

        // Nonce should now be 1, reusing old nonce should fail
        assert!(identity
            .verify_identity(account, 0, &context, &jwk_public_key, &jwt_token)
            .is_err());

        // Now using updated nonce (1) should pass
        assert!(identity
            .verify_identity(account, 1, &context, &jwk_public_key, &jwt_token)
            .unwrap());
    }

    #[test]
    fn test_register_identity_with_invalid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let invalid_token = "invalid.jwt.token";
        let (jwk_public_key, _) = generate_test_jwt(); // Extract real `n` and `e`
        let context = get_context();

        assert!(identity
            .register_identity(account, &context, &jwk_public_key, invalid_token)
            .is_err());
    }

    #[test]
    fn test_verify_identity_with_invalid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let (jwk_public_key, jwt_token) = generate_test_jwt();
        let context = get_context();

        identity
            .register_identity(account, &context, &jwk_public_key, &jwt_token)
            .expect("Failed to register identity");

        let invalid_token = "invalid.jwt.token";
        assert!(identity
            .verify_identity(account, 0, &context, &jwk_public_key, invalid_token)
            .is_err());
    }
}
