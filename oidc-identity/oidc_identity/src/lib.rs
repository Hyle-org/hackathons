use bincode::{Decode, Encode};
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use oidc_provider::{provider::OidcProvider, IdentityAction, IdentityVerification};
use sdk::{ContractInput, Digestable, RunResult};
use sha2::{Digest, Sha256};

#[cfg(feature = "client")]
pub mod client;

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
        n: &str,
        e: &str,
        private_input: &str,
    ) -> Result<(), &'static str> {
        let decoding_key = DecodingKey::from_rsa_components(n, e)
            .expect("Failed to create decoding key from RSA components");

        let data = OidcProvider::verify_id_token_jwt(private_input, &decoding_key)
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
        n: &str,
        e: &str,
        private_input: &str,
    ) -> Result<bool, &'static str> {
        match self.identities.get_mut(account) {
            Some(stored_info) => {
                if nonce != stored_info.nonce {
                    return Err("Invalid nonce");
                }

                let decoding_key = DecodingKey::from_rsa_components(n, e)
                    .expect("Failed to create decoding key from RSA components");

                let data = OidcProvider::verify_id_token_jwt(private_input, &decoding_key)
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
        sdk::StateDigest(self.to_bytes())
    }
}

impl TryFrom<sdk::StateDigest> for OidcIdentity {
    type Error = anyhow::Error;

    fn try_from(state: sdk::StateDigest) -> Result<Self, Self::Error> {
        let (balances, _) = bincode::decode_from_slice(&state.0, bincode::config::standard())
            .map_err(|_| anyhow::anyhow!("Could not decode hydentity state"))?;
        Ok(balances)
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

    sdk::info!("Executing action: {:?}", parsed_blob);

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
    use jsonwebtoken::{encode, EncodingKey, Header};
    use oidc_provider::provider::Claims;
    use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, RsaPublicKey};
    // use serde_json;
    // use sha2::{Digest, Sha256};

    /// Test RSA public key (PEM format)
    const RSA_PUBLIC_PEM: &str = r#"
    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKCAQEApz/3Mvw7UuDJiITkGhW8gFKo6v5JOM5d5FDblBqHpPbYXe+IgbrA
    p9hN9nQnpuX1kS9HbUZAYJ/zmrkTHsAAfwIDAQAB
    -----END RSA PUBLIC KEY-----
    "#;

    /// Extracts `n` and `e` from the RSA public key
    fn extract_n_e_from_rsa() -> (String, String) {
        let rsa_public_key =
            RsaPublicKey::from_pkcs1_pem(RSA_PUBLIC_PEM).expect("Invalid PEM public key");

        let n_bytes = rsa_public_key.n().to_bytes_be();
        let e_bytes = rsa_public_key.e().to_bytes_be();

        let n_base64 = STANDARD.encode(n_bytes);
        let e_base64 = STANDARD.encode(e_bytes);

        (n_base64, e_base64)
    }

    /// Generates a valid RS256 JWT token using the RSA private key
    fn generate_test_jwt() -> String {
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

        let claims = Claims {
            sub: "1234567890".to_string(),
            email: "user@example.com".to_string(),
            exp: 1893456000, // Far future expiry
            aud: OidcProvider::AUDIENCE.to_string(),
            iss: OidcProvider::ISSUER.to_string(),
        };

        encode(
            &Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(rsa_private_pem.as_bytes()).unwrap(),
        )
        .expect("Failed to encode test JWT")
    }

    #[test]
    fn test_register_identity_with_valid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let jwt_token = generate_test_jwt();
        let (n, e) = extract_n_e_from_rsa(); // Extract real `n` and `e`

        assert!(identity
            .register_identity(account, &n, &e, &jwt_token)
            .is_ok());

        let registered = identity.identities.get(account).unwrap();
        assert_eq!(registered.nonce, 0);
    }

    #[test]
    fn test_verify_identity_with_valid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let jwt_token = generate_test_jwt();
        let (n, e) = extract_n_e_from_rsa();

        identity
            .register_identity(account, &n, &e, &jwt_token)
            .expect("Failed to register identity");

        assert!(identity
            .verify_identity(account, 0, &n, &e, &jwt_token)
            .unwrap());

        // Nonce should now be 1, reusing old nonce should fail
        assert!(identity
            .verify_identity(account, 0, &n, &e, &jwt_token)
            .is_err());

        // Now using updated nonce (1) should pass
        assert!(identity
            .verify_identity(account, 1, &n, &e, &jwt_token)
            .unwrap());
    }

    #[test]
    fn test_register_identity_with_invalid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let invalid_token = "invalid.jwt.token";
        let (n, e) = extract_n_e_from_rsa();

        assert!(identity
            .register_identity(account, &n, &e, invalid_token)
            .is_err());
    }

    #[test]
    fn test_verify_identity_with_invalid_token() {
        let mut identity = OidcIdentity::default();
        let account = "test_account";

        let jwt_token = generate_test_jwt();
        let (n, e) = extract_n_e_from_rsa();

        identity
            .register_identity(account, &n, &e, &jwt_token)
            .expect("Failed to register identity");

        let invalid_token = "invalid.jwt.token";
        assert!(identity
            .verify_identity(account, 0, &n, &e, invalid_token)
            .is_err());
    }
}
