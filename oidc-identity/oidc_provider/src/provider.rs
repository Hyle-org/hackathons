use alloc::{
    format,
    string::{String, ToString},
};

use hashbrown::hash_map::HashMap;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreErrorResponseType,
        CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRevocableToken, CoreTokenType, CoreUserInfoClaims,
    },
    reqwest, AccessToken, AccessTokenHash, AuthorizationCode, Client, ClientId, ClientSecret,
    CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RevocationErrorResponseType, Scope, StandardErrorResponse,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// use reqwest::Error;
pub type OidcClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            EmptyAdditionalClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        CoreTokenType,
    >,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, CoreTokenType>,
    CoreRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, Clone)]
pub struct OidcProvider {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
    pub aud: String,
    pub iss: String,
}

// #[derive(Deserialize, Debug, Clone)]
// struct JwksResponse {
//     keys: Vec<Jwk>,
// }

#[derive(Deserialize, Debug, Clone)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
}

pub fn build_http_client() -> reqwest::Client {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");
    http_client
}

impl OidcProvider {
    pub const ISSUER: &'static str = "https://accounts.google.com";
    pub const AUDIENCE: &'static str = "your-client-id.apps.googleusercontent.com";

    pub async fn build(
        issuer_url: String,
        client_id: String,
        client_secret: Option<String>,
        redirect_url: &str,
    ) -> Result<OidcClient> {
        let issuer_url_cleaned = issuer_url.trim_end_matches('/').to_string();

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url_cleaned).context("Invalid issuer URL")?,
            &build_http_client(),
        )
        .await
        .context("Failed to fetch OpenID Provider metadata")?;

        // Create OpenID Connect client
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id),
            client_secret.map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url.to_string()).context("Invalid redirect URL")?,
        );

        Ok(client)
    }

    pub fn generate_auth_url(client: &OidcClient) -> (String, CsrfToken, Nonce, PkceCodeVerifier) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        (auth_url.to_string(), csrf_token, nonce, pkce_verifier)
    }

    pub async fn exchange_code_for_tokens(
        client: &OidcClient,
        auth_code: String,
        pkce_verifier: PkceCodeVerifier,
    ) -> anyhow::Result<(CoreIdToken, AccessToken)> {
        let token_response = client
            .exchange_code(AuthorizationCode::new(auth_code))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&build_http_client())
            .await
            .map_err(|err| anyhow!("Failed to exchange authorization code for tokens: {}", err))?;

        let id_token = token_response
            .id_token()
            .cloned()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

        Ok((id_token, token_response.access_token().clone()))
    }

    pub fn verify_id_token(
        client: &OidcClient,
        id_token: &CoreIdToken,
        nonce: &Nonce,
    ) -> anyhow::Result<CoreIdTokenClaims> {
        let id_token_verifier = client.id_token_verifier();

        id_token
            .claims(&id_token_verifier, nonce)
            .cloned()
            .context("Failed to verify OpenID Connect ID token")
    }

    pub fn verify_access_token(
        client: &OidcClient,
        id_token: &CoreIdToken,
        access_token: &AccessToken,
        claims: &CoreIdTokenClaims,
    ) -> anyhow::Result<AccessTokenHash> {
        let expected_access_token_hash = claims
            .access_token_hash()
            .ok_or_else(|| anyhow!("No access token hash found in claims"))?;

        let id_token_verifier = client.id_token_verifier();
        let actual_access_token_hash = AccessTokenHash::from_token(
            access_token,
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;

        if actual_access_token_hash != *expected_access_token_hash {
            Err(anyhow!("Invalid access token"))
        } else {
            Ok(expected_access_token_hash.clone())
        }
    }

    pub async fn fetch_user_info(
        client: OidcClient,
        access_token: AccessToken,
        http_client: &reqwest::Client,
    ) -> anyhow::Result<CoreUserInfoClaims> {
        client
            .user_info(access_token, None)?
            .request_async(http_client)
            .await
            .map_err(|err| anyhow!("Failed requesting user info: {}", err))
    }

    pub fn verify_id_token_jwt(token: &str, decoding_key: &DecodingKey) -> Result<Claims, String> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[OidcProvider::AUDIENCE]);
        validation.set_issuer(&[OidcProvider::ISSUER]);

        let token_data = decode::<Claims>(token, decoding_key, &validation)
            .map_err(|e| format!("Token verification failed: {:?}", e))?;
        Ok(token_data.claims)
    }

    pub async fn fetch_google_jwks() -> Result<HashMap<String, Jwk>, String> {
        let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";

        let resp = reqwest::get(jwks_url)
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        let jwks: Value =
            serde_json::from_str(&body).map_err(|e| format!("JSON parse failed: {}", e))?;

        let mut keys = HashMap::new();

        if let Some(jwk_keys) = jwks["keys"].as_array() {
            for jwk in jwk_keys {
                if let (Some(kid), Some(jwk_obj)) = (
                    jwk["kid"].as_str(),
                    serde_json::from_value::<Jwk>(jwk.clone()).ok(),
                ) {
                    keys.insert(kid.to_string(), jwk_obj);
                }
            }
        }
        Ok(keys)
    }
}

// // Check expiration manually
// let now = SystemTime::now()
//     .duration_since(UNIX_EPOCH)
//     .unwrap()
//     .as_secs();
// if token_data.claims.exp < now as usize {
//     return Err("Token has expired".to_string());
// }
