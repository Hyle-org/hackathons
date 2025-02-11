use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::decode_header;
use openidconnect::{
    core::{
        CoreAuthDisplay,
        CoreAuthPrompt,
        CoreAuthenticationFlow,
        CoreClient,
        CoreErrorResponseType,
        CoreGenderClaim,
        CoreIdToken,
        CoreIdTokenClaims,
        CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreProviderMetadata,
        CoreRevocableToken,
        CoreTokenType,
        // CoreUserInfoClaims,
    },
    reqwest, AccessToken, AccessTokenHash, AuthorizationCode, Client, ClientId, ClientSecret,
    CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RevocationErrorResponseType, Scope, StandardErrorResponse,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

pub type AuthClient = Client<
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
pub struct OIDCClient {}

#[derive(Deserialize, Serialize, Debug, Clone)]
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

impl OIDCClient {
    pub async fn build(
        issuer_url: String,
        client_id: String,
        client_secret: Option<String>,
        redirect_url: &str,
    ) -> Result<AuthClient> {
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

    pub fn generate_auth_url(client: &AuthClient) -> (String, CsrfToken, Nonce, PkceCodeVerifier) {
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
        client: &AuthClient,
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
        client: &AuthClient,
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
        client: &AuthClient,
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

    // pub async fn fetch_user_info(
    //     client: &AuthClient,
    //     access_token: &AccessToken,
    // ) -> anyhow::Result<CoreUserInfoClaims> {
    //     client
    //         .user_info(access_token.clone(), None)?
    //         .request_async(&build_http_client())
    //         .await
    //         .map_err(|err| anyhow!("Failed requesting user info: {}", err))
    // }

    pub async fn fetch_jwks(jwk_url: &str) -> Result<HashMap<String, Jwk>, String> {
        let resp = reqwest::get(jwk_url)
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

    pub async fn match_jwks(access_token: &str, jwk_url: &str) -> Result<Jwk, String> {
        // Fetch JWKS and return error if the request fails
        let keys = OIDCClient::fetch_jwks(jwk_url)
            .await
            .map_err(|e| format!("Failed to fetch Google JWKS: {:?}", e))?;

        // Decode the JWT header
        let header = decode_header(access_token).map_err(|_| "Invalid JWT header".to_string())?;

        // Ensure the `kid` exists in the JWT header
        let kid = header
            .kid
            .ok_or("JWT header does not contain a Key ID (kid)".to_string())?;

        // Retrieve (modulus `n`, exponent `e`) pair from the JWKS mapping
        keys.get(&kid)
            .cloned() // Clone since we're returning owned values
            .ok_or_else(|| format!("Key ID '{}' not found in JWKS", kid))
    }

    /// Starts a temporary HTTP server to capture the access code from the redirect URL
    pub async fn capture_access_code(redirect_url: &str) -> String {
        let parsed_url = Url::parse(redirect_url).expect("Failed to parse URL");
        let socket_addr = format!(
            "{}:{}",
            parsed_url.host_str().expect("Invalid host"),
            parsed_url.port_or_known_default().expect("Invalid port")
        );

        let listener = TcpListener::bind(&socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind to {:?}: {}", redirect_url, e));

        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = vec![0; 4096]; // Bigger buffer for large OAuth redirects
                let _ = stream
                    .read(&mut buffer)
                    .await
                    .expect("Failed to read stream");

                let request = String::from_utf8_lossy(&buffer);
                println!("Received request:\n{}", request);

                // Extract first line from request
                if let Some(first_line) = request.lines().next() {
                    let request_path = first_line.split_whitespace().nth(1); // Extracts "/callback?..."
                    if let Some(query_part) = request_path {
                        let full_url = format!("{}{}", redirect_url, query_part);
                        let url = Url::parse(&full_url).expect("Failed to parse URL");

                        if let Some(code) = url
                            .query_pairs()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.to_string())
                        {
                            // Send success response
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nAuthentication Complete";
                            stream
                                .write_all(response.as_bytes())
                                .await
                                .expect("Failed to write response");

                            println!("Extracted Auth Code: {}", code);
                            return code;
                        }
                    }
                }
            }
        }
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
