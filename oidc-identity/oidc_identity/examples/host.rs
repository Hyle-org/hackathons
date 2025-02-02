use clap::{Parser, Subcommand};
use client_sdk::contract_states;
use client_sdk::rest_client::NodeApiHttpClient;
use client_sdk::transaction_builder::ProvableBlobTx;
use client_sdk::transaction_builder::TxExecutor;
use client_sdk::transaction_builder::TxExecutorBuilder;
use dotenv::dotenv;
use jsonwebtoken::decode_header;
use oidc_identity::OidcIdentity;
use oidc_provider::{
    provider::{Jwk, OidcProvider},
    IdentityAction,
};
use sdk::ContractName;
use sdk::Hashable;
use std::env;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use url::Url;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "http://localhost:4321")]
    pub host: String,

    #[arg(long, default_value = "http://localhost:8000")]
    pub server: String,
}

#[derive(Subcommand)]
enum Commands {
    RegisterIdentity { identity: String },
    VerifyIdentity { identity: String, nonce: u32 },
}

contract_states!(
    #[derive(Debug, Clone)]
    pub struct States {
        pub oidc_identity: OidcIdentity,
    }
);

async fn build_ctx(client: &NodeApiHttpClient) -> TxExecutor<States> {
    // Fetch the initial state from the node
    let initial_state: OidcIdentity = client
        .get_contract(&"hydentity".into())
        .await
        .unwrap()
        .state
        .try_into()
        .unwrap();

    TxExecutorBuilder::new(States {
        oidc_identity: initial_state,
    })
    .build()
}

/// Starts a temporary HTTP server to capture the access code from the redirect URL
async fn capture_access_code(redirect_url: &str) -> String {
    let listener = TcpListener::bind(redirect_url)
        .await
        .expect("Failed to bind to port 8080");

    println!("Waiting for OpenID provider to redirect with the access code...");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0; 1024];
            let _ = stream.try_read(&mut buffer).expect("Failed to read stream");

            let request = String::from_utf8_lossy(&buffer);
            if let Some(start) = request.find("GET /?") {
                if let Some(end) = request[start..].find(' ') {
                    let query = &request[start + 5..start + end];
                    let url = Url::parse(&format!("{}/?{}", redirect_url, query))
                        .expect("Failed to parse URL");

                    if let Some(code) = url
                        .query_pairs()
                        .find(|(k, _)| k == "code")
                        .map(|(_, v)| v.to_string())
                    {
                        // Send a success response to the browser
                        let response =
                            "HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nAuthentication Complete";
                        stream
                            .write_all(response.as_bytes())
                            .await
                            .expect("Failed to write response");

                        return code;
                    }
                }
            }
        }
    }
}

async fn match_google_jwks(access_token: &str) -> Result<Jwk, String> {
    // Fetch JWKS and return error if the request fails
    let keys = OidcProvider::fetch_google_jwks()
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

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let client = client_sdk::rest_client::NodeApiHttpClient::new(cli.host).unwrap();

    let mut ctx = build_ctx(&client).await;

    match cli.command {
        Commands::RegisterIdentity { identity } => {
            // ----
            // Build the blob transaction
            // ----

            let mut transaction = ProvableBlobTx::new(identity.clone().into());
            let client_secret =
                env::var("CLIENT_SECRET").unwrap_or_else(|_| "default_secret".to_string());

            let oidc_client = OidcProvider::build(
                OidcProvider::ISSUER.to_string(),
                OidcProvider::AUDIENCE.to_string(),
                Some(client_secret),
                &cli.server,
            )
            .await
            .expect("Failed to build provider");

            // let provider = OidcProvider::
            let (auth_url, _, nonce, pkce_verifier) = OidcProvider::generate_auth_url(&oidc_client);

            println!("Open the following URL in your browser to authenticate:");
            println!("{}", auth_url);

            let auth_code = capture_access_code(&cli.server).await;

            let (id_token, access_token) =
                OidcProvider::exchange_code_for_tokens(&oidc_client, auth_code, pkce_verifier)
                    .await
                    .expect("Failed to exchange code");

            let claims = OidcProvider::verify_id_token(&oidc_client, &id_token, &nonce)
                .expect("Failed to verify id token");

            let _ =
                OidcProvider::verify_access_token(&oidc_client, &id_token, &access_token, &claims)
                    .expect("Failed to verify access token");

            let jwk_res = match_google_jwks(access_token.secret())
                .await
                .expect("Failed to match google jwks");

            oidc_identity::client::register_identity(
                &mut transaction,
                ContractName::new("hydentity"),
                &jwk_res.n,
                &jwk_res.e,
                access_token.secret().to_string(),
            )
            .unwrap();

            let transaction = ctx.process(transaction).unwrap();

            // Send the blob transaction
            let blob_tx_hash = client
                .send_tx_blob(&transaction.to_blob_tx())
                .await
                .unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            // ----
            // Prove the state transition
            // ----
            for proof in transaction.iter_prove() {
                let tx = proof.await.unwrap();
                client.send_tx_proof(&tx).await.unwrap();
                println!(
                    "✅ Proof tx sent for {}. Tx hash: {}",
                    tx.contract_name,
                    tx.hash()
                );
            }
        }
        Commands::VerifyIdentity { identity, nonce } => {
            // ----
            // Build the blob transaction
            // ----

            let mut transaction = ProvableBlobTx::new(identity.clone().into());

            let client_secret =
                env::var("CLIENT_SECRET").unwrap_or_else(|_| "default_secret".to_string());

            let oidc_client = OidcProvider::build(
                OidcProvider::ISSUER.to_string(),
                OidcProvider::AUDIENCE.to_string(),
                Some(client_secret),
                &cli.server,
            )
            .await
            .expect("Failed to build provider");

            // let provider = OidcProvider::
            let (auth_url, _, auth_nonce, pkce_verifier) =
                OidcProvider::generate_auth_url(&oidc_client);

            println!("Open the following URL in your browser to authenticate:");
            println!("{}", auth_url);

            let auth_code = capture_access_code(&cli.server).await;

            let (id_token, access_token) =
                OidcProvider::exchange_code_for_tokens(&oidc_client, auth_code, pkce_verifier)
                    .await
                    .expect("Failed to exchange code");

            let claims = OidcProvider::verify_id_token(&oidc_client, &id_token, &auth_nonce)
                .expect("Failed to verify id token");

            let _ =
                OidcProvider::verify_access_token(&oidc_client, &id_token, &access_token, &claims)
                    .expect("Failed to verify access token");

            let jwk_res = match_google_jwks(access_token.secret())
                .await
                .expect("Failed to match google jwks");

            transaction
                .add_action(
                    "hydentity".into(),
                    IdentityAction::VerifyIdentity {
                        account: identity.clone(),
                        nonce,
                        n: jwk_res.n,
                        e: jwk_res.e,
                    },
                    None,
                    None,
                )
                .unwrap()
                .with_private_input(move |_: &OidcIdentity| {
                    Ok(access_token
                        .secret()
                        .to_string()
                        .clone()
                        .into_bytes()
                        .to_vec())
                });

            let transaction = ctx.process(transaction).unwrap();

            // Send the blob transaction
            let blob_tx_hash = client
                .send_tx_blob(&transaction.to_blob_tx())
                .await
                .unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            // ----
            // Prove the state transition
            // ----
            for proof in transaction.iter_prove() {
                let tx = proof.await.unwrap();
                client.send_tx_proof(&tx).await.unwrap();
                println!(
                    "✅ Proof tx sent for {}. Tx hash: {}",
                    tx.contract_name,
                    tx.hash()
                );
            }
        }
    }
}
