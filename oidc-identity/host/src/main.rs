use clap::{Parser, Subcommand};
use client_sdk::helpers::risc0::Risc0Prover;
use dotenv::dotenv;
use oidc_identity::OidcIdentity;
use oidc_provider::IdentityAction;
use oidc_provider::JwkPublicKey;
use oidc_provider::OpenIdContext;
use sdk::api::APIRegisterContract;
use sdk::BlobTransaction;
use sdk::ProofTransaction;
use sdk::{ContractInput, Digestable};

mod config;
mod oidc_client;
use std::path::Path;

use config::load_config;
use oidc_client::OIDCClient;

// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods_identity::{GUEST_ELF, GUEST_ID};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "google")]
    pub provider: String,
}

#[derive(Subcommand)]
enum Commands {
    RegisterContract {},
    RegisterIdentity {},
    VerifyIdentity { nonce: u32 },
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let config = load_config(Some(Path::new("./host/config.toml"))).unwrap();

    let cli = Cli::parse();

    let client = client_sdk::rest_client::NodeApiHttpClient::new(config.server.host).unwrap();

    let contract_name = &config.contract.name;

    let prover = Risc0Prover::new(GUEST_ELF);

    let identity_provider = config
        .identity_providers
        .get(&cli.provider)
        .unwrap_or_else(|| panic!("{} not set in config.toml", cli.provider));

    match cli.command {
        Commands::RegisterContract {} => {
            // Build initial state of contract
            let initial_state = OidcIdentity::new();
            println!("Initial state: {:?}", initial_state);

            // Send the transaction to register the contract
            let res = client
                .register_contract(&APIRegisterContract {
                    verifier: "risc0".into(),
                    program_id: sdk::ProgramId(sdk::to_u8_array(&GUEST_ID).to_vec()),
                    state_digest: initial_state.as_digest(),
                    contract_name: contract_name.clone().into(),
                })
                .await
                .unwrap();

            println!("✅ Register contract tx sent. Tx hash: {}", res);
        }
        Commands::RegisterIdentity {} => {
            // Fetch the initial state from the node
            let initial_state: OidcIdentity = client
                .get_contract(&contract_name.clone().into())
                .await
                .unwrap()
                .state
                .into();

            println!("Initial state {:?}", initial_state.clone());

            let client_secret = &identity_provider.get_client_secret(&cli.provider);
            let oidc_client = OIDCClient::build(
                identity_provider.issuer_url.to_string(),
                identity_provider.audience_url.to_string(),
                Some(client_secret.to_string()),
                &format!("{}/callback", config.server.server_url),
            )
            .await
            .expect("Failed to build provider");

            let (auth_url, _, nonce, pkce_verifier) = OIDCClient::generate_auth_url(&oidc_client);

            println!("Open the following URL in your browser to authenticate:");
            println!("{}", auth_url);

            let auth_code = OIDCClient::capture_access_code(&config.server.server_url).await;

            let (id_token, access_token) =
                OIDCClient::exchange_code_for_tokens(&oidc_client, auth_code, pkce_verifier)
                    .await
                    .expect("Failed to exchange code");

            let claims = OIDCClient::verify_id_token(&oidc_client, &id_token, &nonce)
                .expect("Failed to verify id token");

            let _ =
                OIDCClient::verify_access_token(&oidc_client, &id_token, &access_token, &claims)
                    .expect("Failed to verify access token");

            let jwk_res = OIDCClient::match_jwks(
                &id_token.to_string(),
                &identity_provider.jwk_public_key_url,
            )
            .await
            .expect("Failed to match google jwks");

            println!("{:?}", jwk_res);

            let identity_id = format!("{}.{}", claims.subject().to_string(), config.contract.name);

            // ----
            // Build the blob transaction
            // ----

            let action = IdentityAction::RegisterIdentity {
                account: identity_id.clone(),
                jwk_pub_key: JwkPublicKey {
                    n: jwk_res.n,
                    e: jwk_res.e,
                },
                context: OpenIdContext {
                    issuer: identity_provider.issuer_url.to_string(),
                    audience: identity_provider.audience_url.to_string(),
                },
            };
            let blobs = vec![sdk::Blob {
                contract_name: contract_name.clone().into(),
                data: sdk::BlobData(
                    bincode::encode_to_vec(action, bincode::config::standard())
                        .expect("failed to encode BlobData"),
                ),
            }];
            let blob_tx = BlobTransaction {
                identity: identity_id.into(),
                blobs: blobs.clone(),
            };

            // Send the blob transaction
            let blob_tx_hash = client.send_tx_blob(&blob_tx).await.unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            // ----
            // Prove the state transition
            // ----

            // Build the contract input
            let inputs = ContractInput {
                initial_state: initial_state.as_digest(),
                identity: blob_tx.identity,
                tx_hash: blob_tx_hash,
                private_input: id_token.to_string().clone().into_bytes().to_vec(),
                tx_ctx: None,
                blobs: blobs.clone(),
                index: sdk::BlobIndex(0),
            };

            // Generate the zk proof
            let proof = prover.prove(inputs).await.unwrap();

            let proof_tx = ProofTransaction {
                proof,
                contract_name: contract_name.clone().into(),
            };

            // Send the proof transaction
            let proof_tx_hash = client.send_tx_proof(&proof_tx).await.unwrap();
            println!("✅ Proof tx sent. Tx hash: {}", proof_tx_hash);
        }
        Commands::VerifyIdentity { nonce } => {
            {
                // Fetch the initial state from the node
                let initial_state: OidcIdentity = client
                    .get_contract(&contract_name.clone().into())
                    .await
                    .unwrap()
                    .state
                    .into();

                let client_secret = &identity_provider.get_client_secret(&cli.provider);

                let oidc_client = OIDCClient::build(
                    identity_provider.issuer_url.to_string(),
                    identity_provider.audience_url.to_string(),
                    Some(client_secret.to_string()),
                    &format!("{}/callback", config.server.server_url),
                )
                .await
                .expect("Failed to build provider");

                let (auth_url, _, auth_nonce, pkce_verifier) =
                    OIDCClient::generate_auth_url(&oidc_client);

                println!("Open the following URL in your browser to authenticate:");
                println!("{}", auth_url);

                let auth_code = OIDCClient::capture_access_code(&config.server.server_url).await;

                let (id_token, access_token) =
                    OIDCClient::exchange_code_for_tokens(&oidc_client, auth_code, pkce_verifier)
                        .await
                        .expect("Failed to exchange code");

                let claims = OIDCClient::verify_id_token(&oidc_client, &id_token, &auth_nonce)
                    .expect("Failed to verify id token");

                let _ = OIDCClient::verify_access_token(
                    &oidc_client,
                    &id_token,
                    &access_token,
                    &claims,
                )
                .expect("Failed to verify access token");

                let jwk_res = OIDCClient::match_jwks(
                    &id_token.to_string(),
                    &identity_provider.jwk_public_key_url,
                )
                .await
                .expect("Failed to match google jwks");

                // ----
                // Build the blob transaction
                // ----

                let identity_id =
                    format!("{}.{}", claims.subject().to_string(), config.contract.name);

                let action = IdentityAction::VerifyIdentity {
                    account: identity_id.clone(),
                    nonce,
                    jwk_pub_key: JwkPublicKey {
                        n: jwk_res.n,
                        e: jwk_res.e,
                    },
                    context: OpenIdContext {
                        issuer: identity_provider.issuer_url.to_string(),
                        audience: identity_provider.audience_url.to_string(),
                    },
                };
                let blobs = vec![sdk::Blob {
                    contract_name: contract_name.clone().into(),
                    data: sdk::BlobData(
                        bincode::encode_to_vec(action, bincode::config::standard())
                            .expect("failed to encode BlobData"),
                    ),
                }];
                let blob_tx = BlobTransaction {
                    identity: identity_id.into(),
                    blobs: blobs.clone(),
                };

                // Send the blob transaction
                let blob_tx_hash = client.send_tx_blob(&blob_tx).await.unwrap();
                println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

                // ----
                // Prove the state transition
                // ----

                // Build the contract input
                let inputs = ContractInput {
                    initial_state: initial_state.as_digest(),
                    identity: blob_tx.identity,
                    tx_hash: blob_tx_hash.clone(),
                    private_input: id_token.to_string().clone().into_bytes().to_vec(),
                    tx_ctx: None,
                    blobs: blobs.clone(),
                    index: sdk::BlobIndex(0),
                };

                // Generate the zk proof
                let proof = prover.prove(inputs).await.unwrap();

                let proof_tx = ProofTransaction {
                    proof,
                    contract_name: contract_name.clone().into(),
                };

                // Send the proof transaction
                let proof_tx_hash = client.send_tx_proof(&proof_tx).await.unwrap();
                println!("✅ Proof tx sent. Tx hash: {}", proof_tx_hash);
            }
        }
    }
}
