use clap::{Parser, Subcommand};
use client_sdk::helpers::risc0::Risc0Prover;
use contract_identity::IdentityContractState;
use contract_identity::WebAuthnAction;
use hex;
use methods_identity::{GUEST_ELF, GUEST_ID};
use sdk::api::APIRegisterContract;
use sdk::BlobTransaction;
use sdk::Identity;
use sdk::ProofTransaction;
use sdk::{ContractInput, Digestable};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(long, short)]
    reproducible: bool,

    #[arg(long, default_value = "http://localhost:4321")]
    pub host: String,

    #[arg(long, default_value = "simple_identity")]
    pub contract_name: String,
}

#[derive(Subcommand)]
enum Commands {
    RegisterContract {},
    RegisterWebAuthn {
        username: String,
        credential_id: String,
        public_key: String,
    },
    StartWebAuthn {
        username: String,
        challenge: String,
    },
    VerifyWebAuthn {
        username: String,
        signature: String,
        authenticator_data: String,
        client_data_json: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let client = client_sdk::rest_client::NodeApiHttpClient::new(cli.host).unwrap();

    let contract_name = &cli.contract_name;

    let prover = Risc0Prover::new(GUEST_ELF);

    match cli.command {
        Commands::RegisterContract {} => {
            // Build initial state of contract
            let initial_state = IdentityContractState::new();
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
        Commands::RegisterWebAuthn {
            username,
            credential_id,
            public_key,
        } => {
            // Convert hex inputs to byte vectors.
            let credential_id =
                hex::decode(credential_id).expect("Invalid hex string for credential_id");
            let public_key = hex::decode(public_key).expect("Invalid hex string for public_key");

            let action = WebAuthnAction::Register {
                username: username.clone(),
                credential_id,
                public_key,
            };

            let blobs = vec![sdk::Blob {
                contract_name: contract_name.clone().into(),
                data: sdk::BlobData(
                    bincode::encode_to_vec(action, bincode::config::standard())
                        .expect("failed to encode WebAuthn Register action"),
                ),
            }];

            let blob_tx = BlobTransaction {
                identity: Identity(username.clone()),
                blobs: blobs.clone(),
            };

            let blob_tx_hash = client.send_tx_blob(&blob_tx).await.unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            let initial_state = client
                .get_contract(&contract_name.clone().into())
                .await
                .unwrap()
                .state;
            let inputs = ContractInput {
                initial_state,
                identity: blob_tx.identity,
                tx_hash: blob_tx_hash.clone(),
                private_input: Vec::new(),
                tx_ctx: None,
                blobs: blobs.clone(),
                index: sdk::BlobIndex(0),
            };

            let proof = prover.prove(inputs).await.unwrap();
            let proof_tx = ProofTransaction {
                proof,
                contract_name: contract_name.clone().into(),
            };

            let proof_tx_hash = client.send_tx_proof(&proof_tx).await.unwrap();
            println!("✅ Proof tx sent. Tx hash: {}", proof_tx_hash);
        }
        Commands::StartWebAuthn {
            username,
            challenge,
        } => {
            // Decode the hex-encoded challenge.
            let challenge = hex::decode(challenge).expect("Invalid hex string for challenge");

            let action = WebAuthnAction::StartAuthentication {
                username: username.clone(),
                challenge,
            };

            let blobs = vec![sdk::Blob {
                contract_name: contract_name.clone().into(),
                data: sdk::BlobData(
                    bincode::encode_to_vec(action, bincode::config::standard())
                        .expect("failed to encode WebAuthn StartAuthentication action"),
                ),
            }];

            let blob_tx = BlobTransaction {
                identity: Identity(username.clone()),
                blobs: blobs.clone(),
            };

            let blob_tx_hash = client.send_tx_blob(&blob_tx).await.unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            let initial_state = client
                .get_contract(&contract_name.clone().into())
                .await
                .unwrap()
                .state;
            let inputs = ContractInput {
                initial_state,
                identity: blob_tx.identity,
                tx_hash: blob_tx_hash.clone(),
                private_input: Vec::new(),
                tx_ctx: None,
                blobs: blobs.clone(),
                index: sdk::BlobIndex(0),
            };

            let proof = prover.prove(inputs).await.unwrap();
            let proof_tx = ProofTransaction {
                proof,
                contract_name: contract_name.clone().into(),
            };

            let proof_tx_hash = client.send_tx_proof(&proof_tx).await.unwrap();
            println!("✅ Proof tx sent. Tx hash: {}", proof_tx_hash);
        }
        Commands::VerifyWebAuthn {
            username,
            signature,
            authenticator_data,
            client_data_json,
        } => {
            // Decode hex-encoded fields into byte vectors.
            let signature = hex::decode(signature).expect("Invalid hex string for signature");
            let authenticator_data =
                hex::decode(authenticator_data).expect("Invalid hex string for authenticator_data");
            let client_data_json =
                hex::decode(client_data_json).expect("Invalid hex string for client_data_json");

            let action = WebAuthnAction::VerifyAuthentication {
                username: username.clone(),
                signature,
                authenticator_data,
                client_data_json,
            };

            let blobs = vec![sdk::Blob {
                contract_name: contract_name.clone().into(),
                data: sdk::BlobData(
                    bincode::encode_to_vec(action, bincode::config::standard())
                        .expect("failed to encode WebAuthn VerifyAuthentication action"),
                ),
            }];

            let blob_tx = BlobTransaction {
                identity: Identity(username.clone()),
                blobs: blobs.clone(),
            };

            let blob_tx_hash = client.send_tx_blob(&blob_tx).await.unwrap();
            println!("✅ Blob tx sent. Tx hash: {}", blob_tx_hash);

            let initial_state = client
                .get_contract(&contract_name.clone().into())
                .await
                .unwrap()
                .state;
            let inputs = ContractInput {
                initial_state,
                identity: blob_tx.identity,
                tx_hash: blob_tx_hash.clone(),
                private_input: Vec::new(),
                tx_ctx: None,
                blobs: blobs.clone(),
                index: sdk::BlobIndex(0),
            };

            let proof = prover.prove(inputs).await.unwrap();
            let proof_tx = ProofTransaction {
                proof,
                contract_name: contract_name.clone().into(),
            };

            let proof_tx_hash = client.send_tx_proof(&proof_tx).await.unwrap();
            println!("✅ Proof tx sent. Tx hash: {}", proof_tx_hash);
        }
    }
}
