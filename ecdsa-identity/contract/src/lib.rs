use std::collections::BTreeMap;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use actions::IdentityAction;

use hex::decode;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sdk::{Digestable, RunResult};
use sha2::{Digest, Sha256};

pub mod actions;

extern crate alloc;

/// Entry point of the contract's logic
pub fn execute(contract_input: sdk::ContractInput) -> RunResult<IdentityContractState> {
    // Parse contract inputs
    let (input, action) = sdk::guest::init_raw::<IdentityAction>(contract_input);

    let action = action.ok_or("Failed to parse action")?;

    // Parse initial state
    let state: IdentityContractState = input
        .initial_state
        .clone()
        .try_into()
        .expect("failed to parse state");

    let identity = input.identity;
    let contract_name = &input
        .blobs
        .get(input.index.0)
        .ok_or("No blob")?
        .contract_name;

    if input.index.0 == 0 {
        // Identity blob should be at position 0
        let blobs = input
            .blobs
            .split_first()
            .map(|(_, rest)| rest)
            .ok_or("No blobs")?;
        execute_action(state, action, contract_name, identity, blobs)
    } else {
        // Otherwise, it's less efficient as need to clone blobs & the remove is O(n)
        let mut blobs = input.blobs.clone();
        blobs.remove(input.index.0);
        execute_action(state, action, contract_name, identity, &blobs)
    }
}

/// Struct to hold account's information
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct AccountInfo {
    pub hash: String,
    pub nonce: u32,
}

/// The state of the contract, that is totally serialized on-chain
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct IdentityContractState {
    identities: BTreeMap<String, AccountInfo>,
}

/// Some helper methods for the state
impl IdentityContractState {
    pub fn new() -> Self {
        IdentityContractState {
            identities: BTreeMap::new(),
        }
    }

    pub fn get_nonce(&self, username: &str) -> Result<u32, &'static str> {
        let info = self.identities.get(username).ok_or("Identity not found")?;
        Ok(info.nonce)
    }
}

pub fn execute_action(
    mut state: IdentityContractState,
    action: IdentityAction,
    contract_name: &sdk::ContractName,
    account: sdk::Identity,
    blobs: &[sdk::Blob],
) -> RunResult<IdentityContractState> {
    if !account.0.ends_with(&contract_name.0) {
        return Err(format!(
            "Invalid account extension. '.{contract_name}' expected."
        ));
    }
    let pub_key = account
        .0
        .trim_end_matches(&contract_name.0)
        .trim_end_matches(".");

    let program_output = match action {
        IdentityAction::RegisterIdentity { signature } => {
            state.register_identity(pub_key, &signature)
        }
        IdentityAction::VerifyIdentity { nonce, signature } => match signature {
            Some(sig) => match state.verify_identity(pub_key, nonce, blobs, &sig) {
                Ok(true) => Ok(format!("Identity verified for account: {}", account)),
                Ok(false) => Err(format!(
                    "Identity verification failed for account: {}",
                    account
                )),
                Err(err) => Err(format!("⚠️ Error verifying identity: {}", err)),
            },
            None => Err(format!(
                "Identity verification failed for account {}, missing signature",
                account
            )),
        },
    };
    program_output.map(|output| (output, state, alloc::vec![]))
}

// The IdentityVerification trait is implemented for the IdentityContractState struct
// This trait is given by the sdk, as a "standard" for identity verification contracts
// but you could do the same logic without it.
impl IdentityContractState {
    fn register_identity(&mut self, pub_key: &str, signature: &str) -> Result<String, String> {
        let valid = verify_signature(pub_key, signature, "Hyle Registration").unwrap();

        if !valid {
            return Err("Invalid signature".to_string());
        }

        let mut hasher = Sha256::new();
        hasher.update(pub_key.as_bytes());
        let hash_bytes = hasher.finalize();
        let account_info = AccountInfo {
            hash: hex::encode(hash_bytes),
            nonce: 0,
        };

        if self
            .identities
            .insert(pub_key.to_string(), account_info)
            .is_some()
        {
            return Err("Identity already exists".to_string());
        }
        Ok("Identity registered".to_string())
    }

    fn verify_identity(
        &mut self,
        pub_key: &str,
        nonce: u32,
        blobs: &[sdk::Blob],
        signature: &str,
    ) -> Result<bool, String> {
        match self.identities.get_mut(pub_key) {
            Some(stored_info) => {
                if nonce != stored_info.nonce {
                    return Err("Invalid nonce".to_string());
                }

                let message = blobs
                    .iter()
                    .map(|blob| format!("{} {:?}", blob.contract_name, blob.data.0))
                    .collect::<Vec<String>>()
                    .join(" ");

                let message = format!("verify {} {}", nonce, message);

                let valid = verify_signature(pub_key, signature, &message).unwrap();

                if !valid {
                    return Err("Invalid signature".to_string());
                }

                let mut hasher = Sha256::new();
                hasher.update(pub_key.as_bytes());
                let hashed = hex::encode(hasher.finalize());

                if *stored_info.hash != hashed {
                    return Ok(false);
                }

                stored_info.nonce += 1;
                Ok(true)
            }
            None => Err("Identity not found".to_string()),
        }
    }

    #[allow(dead_code)]
    fn get_identity_info(&self, account: &str) -> Result<String, &'static str> {
        match self.identities.get(account) {
            Some(info) => Ok(serde_json::to_string(&info).map_err(|_| "Failed to serialize")?),
            None => Err("Identity not found"),
        }
    }
}

impl Default for IdentityContractState {
    fn default() -> Self {
        Self::new()
    }
}

/// Helpers to transform the contrat's state in its on-chain state digest version.
/// In an optimal version, you would here only returns a hash of the state,
/// while storing the full-state off-chain
impl Digestable for IdentityContractState {
    fn as_digest(&self) -> sdk::StateDigest {
        sdk::StateDigest(
            bincode::encode_to_vec(self, bincode::config::standard())
                .expect("Failed to encode Balances"),
        )
    }
}
impl From<sdk::StateDigest> for IdentityContractState {
    fn from(state: sdk::StateDigest) -> Self {
        let (state, _) = bincode::decode_from_slice(&state.0, bincode::config::standard())
            .map_err(|_| "Could not decode identity state".to_string())
            .unwrap();
        state
    }
}

fn verify_signature(pub_key: &str, signature_hex: &str, message: &str) -> Result<bool, String> {
    // decode pubkey
    let pubkey_bytes = decode(pub_key).map_err(|_| "Failed to decode Pub key".to_string())?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("Failed to generate verifying key");

    // decode signature
    let signature_bytes =
        decode(signature_hex).map_err(|_| "Failed to decode Signature".to_string())?;
    let signature = Signature::from_der(&signature_bytes).unwrap();

    let msg = message.as_bytes();

    let is_valid = verifying_key.verify(msg, &signature).is_ok();

    Ok(is_valid)
}
