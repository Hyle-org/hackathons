use actions::IdentityAction;
use borsh::{BorshDeserialize, BorshSerialize};
use hex::{decode, encode};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sdk::{Digestable, RunResult};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Keccak256;
use std::collections::BTreeMap;

#[cfg(feature = "client")]
pub mod client;

mod actions;

extern crate alloc;

/// Entry point of the contract's logic
pub fn execute(contract_input: sdk::ContractInput) -> RunResult<IdentityContractState> {
    // Parse contract inputs
    let (input, action) = sdk::guest::init_raw::<IdentityAction>(contract_input);

    let action = action.ok_or("Failed to parse action")?;

    // Parse initial state
    let state: IdentityContractState = input.initial_state.clone().try_into()?;

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
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct AccountInfo {
    pub pub_key_hash: String,
    pub nonce: u32,
}

/// The state of the contract, that is totally serialized on-chain
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
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

    pub fn get_nonce(&self, account: &str) -> Result<u32, &'static str> {
        let info = self.identities.get(account).ok_or("Identity not found")?;
        Ok(info.nonce)
    }
}

fn execute_action(
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
        IdentityAction::VerifyIdentity { nonce, signature } => {
            match state.verify_identity(pub_key, nonce, blobs, &signature) {
                Ok(true) => Ok(format!("Identity verified for account: {}", account)),
                Ok(false) => Err(format!(
                    "Identity verification failed for account: {}",
                    account
                )),
                Err(err) => Err(format!("Error verifying identity: {}", err)),
            }
        }
    };
    program_output.map(|output| (output, state, alloc::vec![]))
}

// The IdentityVerification trait is implemented for the IdentityContractState struct
// This trait is given by the sdk, as a "standard" for identity verification contracts
// but you could do the same logic without it.
impl IdentityContractState {
    fn register_identity(&mut self, pub_key: &str, signature: &str) -> Result<String, String> {
        // Parse the signature
        let valid = k256_verifier(pub_key, signature, "hyle registration");

        if !valid {
            return Err(format!(
                "Invalid register signature for {pub_key}, {signature}"
            ));
        }

        let pub_key_hash = Keccak256::digest(pub_key.as_bytes());
        let pub_key_hash_hex = encode(pub_key_hash);

        let account_info = AccountInfo {
            pub_key_hash: pub_key_hash_hex,
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
                // Compute Keccak256 hash of the account (to match register_identity)
                let pub_key_hash = Keccak256::digest(pub_key.as_bytes());
                let computed_hash = encode(pub_key_hash);

                if *stored_info.pub_key_hash != computed_hash {
                    return Ok(false);
                }

                // const message = `verify ${nonce} ${blobs.map((blob) => blob.contract_name + " " + blob.data).join(" ")}`;

                let message = blobs
                    .iter()
                    .map(|blob| format!("{} {:?}", blob.contract_name, blob.data.0))
                    .collect::<Vec<String>>()
                    .join(" ");
                let message = format!("verify {} {}", nonce, message);

                let valid = k256_verifier(pub_key, signature, &message);

                if !valid {
                    return Err(format!("Invalid signature for message {message}"));
                }

                stored_info.nonce += 1;
                Ok(true)
            }
            None => Err("Identity not found".to_string()),
        }
    }

    #[allow(dead_code)]
    fn get_identity_info(&self, account: &str) -> Result<AccountInfo, &'static str> {
        self.identities
            .get(account)
            .cloned()
            .ok_or("Identity not found")
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
        sdk::StateDigest(borsh::to_vec(&self).expect("Failed to encode Balances"))
    }
}

impl TryFrom<sdk::StateDigest> for IdentityContractState {
    type Error = String;

    fn try_from(state: sdk::StateDigest) -> Result<Self, Self::Error> {
        borsh::from_slice(&state.0).map_err(|_| "Could not decode identity state".to_string())
    }
}

pub fn k256_verifier(mut pub_key: &str, mut signature_hex: &str, message: &str) -> bool {
    pub_key = sanitize_hex(pub_key);
    signature_hex = sanitize_hex(signature_hex);

    let msg = message.as_bytes();

    // Apply Ethereum Signed Message Prefix (EIP-191)
    let eth_message = format!(
        "\x19Ethereum Signed Message:\n{}{}",
        msg.len(),
        String::from_utf8_lossy(msg)
    );

    let signature_bytes = decode(signature_hex).expect("Invalid hex string");
    let recovery_id_byte = signature_bytes.last().copied().expect("Signature is empty");
    // Normalize Ethereum's recovery ID
    let recovery_id_byte = if recovery_id_byte >= 27 {
        recovery_id_byte - 27
    } else {
        recovery_id_byte
    };
    let recovery_id = RecoveryId::try_from(recovery_id_byte).expect("Wrong recover id byte");

    let signature = Signature::from_slice(&signature_bytes[..64]).expect("Wrong signature");

    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(eth_message),
        &signature,
        recovery_id,
    )
    .expect("Error when recovering public key");

    let encoded_point = recovered_key.to_encoded_point(false);
    let pub_key_bytes = encoded_point.as_bytes();

    // Hash the public key (skip the first byte which is always 0x04)
    let hashed_key = Keccak256::digest(&pub_key_bytes[1..]);

    // Extract the last 20 bytes (Ethereum address format)
    let recovered_address = &hashed_key[12..]; // Last 20 bytes
    hex::encode(recovered_address) == pub_key
}

fn sanitize_hex(hex_str: &str) -> &str {
    hex_str.strip_prefix("0x").unwrap_or(hex_str)
}
