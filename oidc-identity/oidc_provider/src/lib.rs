#![no_std]

extern crate alloc;
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use hyle_model::{Blob, BlobData, BlobIndex, ContractAction, ContractName, Digestable};
use sdk::RunResult;

pub mod provider;

use alloc::{format, string::String, vec::Vec};

pub trait IdentityVerification {
    fn register_identity(
        &mut self,
        account: &str,
        n: &str,
        e: &str,
        private_input: &str,
    ) -> Result<(), &'static str>;

    fn verify_identity(
        &mut self,
        account: &str,
        nonce: u32,
        n: &str,
        e: &str,
        private_input: &str,
    ) -> Result<bool, &'static str>;

    fn get_identity_info(&self, account: &str) -> Result<String, &'static str>;
}

/// Enum representing the actions that can be performed by the IdentityVerification contract.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum IdentityAction {
    RegisterIdentity {
        account: String,
        n: String,
        e: String,
    },
    VerifyIdentity {
        account: String,
        nonce: u32,
        n: String,
        e: String,
    },
    GetIdentityInfo {
        account: String,
    },
}

impl IdentityAction {
    pub fn as_blob(&self, contract_name: ContractName) -> Blob {
        <Self as ContractAction>::as_blob(self, contract_name, None, None)
    }
}

impl ContractAction for IdentityAction {
    fn as_blob(
        &self,
        contract_name: ContractName,
        _caller: Option<BlobIndex>,
        _callees: Option<Vec<BlobIndex>>,
    ) -> Blob {
        Blob {
            contract_name,
            data: BlobData(
                bincode::encode_to_vec(self, bincode::config::standard())
                    .expect("failed to encode program inputs"),
            ),
        }
    }
}

pub fn execute_action<T: IdentityVerification + Digestable>(
    mut state: T,
    action: IdentityAction,
    private_input: &str,
) -> RunResult<T> {
    let program_output = match action {
        IdentityAction::RegisterIdentity { account, n, e } => {
            match state.register_identity(&account, &n, &e, private_input) {
                Ok(()) => Ok(format!(
                    "Successfully registered identity for account: {}",
                    account
                )),
                Err(err) => Err(format!("Failed to register identity: {}", err)),
            }
        }
        IdentityAction::VerifyIdentity {
            account,
            nonce,
            n,
            e,
        } => match state.verify_identity(&account, nonce, &n, &e, private_input) {
            Ok(true) => Ok(format!("Identity verified for account: {}", account)),
            Ok(false) => Err(format!(
                "Identity verification failed for account: {}",
                account
            )),
            Err(err) => Err(format!("Error verifying identity: {}", err)),
        },
        IdentityAction::GetIdentityInfo { account } => match state.get_identity_info(&account) {
            Ok(info) => Ok(format!(
                "Retrieved identity info for account: {}: {}",
                account, info
            )),
            Err(err) => Err(format!("Failed to get identity info: {}", err)),
        },
    };
    program_output.map(|output| (output, state, alloc::vec![]))
}
