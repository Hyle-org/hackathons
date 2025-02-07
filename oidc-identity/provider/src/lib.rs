#![no_std]

extern crate alloc;
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use hyle_model::{Blob, BlobData, BlobIndex, ContractAction, ContractName, Digestable};
use sdk::RunResult;

use alloc::{format, string::String, vec::Vec};

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct JwkPublicKey {
    pub n: String,
    pub e: String,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct OpenIdContext {
    pub issuer: String,
    pub audience: String,
}

pub trait IdentityVerification {
    fn register_identity(
        &mut self,
        account: &str,
        context: &OpenIdContext,
        jwk_pub_key: &JwkPublicKey,
        private_input: &str,
    ) -> Result<(), &'static str>;

    fn verify_identity(
        &mut self,
        account: &str,
        nonce: u32,
        context: &OpenIdContext,
        jwk_pub_key: &JwkPublicKey,
        private_input: &str,
    ) -> Result<bool, &'static str>;

    fn get_identity_info(&self, account: &str) -> Result<String, &'static str>;
}

/// Enum representing the actions that can be performed by the IdentityVerification contract.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum IdentityAction {
    RegisterIdentity {
        account: String,
        context: OpenIdContext,
        jwk_pub_key: JwkPublicKey,
    },
    VerifyIdentity {
        account: String,
        nonce: u32,
        context: OpenIdContext,
        jwk_pub_key: JwkPublicKey,
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
        IdentityAction::RegisterIdentity {
            account,
            context,
            jwk_pub_key,
        } => match state.register_identity(&account, &context, &jwk_pub_key, private_input) {
            Ok(()) => Ok(format!(
                "Successfully registered identity for account: {}",
                account
            )),
            Err(err) => Err(format!("Failed to register identity: {}", err)),
        },
        IdentityAction::VerifyIdentity {
            account,
            nonce,
            context,
            jwk_pub_key,
        } => match state.verify_identity(&account, nonce, &context, &jwk_pub_key, private_input) {
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
