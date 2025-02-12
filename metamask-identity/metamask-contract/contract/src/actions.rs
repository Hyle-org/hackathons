use borsh::{BorshDeserialize, BorshSerialize};
use sdk::{Blob, BlobData, BlobIndex, ContractAction, ContractName};
use serde::{Deserialize, Serialize};

extern crate alloc;

/// Enum representing the actions that can be performed by the IdentityVerification contract.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum IdentityAction {
    RegisterIdentity { signature: String },
    VerifyIdentity { nonce: u32, signature: String },
}

impl IdentityAction {
    #[allow(dead_code)]
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
            data: BlobData(borsh::to_vec(self).expect("failed to encode program inputs")),
        }
    }
}
