use std::any::Any;

use client_sdk::{
    helpers::{risc0::Risc0Prover, ClientSdkExecutor},
    transaction_builder::{ProvableBlobTx, StateUpdater, TxExecutorBuilder},
};
use sdk::{utils::as_hyle_output, ContractName, Digestable, HyleOutput};

use crate::{execute, OidcIdentity};

use oidc_provider::IdentityAction;

pub mod metadata {
    pub const OIDC_IDENTITY_ELF: &[u8] = include_bytes!("../oidc_identity.img");
    pub const PROGRAM_ID: [u8; 32] = sdk::str_to_u8(include_str!("../oidc_identity.txt"));
}
use metadata::*;

struct OidcIdentityPseudoExecutor {}
impl ClientSdkExecutor for OidcIdentityPseudoExecutor {
    fn execute(
        &self,
        contract_input: &sdk::ContractInput,
    ) -> anyhow::Result<(Box<dyn Any>, HyleOutput)> {
        let mut res = execute(contract_input.clone());
        let output = as_hyle_output(contract_input.clone(), &mut res);
        match res {
            Ok(res) => Ok((Box::new(res.1.clone()), output)),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }
}

impl OidcIdentity {
    pub fn setup_builder<S: StateUpdater>(
        &self,
        contract_name: ContractName,
        builder: &mut TxExecutorBuilder<S>,
    ) {
        builder.init_with(
            contract_name,
            self.as_digest(),
            OidcIdentityPseudoExecutor {},
            Risc0Prover::new(OIDC_IDENTITY_ELF),
        );
    }
}

pub fn verify_identity(
    builder: &mut ProvableBlobTx,
    contract_name: ContractName,
    state: &OidcIdentity,
    n: &str,
    e: &str,
    jwt: String,
) -> anyhow::Result<()> {
    let nonce = state
        .get_nonce(builder.identity.0.as_str())
        .map_err(|e| anyhow::anyhow!(e))?;

    let jwt = jwt.into_bytes().to_vec();

    builder
        .add_action(
            contract_name,
            IdentityAction::VerifyIdentity {
                account: builder.identity.0.clone(),
                nonce,
                n: n.to_string(),
                e: e.to_string(),
            },
            None,
            None,
        )?
        .with_private_input(move |_: &OidcIdentity| Ok(jwt.clone()));
    Ok(())
}

pub fn register_identity(
    builder: &mut ProvableBlobTx,
    contract_name: ContractName,
    n: &str,
    e: &str,
    jwt: String,
) -> anyhow::Result<()> {
    let jwt = jwt.into_bytes().to_vec();

    builder
        .add_action(
            contract_name,
            IdentityAction::RegisterIdentity {
                account: builder.identity.0.clone(),
                n: n.to_string(),
                e: e.to_string(),
            },
            None,
            None,
        )?
        .with_private_input(move |_: &OidcIdentity| Ok(jwt.clone()));
    Ok(())
}
