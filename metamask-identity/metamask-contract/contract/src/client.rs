use std::any::Any;

use client_sdk::{
    helpers::{risc0::Risc0Prover, ClientSdkExecutor, ClientSdkProver},
    transaction_builder::{StateUpdater, TxExecutorBuilder},
};
use sdk::{utils::as_hyle_output, ContractName, Digestable, HyleOutput};

use crate::{execute, IdentityContractState};

pub mod metadata {
    pub const ELF: &[u8] = methods_identity::GUEST_ELF;
    //pub const PROGRAM_ID: [u8; 32] = methods_identity::GUEST_ID;
}
use metadata::*;

struct PseudoExecutor {}
impl ClientSdkExecutor for PseudoExecutor {
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

impl IdentityContractState {
    pub fn setup_builder<S: StateUpdater>(
        &self,
        contract_name: ContractName,
        builder: &mut TxExecutorBuilder<S>,
    ) {
        builder.init_with(
            contract_name,
            self.as_digest(),
            PseudoExecutor {},
            NoProver {},
        );
    }
}

struct NoProver {}

impl ClientSdkProver for NoProver {
    fn prove(
        &self,
        contract_input: sdk::ContractInput,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<sdk::ProofData>> + Send + '_>,
    > {
        Box::pin(async move { Err(anyhow::anyhow!("mmm_id proofs will be proved later")) })
    }
}
