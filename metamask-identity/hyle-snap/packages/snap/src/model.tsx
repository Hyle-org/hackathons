import { borshSerialize, borshDeserialize, BorshSchema, Unit } from 'borsher';
import { Blob, ContractName } from './hyle';

//pub enum IdentityAction {
//    RegisterIdentity { account: String },
//    VerifyIdentity { account: String, nonce: u32 },
//    GetIdentityInfo { account: String },
//}

export type IdentityAction =
  {
    RegisterIdentity: {
      account: string;
    };
  }
  | {
    VerifyIdentity: {
      account: string;
      nonce: number;
    };
  };

export const serialize = (action: IdentityAction): number[] => {
  return Array.from(borshSerialize(schema, action));
};

export const deserializeIdentityAction = (blob: Blob): IdentityAction => {
  return borshDeserialize(schema, Buffer.from(blob.data));
}

const schema = BorshSchema.Enum({
  RegisterIdentity: BorshSchema.Struct({
    account: BorshSchema.String,
  }),
  Circle: BorshSchema.Struct({
    account: BorshSchema.String,
    nonce: BorshSchema.u32,
  }),
});


export type ERC20Action =
  | { TotalSupply: {} }
  | { BalanceOf: { account: string } }
  | { Transfer: { recipient: string; amount: number } }
  | { TransferFrom: { sender: string; recipient: string; amount: number } }
  | { Approve: { spender: string; amount: number } }
  | { Allowance: { owner: string; spender: string } };

export const buildTransferBlob = (
  recipient: string,
  token: ContractName,
  amount: number,
): Blob => {
  const action: ERC20Action = {
    Transfer: { recipient, amount },
  };

  const blob: Blob = {
    contract_name: token,
    data: serializeERC20Action(action),
  };
  return blob;
};

export const serializeERC20Action = (action: ERC20Action): number[] => {
  return Array.from(borshSerialize(erc20Schema, action));
};

export const deserializeERC20Action = (blob: Blob): ERC20Action => {
  return borshDeserialize(erc20Schema, Buffer.from(blob.data));
};

const erc20Schema = BorshSchema.Enum({
  TotalSupply: BorshSchema.Unit,

  BalanceOf: BorshSchema.Struct({
    account: BorshSchema.String,
  }),

  Transfer: BorshSchema.Struct({
    recipient: BorshSchema.String,
    amount: BorshSchema.u128,
  }),

  TransferFrom: BorshSchema.Struct({
    sender: BorshSchema.String,
    recipient: BorshSchema.String,
    amount: BorshSchema.u128,
  }),

  Approve: BorshSchema.Struct({
    spender: BorshSchema.String,
    amount: BorshSchema.u128,
  }),

  Allowance: BorshSchema.Struct({
    owner: BorshSchema.String,
    spender: BorshSchema.String,
  }),
});

