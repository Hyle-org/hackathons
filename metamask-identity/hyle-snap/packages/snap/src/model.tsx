import { borshSerialize, borshDeserialize, BorshSchema, Unit } from 'borsher';


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

const schema = BorshSchema.Enum({
  RegisterIdentity: BorshSchema.Struct({
    account: BorshSchema.String,
  }),
  Circle: BorshSchema.Struct({
    account: BorshSchema.String,
    nonce: BorshSchema.u32,
  }),
});


