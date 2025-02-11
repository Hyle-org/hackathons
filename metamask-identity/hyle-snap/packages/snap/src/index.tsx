import {
  OnUserInputHandler,
  OnHomePageHandler,
  OnInstallHandler,
  OnSignatureHandler,
  OnRpcRequestHandler,
  SeverityLevel,
} from '@metamask/snaps-sdk';
import { UserInputEventType } from '@metamask/snaps-sdk';
import { Box, Heading, Text, Divider, Button } from '@metamask/snaps-sdk/jsx';

import { Blob, BlobTransaction, contract_name, getIdentity, HYLE_NODE_URL, registerIdentity, transfer } from './hyle';
import { deserializeERC20Action, deserializeIdentityAction, ERC20Action } from './model';

async function getAccount() {
  // Retrieve stored account
  let state = await snap.request({
    method: 'snap_manageState',
    params: { operation: 'get' },
  });

  // If no stored account, request from MetaMask
  if (!state || !state.account) {
    const accounts = await ethereum.request({ method: 'eth_requestAccounts' });

    // If accounts exist, store the first one
    if (accounts.length > 0) {
      state = { account: accounts[0] };

      // Save account in Snap state
      await snap.request({
        method: 'snap_manageState',
        params: { operation: 'update', newState: state },
      });
    } else {
      state = { account: 'No account found' };
    }
  }

  return state.account;
}

// Sign message using personal_sign
async function signMessage(message: string) {
  const hexMessage = toHexMessage(message); // Convert message to hex
  console.log(hexMessage);
  const ethAddr = await ethereum.request({
    method: 'eth_requestAccounts',
  });
  console.log(ethAddr[0]);

  try {
    const signature = await ethereum.request<string>({
      method: 'personal_sign',
      params: [hexMessage, ethAddr[0]],
    });

    return signature;
  } catch (error) {
    console.log(error);
    await snap.request({
      method: 'snap_notify',
      params: {
        type: 'inApp',
        message: `Signing failed: ${error.message} with account ${account} and message ${message}`,
      },
    });
    return 'Signing failed';
  }
}

// Convert message to hex format
function toHexMessage(message: string): string {
  return `0x${Buffer.from(message, 'utf8').toString('hex')}`;
}

function fromHexMessage(hexMessage: string): string {
  if (hexMessage.startsWith('0x')) {
    hexMessage = hexMessage.slice(2);
  }
  return Buffer.from(hexMessage, 'hex').toString('utf8').replace(/\0/g, '');
}

export const onRpcRequest: OnRpcRequestHandler = async ({
  origin,
  request,
}) => {
  console.log('RPC request', request);
  switch (request.method) {
    case "get_account":
      return await getIdentity();
    case "register_account":
      {
        const signature = await signMessage("hyle registration");
        const generatedProof = await registerIdentity(signature);

        //await snap.request({
        //  method: 'snap_dialog',
        //  params: {
        //    type: 'alert',
        //    content: (
        //      <Box>
        //        <Text>Registration Completed !</Text>
        //        <Divider />
        //        <Text>generatedProof tx:</Text>
        //        <Text>{generatedProof}</Text>
        //      </Box>
        //    ),
        //  },
        //});
      }
      return "done!"

    default:
      throw new Error("Method not found.")
  }
}

//// Store account on Snap install
//export const onInstall: OnInstallHandler = async () => {
//  const account = await getAccount();
//  await snap.request({
//    method: 'snap_dialog',
//    params: {
//      type: 'alert',
//      content: (
//        <Box>
//          <Text>Connected Account: {account}</Text>
//        </Box>
//      ),
//    },
//  });
//};

// Use stored account in Home Page
export const onHomePage: OnHomePageHandler = async () => {
  const account = `${await getAccount()}.${contract_name}`;
  let balances = new Map<string, number>();
  try {
    const response = await fetch(`${HYLE_NODE_URL}/v1/indexer/contract/hyllar/state`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    const state = await response.json();
    balances.set("hyllar", state.balances[account]);

  } catch (error) {
  }
  try {
    const response = await fetch(`${HYLE_NODE_URL}/v1/indexer/contract/hyllar2/state`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    const state = await response.json();
    balances.set("hyllar2", state.balances[account]);

  } catch (error) {
  }

  console.log("balances", balances);

  return {
    content: (
      <Box>
        <Text>Account: {account}</Text>
        <Text>Balances:</Text>
        {Array.from(balances).map(([key, value]) => (
          <Text key={key}>
            {key}: {value?.toString() || "0"}
          </Text>
        ))}
        <Divider />
      </Box>
    ),
  };
};

// Handle user actions
export const onUserInput: OnUserInputHandler = async ({ id, event }) => {
  if (event.type === UserInputEventType.ButtonClickEvent) {
    switch (event.name) {
      case 'register-button': {
        const signature = await signMessage();
        const generatedProof = await registerIdentity(signature);

        await snap.request({
          method: 'snap_dialog',
          params: {
            type: 'alert',
            content: (
              <Box>
                <Text>Registration Completed !</Text>
                <Divider />
                <Text>generatedProof tx:</Text>
                <Text>{generatedProof}</Text>
              </Box>
            ),
          },
        });
        break;
      }
    }
  }
};

export const onSignature: OnSignatureHandler = async ({
  signature,
}) => {
  if (typeof signature.data !== 'string') {
    return {
      content: <Text>Invalid signature data</Text>,
      severity: SeverityLevel.Critical,
    };
  }
  const { blobs }: { blobs: Array<Blob> } = JSON.parse(fromHexMessage(signature.data));

  const renderInsight = (blob: Blob) => {
    console.log("render", blob);
    switch (blob.contract_name) {
      case "hyllar":
      case "hyllar2":
        {
          const action = deserializeERC20Action(blob);
          return erc20ActionToInsight(action);
        }
      default:
        return (<Text key="unknown">Unknown contract {blob.contract_name} </Text>);
    }
  }

  return {
    content: (
      <Box>
        {blobs.map((blob, index) => (
          <Box key={`${blob.contract_name}-${index}`} >
            <Divider />
            <Heading>Blob #{index.toString()}:</Heading>
            <Text>Contract: {blob.contract_name}</Text>
            <Text>Data: {renderInsight(blob)}</Text>
          </Box>
        ))
        }
      </Box >
    ),
    severity: SeverityLevel.Critical,
  };
};

export const erc20ActionToInsight = (action: ERC20Action): string => {
  if ("TotalSupply" in action) {
    return "TotalSupply";
  } else if ("BalanceOf" in action) {
    return `BalanceOf { account: ${action.BalanceOf.account} }`;
  } else if ("Transfer" in action) {
    return `Transfer { recipient: ${action.Transfer.recipient}, amount: ${action.Transfer.amount} }`;
  } else if ("TransferFrom" in action) {
    return `TransferFrom { sender: ${action.TransferFrom.sender}, recipient: ${action.TransferFrom.recipient}, amount: ${action.TransferFrom.amount} }`;
  } else if ("Approve" in action) {
    return `Approve { spender: ${action.Approve.spender}, amount: ${action.Approve.amount} }`
  } else if ("Allowance" in action) {
    return `Allowance { owner: ${action.Allowance.owner}, spender: ${action.Allowance.spender} }`;
  }
  return "Unknown ERC20Action"
};
