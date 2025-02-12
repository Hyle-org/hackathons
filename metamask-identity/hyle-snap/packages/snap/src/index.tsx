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
//
//// Sign message using personal_sign
//async function signMessage(message: string) {
//  const hexMessage = toHexMessage(message); // Convert message to hex
//  console.log(hexMessage);
//  const ethAddr = await ethereum.request({
//    method: 'eth_requestAccounts',
//  });
//  console.log("account", ethAddr[0], hexMessage);
//
//  try {
//    const signature = await ethereum.request<string>({
//      method: 'personal_sign',
//      params: [hexMessage, ethAddr[0]],
//    });
//    console.log("signed");
//
//    console.log("signature", signature, hexMessage);
//    return signature;
//  } catch (error) {
//    console.log("error in signature", error);
//    await snap.request({
//      method: 'snap_notify',
//      params: {
//        type: 'inApp',
//        message: `Signing failed: ${error.message} with account ${account} and message ${message}`,
//      },
//    });
//    return 'Signing failed';
//  }
//}

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
//
//export const onRpcRequest: OnRpcRequestHandler = async ({
//  origin,
//  request,
//}) => {
//  console.log('RPC request', request);
//  switch (request.method) {
//    case "get_account":
//      return await getIdentity();
//    case "register_account":
//      {
//        console.log("register_account");
//        const signature = await signMessage("hyle registration");
//        console.log("ouch", signature);
//        const generatedProof = await registerIdentity(signature);
//
//        //await snap.request({
//        //  method: 'snap_dialog',
//        //  params: {
//        //    type: 'alert',
//        //    content: (
//        //      <Box>
//        //        <Text>Registration Completed !</Text>
//        //        <Divider />
//        //        <Text>generatedProof tx:</Text>
//        //        <Text>{generatedProof}</Text>
//        //      </Box>
//        //    ),
//        //  },
//        //});
//      }
//      return "done!"
//
//    default:
//      throw new Error("Method not found.")
//  }
//}
//
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

//// Handle user actions
//export const onUserInput: OnUserInputHandler = async ({ id, event }) => {
//  if (event.type === UserInputEventType.ButtonClickEvent) {
//    switch (event.name) {
//      case 'register-button': {
//        const signature = await signMessage();
//        const generatedProof = await registerIdentity(signature);
//
//        await snap.request({
//          method: 'snap_dialog',
//          params: {
//            type: 'alert',
//            content: (
//              <Box>
//                <Text>Registration Completed !</Text>
//                <Divider />
//                <Text>generatedProof tx:</Text>
//                <Text>{generatedProof}</Text>
//              </Box>
//            ),
//          },
//        });
//        break;
//      }
//    }
//  }
//};

export const onSignature: OnSignatureHandler = async ({
  signature,
}) => {
  if (typeof signature.data !== 'string') {
    return {
      content: <Text>Invalid signature data</Text>,
      severity: SeverityLevel.Critical,
    };
  }

  const { blobs, nonce } = parseMessage(fromHexMessage(signature.data));

  const renderInsight = (blob: Blob) => {
    console.log("render", blob);
    switch (blob.contract_name) {
      case "hyllar":
      case "hyllar2":
        {
          const action = deserializeERC20Action(blob);
          return erc20ActionToInsight(action.parameters);
        }
      default:
        return (<Text key="unknown">Unknown contract {blob.contract_name} </Text>);
    }
  }

  return {
    content: (
      <Box>
        <Heading>Signature Data:</Heading>
        <Text>Nonce: {nonce.toString()}</Text>
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

function parseMessage(message: string): { blobs: Blob[], nonce: number } {
  const blobs: Blob[] = [];

  const firstSpace = message.indexOf(' ');
  const nonce = parseInt(message.slice(firstSpace + 1, message.indexOf(' ', firstSpace + 1)), 10);

  // Retirer le nonce et le mot "verify" pour traiter le reste
  const remaining = message.slice(firstSpace + 1 + nonce.toString().length).trim();

  // Séparer les parties en fonction du nom du contrat suivi des crochets
  const regex = /(\w+\d*)\s\[(.*?)\]/g;
  let match;

  while ((match = regex.exec(remaining)) !== null) {
    const contractName = match[1] || ""; // Nom du contrat
    const dataString = match[2] || ""; // Contenu du tableau sous forme de string

    // Convertir la chaîne des données en tableau de nombres
    const data = dataString
      .split(',') // Diviser par la virgule
      .map(num => parseInt(num.trim(), 10)); // Convertir chaque élément en nombre

    // Ajouter le Blob avec le nonce
    blobs.push({
      contract_name: contractName, // Nom du contrat
      data: data,
    });
  }

  return { blobs, nonce };
}

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
