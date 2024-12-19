import { NextResponse } from 'next/server';
import { Connection, PublicKey } from '@solana/web3.js';
import { createAccountInstruction, generateMarketKeypairs } from '@/utils/contractParser';
import { TOKEN_PROGRAM_ID } from '@solana/spl-token';

const OPENBOOK_PROGRAM_ID = new PublicKey('opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb');
const RPC_URL = "https://api.devnet.solana.com";

const ACCOUNT_SIZES = {
  BIDS: 65536,
  ASKS: 65536,
  EVENT_HEAP: 65536,
  OPEN_ORDERS: 8192,
  OPEN_ORDERS_INDEXER: 4096,
  MARKET: 1024,
  STUB_ORACLE: 512
};

// Add type for account names
type AccountSizeKey = keyof typeof ACCOUNT_SIZES;

async function getInstructionAccounts(functionName: string, idl: any) {
  const instruction = idl.instructions.find((ix: any) => ix.name === functionName);
  if (!instruction) {
    throw new Error(`Instruction ${functionName} not found in IDL`);
  }
  return instruction.accounts;
}

async function generateAccountsForInstruction(
  connection: Connection,
  payer: PublicKey,
  accounts: any[],
  keypairs: Map<string, any>
) {
  const result: Record<string, any> = {};
  const instructions: Record<string, any> = {};

  for (const acc of accounts) {
    if (acc.name === 'systemProgram') {
      result[acc.name] = PublicKey.default.toString();
      continue;
    }
    if (acc.name === 'tokenProgram') {
      result[acc.name] = TOKEN_PROGRAM_ID.toString();
      continue;
    }

    // Generate new account if it needs to be mutable
    if (acc.isMut) {
      const size = ACCOUNT_SIZES[acc.name.toUpperCase() as AccountSizeKey] || 1024; // Default size if not specified
      const [newAccount, ix] = await createAccountInstruction(
        connection,
        payer,
        size,
        OPENBOOK_PROGRAM_ID
      );
      result[acc.name] = newAccount.publicKey.toString();
      instructions[`${acc.name}Ix`] = ix;
    } else {
      // Use existing keypair or payer for non-mutable accounts
      result[acc.name] = acc.isSigner ? payer.toString() : 
        (keypairs.get(acc.name)?.publicKey.toString() || payer.toString());
    }
  }

  return {
    ...result,
    instructions: Object.keys(instructions).length > 0 ? instructions : undefined
  };
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const functionName = searchParams.get('function');

    if (!functionName) {
      return NextResponse.json(
        { error: 'Function name is required' },
        { status: 400 }
      );
    }

    const connection = new Connection(RPC_URL, 'confirmed');
    const keypairs = generateMarketKeypairs();
    const payer = keypairs.get('payer');
    
    if (!payer) {
      throw new Error('Failed to generate payer keypair');
    }

    // Fetch IDL
    const idl = await fetch('http://localhost:3000/idl.json').then(res => res.json());
    
    // Get accounts structure for the function
    const accounts = await getInstructionAccounts(functionName, idl);
    
    // Generate accounts and instructions
    const result = await generateAccountsForInstruction(
      connection,
      payer.publicKey,
      accounts,
      keypairs
    );

    return NextResponse.json({
      success: true,
      data: result
    });

  } catch (error) {
    console.error('Error generating accounts:', error);
    return NextResponse.json(
      { error: 'Failed to generate accounts' },
      { status: 500 }
    );
  }
}
