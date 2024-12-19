import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY, Signer } from '@solana/web3.js';
import { Program, AnchorProvider, web3, BN } from '@project-serum/anchor';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '@solana/spl-token';
import bs58 from 'bs58';

const OPENBOOK_PROGRAM_ID = new PublicKey('opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb');
// Devnet USDC mint
const USDC_MINT = new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr');
// Devnet SOL mint (wrapped)
const WSOL_MINT = new PublicKey('So11111111111111111111111111111111111111112');
// Pre-funded keypair for testing (ONLY FOR DEVNET/TESTNET)
// Update the oracle addresses to use Pyth price accounts for devnet
const ORACLE_A_DEVNET = new PublicKey('J83w4HKfqxwcq3BEMMkPFSppX3gqekLyLJBexebFVkix'); // Pyth SOL/USD
const ORACLE_B_DEVNET = new PublicKey('Gnt27xtC473ZT2Mw5u8wZ68Z3gULkSTb5DuxJy7eJotD'); // Pyth USDC/USD

// Update the CreateMarketArgs class
export class CreateMarketArgs {
  name: string;
  quoteLotSize: BN;
  baseLotSize: BN;
  makerFee: BN;
  takerFee: BN;
  timeExpiry: BN;

  constructor(args: {
    name?: string;
    quoteLotSize?: number;
    baseLotSize?: number;
    makerFee?: number;
    takerFee?: number;
    timeExpiry?: number;
  }) {
    this.name = args.name || "SOL-USDC";
    this.quoteLotSize = new BN(args.quoteLotSize || 100); // 0.1 USDC
    this.baseLotSize = new BN(args.baseLotSize || 100);  // 0.1 SOL
    this.makerFee = new BN(args.makerFee || -200);      // -0.02%
    this.takerFee = new BN(args.takerFee || 400);       // 0.04%
    this.timeExpiry = new BN(args.timeExpiry || 0);
  }
}

interface AccountField {
  name: string;
  type: string;
  isMut: boolean;
  isSigner: boolean;
  isOptional?: boolean;
}

interface AccountDefinition {
  name: string;
  accounts: AccountField[];
}

export function generateAccountStructure(instructionName: string): AccountDefinition {
  // Base common accounts that most instructions use
  const commonAccounts: AccountField[] = [
    {
      name: 'systemProgram',
      type: 'publicKey',
      isMut: false,
      isSigner: false,
    },
    {
      name: 'tokenProgram',
      type: 'publicKey',
      isMut: false,
      isSigner: false,
    },
    {
      name: 'rent',
      type: 'publicKey',
      isMut: false,
      isSigner: false,
    }
  ];

  // Instruction-specific accounts
  const accountMap: { [key: string]: AccountField[] } = {
    createMarket: [
      {
        name: 'market',
        type: 'publicKey',
        isMut: true,
        isSigner: true,
      },
      {
        name: 'marketAuthority',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'bids',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'asks',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'eventHeap',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'payer',
        type: 'publicKey',
        isMut: true,
        isSigner: true,
      },
      {
        name: 'marketBaseVault',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'marketQuoteVault',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'baseMint',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'quoteMint',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'oracleA',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'oracleB',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'collectFeeAdmin',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
      {
        name: 'openOrdersAdmin',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
        isOptional: true,
      },
      {
        name: 'consumeEventsAdmin',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
        isOptional: true,
      },
      {
        name: 'eventAuthority',
        type: 'publicKey',
        isMut: false,
        isSigner: false,
      },
    ],
    placeOrder: [
      {
        name: 'signer',
        type: 'publicKey',
        isMut: false,
        isSigner: true,
      },
      {
        name: 'openOrdersAccount',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'market',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'bids',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'asks',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'eventHeap',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'marketVault',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
      {
        name: 'userTokenAccount',
        type: 'publicKey',
        isMut: true,
        isSigner: false,
      },
    ],
    // Add more instruction account structures as needed
  };

  // Get instruction-specific accounts or return empty array if not found
  const instructionAccounts = accountMap[instructionName] || [];

  // Generate class name
  const className = instructionName.charAt(0).toUpperCase() + 
                   instructionName.slice(1) + 
                   'Accounts';

  // Combine instruction-specific accounts with common accounts
  return {
    name: className,
    accounts: [...instructionAccounts, ...commonAccounts]
  };
}

export function generateAccountClass(accountDef: AccountDefinition): string {
  const fields = accountDef.accounts.map(acc => {
    const optional = acc.isOptional ? '?' : '';
    return `  ${acc.name}${optional}: PublicKey;`;
  }).join('\n');

  const constructorParams = accountDef.accounts.map(acc => {
    const optional = acc.isOptional ? '?' : '';
    return `    ${acc.name}${optional}: PublicKey`;
  }).join(',\n');

  const constructorAssignments = accountDef.accounts.map(acc => {
    if (acc.name === 'systemProgram') {
      return `    this.systemProgram = SystemProgram.programId;`;
    }
    if (acc.name === 'tokenProgram') {
      return `    this.tokenProgram = TOKEN_PROGRAM_ID;`;
    }
    if (acc.name === 'rent') {
      return `    this.rent = SYSVAR_RENT_PUBKEY;`;
    }
    return `    this.${acc.name} = ${acc.name};`;
  }).join('\n');

  return `
export class ${accountDef.name} {
${fields}

  constructor({
${constructorParams}
  }) {
${constructorAssignments}
  }

  toJSON() {
    return {
${accountDef.accounts.map(acc => 
        `      ${acc.name}: this.${acc.name}${acc.isOptional ? '?' : ''}.toString()`
      ).join(',\n')}
    };
  }
}`;
}

export function generateAccountInstances(instructionName: string): string {
  const accountDef = generateAccountStructure(instructionName);
  return generateAccountClass(accountDef);
}

const RPC_URL = "https://api.devnet.solana.com";

async function requestAirdropWithRetry(
  connection: Connection,
  address: PublicKey,
  amount: number,
  maxRetries = 3
): Promise<string> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const signature = await connection.requestAirdrop(address, amount);
      
      // Wait for confirmation with timeout
      const latestBlockhash = await connection.getLatestBlockhash();
      await connection.confirmTransaction({
        signature,
        ...latestBlockhash
      }, 'confirmed');
      
      // Verify the balance after airdrop
      const balance = await connection.getBalance(address);
      if (balance > 0) {
        console.log(`Airdrop successful. New balance: ${balance / web3.LAMPORTS_PER_SOL} SOL`);
        return signature;
      }
      throw new Error('Airdrop failed: Balance not updated');
    } catch (error) {
      console.log(`Airdrop attempt ${i + 1} failed:`, error);
      if (i === maxRetries - 1) throw error;
      // Wait before retry with exponential backoff
      await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
    }
  }
  throw new Error('All airdrop attempts failed');
}

export async function createAccountInstruction(
  connection: Connection,
  payer: PublicKey,
  space: number,
  owner: PublicKey,
  lamports?: number
): Promise<[Keypair, TransactionInstruction]> {
  const account = Keypair.generate();
  const rentExemptBalance = lamports ?? await connection.getMinimumBalanceForRentExemption(space);
  
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: payer,
    newAccountPubkey: account.publicKey,
    lamports: rentExemptBalance,
    space,
    programId: owner,
  });

  return [account, createAccountIx];
}

export async function executeTransaction(
  functionName: string,
  args: Record<string, string>,
  options: { gas?: string; attachedDeposit?: string } = {}
): Promise<string> {
  try {
    console.log('Executing function:', functionName);
    console.log('Raw arguments:', args);

    const connection = new Connection(RPC_URL, {
      commitment: 'confirmed',
      disableRetryOnRateLimit: true,
      confirmTransactionInitialTimeout: 60000
    });

    const keypair = generateMarketKeypairs();
    // Initialize payer
    const payer = keypair.get('payer');

    // Check payer balance
    const balance = await connection.getBalance(payer?.publicKey || new PublicKey(''));
    console.log(`Payer balance: ${balance / web3.LAMPORTS_PER_SOL} SOL`);
    
    if (balance < web3.LAMPORTS_PER_SOL) {
      throw new Error(`Insufficient balance: ${balance / web3.LAMPORTS_PER_SOL} SOL. Please fund the address: ${payer?.publicKey.toString() || ''}`);
    }

    // Create market and other accounts
    const marketKeypair = keypair.get('market');
    const [marketAuthority] = PublicKey.findProgramAddressSync(
      [Buffer.from('Market'), marketKeypair?.publicKey.toBuffer() || new Buffer('')],
      OPENBOOK_PROGRAM_ID
    );

    // Create accounts with proper space
    const [bidsAccount, bidsIx] = await createAccountInstruction(
      connection,
      payer?.publicKey || new PublicKey(''),
      65536,
      OPENBOOK_PROGRAM_ID
    );

    const [asksAccount, asksIx] = await createAccountInstruction(
      connection,
      payer?.publicKey || new PublicKey(''),
      65536,
      OPENBOOK_PROGRAM_ID
    );

    const [eventHeapAccount, eventHeapIx] = await createAccountInstruction(
      connection,
      payer?.publicKey || new PublicKey('') ,
      65536,
      OPENBOOK_PROGRAM_ID
    );

    // Create setup transaction
    const setupTx = new Transaction();
    setupTx.add(bidsIx, asksIx, eventHeapIx);
    setupTx.feePayer = payer?.publicKey || new PublicKey('')  ;
    
    const { blockhash } = await connection.getLatestBlockhash();
    setupTx.recentBlockhash = blockhash;

    // Sign setup transaction with all required signers
    const setupSigners = [payer, bidsAccount, asksAccount, eventHeapAccount];
    setupTx.sign(...setupSigners as Signer[]);
    
    const setupSignature = await connection.sendRawTransaction(setupTx.serialize());
    await connection.confirmTransaction(setupSignature);
    console.log('Setup transaction confirmed:', setupSignature);

    const createMarketArgs = new CreateMarketArgs({});
    const marketAccounts = {
      market: marketKeypair?.publicKey || new PublicKey(''),
      marketAuthority,
      bids: bidsAccount.publicKey,
      asks: asksAccount.publicKey,
      eventHeap: eventHeapAccount.publicKey,
      payer: payer?.publicKey || new PublicKey(''),
      marketBaseVault: await getAssociatedTokenAddress(
        WSOL_MINT,
        marketAuthority,
        true
      ),
      marketQuoteVault: await getAssociatedTokenAddress(
        USDC_MINT,
        marketAuthority,
        true
      ),
      baseMint: WSOL_MINT,
      quoteMint: USDC_MINT,
      systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID,
      associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      rent: SYSVAR_RENT_PUBKEY,
      oracleA: new PublicKey('GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU'),
      oracleB: new PublicKey('GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU'),
      collectFeeAdmin: payer?.publicKey || new PublicKey(''),
      openOrdersAdmin: null,
      consumeEventsAdmin: null,
      closeMarketAdmin: null,
      eventAuthority: PublicKey.findProgramAddressSync(
        [Buffer.from('__event_authority')],
        OPENBOOK_PROGRAM_ID
      )[0],
      program: OPENBOOK_PROGRAM_ID
    };

    const provider = new AnchorProvider(
      connection,
      {
        publicKey: payer?.publicKey || new PublicKey(''),
        signTransaction: async (tx: Transaction) => {
          tx.partialSign(payer as Signer);
          return tx;
        },
        signAllTransactions: async (txs: Transaction[]) => {
          return txs.map((tx) => {
            tx.partialSign(payer as Signer);
            return tx;
          });
        },
      },
      { commitment: 'confirmed' }
    );

    const idl = await (await fetch('/idl.json')).json();
    const program = new Program(idl, OPENBOOK_PROGRAM_ID, provider);

    const ix = await program.methods.createMarket(
      createMarketArgs.name,
      {
        confFilter: 0.1,
        maxStalenessSlots: new BN(100),
      },
      createMarketArgs.quoteLotSize,
      createMarketArgs.baseLotSize,
      createMarketArgs.makerFee,
      createMarketArgs.takerFee,
      createMarketArgs.timeExpiry
    )
      .accounts({
        ...marketAccounts,
        oracleA: ORACLE_A_DEVNET,
        oracleB: ORACLE_B_DEVNET,
      })
      .instruction();

    const transaction = new Transaction();
    transaction.add(ix);
    transaction.feePayer = payer?.publicKey || new PublicKey('');
    transaction.recentBlockhash = blockhash;

    // Sign with all required signers
    const signers = [payer, marketKeypair];
    transaction.sign(...signers as Signer[]);

    console.log('Transaction signatures:', transaction.signatures.map(s => s.publicKey.toString()));

    const rawTx = transaction.serialize();
    const signature = await connection.sendRawTransaction(rawTx, {
      skipPreflight: false,
      preflightCommitment: 'confirmed',
    });

    await connection.confirmTransaction(signature, 'confirmed');
    return signature;

  } catch (error) {
    console.error('Transaction error:', error);
    throw error;
  }
}

export interface ContractFunction {
  name: string;
  arguments: { name: string; type: string }[];
  returnType: string;
}

export async function parseRustContract(idlJson: string): Promise<ContractFunction[]> {
  try {
    const idl = JSON.parse(idlJson);
    return idl.instructions.map((instruction: any) => ({
      name: instruction.name,
      arguments: instruction.args.map((arg: any) => ({
        name: arg.name,
        type: typeof arg.type === 'string' ? arg.type : JSON.stringify(arg.type)
      })),
      returnType: instruction.returns ? JSON.stringify(instruction.returns) : 'void'
    }));
  } catch (error) {
    console.error('Error parsing IDL:', error);
    return [];
  }
}

export function generateKeypairsForAccounts(accountDef: AccountDefinition): Map<string, Keypair> {
  const generatedKeypairs = new Map<string, Keypair>();
  
  accountDef.accounts.forEach(account => {
    // Only generate keypairs for mutable accounts that are signers
    if (account.isMut && account.isSigner) {
      const keypair = Keypair.generate();
      generatedKeypairs.set(account.name, keypair);
      console.log(`Generated keypair for ${account.name}:`, keypair.publicKey.toString());
    }
  });

  return generatedKeypairs;
}

// Add this function to generate and store keypairs
export function generateMarketKeypairs() {
  const marketAccounts = generateAccountStructure('createMarket');
  // Store keypairs in a map
  const storedKeypairs = new Map<string, Keypair>();
  
  // Generate required keypairs
  const payer = Keypair.generate();
  const marketKeypair = Keypair.generate();
  const bidsAccount = Keypair.generate();
  const asksAccount = Keypair.generate();
  const eventHeapAccount = Keypair.generate();

  // Store them with labels
  storedKeypairs.set('payer', payer);
  storedKeypairs.set('market', marketKeypair);
  storedKeypairs.set('bids', bidsAccount);
  storedKeypairs.set('asks', asksAccount);
  storedKeypairs.set('eventHeap', eventHeapAccount);

  // Log the public keys
  storedKeypairs.forEach((keypair, name) => {
    console.log(`Generated ${name} keypair with pubkey:`, keypair.publicKey.toString());
  });

  return storedKeypairs;
}

