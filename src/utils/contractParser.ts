import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } from '@solana/web3.js';
import { Program, AnchorProvider, web3, BN } from '@project-serum/anchor';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '@solana/spl-token';
import bs58 from 'bs58';

const OPENBOOK_PROGRAM_ID = new PublicKey('opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb');
// Devnet USDC mint
const USDC_MINT = new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr');
// Devnet SOL mint (wrapped)
const WSOL_MINT = new PublicKey('So11111111111111111111111111111111111111112');
// Pre-funded keypair for testing (ONLY FOR DEVNET/TESTNET)
const PREFUNDED_KEYPAIR = Keypair.fromSecretKey(
  bs58.decode(process.env.PRIVATE_KEY || '')
);

// Store keypairs in map for signing
const keypairs = new Map<string, Keypair>();
function addKeypair(keypair: Keypair, name: string) {
  keypairs.set(keypair.publicKey.toString(), keypair);
  console.log(`Added ${name} keypair with pubkey:`, keypair.publicKey.toString());
  return keypair;
}

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

export class CreateMarketAccounts {
  market: PublicKey;
  marketAuthority: PublicKey;
  bids: PublicKey;
  asks: PublicKey;
  eventHeap: PublicKey;
  payer: PublicKey;
  marketBaseVault: PublicKey;
  marketQuoteVault: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  systemProgram: PublicKey;
  tokenProgram: PublicKey;
  associatedTokenProgram: PublicKey;
  rent: PublicKey;
  oracleA: PublicKey;
  oracleB: PublicKey;
  collectFeeAdmin: PublicKey;
  openOrdersAdmin: PublicKey | null;
  consumeEventsAdmin: PublicKey | null;
  closeMarketAdmin: PublicKey | null;
  eventAuthority: PublicKey;
  program: PublicKey;

  constructor(args: {
    market: PublicKey;
    marketAuthority: PublicKey;
    bids: PublicKey;
    asks: PublicKey;
    eventHeap: PublicKey;
    payer: PublicKey;
    marketBaseVault: PublicKey;
    marketQuoteVault: PublicKey;
    baseMint: PublicKey;
    quoteMint: PublicKey;
    oracleA?: PublicKey;
    oracleB?: PublicKey;
    collectFeeAdmin?: PublicKey;
    openOrdersAdmin?: PublicKey;
    consumeEventsAdmin?: PublicKey;
    closeMarketAdmin?: PublicKey;
  }) {
    this.market = args.market;
    this.marketAuthority = args.marketAuthority;
    this.bids = args.bids;
    this.asks = args.asks;
    this.eventHeap = args.eventHeap;
    this.payer = args.payer;
    this.marketBaseVault = args.marketBaseVault;
    this.marketQuoteVault = args.marketQuoteVault;
    this.baseMint = args.baseMint;
    this.quoteMint = args.quoteMint;
    this.systemProgram = SystemProgram.programId;
    this.tokenProgram = TOKEN_PROGRAM_ID;
    this.associatedTokenProgram = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
    this.rent = SYSVAR_RENT_PUBKEY;
    this.oracleA = args.oracleA || new PublicKey('GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU');
    this.oracleB = args.oracleB || new PublicKey('GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU');
    this.collectFeeAdmin = args.collectFeeAdmin || args.payer;
    this.openOrdersAdmin = args.openOrdersAdmin || null;
    this.consumeEventsAdmin = args.consumeEventsAdmin || null;
    this.closeMarketAdmin = args.closeMarketAdmin || null;
    this.eventAuthority = PublicKey.findProgramAddressSync(
      [Buffer.from('__event_authority')],
      OPENBOOK_PROGRAM_ID
    )[0];
    this.program = OPENBOOK_PROGRAM_ID;
  }

  toJSON() {
    return {
      market: this.market.toString(),
      marketAuthority: this.marketAuthority.toString(),
      bids: this.bids.toString(),
      asks: this.asks.toString(),
      eventHeap: this.eventHeap.toString(),
      payer: this.payer.toString(),
      marketBaseVault: this.marketBaseVault.toString(),
      marketQuoteVault: this.marketQuoteVault.toString(),
      baseMint: this.baseMint.toString(),
      quoteMint: this.quoteMint.toString(),
      systemProgram: this.systemProgram.toString(),
      tokenProgram: this.tokenProgram.toString(),
      associatedTokenProgram: this.associatedTokenProgram.toString(),
      rent: this.rent.toString(),
      oracleA: this.oracleA.toString(),
      oracleB: this.oracleB.toString(),
      collectFeeAdmin: this.collectFeeAdmin.toString(),
      openOrdersAdmin: this.openOrdersAdmin?.toString() || null,
      consumeEventsAdmin: this.consumeEventsAdmin?.toString() || null,
      closeMarketAdmin: this.closeMarketAdmin?.toString() || null,
      eventAuthority: this.eventAuthority.toString(),
      program: this.program.toString(),
    };
  }
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

async function createAccountInstruction(
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

    // Initialize payer
    const payer = addKeypair(PREFUNDED_KEYPAIR, 'payer');

    // Check payer balance
    const balance = await connection.getBalance(payer.publicKey);
    console.log(`Payer balance: ${balance / web3.LAMPORTS_PER_SOL} SOL`);
    
    if (balance < web3.LAMPORTS_PER_SOL) {
      throw new Error(`Insufficient balance: ${balance / web3.LAMPORTS_PER_SOL} SOL. Please fund the address: ${payer.publicKey.toString()}`);
    }

    // Create market and other accounts
    const marketKeypair = addKeypair(Keypair.generate(), 'market');
    const [marketAuthority] = PublicKey.findProgramAddressSync(
      [Buffer.from('Market'), marketKeypair.publicKey.toBuffer()],
      OPENBOOK_PROGRAM_ID
    );

    // Create accounts with proper space
    const [bidsAccount, bidsIx] = await createAccountInstruction(
      connection,
      payer.publicKey,
      65536,
      OPENBOOK_PROGRAM_ID
    );
    addKeypair(bidsAccount, 'bids');

    const [asksAccount, asksIx] = await createAccountInstruction(
      connection,
      payer.publicKey,
      65536,
      OPENBOOK_PROGRAM_ID
    );
    addKeypair(asksAccount, 'asks');

    const [eventHeapAccount, eventHeapIx] = await createAccountInstruction(
      connection,
      payer.publicKey,
      65536,
      OPENBOOK_PROGRAM_ID
    );
    addKeypair(eventHeapAccount, 'eventHeap');

    // Create setup transaction
    const setupTx = new Transaction();
    setupTx.add(bidsIx, asksIx, eventHeapIx);
    setupTx.feePayer = payer.publicKey;
    
    const { blockhash } = await connection.getLatestBlockhash();
    setupTx.recentBlockhash = blockhash;

    // Sign setup transaction with all required signers
    const setupSigners = [payer, bidsAccount, asksAccount, eventHeapAccount];
    setupTx.sign(...setupSigners);
    
    const setupSignature = await connection.sendRawTransaction(setupTx.serialize());
    await connection.confirmTransaction(setupSignature);
    console.log('Setup transaction confirmed:', setupSignature);

    const createMarketArgs = new CreateMarketArgs({});
    const marketAccounts = {
      market: marketKeypair.publicKey,
      marketAuthority,
      bids: bidsAccount.publicKey,
      asks: asksAccount.publicKey,
      eventHeap: eventHeapAccount.publicKey,
      payer: payer.publicKey,
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
      collectFeeAdmin: payer.publicKey,
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
        publicKey: payer.publicKey,
        signTransaction: async (tx: Transaction) => {
          tx.partialSign(payer);
          return tx;
        },
        signAllTransactions: async (txs: Transaction[]) => {
          return txs.map((tx) => {
            tx.partialSign(payer);
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
    transaction.feePayer = payer.publicKey;
    transaction.recentBlockhash = blockhash;

    // Sign with all required signers
    const signers = [payer, marketKeypair];
    transaction.sign(...signers);

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

