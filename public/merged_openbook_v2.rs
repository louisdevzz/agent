// File: openbook-v2/programs/openbook-v2/fuzz/fuzz_targets/multiple_orders.rs
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};
use log::info;
use openbook_v2::instructions::MAX_EVENTS_CONSUME;
use openbook_v2_fuzz::{
    processor::TestSyscallStubs, FuzzContext, OracleId, ReferrerId, UserId, INITIAL_BALANCE,
};
use std::{collections::HashSet, sync::Once};

#[derive(Debug, Arbitrary, Clone)]
struct FuzzData {
    oracles: Option<OracleId>,
    market: openbook_v2::instruction::CreateMarket,
    instructions: Vec<FuzzInstruction>,
}

impl FuzzData {
    fn is_borsh_serializable(&self) -> bool {
        self.instructions.iter().all(|ix| match ix {
            FuzzInstruction::StubOracleSet { data, .. } => !data.price.is_nan(),
            _ => true,
        })
    }

    fn contains_place_order_ixs(&self) -> bool {
        self.instructions.iter().any(|ix| {
            matches!(
                ix,
                FuzzInstruction::PlaceOrder { .. }
                    | FuzzInstruction::PlaceOrderPegged { .. }
                    | FuzzInstruction::PlaceTakeOrder { .. }
                    | FuzzInstruction::CancelAllAndPlaceOrders { .. }
            )
        })
    }
}

#[derive(Debug, Arbitrary, Clone)]
enum FuzzInstruction {
    Deposit {
        user_id: UserId,
        data: openbook_v2::instruction::Deposit,
    },
    Refill {
        user_id: UserId,
        data: openbook_v2::instruction::Refill,
    },
    PlaceOrder {
        user_id: UserId,
        data: openbook_v2::instruction::PlaceOrder,
        makers: Option<HashSet<UserId>>,
    },
    PlaceOrderPegged {
        user_id: UserId,
        data: openbook_v2::instruction::PlaceOrderPegged,
        makers: Option<HashSet<UserId>>,
    },
    PlaceTakeOrder {
        user_id: UserId,
        data: openbook_v2::instruction::PlaceTakeOrder,
        makers: Option<HashSet<UserId>>,
    },
    EditOrder {
        user_id: UserId,
        data: openbook_v2::instruction::EditOrder,
        makers: Option<HashSet<UserId>>,
    },
    EditOrderPegged {
        user_id: UserId,
        data: openbook_v2::instruction::EditOrderPegged,
        makers: Option<HashSet<UserId>>,
    },
    CancelAllAndPlaceOrders {
        user_id: UserId,
        data: openbook_v2::instruction::CancelAllAndPlaceOrders,
        makers: Option<HashSet<UserId>>,
    },
    CancelOrder {
        user_id: UserId,
        data: openbook_v2::instruction::CancelOrder,
    },
    CancelOrderByClientOrderId {
        user_id: UserId,
        data: openbook_v2::instruction::CancelOrderByClientOrderId,
    },
    CancelAllOrders {
        user_id: UserId,
        data: openbook_v2::instruction::CancelAllOrders,
    },
    ConsumeEvents {
        user_ids: HashSet<UserId>,
        data: openbook_v2::instruction::ConsumeEvents,
    },
    ConsumeGivenEvents {
        user_ids: HashSet<UserId>,
        data: openbook_v2::instruction::ConsumeGivenEvents,
    },
    SettleFunds {
        user_id: UserId,
        data: openbook_v2::instruction::SettleFunds,
        referrer_id: Option<ReferrerId>,
    },
    SweepFees {
        data: openbook_v2::instruction::SweepFees,
    },
    StubOracleSet {
        oracle_id: OracleId,
        data: openbook_v2::instruction::StubOracleSet,
    },
}

trait FuzzRunner {
    fn run(&mut self, fuzz_ix: &FuzzInstruction) -> Corpus;
}

impl FuzzRunner for FuzzContext {
    fn run(&mut self, fuzz_ix: &FuzzInstruction) -> Corpus {
        info!("{:#?}", fuzz_ix);
        let keep = |_| Corpus::Keep;

        match fuzz_ix {
            FuzzInstruction::Deposit { user_id, data } => self
                .deposit(user_id, data)
                .map_or_else(error_parser::deposit, keep),

            FuzzInstruction::Refill { user_id, data } => self
                .refill(user_id, data)
                .map_or_else(error_parser::refill, keep),

            FuzzInstruction::PlaceOrder {
                user_id,
                data,
                makers,
            } => self
                .place_order(user_id, data, makers.as_ref())
                .map_or_else(error_parser::place_order, keep),

            FuzzInstruction::PlaceOrderPegged {
                user_id,
                data,
                makers,
            } => self
                .place_order_pegged(user_id, data, makers.as_ref())
                .map_or_else(error_parser::place_order_pegged, keep),

            FuzzInstruction::PlaceTakeOrder {
                user_id,
                data,
                makers,
            } => self
                .place_take_order(user_id, data, makers.as_ref())
                .map_or_else(error_parser::place_take_order, keep),

            FuzzInstruction::EditOrder {
                user_id,
                data,
                makers,
            } => self
                .edit_order(user_id, data, makers.as_ref())
                .map_or_else(error_parser::edit_order, keep),

            FuzzInstruction::EditOrderPegged {
                user_id,
                data,
                makers,
            } => self
                .edit_order_pegged(user_id, data, makers.as_ref())
                .map_or_else(error_parser::edit_order_pegged, keep),

            FuzzInstruction::CancelAllAndPlaceOrders {
                user_id,
                data,
                makers,
            } => self
                .cancel_all_and_place_orders(user_id, data, makers.as_ref())
                .map_or_else(error_parser::cancel_all_and_place_orders, keep),

            FuzzInstruction::CancelOrder { user_id, data } => self
                .cancel_order(user_id, data)
                .map_or_else(error_parser::cancel_order, keep),

            FuzzInstruction::CancelOrderByClientOrderId { user_id, data } => self
                .cancel_order_by_client_order_id(user_id, data)
                .map_or_else(error_parser::cancel_order_by_client_order_id, keep),

            FuzzInstruction::CancelAllOrders { user_id, data } => self
                .cancel_all_orders(user_id, data)
                .map_or_else(error_parser::cancel_all_orders, keep),

            FuzzInstruction::ConsumeEvents { user_ids, data } => self
                .consume_events(user_ids, data)
                .map_or_else(error_parser::consume_events, keep),

            FuzzInstruction::ConsumeGivenEvents { user_ids, data } => self
                .consume_given_events(user_ids, data)
                .map_or_else(error_parser::consume_given_events, keep),

            FuzzInstruction::SettleFunds {
                user_id,
                data,
                referrer_id,
            } => self
                .settle_funds(user_id, data, referrer_id.as_ref())
                .map_or_else(error_parser::settle_funds, keep),

            FuzzInstruction::SweepFees { data } => self
                .sweep_fees(data)
                .map_or_else(error_parser::sweep_fees, keep),

            FuzzInstruction::StubOracleSet { oracle_id, data } => self
                .stub_oracle_set(oracle_id, data)
                .map_or_else(error_parser::stub_oracle_set, keep),
        }
    }
}

fuzz_target!(|fuzz_data: FuzzData| -> Corpus {
    static ONCE: Once = Once::new();
    ONCE.call_once(env_logger::init);
    solana_program::program_stubs::set_syscall_stubs(Box::new(TestSyscallStubs {}));
    run_fuzz(fuzz_data)
});

fn run_fuzz(fuzz_data: FuzzData) -> Corpus {
    if !fuzz_data.is_borsh_serializable() || !fuzz_data.contains_place_order_ixs() {
        return Corpus::Reject;
    }

    info!("initializing");
    info!(
        "{:#?}, number oracles = {:?}",
        fuzz_data.market,
        fuzz_data
            .oracles
            .as_ref()
            .map_or(0_u8, |id| id.clone().into()),
    );

    let mut ctx = FuzzContext::new(fuzz_data.oracles);
    if matches!(
        ctx.initialize()
            .create_market(fuzz_data.market)
            .map_or_else(error_parser::create_market, |_| Corpus::Keep),
        Corpus::Reject
    ) {
        return Corpus::Reject;
    }

    info!("fuzzing");
    if fuzz_data
        .instructions
        .iter()
        .any(|ix| matches!(ctx.run(ix), Corpus::Reject))
    {
        return Corpus::Reject;
    };

    info!("validating");
    {
        let referrer_rebates: u64 = ctx
            .users
            .values()
            .map(|user| {
                let oo = ctx
                    .state
                    .get_account::<openbook_v2::state::OpenOrdersAccount>(&user.open_orders)
                    .unwrap();
                oo.position.referrer_rebates_available
            })
            .sum();

        let base_amount = ctx.state.get_balance(&ctx.market_base_vault);
        let quote_amount = ctx.state.get_balance(&ctx.market_quote_vault);

        let market = ctx
            .state
            .get_account::<openbook_v2::state::Market>(&ctx.market)
            .unwrap();

        assert_eq!(market.base_deposit_total, base_amount);
        assert_eq!(market.quote_deposit_total, quote_amount);
        assert_eq!(market.referrer_rebates_accrued, referrer_rebates);
    }

    {
        info!("cleaning event_heap");
        let consume_events_fuzz = FuzzInstruction::ConsumeEvents {
            user_ids: HashSet::from_iter(ctx.users.keys().cloned()),
            data: openbook_v2::instruction::ConsumeEvents {
                limit: MAX_EVENTS_CONSUME,
            },
        };

        let event_heap_len = |ctx: &FuzzContext| -> usize {
            let event_heap = ctx
                .state
                .get_account::<openbook_v2::state::EventHeap>(&ctx.event_heap)
                .unwrap();
            event_heap.len()
        };

        for _ in (0..event_heap_len(&ctx)).step_by(MAX_EVENTS_CONSUME) {
            ctx.run(&consume_events_fuzz);
        }

        assert_eq!(event_heap_len(&ctx), 0);
    }

    {
        let positions = ctx
            .users
            .values()
            .map(|user| {
                let oo = ctx
                    .state
                    .get_account::<openbook_v2::state::OpenOrdersAccount>(&user.open_orders)
                    .unwrap();
                oo.position
            })
            .collect::<Vec<_>>();

        let maker_volume_in_oo: u128 = positions.iter().map(|pos| pos.maker_volume).sum();
        let taker_volume_in_oo: u128 = positions.iter().map(|pos| pos.taker_volume).sum();

        let market = ctx
            .state
            .get_account::<openbook_v2::state::Market>(&ctx.market)
            .unwrap();

        assert_eq!(maker_volume_in_oo, market.maker_volume);
        assert_eq!(
            maker_volume_in_oo,
            taker_volume_in_oo + market.taker_volume_wo_oo
        );
    }

    ctx.users
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .for_each(|user_id| {
            info!("cleaning {:?}", user_id);
            ctx.run(&FuzzInstruction::CancelAllOrders {
                user_id,
                data: openbook_v2::instruction::CancelAllOrders {
                    limit: u8::MAX,
                    side_option: None,
                },
            });
            ctx.run(&FuzzInstruction::SettleFunds {
                user_id,
                data: openbook_v2::instruction::SettleFunds {},
                referrer_id: None,
            });

            let position = {
                let user = ctx.users.get(&user_id).unwrap();
                let open_orders = ctx
                    .state
                    .get_account::<openbook_v2::state::OpenOrdersAccount>(&user.open_orders)
                    .unwrap();
                open_orders.position
            };

            assert_eq!(position.bids_base_lots, 0);
            assert_eq!(position.bids_quote_lots, 0);
            assert_eq!(position.asks_base_lots, 0);
            assert_eq!(position.base_free_native, 0);
            assert_eq!(position.quote_free_native, 0);
            assert_eq!(position.locked_maker_fees, 0);
            assert_eq!(position.referrer_rebates_available, 0);
        });

    {
        let is_empty = |pubkey| -> bool {
            let book_side = ctx
                .state
                .get_account::<openbook_v2::state::BookSide>(pubkey)
                .unwrap();
            book_side.is_empty()
        };

        assert!(is_empty(&ctx.asks));
        assert!(is_empty(&ctx.bids));
    }

    let referrers_balances: u64 = ctx
        .referrers
        .values()
        .map(|quote_vault| ctx.state.get_balance(quote_vault))
        .sum();

    {
        info!("cleaning market");
        ctx.run(&FuzzInstruction::SweepFees {
            data: openbook_v2::instruction::SweepFees {},
        });

        let market = ctx
            .state
            .get_account::<openbook_v2::state::Market>(&ctx.market)
            .unwrap();

        assert_eq!(ctx.state.get_balance(&ctx.market_base_vault), 0);
        assert_eq!(ctx.state.get_balance(&ctx.market_quote_vault), 0);
        assert_eq!(market.base_deposit_total, 0);
        assert_eq!(market.quote_deposit_total, 0);
        assert_eq!(market.fees_available, 0);
        assert_eq!(market.referrer_rebates_accrued, 0);
        assert_eq!(market.fees_to_referrers as u64, referrers_balances);
    }

    {
        let base_balances: u64 = ctx
            .users
            .values()
            .map(|user| ctx.state.get_balance(&user.base_vault))
            .sum();

        let quote_balances: u64 = ctx
            .users
            .values()
            .map(|user| ctx.state.get_balance(&user.quote_vault))
            .sum();

        let n_users = ctx.users.len() as u64;
        assert_eq!(INITIAL_BALANCE * n_users, base_balances);
        assert_eq!(
            INITIAL_BALANCE * n_users,
            quote_balances
                + referrers_balances
                + ctx.state.get_balance(&ctx.collect_fee_admin_quote_vault)
        );
    }

    Corpus::Keep
}

mod error_parser {
    use anchor_spl::token::spl_token::error::TokenError;
    use libfuzzer_sys::Corpus;
    use openbook_v2::error::OpenBookError;
    use solana_program::program_error::ProgramError;

    pub fn create_market(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputNameLength.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputMarketExpired.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputMarketFees.into() => Corpus::Reject,
            _ => panic!("{}", err),
        }
    }

    pub fn deposit(err: ProgramError) -> Corpus {
        match err {
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn refill(err: ProgramError) -> Corpus {
        match err {
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn place_order(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputLotsSize.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputPriceLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidOraclePrice.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPostAmount.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPriceLots.into() => Corpus::Keep,
            e if e == OpenBookError::OpenOrdersFull.into() => Corpus::Keep,
            e if e == OpenBookError::WouldSelfTrade.into() => Corpus::Keep,
            e if e == OpenBookError::WouldExecutePartially.into() => Corpus::Keep,
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn place_order_pegged(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputLotsSize.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputPegLimit.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputPriceLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidOraclePrice.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidOrderPostIOC.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidOrderPostMarket.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPostAmount.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPriceLots.into() => Corpus::Keep,
            e if e == OpenBookError::OpenOrdersFull.into() => Corpus::Keep,
            e if e == OpenBookError::OraclePegInvalidOracleState.into() => Corpus::Keep,
            e if e == OpenBookError::WouldSelfTrade.into() => Corpus::Keep,
            e if e == OpenBookError::WouldExecutePartially.into() => Corpus::Keep,
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn place_take_order(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputLotsSize.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputOrderType.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputPriceLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidOraclePrice.into() => Corpus::Keep,
            e if e == OpenBookError::WouldExecutePartially.into() => Corpus::Keep,
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn edit_order(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputCancelSize.into() => Corpus::Reject,
            e if e == OpenBookError::OpenOrdersOrderNotFound.into() => Corpus::Keep,
            e if e == OpenBookError::OrderIdNotFound.into() => Corpus::Keep,
            _ => place_order(err),
        }
    }

    pub fn edit_order_pegged(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputCancelSize.into() => Corpus::Reject,
            e if e == OpenBookError::OpenOrdersOrderNotFound.into() => Corpus::Keep,
            e if e == OpenBookError::OrderIdNotFound.into() => Corpus::Keep,
            _ => place_order_pegged(err),
        }
    }

    pub fn cancel_all_and_place_orders(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputLotsSize.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputOrdersAmounts.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidInputPriceLots.into() => Corpus::Reject,
            e if e == OpenBookError::InvalidOraclePrice.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPostAmount.into() => Corpus::Keep,
            e if e == OpenBookError::InvalidPriceLots.into() => Corpus::Keep,
            e if e == OpenBookError::OpenOrdersFull.into() => Corpus::Keep,
            e if e == OpenBookError::WouldSelfTrade.into() => Corpus::Keep,
            e if e == OpenBookError::WouldExecutePartially.into() => Corpus::Keep,
            e if e == TokenError::InsufficientFunds.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn cancel_order(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputOrderId.into() => Corpus::Reject,
            e if e == OpenBookError::OpenOrdersOrderNotFound.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn cancel_order_by_client_order_id(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::OpenOrdersOrderNotFound.into() => Corpus::Keep,
            e if e == OpenBookError::OrderIdNotFound.into() => Corpus::Keep,
            _ => panic!("{}", err),
        }
    }

    pub fn consume_events(err: ProgramError) -> Corpus {
        panic!("{}", err);
    }

    pub fn consume_given_events(err: ProgramError) -> Corpus {
        match err {
            e if e == OpenBookError::InvalidInputHeapSlots.into() => Corpus::Reject,
            _ => panic!("{}", err),
        }
    }

    pub fn cancel_all_orders(err: ProgramError) -> Corpus {
        panic!("{}", err);
    }

    pub fn settle_funds(err: ProgramError) -> Corpus {
        panic!("{}", err);
    }

    pub fn sweep_fees(err: ProgramError) -> Corpus {
        panic!("{}", err);
    }

    pub fn stub_oracle_set(err: ProgramError) -> Corpus {
        panic!("{}", err);
    }
}


// File: openbook-v2/programs/openbook-v2/fuzz/src/accounts_state.rs
use anchor_lang::AccountDeserialize;
use anchor_spl::token::spl_token::{
    self,
    state::{Account as TokenAccount, AccountState, Mint},
};
use bumpalo::Bump;
use solana_program::{
    account_info::AccountInfo, bpf_loader, clock::Epoch, instruction::AccountMeta,
    program_pack::Pack, pubkey::Pubkey, rent::Rent, system_program,
};
use solana_sdk::account::{Account, WritableAccount};
use std::collections::HashMap;

pub struct UserAccounts {
    pub owner: Pubkey,
    pub base_vault: Pubkey,
    pub quote_vault: Pubkey,
    pub open_orders: Pubkey,
}

pub struct AccountsState(HashMap<Pubkey, Account>);

impl Default for AccountsState {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountsState {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, pubkey: Pubkey, account: Account) {
        self.0.insert(pubkey, account);
    }

    pub fn get_account<T: AccountDeserialize>(&self, pubkey: &Pubkey) -> Option<T> {
        self.0
            .get(pubkey)
            .and_then(|acc| AccountDeserialize::try_deserialize(&mut &acc.data[..]).ok())
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> u64 {
        self.get_account::<anchor_spl::token::TokenAccount>(pubkey)
            .unwrap()
            .amount
    }

    pub fn account_infos<'a, 'b: 'a>(
        &'a self,
        bump: &'b Bump,
        metas: Vec<AccountMeta>,
    ) -> Vec<AccountInfo<'b>> {
        let mut infos: Vec<AccountInfo> = vec![];

        metas.iter().for_each(|meta| {
            if let Some(info) = infos.iter().find(|info| info.key == &meta.pubkey) {
                infos.push(info.clone());
            } else {
                let account = self.0.get(&meta.pubkey).unwrap();
                infos.push(AccountInfo::new(
                    bump.alloc(meta.pubkey),
                    meta.is_signer,
                    meta.is_writable,
                    bump.alloc(account.lamports),
                    bump.alloc_slice_copy(&account.data),
                    bump.alloc(account.owner),
                    account.executable,
                    account.rent_epoch,
                ));
            }
        });

        infos
    }

    pub fn update(&mut self, infos: &[AccountInfo]) {
        infos.iter().for_each(|info| {
            let account = self.0.get_mut(info.key).unwrap();
            let new_data = info.data.borrow();
            let new_lamports = **info.lamports.borrow();
            if new_lamports != account.lamports || *new_data != account.data {
                account.data.copy_from_slice(*new_data);
                account.lamports = new_lamports;
            }
        });
    }

    pub fn add_program(&mut self, pubkey: Pubkey) -> &mut Self {
        self.insert(
            pubkey,
            Account::create(0, vec![], bpf_loader::ID, true, Epoch::default()),
        );
        self
    }

    pub fn add_account_with_lamports(&mut self, pubkey: Pubkey, lamports: u64) -> &mut Self {
        self.insert(
            pubkey,
            Account::create(
                lamports,
                vec![],
                system_program::ID,
                false,
                Epoch::default(),
            ),
        );
        self
    }

    pub fn add_token_account_with_lamports(
        &mut self,
        pubkey: Pubkey,
        owner: Pubkey,
        mint: Pubkey,
        amount: u64,
    ) -> &mut Self {
        let mut data = vec![0_u8; TokenAccount::LEN];
        let account = TokenAccount {
            state: AccountState::Initialized,
            mint,
            owner,
            amount,
            ..TokenAccount::default()
        };
        TokenAccount::pack(account, &mut data).unwrap();
        self.insert(
            pubkey,
            Account::create(
                Rent::default().minimum_balance(data.len()),
                data,
                spl_token::ID,
                false,
                Epoch::default(),
            ),
        );
        self
    }

    pub fn add_mint(&mut self, pubkey: Pubkey) -> &mut Self {
        let mut data = vec![0_u8; Mint::LEN];
        let mint = Mint {
            is_initialized: true,
            ..Mint::default()
        };
        Mint::pack(mint, &mut data).unwrap();
        self.insert(
            pubkey,
            Account::create(
                Rent::default().minimum_balance(data.len()),
                data,
                spl_token::ID,
                false,
                Epoch::default(),
            ),
        );
        self
    }

    pub fn add_empty_system_account(&mut self, pubkey: Pubkey) -> &mut Self {
        self.insert(pubkey, Account::new(0, 0, &system_program::ID));
        self
    }

    pub fn add_openbook_account<T>(&mut self, pubkey: Pubkey) -> &mut Self {
        let len = 8 + std::mem::size_of::<T>();
        self.insert(pubkey, zero_account(len));
        self
    }

    pub fn add_open_orders_indexer<T>(&mut self, pubkey: Pubkey) -> &mut Self {
        let len = openbook_v2::state::OpenOrdersIndexer::space(1);
        self.insert(pubkey, zero_account(len));
        self
    }
}

fn zero_account(len: usize) -> Account {
    Account::create(
        Rent::default().minimum_balance(len),
        vec![0; len],
        openbook_v2::ID,
        false,
        Epoch::default(),
    )
}


// File: openbook-v2/programs/openbook-v2/fuzz/src/lib.rs
pub mod accounts_state;
pub mod processor;

use accounts_state::*;
use anchor_spl::token::spl_token;
use arbitrary::{Arbitrary, Unstructured};
use num_enum::IntoPrimitive;
use openbook_v2::state::*;
use processor::*;
use solana_program::{
    entrypoint::ProgramResult, instruction::AccountMeta, pubkey::Pubkey, system_program,
};
use spl_associated_token_account::get_associated_token_address;
use std::collections::{HashMap, HashSet};

pub const NUM_USERS: u8 = 8;
pub const INITIAL_BALANCE: u64 = 1_000_000_000;

#[derive(Debug, Clone, IntoPrimitive, Arbitrary)]
#[repr(u8)]
pub enum OracleId {
    OracleA = 1,
    OracleB = 2,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct UserId(u8);

impl Arbitrary<'_> for UserId {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let i: u8 = u.arbitrary()?;
        Ok(Self(i % NUM_USERS))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct ReferrerId(u8);

impl Arbitrary<'_> for ReferrerId {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let i: u8 = u.arbitrary()?;
        Ok(Self(i % NUM_USERS))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

pub struct FuzzContext {
    pub payer: Pubkey,
    pub admin: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub market: Pubkey,
    pub market_authority: Pubkey,
    pub event_authority: Pubkey,
    pub bids: Pubkey,
    pub asks: Pubkey,
    pub event_heap: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub oracle_a: Option<Pubkey>,
    pub oracle_b: Option<Pubkey>,
    pub collect_fee_admin: Pubkey,
    pub collect_fee_admin_quote_vault: Pubkey,
    pub users: HashMap<UserId, UserAccounts>,
    pub referrers: HashMap<ReferrerId, Pubkey>,
    pub state: AccountsState,
}

impl FuzzContext {
    pub fn new(oracles: Option<OracleId>) -> Self {
        let payer = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        let market = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();

        let (event_authority, _bump) =
            Pubkey::find_program_address(&[b"__event_authority".as_ref()], &openbook_v2::ID);

        let (market_authority, _bump) =
            Pubkey::find_program_address(&[b"Market".as_ref(), market.as_ref()], &openbook_v2::ID);

        let (oracle_a, oracle_b) = if let Some(oracles) = oracles {
            let seeds_a = &[b"StubOracle".as_ref(), admin.as_ref(), base_mint.as_ref()];
            let seeds_b = &[b"StubOracle".as_ref(), admin.as_ref(), quote_mint.as_ref()];
            match oracles {
                OracleId::OracleA => (
                    Some(Pubkey::find_program_address(seeds_a, &openbook_v2::ID).0),
                    None,
                ),
                OracleId::OracleB => (
                    Some(Pubkey::find_program_address(seeds_a, &openbook_v2::ID).0),
                    Some(Pubkey::find_program_address(seeds_b, &openbook_v2::ID).0),
                ),
            }
        } else {
            (None, None)
        };

        let bids = Pubkey::new_unique();
        let asks = Pubkey::new_unique();
        let event_heap = Pubkey::new_unique();

        let market_base_vault = get_associated_token_address(&market_authority, &base_mint);
        let market_quote_vault = get_associated_token_address(&market_authority, &quote_mint);

        let collect_fee_admin = Pubkey::new_unique();
        let collect_fee_admin_quote_vault =
            get_associated_token_address(&collect_fee_admin, &quote_mint);

        Self {
            payer,
            admin,
            base_mint,
            quote_mint,
            market,
            market_authority,
            event_authority,
            bids,
            asks,
            event_heap,
            market_base_vault,
            market_quote_vault,
            oracle_a,
            oracle_b,
            collect_fee_admin,
            collect_fee_admin_quote_vault,
            users: HashMap::new(),
            referrers: HashMap::new(),
            state: AccountsState::new(),
        }
    }

    pub fn initialize(&mut self) -> &mut Self {
        self.state
            .add_account_with_lamports(self.admin, INITIAL_BALANCE)
            .add_account_with_lamports(self.collect_fee_admin, 0)
            .add_account_with_lamports(self.payer, INITIAL_BALANCE)
            .add_mint(self.base_mint)
            .add_mint(self.quote_mint)
            .add_openbook_account::<BookSide>(self.asks)
            .add_openbook_account::<BookSide>(self.bids)
            .add_openbook_account::<EventHeap>(self.event_heap)
            .add_openbook_account::<Market>(self.market)
            .add_empty_system_account(self.market_authority)
            .add_empty_system_account(self.event_authority)
            .add_program(openbook_v2::ID) // optional accounts use this pubkey
            .add_program(spl_associated_token_account::ID)
            .add_program(spl_token::ID)
            .add_program(system_program::ID)
            .add_token_account_with_lamports(
                self.market_base_vault,
                self.market_authority,
                self.base_mint,
                0,
            )
            .add_token_account_with_lamports(
                self.market_quote_vault,
                self.market_authority,
                self.quote_mint,
                0,
            )
            .add_token_account_with_lamports(
                self.collect_fee_admin_quote_vault,
                self.collect_fee_admin,
                self.quote_mint,
                0,
            );

        if let Some(oracle_a) = self.oracle_a {
            self.state.add_openbook_account::<StubOracle>(oracle_a);
            self.stub_oracle_create(OracleId::OracleA).unwrap();
        }

        if let Some(oracle_b) = self.oracle_b {
            self.state.add_openbook_account::<StubOracle>(oracle_b);
            self.stub_oracle_create(OracleId::OracleB).unwrap();
        }

        self
    }

    fn get_or_create_new_user(&mut self, user_id: &UserId) -> &UserAccounts {
        let create_new_user = || -> UserAccounts {
            let owner = Pubkey::new_unique();
            let base_vault = Pubkey::new_unique();
            let quote_vault = Pubkey::new_unique();

            let indexer = Pubkey::find_program_address(
                &[b"OpenOrdersIndexer".as_ref(), owner.as_ref()],
                &openbook_v2::ID,
            )
            .0;

            let open_orders = Pubkey::find_program_address(
                &[b"OpenOrders".as_ref(), owner.as_ref(), &1_u32.to_le_bytes()],
                &openbook_v2::ID,
            )
            .0;

            self.state
                .add_account_with_lamports(owner, INITIAL_BALANCE)
                .add_account_with_lamports(owner, INITIAL_BALANCE)
                .add_token_account_with_lamports(base_vault, owner, self.base_mint, INITIAL_BALANCE)
                .add_token_account_with_lamports(
                    quote_vault,
                    owner,
                    self.quote_mint,
                    INITIAL_BALANCE,
                )
                .add_open_orders_indexer::<OpenOrdersIndexer>(indexer)
                .add_openbook_account::<OpenOrdersAccount>(open_orders);

            let accounts = openbook_v2::accounts::CreateOpenOrdersIndexer {
                open_orders_indexer: indexer,
                owner,
                payer: self.payer,
                system_program: system_program::ID,
            };
            let data = openbook_v2::instruction::CreateOpenOrdersIndexer {};
            process_instruction(&mut self.state, &data, &accounts, &[]).unwrap();

            let accounts = openbook_v2::accounts::CreateOpenOrdersAccount {
                open_orders_indexer: indexer,
                open_orders_account: open_orders,
                owner,
                delegate_account: None,
                payer: self.payer,
                market: self.market,
                system_program: system_program::ID,
            };
            let data = openbook_v2::instruction::CreateOpenOrdersAccount {
                name: "fuzz test".to_string(),
            };
            process_instruction(&mut self.state, &data, &accounts, &[]).unwrap();

            UserAccounts {
                owner,
                open_orders,
                base_vault,
                quote_vault,
            }
        };

        self.users.entry(*user_id).or_insert_with(create_new_user)
    }

    fn get_or_create_new_referrer(&mut self, referrer_id: &ReferrerId) -> &Pubkey {
        let create_new_referrer = || -> Pubkey {
            let quote_vault = Pubkey::new_unique();

            self.state.add_token_account_with_lamports(
                quote_vault,
                Pubkey::new_unique(),
                self.quote_mint,
                0,
            );

            quote_vault
        };

        self.referrers
            .entry(*referrer_id)
            .or_insert_with(create_new_referrer)
    }

    fn stub_oracle_create(&mut self, oracle_id: OracleId) -> ProgramResult {
        let (oracle, mint) = match oracle_id {
            OracleId::OracleA => (self.oracle_a.unwrap(), self.base_mint),
            OracleId::OracleB => (self.oracle_b.unwrap(), self.quote_mint),
        };

        let accounts = openbook_v2::accounts::StubOracleCreate {
            oracle,
            mint,
            owner: self.admin,
            payer: self.payer,
            system_program: system_program::ID,
        };
        let data = openbook_v2::instruction::StubOracleCreate { price: 1. };
        process_instruction(&mut self.state, &data, &accounts, &[])
    }

    pub fn create_market(&mut self, data: openbook_v2::instruction::CreateMarket) -> ProgramResult {
        let accounts = openbook_v2::accounts::CreateMarket {
            market: self.market,
            market_authority: self.market_authority,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            payer: self.payer,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            base_mint: self.base_mint,
            quote_mint: self.quote_mint,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            system_program: system_program::ID,
            token_program: spl_token::ID,
            associated_token_program: spl_associated_token_account::ID,
            collect_fee_admin: self.collect_fee_admin,
            open_orders_admin: None,
            consume_events_admin: None,
            close_market_admin: None,
            event_authority: self.event_authority,
            program: openbook_v2::ID,
        };
        process_instruction(&mut self.state, &data, &accounts, &[])
    }

    pub fn deposit(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::Deposit,
    ) -> ProgramResult {
        let user = self.get_or_create_new_user(user_id);

        let accounts = openbook_v2::accounts::Deposit {
            owner: user.owner,
            user_base_account: user.base_vault,
            user_quote_account: user.quote_vault,
            open_orders_account: user.open_orders,
            market: self.market,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            token_program: spl_token::ID,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn refill(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::Refill,
    ) -> ProgramResult {
        let user = self.get_or_create_new_user(user_id);

        let accounts = openbook_v2::accounts::Deposit {
            owner: user.owner,
            user_base_account: user.base_vault,
            user_quote_account: user.quote_vault,
            open_orders_account: user.open_orders,
            market: self.market,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            token_program: spl_token::ID,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn place_order(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::PlaceOrder,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        let market_vault = match data.args.side {
            Side::Ask => self.market_base_vault,
            Side::Bid => self.market_quote_vault,
        };

        let user = self.get_or_create_new_user(user_id);
        let user_token_account = match data.args.side {
            Side::Ask => user.base_vault,
            Side::Bid => user.quote_vault,
        };

        let accounts = openbook_v2::accounts::PlaceOrder {
            open_orders_account: user.open_orders,
            signer: user.owner,
            user_token_account,
            open_orders_admin: None,
            market: self.market,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            market_vault,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn place_order_pegged(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::PlaceOrderPegged,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        if self.oracle_a.is_none() {
            return Ok(());
        }

        let market_vault = match data.args.side {
            Side::Ask => self.market_base_vault,
            Side::Bid => self.market_quote_vault,
        };

        let user = self.get_or_create_new_user(user_id);
        let user_token_account = match data.args.side {
            Side::Ask => user.base_vault,
            Side::Bid => user.quote_vault,
        };

        let accounts = openbook_v2::accounts::PlaceOrder {
            open_orders_account: user.open_orders,
            signer: user.owner,
            user_token_account,
            open_orders_admin: None,
            market: self.market,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            market_vault,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn place_take_order(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::PlaceTakeOrder,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        let user = self.get_or_create_new_user(user_id);

        let accounts = openbook_v2::accounts::PlaceTakeOrder {
            signer: user.owner,
            penalty_payer: user.owner,
            user_base_account: user.base_vault,
            user_quote_account: user.quote_vault,
            market: self.market,
            market_authority: self.market_authority,
            bids: self.bids,
            asks: self.asks,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            event_heap: self.event_heap,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
            system_program: system_program::ID,
            open_orders_admin: None,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn edit_order(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::EditOrder,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        let market_vault = match data.place_order.side {
            Side::Ask => self.market_base_vault,
            Side::Bid => self.market_quote_vault,
        };

        let user = self.get_or_create_new_user(user_id);
        let user_token_account = match data.place_order.side {
            Side::Ask => user.base_vault,
            Side::Bid => user.quote_vault,
        };

        let accounts = openbook_v2::accounts::PlaceOrder {
            open_orders_account: user.open_orders,
            signer: user.owner,
            user_token_account,
            open_orders_admin: None,
            market: self.market,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            market_vault,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn edit_order_pegged(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::EditOrderPegged,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        if self.oracle_a.is_none() {
            return Ok(());
        }

        let market_vault = match data.place_order.side {
            Side::Ask => self.market_base_vault,
            Side::Bid => self.market_quote_vault,
        };

        let user = self.get_or_create_new_user(user_id);
        let user_token_account = match data.place_order.side {
            Side::Ask => user.base_vault,
            Side::Bid => user.quote_vault,
        };

        let accounts = openbook_v2::accounts::PlaceOrder {
            open_orders_account: user.open_orders,
            signer: user.owner,
            user_token_account,
            open_orders_admin: None,
            market: self.market,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            market_vault,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn cancel_all_and_place_orders(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::CancelAllAndPlaceOrders,
        makers: Option<&HashSet<UserId>>,
    ) -> ProgramResult {
        let user = self.get_or_create_new_user(user_id);

        let accounts = openbook_v2::accounts::CancelAllAndPlaceOrders {
            open_orders_account: user.open_orders,
            signer: user.owner,
            user_base_account: user.base_vault,
            user_quote_account: user.quote_vault,
            open_orders_admin: None,
            market: self.market,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            token_program: spl_token::ID,
        };

        let remaining = makers.map_or_else(Vec::new, |makers| {
            makers
                .iter()
                .filter(|id| id != &user_id)
                .filter_map(|id| self.users.get(id))
                .map(|user| AccountMeta {
                    pubkey: user.open_orders,
                    is_signer: false,
                    is_writable: true,
                })
                .collect::<Vec<_>>()
        });

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn cancel_order(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::CancelOrder,
    ) -> ProgramResult {
        let Some(user) = self.users.get(user_id) else {
            return Ok(());
        };

        let accounts = openbook_v2::accounts::CancelOrder {
            signer: user.owner,
            open_orders_account: user.open_orders,
            market: self.market,
            asks: self.asks,
            bids: self.bids,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn cancel_order_by_client_order_id(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::CancelOrderByClientOrderId,
    ) -> ProgramResult {
        let Some(user) = self.users.get(user_id) else {
            return Ok(());
        };

        let accounts = openbook_v2::accounts::CancelOrder {
            signer: user.owner,
            open_orders_account: user.open_orders,
            market: self.market,
            asks: self.asks,
            bids: self.bids,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn cancel_all_orders(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::CancelAllOrders,
    ) -> ProgramResult {
        let Some(user) = self.users.get(user_id) else {
            return Ok(());
        };

        let accounts = openbook_v2::accounts::CancelOrder {
            signer: user.owner,
            open_orders_account: user.open_orders,
            market: self.market,
            asks: self.asks,
            bids: self.bids,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn consume_events(
        &mut self,
        user_ids: &HashSet<UserId>,
        data: &openbook_v2::instruction::ConsumeEvents,
    ) -> ProgramResult {
        let accounts = openbook_v2::accounts::ConsumeEvents {
            consume_events_admin: None,
            market: self.market,
            event_heap: self.event_heap,
        };

        let remaining = user_ids
            .iter()
            .filter_map(|user_id| self.users.get(user_id))
            .map(|user| AccountMeta {
                pubkey: user.open_orders,
                is_signer: false,
                is_writable: true,
            })
            .collect::<Vec<_>>();

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn consume_given_events(
        &mut self,
        user_ids: &HashSet<UserId>,
        data: &openbook_v2::instruction::ConsumeGivenEvents,
    ) -> ProgramResult {
        let accounts = openbook_v2::accounts::ConsumeEvents {
            consume_events_admin: None,
            market: self.market,
            event_heap: self.event_heap,
        };

        let remaining = user_ids
            .iter()
            .filter_map(|user_id| self.users.get(user_id))
            .map(|user| AccountMeta {
                pubkey: user.open_orders,
                is_signer: false,
                is_writable: true,
            })
            .collect::<Vec<_>>();

        process_instruction(&mut self.state, data, &accounts, &remaining)
    }

    pub fn settle_funds(
        &mut self,
        user_id: &UserId,
        data: &openbook_v2::instruction::SettleFunds,
        referrer_id: Option<&ReferrerId>,
    ) -> ProgramResult {
        let referrer_account = referrer_id.map(|id| *self.get_or_create_new_referrer(id));
        let Some(user) = self.users.get(user_id) else {
            return Ok(());
        };

        let accounts = openbook_v2::accounts::SettleFunds {
            owner: user.owner,
            penalty_payer: user.owner,
            open_orders_account: user.open_orders,
            user_base_account: user.base_vault,
            user_quote_account: user.quote_vault,
            market: self.market,
            market_authority: self.market_authority,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            token_program: spl_token::ID,
            system_program: system_program::ID,
            referrer_account,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn sweep_fees(&mut self, data: &openbook_v2::instruction::SweepFees) -> ProgramResult {
        let accounts = openbook_v2::accounts::SweepFees {
            collect_fee_admin: self.collect_fee_admin,
            token_receiver_account: self.collect_fee_admin_quote_vault,
            market: self.market,
            market_authority: self.market_authority,
            market_quote_vault: self.market_quote_vault,
            token_program: spl_token::ID,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }

    pub fn stub_oracle_set(
        &mut self,
        oracle_id: &OracleId,
        data: &openbook_v2::instruction::StubOracleSet,
    ) -> ProgramResult {
        let oracle = match oracle_id {
            OracleId::OracleA => self.oracle_a,
            OracleId::OracleB => self.oracle_b,
        };

        let Some(oracle) = oracle else {
            return Ok(());
        };

        let accounts = openbook_v2::accounts::StubOracleSet {
            oracle,
            owner: self.admin,
        };

        process_instruction(&mut self.state, data, &accounts, &[])
    }
}


// File: openbook-v2/programs/openbook-v2/fuzz/src/processor.rs
use crate::accounts_state::AccountsState;
use anchor_spl::token::spl_token;
use base64::{prelude::BASE64_STANDARD, Engine};
use bumpalo::Bump;
use itertools::Itertools;
use log::debug;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, instruction::AccountMeta,
    instruction::Instruction, program_error::ProgramError, program_stubs, pubkey::Pubkey,
    rent::Rent, system_program,
};

pub struct TestSyscallStubs {}
impl program_stubs::SyscallStubs for TestSyscallStubs {
    fn sol_log(&self, message: &str) {
        debug!("Program log: {}", message);
    }

    fn sol_log_data(&self, fields: &[&[u8]]) {
        debug!(
            "Program data: {}",
            fields.iter().map(|b| BASE64_STANDARD.encode(b)).join(" ")
        );
    }

    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        account_infos: &[AccountInfo],
        signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        let mut new_account_infos = vec![];

        let pdas = signers_seeds
            .iter()
            .map(|seeds| Pubkey::create_program_address(seeds, &openbook_v2::id()).unwrap())
            .collect::<Vec<_>>();

        for meta in instruction.accounts.iter() {
            for account_info in account_infos.iter() {
                if meta.pubkey == *account_info.key {
                    let mut new_account_info = account_info.clone();
                    if pdas.iter().any(|pda| pda == account_info.key) {
                        new_account_info.is_signer = true;
                    }
                    new_account_infos.push(new_account_info);
                }
            }
        }

        match instruction.program_id {
            // accounts should already be created & reallocated
            id if id == system_program::ID => Ok(()),
            id if id == spl_associated_token_account::ID => Ok(()),
            id if id == spl_token::ID => spl_token::processor::Processor::process(
                &instruction.program_id,
                &new_account_infos,
                &instruction.data,
            ),
            id if id == openbook_v2::ID => {
                let extended_lifetime_accs = unsafe {
                    core::mem::transmute::<&[AccountInfo], &[AccountInfo<'_>]>(
                        new_account_infos.as_ref(),
                    )
                };
                openbook_v2::entry(
                    &instruction.program_id,
                    &extended_lifetime_accs,
                    &instruction.data,
                )
            }
            _ => Err(ProgramError::IncorrectProgramId),
        }
    }

    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        unsafe {
            *(var_addr as *mut _ as *mut Clock) = Clock::default();
        }
        solana_program::entrypoint::SUCCESS
    }

    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        unsafe {
            *(var_addr as *mut _ as *mut Rent) = Rent::default();
        }
        solana_program::entrypoint::SUCCESS
    }
}

pub fn process_instruction(
    state: &mut AccountsState,
    data: &impl anchor_lang::InstructionData,
    accounts: &impl anchor_lang::ToAccountMetas,
    remaining_accounts: &[AccountMeta],
) -> ProgramResult {
    let bump = Bump::new();
    let mut metas = anchor_lang::ToAccountMetas::to_account_metas(accounts, None);
    metas.extend_from_slice(remaining_accounts);
    let account_infos = state.account_infos(&bump, metas);

    let res = openbook_v2::entry(
        &openbook_v2::ID,
        &account_infos,
        &anchor_lang::InstructionData::data(data),
    );

    if res.is_ok() {
        state.update(&account_infos);
    }

    res
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/cancel_all_and_place_orders.rs
use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct CancelAllAndPlaceOrders<'info> {
    pub signer: Signer<'info>,
    #[account(
        mut,
        has_one = market,
        constraint = open_orders_account.load()?.is_owner_or_delegate(signer.key()) @ OpenBookError::NoOwnerOrDelegate
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    pub open_orders_admin: Option<Signer<'info>>,

    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub user_quote_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = market_base_vault.mint
    )]
    pub user_base_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        has_one = bids,
        has_one = asks,
        has_one = event_heap,
        has_one = market_base_vault,
        has_one = market_quote_vault,
        constraint = market.load()?.oracle_a == oracle_a.non_zero_key(),
        constraint = market.load()?.oracle_b == oracle_b.non_zero_key(),
        constraint = market.load()?.open_orders_admin == open_orders_admin.non_zero_key() @ OpenBookError::InvalidOpenOrdersAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub asks: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub event_heap: AccountLoader<'info, EventHeap>,

    #[account(mut)]
    pub market_quote_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub market_base_vault: Box<Account<'info, TokenAccount>>,

    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_a: Option<UncheckedAccount<'info>>,
    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_b: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/cancel_order.rs
use crate::error::OpenBookError;
use crate::state::{BookSide, Market, OpenOrdersAccount};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CancelOrder<'info> {
    pub signer: Signer<'info>,
    #[account(
        mut,
        has_one = market,
        constraint = open_orders_account.load()?.is_owner_or_delegate(signer.key()) @ OpenBookError::NoOwnerOrDelegate
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    #[account(
        has_one = bids,
        has_one = asks,
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub asks: AccountLoader<'info, BookSide>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/close_market.rs
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::Token;

#[derive(Accounts)]
pub struct CloseMarket<'info> {
    pub close_market_admin: Signer<'info>,
    #[account(
        mut,
        has_one = bids,
        has_one = asks,
        has_one = event_heap,
        close = sol_destination,
        constraint = market.load()?.close_market_admin.is_some() @ OpenBookError::NoCloseMarketAdmin,
        constraint = market.load()?.close_market_admin == close_market_admin.key() @ OpenBookError::InvalidCloseMarketAdmin
    )]
    pub market: AccountLoader<'info, Market>,

    #[account(
        mut,
        close = sol_destination
    )]
    pub bids: AccountLoader<'info, BookSide>,

    #[account(
        mut,
        close = sol_destination
    )]
    pub asks: AccountLoader<'info, BookSide>,

    #[account(
        mut,
        close = sol_destination
    )]
    pub event_heap: AccountLoader<'info, EventHeap>,

    #[account(mut)]
    /// CHECK: target for account rent needs no checks
    pub sol_destination: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/close_open_orders_account.rs
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseOpenOrdersAccount<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [b"OpenOrdersIndexer".as_ref(), owner.key().as_ref()],
        bump = open_orders_indexer.bump,
        realloc = OpenOrdersIndexer::space(open_orders_indexer.addresses.len()-1),
        realloc::payer = sol_destination,
        realloc::zero = false,
    )]
    pub open_orders_indexer: Account<'info, OpenOrdersIndexer>,

    #[account(
        mut,
        has_one = owner,
        close = sol_destination,
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    #[account(mut)]
    /// CHECK: target for account rent needs no checks
    pub sol_destination: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/close_open_orders_indexer.rs
use crate::state::OpenOrdersIndexer;
use anchor_lang::prelude::*;
use anchor_spl::token::Token;

#[derive(Accounts)]
pub struct CloseOpenOrdersIndexer<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [b"OpenOrdersIndexer".as_ref(), owner.key().as_ref()],
        bump = open_orders_indexer.bump,
        close = sol_destination
    )]
    pub open_orders_indexer: Account<'info, OpenOrdersIndexer>,

    #[account(mut)]
    /// CHECK: target for account rent needs no checks
    pub sol_destination: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/consume_events.rs
use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ConsumeEvents<'info> {
    pub consume_events_admin: Option<Signer<'info>>,
    #[account(
        mut,
        has_one = event_heap,
        constraint = market.load()?.consume_events_admin == consume_events_admin.non_zero_key() @ OpenBookError::InvalidConsumeEventsAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub event_heap: AccountLoader<'info, EventHeap>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/create_market.rs
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
};

#[event_cpi]
#[derive(Accounts)]
pub struct CreateMarket<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<Market>(),
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(
        seeds = [b"Market".as_ref(), market.key().to_bytes().as_ref()],
        bump,
    )]
    /// CHECK:
    pub market_authority: UncheckedAccount<'info>,

    /// Accounts are initialized by client,
    /// anchor discriminator is set first when ix exits,
    #[account(zero)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(zero)]
    pub asks: AccountLoader<'info, BookSide>,
    #[account(zero)]
    pub event_heap: AccountLoader<'info, EventHeap>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        associated_token::mint = base_mint,
        associated_token::authority = market_authority,
    )]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = payer,
        associated_token::mint = quote_mint,
        associated_token::authority = market_authority,
    )]
    pub market_quote_vault: Account<'info, TokenAccount>,

    #[account(constraint = base_mint.key() != quote_mint.key())]
    pub base_mint: Box<Account<'info, Mint>>,
    pub quote_mint: Box<Account<'info, Mint>>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// CHECK: The oracle can be one of several different account types
    pub oracle_a: Option<UncheckedAccount<'info>>,
    /// CHECK: The oracle can be one of several different account types
    pub oracle_b: Option<UncheckedAccount<'info>>,

    /// CHECK:
    pub collect_fee_admin: UncheckedAccount<'info>,
    /// CHECK:
    pub open_orders_admin: Option<UncheckedAccount<'info>>,
    /// CHECK:
    pub consume_events_admin: Option<UncheckedAccount<'info>>,
    /// CHECK:
    pub close_market_admin: Option<UncheckedAccount<'info>>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/create_open_orders_account.rs
use crate::state::{Market, OpenOrdersAccount, OpenOrdersIndexer};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateOpenOrdersAccount<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub owner: Signer<'info>,
    /// CHECK:
    pub delegate_account: Option<UncheckedAccount<'info>>,
    #[account(
        mut,
        seeds = [b"OpenOrdersIndexer".as_ref(), owner.key().as_ref()],
        bump = open_orders_indexer.bump,
        realloc = OpenOrdersIndexer::space(open_orders_indexer.addresses.len()+1),
        realloc::payer = payer,
        realloc::zero = false,
        constraint = open_orders_indexer.addresses.len() < 256,
    )]
    pub open_orders_indexer: Account<'info, OpenOrdersIndexer>,
    #[account(
        init,
        seeds = [b"OpenOrders".as_ref(), owner.key().as_ref(), &(open_orders_indexer.created_counter + 1).to_le_bytes()],
        bump,
        payer = payer,
        space = OpenOrdersAccount::space(),
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    pub market: AccountLoader<'info, Market>,
    pub system_program: Program<'info, System>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/create_open_orders_indexer.rs
use crate::state::OpenOrdersIndexer;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateOpenOrdersIndexer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub owner: Signer<'info>,
    #[account(
        init,
        seeds = [b"OpenOrdersIndexer".as_ref(), owner.key().as_ref()],
        bump,
        payer = payer,
        space = OpenOrdersIndexer::space(0),
    )]
    pub open_orders_indexer: Account<'info, OpenOrdersIndexer>,
    pub system_program: Program<'info, System>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/deposit.rs
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        token::mint = market_base_vault.mint
    )]
    pub user_base_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub user_quote_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        has_one = market,
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,

    #[account(
        mut,
        has_one = market_base_vault,
        has_one = market_quote_vault,
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub market_quote_vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/mod.rs
pub use cancel_all_and_place_orders::*;
pub use cancel_order::*;
pub use close_market::*;
pub use close_open_orders_account::*;
pub use close_open_orders_indexer::*;
pub use consume_events::*;
pub use create_market::*;
pub use create_open_orders_account::*;
pub use create_open_orders_indexer::*;
pub use deposit::*;
pub use place_order::*;
pub use place_take_order::*;
pub use prune_orders::*;
pub use set_delegate::*;
pub use set_market_expired::*;
pub use settle_funds::*;
pub use settle_funds_expired::*;
pub use stub_oracle_close::*;
pub use stub_oracle_create::*;
pub use stub_oracle_set::*;
pub use sweep_fees::*;

mod cancel_all_and_place_orders;
mod cancel_order;
mod close_market;
mod close_open_orders_account;
mod close_open_orders_indexer;
mod consume_events;
mod create_market;
mod create_open_orders_account;
mod create_open_orders_indexer;
mod deposit;
mod place_order;
mod place_take_order;
mod prune_orders;
mod set_delegate;
mod set_market_expired;
mod settle_funds;
mod settle_funds_expired;
mod stub_oracle_close;
mod stub_oracle_create;
mod stub_oracle_set;
mod sweep_fees;


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/place_order.rs
use crate::accounts_ix::{CancelOrder, CancelOrderBumps};
use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct PlaceOrder<'info> {
    pub signer: Signer<'info>,
    #[account(
        mut,
        has_one = market,
        constraint = open_orders_account.load()?.is_owner_or_delegate(signer.key()) @ OpenBookError::NoOwnerOrDelegate
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    pub open_orders_admin: Option<Signer<'info>>,

    #[account(
        mut,
        token::mint = market_vault.mint
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        has_one = bids,
        has_one = asks,
        has_one = event_heap,
        constraint = market.load()?.oracle_a == oracle_a.non_zero_key(),
        constraint = market.load()?.oracle_b == oracle_b.non_zero_key(),
        constraint = market.load()?.open_orders_admin == open_orders_admin.non_zero_key() @ OpenBookError::InvalidOpenOrdersAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub asks: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub event_heap: AccountLoader<'info, EventHeap>,
    #[account(
        mut,
        // The side of the vault is checked inside the ix
        constraint = market.load()?.is_market_vault(market_vault.key())
    )]
    pub market_vault: Account<'info, TokenAccount>,

    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_a: Option<UncheckedAccount<'info>>,
    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_b: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,
}

impl<'info> PlaceOrder<'info> {
    pub fn to_cancel_order(&self) -> CancelOrder<'info> {
        CancelOrder {
            signer: self.signer.clone(),
            bids: self.bids.clone(),
            asks: self.asks.clone(),
            open_orders_account: self.open_orders_account.clone(),
            market: self.market.clone(),
        }
    }
}

impl PlaceOrderBumps {
    pub fn to_cancel_order(&self) -> CancelOrderBumps {
        CancelOrderBumps {}
    }
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/place_take_order.rs
use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct PlaceTakeOrder<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(mut)]
    pub penalty_payer: Signer<'info>,

    #[account(
        mut,
        has_one = bids,
        has_one = asks,
        has_one = event_heap,
        has_one = market_base_vault,
        has_one = market_quote_vault,
        has_one = market_authority,
        constraint = market.load()?.oracle_a == oracle_a.non_zero_key(),
        constraint = market.load()?.oracle_b == oracle_b.non_zero_key(),
        constraint = market.load()?.open_orders_admin == open_orders_admin.non_zero_key() @ OpenBookError::InvalidOpenOrdersAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    /// CHECK: checked on has_one in market
    pub market_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub asks: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub market_quote_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub event_heap: AccountLoader<'info, EventHeap>,

    #[account(
        mut,
        token::mint = market_base_vault.mint
    )]
    pub user_base_account: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub user_quote_account: Box<Account<'info, TokenAccount>>,

    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_a: Option<UncheckedAccount<'info>>,
    /// CHECK: The oracle can be one of several different account types and the pubkey is checked above
    pub oracle_b: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub open_orders_admin: Option<Signer<'info>>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/prune_orders.rs
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct PruneOrders<'info> {
    pub close_market_admin: Signer<'info>,
    #[account(
        mut,
        has_one = market
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    #[account(
        has_one = bids,
        has_one = asks,
        constraint = market.load()?.close_market_admin.is_some() @ OpenBookError::NoCloseMarketAdmin,
        constraint = market.load()?.close_market_admin == close_market_admin.key() @ OpenBookError::InvalidCloseMarketAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub bids: AccountLoader<'info, BookSide>,
    #[account(mut)]
    pub asks: AccountLoader<'info, BookSide>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/set_delegate.rs
use anchor_lang::prelude::*;

use crate::state::OpenOrdersAccount;

#[derive(Accounts)]
pub struct SetDelegate<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        has_one = owner,
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    /// CHECK:
    pub delegate_account: Option<UncheckedAccount<'info>>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/set_market_expired.rs
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SetMarketExpired<'info> {
    pub close_market_admin: Signer<'info>,
    #[account(
        mut,
        constraint = market.load()?.close_market_admin.is_some() @ OpenBookError::NoCloseMarketAdmin,
        constraint = market.load()?.close_market_admin == close_market_admin.key() @ OpenBookError::InvalidCloseMarketAdmin
    )]
    pub market: AccountLoader<'info, Market>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/settle_funds.rs
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct SettleFunds<'info> {
    pub owner: Signer<'info>,
    #[account(mut)]
    pub penalty_payer: Signer<'info>,

    #[account(
        mut,
        has_one = market,
        constraint = open_orders_account.load()?.is_owner_or_delegate(owner.key()) @ OpenBookError::NoOwnerOrDelegate
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    #[account(
        mut,
        has_one = market_base_vault,
        has_one = market_quote_vault,
        has_one = market_authority,
    )]
    pub market: AccountLoader<'info, Market>,
    /// CHECK: checked on has_one in market
    pub market_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub market_quote_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_base_vault.mint,
        constraint = open_orders_account.load()?.is_settle_destination_allowed(owner.key(), user_base_account.owner)
    )]
    pub user_base_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint,
        constraint = open_orders_account.load()?.is_settle_destination_allowed(owner.key(), user_quote_account.owner)
    )]
    pub user_quote_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub referrer_account: Option<Box<Account<'info, TokenAccount>>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/settle_funds_expired.rs
use crate::accounts_ix::{SettleFunds, SettleFundsBumps};
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct SettleFundsExpired<'info> {
    pub close_market_admin: Signer<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut)]
    pub penalty_payer: Signer<'info>,
    #[account(
        mut,
        has_one = market,
    )]
    pub open_orders_account: AccountLoader<'info, OpenOrdersAccount>,
    #[account(
        mut,
        has_one = market_base_vault,
        has_one = market_quote_vault,
        has_one = market_authority,
        constraint = market.load()?.close_market_admin.is_some() @ OpenBookError::NoCloseMarketAdmin,
        constraint = market.load()?.close_market_admin == close_market_admin.key() @ OpenBookError::InvalidCloseMarketAdmin
    )]
    pub market: AccountLoader<'info, Market>,
    /// CHECK: checked on has_one in market
    pub market_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub market_quote_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_base_vault.mint,
        constraint = user_base_account.owner == open_orders_account.load()?.owner
    )]
    pub user_base_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint,
        constraint = user_quote_account.owner == open_orders_account.load()?.owner
    )]
    pub user_quote_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub referrer_account: Option<Box<Account<'info, TokenAccount>>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> SettleFundsExpired<'info> {
    pub fn to_settle_funds(&self) -> SettleFunds<'info> {
        SettleFunds {
            owner: self.owner.clone(),
            penalty_payer: self.penalty_payer.clone(),
            open_orders_account: self.open_orders_account.clone(),
            market: self.market.clone(),
            market_authority: self.market_authority.clone(),
            market_base_vault: self.market_base_vault.clone(),
            market_quote_vault: self.market_quote_vault.clone(),
            user_base_account: self.user_base_account.clone(),
            user_quote_account: self.user_quote_account.clone(),
            referrer_account: self.referrer_account.clone(),
            token_program: self.token_program.clone(),
            system_program: self.system_program.clone(),
        }
    }
}

impl SettleFundsExpiredBumps {
    pub fn to_settle_funds(&self) -> SettleFundsBumps {
        SettleFundsBumps {}
    }
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/stub_oracle_close.rs
use anchor_lang::prelude::*;
use anchor_spl::token::Token;

use crate::state::*;

#[derive(Accounts)]
pub struct StubOracleClose<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        has_one = owner,
        close = sol_destination
    )]
    pub oracle: AccountLoader<'info, StubOracle>,
    #[account(mut)]
    /// CHECK: target for account rent needs no checks
    pub sol_destination: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/stub_oracle_create.rs
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

#[derive(Accounts)]
pub struct StubOracleCreate<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub owner: Signer<'info>,
    #[account(
        init,
        seeds = [b"StubOracle".as_ref(), owner.key().as_ref(), mint.key().as_ref()],
        bump,
        payer = payer,
        space = 8 + std::mem::size_of::<StubOracle>(),
    )]
    pub oracle: AccountLoader<'info, StubOracle>,
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/stub_oracle_set.rs
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct StubOracleSet<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        has_one = owner
    )]
    pub oracle: AccountLoader<'info, StubOracle>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_ix/sweep_fees.rs
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

#[derive(Accounts)]
pub struct SweepFees<'info> {
    pub collect_fee_admin: Signer<'info>,
    #[account(
        mut,
        has_one = market_quote_vault,
        has_one = collect_fee_admin,
        has_one = market_authority
    )]
    pub market: AccountLoader<'info, Market>,
    /// CHECK: checked on has_one in market
    pub market_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub market_quote_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = market_quote_vault.mint
    )]
    pub token_receiver_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}


// File: openbook-v2/programs/openbook-v2/src/accounts_zerocopy.rs
use anchor_lang::prelude::*;
use anchor_lang::ZeroCopy;
use arrayref::array_ref;
use std::cell::RefMut;
use std::{cell::Ref, mem};

/// Functions should prefer to work with AccountReader where possible, to abstract over
/// AccountInfo and AccountSharedData. That way the functions become usable in the program
/// and in client code.
// NOTE: would love to use solana's ReadableAccount, but that's in solana_sdk -- unavailable for programs
pub trait AccountReader {
    fn owner(&self) -> &Pubkey;
    fn data(&self) -> &[u8];
}

/// Like AccountReader, but can also get the account pubkey
pub trait KeyedAccountReader: AccountReader {
    fn key(&self) -> &Pubkey;
}

/// A Ref to an AccountInfo - makes AccountInfo compatible with AccountReader
pub struct AccountInfoRef<'a, 'info: 'a> {
    pub key: &'info Pubkey,
    pub owner: &'info Pubkey,
    pub data: Ref<'a, &'info mut [u8]>,
}

impl<'a, 'info: 'a> AccountInfoRef<'a, 'info> {
    pub fn borrow(account_info: &'a AccountInfo<'info>) -> Result<Self> {
        Ok(Self {
            key: account_info.key,
            owner: account_info.owner,
            data: account_info
                .data
                .try_borrow()
                .map_err(|_| ProgramError::AccountBorrowFailed)?,
            // Why is the following not acceptable?
            //data: account_info.try_borrow_data()?,
        })
    }

    pub fn borrow_some(account_info: Option<&'a UncheckedAccount<'info>>) -> Result<Option<Self>> {
        Ok(match account_info {
            Some(acc) => Some(AccountInfoRef::borrow(acc)?),
            _ => None,
        })
    }

    pub fn borrow_slice(ais: &'a [AccountInfo<'info>]) -> Result<Vec<Self>> {
        ais.iter().map(Self::borrow).collect()
    }
}

pub struct AccountInfoRefMut<'a, 'info: 'a> {
    pub key: &'info Pubkey,
    pub owner: &'info Pubkey,
    pub data: RefMut<'a, &'info mut [u8]>,
}

impl<'a, 'info: 'a> AccountInfoRefMut<'a, 'info> {
    pub fn borrow(account_info: &'a AccountInfo<'info>) -> Result<Self> {
        Ok(Self {
            key: account_info.key,
            owner: account_info.owner,
            data: account_info
                .data
                .try_borrow_mut()
                .map_err(|_| ProgramError::AccountBorrowFailed)?,
        })
    }

    pub fn borrow_slice(ais: &'a [AccountInfo<'info>]) -> Result<Vec<Self>> {
        ais.iter().map(Self::borrow).collect()
    }
}

impl<'info, 'a> AccountReader for AccountInfoRef<'info, 'a> {
    fn owner(&self) -> &Pubkey {
        self.owner
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'info, 'a> AccountReader for AccountInfoRefMut<'info, 'a> {
    fn owner(&self) -> &Pubkey {
        self.owner
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'info, 'a> KeyedAccountReader for AccountInfoRef<'info, 'a> {
    fn key(&self) -> &Pubkey {
        self.key
    }
}

impl<'info, 'a> KeyedAccountReader for AccountInfoRefMut<'info, 'a> {
    fn key(&self) -> &Pubkey {
        self.key
    }
}

#[cfg(feature = "solana-sdk")]
impl<T: solana_sdk::account::ReadableAccount> AccountReader for T {
    fn owner(&self) -> &Pubkey {
        self.owner()
    }

    fn data(&self) -> &[u8] {
        self.data()
    }
}

#[cfg(feature = "solana-sdk")]
#[derive(Clone)]
pub struct KeyedAccount {
    pub key: Pubkey,
    pub account: solana_sdk::account::Account,
}

#[cfg(feature = "solana-sdk")]
impl AccountReader for KeyedAccount {
    fn owner(&self) -> &Pubkey {
        self.account.owner()
    }

    fn data(&self) -> &[u8] {
        self.account.data()
    }
}

#[cfg(feature = "solana-sdk")]
impl KeyedAccountReader for KeyedAccount {
    fn key(&self) -> &Pubkey {
        &self.key
    }
}

#[cfg(feature = "solana-sdk")]
#[derive(Clone)]
pub struct KeyedAccountSharedData {
    pub key: Pubkey,
    pub data: solana_sdk::account::AccountSharedData,
}

#[cfg(feature = "solana-sdk")]
impl KeyedAccountSharedData {
    pub fn new(key: Pubkey, data: solana_sdk::account::AccountSharedData) -> Self {
        Self { key, data }
    }
}

#[cfg(feature = "solana-sdk")]
impl AccountReader for KeyedAccountSharedData {
    fn owner(&self) -> &Pubkey {
        AccountReader::owner(&self.data)
    }

    fn data(&self) -> &[u8] {
        AccountReader::data(&self.data)
    }
}

#[cfg(feature = "solana-sdk")]
impl KeyedAccountReader for KeyedAccountSharedData {
    fn key(&self) -> &Pubkey {
        &self.key
    }
}

//
// Common traits for loading from account data.
//

pub trait LoadZeroCopy {
    /// Using AccountLoader forces a AccountInfo.clone() and then binds the loaded
    /// lifetime to the AccountLoader's lifetime. This function avoids both.
    /// It checks the account owner and discriminator, then casts the data.
    fn load<T: ZeroCopy + Owner>(&self) -> Result<&T>;

    /// Same as load(), but doesn't check the discriminator or owner.
    fn load_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<&T>;
}

pub trait LoadMutZeroCopy {
    /// Same as load(), but mut
    fn load_mut<T: ZeroCopy + Owner>(&mut self) -> Result<&mut T>;

    /// Same as load_fully_unchecked(), but mut
    fn load_mut_fully_unchecked<T: ZeroCopy + Owner>(&mut self) -> Result<&mut T>;
}

pub trait LoadZeroCopyRef {
    /// Using AccountLoader forces a AccountInfo.clone() and then binds the loaded
    /// lifetime to the AccountLoader's lifetime. This function avoids both.
    /// It checks the account owner and discriminator, then casts the data.
    fn load<T: ZeroCopy + Owner>(&self) -> Result<Ref<T>>;

    /// Same as load(), but doesn't check the discriminator or owner.
    fn load_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<Ref<T>>;
}

pub trait LoadMutZeroCopyRef {
    /// Same as load(), but mut
    fn load_mut<T: ZeroCopy + Owner>(&self) -> Result<RefMut<T>>;

    /// Same as load_fully_unchecked(), but mut
    fn load_mut_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<RefMut<T>>;
}

impl<A: AccountReader> LoadZeroCopy for A {
    fn load<T: ZeroCopy + Owner>(&self) -> Result<&T> {
        if self.owner() != &T::owner() {
            return Err(ErrorCode::AccountOwnedByWrongProgram.into());
        }

        let data = self.data();
        if data.len() < 8 {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }
        let disc_bytes = array_ref![data, 0, 8];
        if disc_bytes != &T::discriminator() {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        Ok(bytemuck::from_bytes(&data[8..mem::size_of::<T>() + 8]))
    }

    fn load_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<&T> {
        Ok(bytemuck::from_bytes(
            &self.data()[8..mem::size_of::<T>() + 8],
        ))
    }
}

impl<'info, 'a> LoadMutZeroCopy for AccountInfoRefMut<'info, 'a> {
    fn load_mut<T: ZeroCopy + Owner>(&mut self) -> Result<&mut T> {
        if self.owner != &T::owner() {
            return Err(ErrorCode::AccountOwnedByWrongProgram.into());
        }

        if self.data.len() < 8 {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }
        let disc_bytes = array_ref![self.data, 0, 8];
        if disc_bytes != &T::discriminator() {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        Ok(bytemuck::from_bytes_mut(
            &mut self.data[8..mem::size_of::<T>() + 8],
        ))
    }

    fn load_mut_fully_unchecked<T: ZeroCopy + Owner>(&mut self) -> Result<&mut T> {
        Ok(bytemuck::from_bytes_mut(
            &mut self.data[8..mem::size_of::<T>() + 8],
        ))
    }
}

impl<'info> LoadZeroCopyRef for AccountInfo<'info> {
    fn load<T: ZeroCopy + Owner>(&self) -> Result<Ref<T>> {
        if self.owner != &T::owner() {
            return Err(ErrorCode::AccountOwnedByWrongProgram.into());
        }

        let data = self.try_borrow_data()?;
        if data.len() < 8 {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }

        let disc_bytes = array_ref![data, 0, 8];
        if disc_bytes != &T::discriminator() {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        Ok(Ref::map(data, |data| {
            bytemuck::from_bytes(&data[8..mem::size_of::<T>() + 8])
        }))
    }

    fn load_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<Ref<T>> {
        let data = self.try_borrow_data()?;
        Ok(Ref::map(data, |data| {
            bytemuck::from_bytes(&data[8..mem::size_of::<T>() + 8])
        }))
    }
}

impl<'info> LoadMutZeroCopyRef for AccountInfo<'info> {
    fn load_mut<T: ZeroCopy + Owner>(&self) -> Result<RefMut<T>> {
        if self.owner != &T::owner() {
            return Err(ErrorCode::AccountOwnedByWrongProgram.into());
        }

        let data = self.try_borrow_mut_data()?;
        if data.len() < 8 {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }

        let disc_bytes = array_ref![data, 0, 8];
        if disc_bytes != &T::discriminator() {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        Ok(RefMut::map(data, |data| {
            bytemuck::from_bytes_mut(&mut data[8..mem::size_of::<T>() + 8])
        }))
    }

    fn load_mut_fully_unchecked<T: ZeroCopy + Owner>(&self) -> Result<RefMut<T>> {
        let data = self.try_borrow_mut_data()?;
        Ok(RefMut::map(data, |data| {
            bytemuck::from_bytes_mut(&mut data[8..mem::size_of::<T>() + 8])
        }))
    }
}


// File: openbook-v2/programs/openbook-v2/src/error.rs
use anchor_lang::prelude::*;
use core::fmt::Display;

#[error_code]
pub enum OpenBookError {
    #[msg("")]
    SomeError,

    #[msg("Name lenght above limit")]
    InvalidInputNameLength,
    #[msg("Market cannot be created as expired")]
    InvalidInputMarketExpired,
    #[msg("Taker fees should be positive and if maker fees are negative, greater or equal to their abs value")]
    InvalidInputMarketFees,
    #[msg("Lots cannot be negative")]
    InvalidInputLots,
    #[msg("Lots size above market limits")]
    InvalidInputLotsSize,
    #[msg("Input amounts above limits")]
    InvalidInputOrdersAmounts,
    #[msg("Price lots should be greater than zero")]
    InvalidInputCancelSize,
    #[msg("Expected cancel size should be greater than zero")]
    InvalidInputPriceLots,
    #[msg("Peg limit should be greater than zero")]
    InvalidInputPegLimit,
    #[msg("The order type is invalid. A taker order must be Market or ImmediateOrCancel")]
    InvalidInputOrderType,
    #[msg("Order id cannot be zero")]
    InvalidInputOrderId,
    #[msg("Slot above heap limit")]
    InvalidInputHeapSlots,
    #[msg("Cannot combine two oracles of different providers")]
    InvalidOracleTypes,
    #[msg("Cannot configure secondary oracle without primary")]
    InvalidSecondOracle,

    #[msg("This market does not have a `close_market_admin` and thus cannot be closed.")]
    NoCloseMarketAdmin,
    #[msg("The signer of this transaction is not this market's `close_market_admin`.")]
    InvalidCloseMarketAdmin,
    #[msg("The `open_orders_admin` required by this market to sign all instructions that creates orders is missing or is not valid")]
    InvalidOpenOrdersAdmin,
    #[msg("The `consume_events_admin` required by this market to sign all instructions that consume events is missing or is not valid")]
    InvalidConsumeEventsAdmin,
    #[msg("Provided `market_vault` is invalid")]
    InvalidMarketVault,

    #[msg("Cannot be closed due to the existence of open orders accounts")]
    IndexerActiveOO,

    #[msg("Cannot place a peg order due to invalid oracle state")]
    OraclePegInvalidOracleState,
    #[msg("oracle type cannot be determined")]
    UnknownOracleType,
    #[msg("an oracle does not reach the confidence threshold")]
    OracleConfidence,
    #[msg("an oracle is stale")]
    OracleStale,
    #[msg("Order id not found on the orderbook")]
    OrderIdNotFound,
    #[msg("Event heap contains elements and market can't be closed")]
    EventHeapContainsElements,
    #[msg("ImmediateOrCancel is not a PostOrderType")]
    InvalidOrderPostIOC,
    #[msg("Market is not a PostOrderType")]
    InvalidOrderPostMarket,
    #[msg("would self trade")]
    WouldSelfTrade,
    #[msg("The Market has already expired.")]
    MarketHasExpired,
    #[msg("Price lots should be greater than zero")]
    InvalidPriceLots,
    #[msg("Oracle price above market limits")]
    InvalidOraclePrice,
    #[msg("The Market has not expired yet.")]
    MarketHasNotExpired,
    #[msg("No correct owner or delegate.")]
    NoOwnerOrDelegate,
    #[msg("No correct owner")]
    NoOwner,
    #[msg("No free order index in open orders account")]
    OpenOrdersFull,
    #[msg("Book contains elements")]
    BookContainsElements,
    #[msg("Could not find order in user account")]
    OpenOrdersOrderNotFound,
    #[msg("Amount to post above book limits")]
    InvalidPostAmount,
    #[msg("Oracle peg orders are not enabled for this market")]
    DisabledOraclePeg,
    #[msg("Cannot close a non-empty market")]
    NonEmptyMarket,
    #[msg("Cannot close a non-empty open orders account")]
    NonEmptyOpenOrdersPosition,
    #[msg("Fill-Or-Kill order would generate a partial execution")]
    WouldExecutePartially,
}

impl From<OpenBookError> for ProgramError {
    fn from(error: OpenBookError) -> Self {
        ProgramError::from(Error::from(error))
    }
}

impl OpenBookError {
    pub fn error_code(&self) -> u32 {
        (*self).into()
    }
}

pub trait IsAnchorErrorWithCode {
    fn is_anchor_error_with_code(&self, code: u32) -> bool;
}

impl<T> IsAnchorErrorWithCode for anchor_lang::Result<T> {
    fn is_anchor_error_with_code(&self, code: u32) -> bool {
        match self {
            Err(Error::AnchorError(error)) => error.error_code_number == code,
            _ => false,
        }
    }
}

pub trait Contextable {
    /// Add a context string `c` to a Result or Error
    ///
    /// Example: foo().context("calling foo")?;
    fn context(self, c: impl Display) -> Self;

    /// Like `context()`, but evaluate the context string lazily
    ///
    /// Use this if it's expensive to generate, like a format!() call.
    fn with_context<C, F>(self, c: F) -> Self
    where
        C: Display,
        F: FnOnce() -> C;
}

impl Contextable for Error {
    fn context(self, c: impl Display) -> Self {
        match self {
            Error::AnchorError(err) => Error::AnchorError(Box::new(AnchorError {
                error_msg: if err.error_msg.is_empty() {
                    format!("{}", c)
                } else {
                    format!("{}; {}", err.error_msg, c)
                },
                ..*err
            })),
            // Maybe wrap somehow?
            Error::ProgramError(err) => Error::ProgramError(err),
        }
    }
    fn with_context<C, F>(self, c: F) -> Self
    where
        C: Display,
        F: FnOnce() -> C,
    {
        self.context(c())
    }
}

impl<T> Contextable for Result<T> {
    fn context(self, c: impl Display) -> Self {
        if let Err(err) = self {
            Err(err.context(c))
        } else {
            self
        }
    }
    fn with_context<C, F>(self, c: F) -> Self
    where
        C: Display,
        F: FnOnce() -> C,
    {
        if let Err(err) = self {
            Err(err.context(c()))
        } else {
            self
        }
    }
}

/// Creates an Error with a particular message, using format!() style arguments
///
/// Example: error_msg!("index {} not found", index)
#[macro_export]
macro_rules! error_msg {
    ($($arg:tt)*) => {
        error!(OpenBookError::SomeError).context(format!($($arg)*))
    };
}

/// Creates an Error with a particular message, using format!() style arguments
///
/// Example: error_msg_typed!(TokenPositionMissing, "index {} not found", index)
#[macro_export]
macro_rules! error_msg_typed {
    ($code:expr, $($arg:tt)*) => {
        error!($code).context(format!($($arg)*))
    };
}

pub use error_msg;
pub use error_msg_typed;


// File: openbook-v2/programs/openbook-v2/src/i80f48.rs
// regression test for https://gitlab.com/tspiteri/fixed/-/issues/57
// see https://github.com/blockworks-foundation/fixed/issues/1
#[test]
fn bug_fixed_comparison_u64() {
    use fixed::types::I80F48;

    let a: u64 = 66000;
    let b: u64 = 1000;
    assert!(I80F48::from(a) > b); // fails!
}


// File: openbook-v2/programs/openbook-v2/src/instructions/cancel_all_and_place_orders.rs
use anchor_lang::prelude::*;
use std::cmp;

use crate::accounts_ix::*;
use crate::accounts_zerocopy::AccountInfoRef;
use crate::error::*;
use crate::state::*;
use crate::token_utils::*;

#[allow(clippy::too_many_arguments)]
pub fn cancel_all_and_place_orders<'c: 'info, 'info>(
    ctx: Context<'_, '_, 'c, 'info, CancelAllAndPlaceOrders<'info>>,
    cancel: bool,
    mut orders: Vec<Order>,
    limit: u8,
) -> Result<Vec<Option<u128>>> {
    let mut open_orders_account = ctx.accounts.open_orders_account.load_mut()?;
    let open_orders_account_pk = ctx.accounts.open_orders_account.key();

    let clock = Clock::get()?;

    let mut market = ctx.accounts.market.load_mut()?;
    require!(
        !market.is_expired(clock.unix_timestamp),
        OpenBookError::MarketHasExpired
    );

    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };
    let mut event_heap = ctx.accounts.event_heap.load_mut()?;
    let event_heap_size_before = event_heap.len();

    let now_ts: u64 = clock.unix_timestamp.try_into().unwrap();

    let oracle_price_lots = market.oracle_price_lots(
        AccountInfoRef::borrow_some(ctx.accounts.oracle_a.as_ref())?.as_ref(),
        AccountInfoRef::borrow_some(ctx.accounts.oracle_b.as_ref())?.as_ref(),
        clock.slot,
    )?;

    if cancel {
        book.cancel_all_orders(&mut open_orders_account, *market, u8::MAX, None, None)?;
    }

    let mut base_amount = 0_u64;
    let mut quote_amount = 0_u64;
    let mut order_ids = Vec::new();
    for order in orders.iter_mut() {
        order.max_base_lots = market.max_base_lots();
        require_gte!(
            order.max_quote_lots_including_fees,
            0,
            OpenBookError::InvalidInputLots
        );

        match order.side {
            Side::Ask => {
                let max_available_base = ctx.accounts.user_base_account.amount
                    + open_orders_account.position.base_free_native
                    - base_amount;
                order.max_base_lots = std::cmp::min(
                    order.max_base_lots,
                    market.max_base_lots_from_lamports(max_available_base),
                );
            }
            Side::Bid => {
                let max_available_quote = ctx.accounts.user_quote_account.amount
                    + open_orders_account.position.quote_free_native
                    - quote_amount;
                order.max_quote_lots_including_fees = std::cmp::min(
                    order.max_quote_lots_including_fees,
                    market.max_quote_lots_from_lamports(max_available_quote),
                );
            }
        }

        let OrderWithAmounts {
            order_id,
            total_base_taken_native,
            total_quote_taken_native,
            posted_base_native,
            posted_quote_native,
            taker_fees,
            maker_fees,
            ..
        } = book.new_order(
            order,
            &mut market,
            &ctx.accounts.market.key(),
            &mut event_heap,
            oracle_price_lots,
            Some(&mut open_orders_account),
            &open_orders_account_pk,
            now_ts,
            limit,
            ctx.remaining_accounts,
        )?;

        match order.side {
            Side::Bid => {
                quote_amount = quote_amount
                    .checked_add(
                        total_quote_taken_native + posted_quote_native + taker_fees + maker_fees,
                    )
                    .ok_or(OpenBookError::InvalidInputOrdersAmounts)?;
            }
            Side::Ask => {
                base_amount = base_amount
                    .checked_add(total_base_taken_native + posted_base_native)
                    .ok_or(OpenBookError::InvalidInputOrdersAmounts)?;
            }
        };

        order_ids.push(order_id);
    }

    let position = &mut open_orders_account.position;

    let free_base_to_lock = cmp::min(base_amount, position.base_free_native);
    let free_quote_to_lock = cmp::min(quote_amount, position.quote_free_native);

    let deposit_base_amount = base_amount - free_base_to_lock;
    let deposit_quote_amount = quote_amount - free_quote_to_lock;

    position.base_free_native -= free_base_to_lock;
    position.quote_free_native -= free_quote_to_lock;

    market.base_deposit_total += deposit_base_amount;
    market.quote_deposit_total += deposit_quote_amount;

    if event_heap.len() > event_heap_size_before {
        position.penalty_heap_count += 1;
    }

    token_transfer(
        deposit_quote_amount,
        &ctx.accounts.token_program,
        &ctx.accounts.user_quote_account,
        &ctx.accounts.market_quote_vault,
        &ctx.accounts.signer,
    )?;
    token_transfer(
        deposit_base_amount,
        &ctx.accounts.token_program,
        &ctx.accounts.user_base_account,
        &ctx.accounts.market_base_vault,
        &ctx.accounts.signer,
    )?;

    Ok(order_ids)
}


// File: openbook-v2/programs/openbook-v2/src/instructions/cancel_all_orders.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::state::*;

pub fn cancel_all_orders(
    ctx: Context<CancelOrder>,
    side_option: Option<Side>,
    limit: u8,
) -> Result<()> {
    let mut account = ctx.accounts.open_orders_account.load_mut()?;

    let market = ctx.accounts.market.load()?;
    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };

    book.cancel_all_orders(&mut account, *market, limit, side_option, None)?;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/cancel_order.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::error::*;
use crate::state::*;

pub fn cancel_order(ctx: Context<CancelOrder>, order_id: u128) -> Result<()> {
    require_gt!(order_id, 0, OpenBookError::InvalidInputOrderId);

    let mut open_orders_account = ctx.accounts.open_orders_account.load_mut()?;
    let oo = open_orders_account
        .find_order_with_order_id(order_id)
        .ok_or_else(|| {
            error_msg_typed!(OpenBookError::OpenOrdersOrderNotFound, "id = {order_id}")
        })?;

    let order_id = oo.id;
    let order_side_and_tree = oo.side_and_tree();

    let market = ctx.accounts.market.load()?;
    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };

    book.cancel_order(
        &mut open_orders_account,
        order_id,
        order_side_and_tree,
        *market,
        Some(ctx.accounts.open_orders_account.key()),
    )?;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/cancel_order_by_client_order_id.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::state::*;

pub fn cancel_order_by_client_order_id(
    ctx: Context<CancelOrder>,
    client_order_id: u64,
) -> Result<i64> {
    let mut account = ctx.accounts.open_orders_account.load_mut()?;

    let market = ctx.accounts.market.load()?;
    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };

    book.cancel_all_orders(&mut account, *market, u8::MAX, None, Some(client_order_id))
}


// File: openbook-v2/programs/openbook-v2/src/instructions/close_market.rs
use crate::accounts_ix::*;
use crate::error::OpenBookError;
use crate::state::*;
use anchor_lang::prelude::*;

pub fn close_market(ctx: Context<CloseMarket>) -> Result<()> {
    let market = ctx.accounts.market.load()?;
    require!(
        market.is_expired(Clock::get()?.unix_timestamp),
        OpenBookError::MarketHasNotExpired
    );
    require!(market.is_empty(), OpenBookError::NonEmptyMarket);

    let book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };
    require!(book.is_empty(), OpenBookError::BookContainsElements);

    let event_heap = ctx.accounts.event_heap.load()?;
    require!(
        event_heap.is_empty(),
        OpenBookError::EventHeapContainsElements
    );

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/close_open_orders_account.rs
use crate::accounts_ix::*;
use crate::error::OpenBookError;
use anchor_lang::prelude::*;

pub fn close_open_orders_account(ctx: Context<CloseOpenOrdersAccount>) -> Result<()> {
    let open_orders_account = ctx.accounts.open_orders_account.load()?;

    require!(
        open_orders_account
            .position
            .is_empty(open_orders_account.version),
        OpenBookError::NonEmptyOpenOrdersPosition
    );

    let indexer = &mut ctx.accounts.open_orders_indexer;
    let index = indexer
        .addresses
        .iter()
        .position(|x| *x == ctx.accounts.open_orders_account.key())
        .unwrap();
    indexer.addresses.remove(index);

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/close_open_orders_indexer.rs
use crate::accounts_ix::CloseOpenOrdersIndexer;
use crate::error::OpenBookError;
use anchor_lang::prelude::*;

pub fn close_open_orders_indexer(ctx: Context<CloseOpenOrdersIndexer>) -> Result<()> {
    require!(
        !ctx.accounts
            .open_orders_indexer
            .has_active_open_orders_accounts(),
        OpenBookError::IndexerActiveOO
    );

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/consume_events.rs
use anchor_lang::prelude::*;
use bytemuck::cast_ref;
use itertools::Itertools;

use crate::error::OpenBookError;
use crate::state::*;

use crate::accounts_ix::*;

// Max events to consume per ix.
pub const MAX_EVENTS_CONSUME: usize = 8;

/// Load a open_orders account by key from the list of account infos.
///
/// Message and return Ok() if it's missing, to lock in successful processing
/// of previous events.
macro_rules! load_open_orders_account {
    ($name:ident, $key:expr, $ais:expr) => {
        let loader = match $ais.iter().find(|ai| ai.key == &$key) {
            None => {
                msg!(
                    "Unable to find {} account {}, skipping",
                    stringify!($name),
                    $key.to_string()
                );
                continue;
            }

            Some(ai) => {
                let ooa: AccountLoader<OpenOrdersAccount> = AccountLoader::try_from(ai)?;
                ooa
            }
        };
        let mut $name = loader.load_mut()?;
    };
}

pub fn consume_events<'c: 'info, 'info>(
    ctx: Context<'_, '_, 'c, 'info, ConsumeEvents>,
    limit: usize,
    slots: Option<Vec<usize>>,
) -> Result<()> {
    let limit = std::cmp::min(limit, MAX_EVENTS_CONSUME);

    let mut market = ctx.accounts.market.load_mut()?;
    let mut event_heap = ctx.accounts.event_heap.load_mut()?;
    let remaining_accs = &ctx.remaining_accounts;

    let slots_to_consume = slots
        .unwrap_or_default()
        .into_iter()
        .filter(|slot| !event_heap.nodes[*slot].is_free())
        .chain(event_heap.iter().map(|(_event, slot)| slot))
        .unique()
        .take(limit)
        .collect_vec();

    for slot in slots_to_consume {
        let event = event_heap.at_slot(slot).unwrap();

        match EventType::try_from(event.event_type).map_err(|_| error!(OpenBookError::SomeError))? {
            EventType::Fill => {
                let fill: &FillEvent = cast_ref(event);
                load_open_orders_account!(maker, fill.maker, remaining_accs);
                maker.execute_maker(&mut market, fill);
            }
            EventType::Out => {
                let out: &OutEvent = cast_ref(event);
                load_open_orders_account!(owner, out.owner, remaining_accs);
                owner.cancel_order(out.owner_slot as usize, out.quantity, *market);
            }
        }

        // consume this event
        event_heap.delete_slot(slot)?;
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/create_market.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::accounts_zerocopy::*;
use crate::error::*;
use crate::logs::MarketMetaDataLog;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use crate::util::fill_from_str;

#[allow(clippy::too_many_arguments)]
pub fn create_market(
    ctx: Context<CreateMarket>,
    name: String,
    oracle_config: OracleConfigParams,
    quote_lot_size: i64,
    base_lot_size: i64,
    maker_fee: i64,
    taker_fee: i64,
    time_expiry: i64,
) -> Result<()> {
    let registration_time = Clock::get()?.unix_timestamp;

    require!(
        maker_fee.unsigned_abs() as i128 <= FEES_SCALE_FACTOR,
        OpenBookError::InvalidInputMarketFees
    );
    require!(
        taker_fee.unsigned_abs() as i128 <= FEES_SCALE_FACTOR,
        OpenBookError::InvalidInputMarketFees
    );
    require!(
        taker_fee >= 0 && (maker_fee >= 0 || maker_fee.abs() <= taker_fee),
        OpenBookError::InvalidInputMarketFees
    );

    require!(
        time_expiry == 0 || time_expiry > Clock::get()?.unix_timestamp,
        OpenBookError::InvalidInputMarketExpired
    );

    require_gt!(quote_lot_size, 0, OpenBookError::InvalidInputLots);
    require_gt!(base_lot_size, 0, OpenBookError::InvalidInputLots);

    let oracle_a = ctx.accounts.oracle_a.non_zero_key();
    let oracle_b = ctx.accounts.oracle_b.non_zero_key();

    if oracle_a.is_some() && oracle_b.is_some() {
        let oracle_a = AccountInfoRef::borrow(ctx.accounts.oracle_a.as_ref().unwrap())?;
        let oracle_b = AccountInfoRef::borrow(ctx.accounts.oracle_b.as_ref().unwrap())?;

        require_keys_neq!(*oracle_a.key, *oracle_b.key);
        require!(
            oracle::determine_oracle_type(&oracle_a)? == oracle::determine_oracle_type(&oracle_b)?,
            OpenBookError::InvalidOracleTypes
        );
    } else if oracle_a.is_some() {
        let oracle_a = AccountInfoRef::borrow(ctx.accounts.oracle_a.as_ref().unwrap())?;
        oracle::determine_oracle_type(&oracle_a)?;
    } else if oracle_b.is_some() {
        return Err(OpenBookError::InvalidSecondOracle.into());
    }

    let mut openbook_market = ctx.accounts.market.load_init()?;
    *openbook_market = Market {
        market_authority: ctx.accounts.market_authority.key(),
        collect_fee_admin: ctx.accounts.collect_fee_admin.key(),
        open_orders_admin: ctx.accounts.open_orders_admin.non_zero_key(),
        consume_events_admin: ctx.accounts.consume_events_admin.non_zero_key(),
        close_market_admin: ctx.accounts.close_market_admin.non_zero_key(),
        bump: ctx.bumps.market_authority,
        base_decimals: ctx.accounts.base_mint.decimals,
        quote_decimals: ctx.accounts.quote_mint.decimals,
        padding1: Default::default(),
        time_expiry,
        name: fill_from_str(&name)?,
        bids: ctx.accounts.bids.key(),
        asks: ctx.accounts.asks.key(),
        event_heap: ctx.accounts.event_heap.key(),
        oracle_a,
        oracle_b,
        oracle_config: oracle_config.to_oracle_config(),
        quote_lot_size,
        base_lot_size,
        seq_num: 0,
        registration_time,
        maker_fee,
        taker_fee,
        fees_accrued: 0,
        fees_to_referrers: 0,
        maker_volume: 0,
        taker_volume_wo_oo: 0,
        base_mint: ctx.accounts.base_mint.key(),
        quote_mint: ctx.accounts.quote_mint.key(),
        market_base_vault: ctx.accounts.market_base_vault.key(),
        base_deposit_total: 0,
        market_quote_vault: ctx.accounts.market_quote_vault.key(),
        quote_deposit_total: 0,
        fees_available: 0,
        referrer_rebates_accrued: 0,

        reserved: [0; 128],
    };

    let mut orderbook = Orderbook {
        bids: ctx.accounts.bids.load_init()?,
        asks: ctx.accounts.asks.load_init()?,
    };
    orderbook.init();

    let mut event_heap = ctx.accounts.event_heap.load_init()?;
    event_heap.init();

    emit_cpi!(MarketMetaDataLog {
        market: ctx.accounts.market.key(),
        name,
        base_mint: ctx.accounts.base_mint.key(),
        quote_mint: ctx.accounts.quote_mint.key(),
        base_decimals: ctx.accounts.base_mint.decimals,
        quote_decimals: ctx.accounts.quote_mint.decimals,
        base_lot_size,
        quote_lot_size,
    });

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/create_open_orders_account.rs
use crate::accounts_ix::CreateOpenOrdersAccount;
use crate::pubkey_option::NonZeroKey;
use crate::state::*;
use crate::util::fill_from_str;
use anchor_lang::prelude::*;

pub fn create_open_orders_account(
    ctx: Context<CreateOpenOrdersAccount>,
    name: String,
) -> Result<()> {
    let mut account = ctx.accounts.open_orders_account.load_init()?;
    let indexer = &mut ctx.accounts.open_orders_indexer;
    indexer
        .addresses
        .push(ctx.accounts.open_orders_account.key());
    indexer.created_counter += 1;

    account.name = fill_from_str(&name)?;
    account.account_num = indexer.created_counter;
    account.market = ctx.accounts.market.key();
    account.bump = ctx.bumps.open_orders_account;
    account.owner = ctx.accounts.owner.key();
    account.delegate = ctx.accounts.delegate_account.non_zero_key();
    account.version = 1;
    account.open_orders = [OpenOrder::default(); MAX_OPEN_ORDERS];

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/create_open_orders_indexer.rs
use crate::accounts_ix::CreateOpenOrdersIndexer;
use anchor_lang::prelude::*;

pub fn create_open_orders_indexer(ctx: Context<CreateOpenOrdersIndexer>) -> Result<()> {
    let indexer = &mut ctx.accounts.open_orders_indexer;

    indexer.bump = ctx.bumps.open_orders_indexer;
    indexer.created_counter = 0;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/deposit.rs
use crate::accounts_ix::Deposit;
use crate::error::*;
use crate::logs::{emit_stack, DepositLog};
use crate::token_utils::*;
use anchor_lang::prelude::*;

pub fn deposit(ctx: Context<Deposit>, base_amount: u64, quote_amount: u64) -> Result<()> {
    let mut open_orders_account = ctx.accounts.open_orders_account.load_mut()?;
    let mut market = ctx.accounts.market.load_mut()?;
    require!(
        !market.is_expired(Clock::get()?.unix_timestamp),
        OpenBookError::MarketHasExpired
    );

    token_transfer(
        base_amount,
        &ctx.accounts.token_program,
        &ctx.accounts.user_base_account,
        &ctx.accounts.market_base_vault,
        &ctx.accounts.owner,
    )?;
    open_orders_account.position.base_free_native += base_amount;
    market.base_deposit_total += base_amount;

    token_transfer(
        quote_amount,
        &ctx.accounts.token_program,
        &ctx.accounts.user_quote_account,
        &ctx.accounts.market_quote_vault,
        &ctx.accounts.owner,
    )?;
    open_orders_account.position.quote_free_native += quote_amount;
    market.quote_deposit_total += quote_amount;

    if base_amount > 0 || quote_amount > 0 {
        emit_stack(DepositLog {
            open_orders_account: ctx.accounts.open_orders_account.key(),
            signer: ctx.accounts.owner.key(),
            base_amount,
            quote_amount,
        });
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/edit_order.rs
use crate::accounts_ix::*;
use crate::error::*;
use crate::state::Order;
use anchor_lang::prelude::*;

pub fn edit_order<'c: 'info, 'info>(
    ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
    cancel_client_order_id: u64,
    expected_cancel_size: i64,
    mut order: Order,
    limit: u8,
) -> Result<Option<u128>> {
    require_gte!(
        expected_cancel_size,
        0,
        OpenBookError::InvalidInputCancelSize
    );

    let leaf_node_quantity = crate::instructions::cancel_order_by_client_order_id(
        Context::new(
            ctx.program_id,
            &mut ctx.accounts.to_cancel_order(),
            ctx.remaining_accounts,
            ctx.bumps.to_cancel_order(),
        ),
        cancel_client_order_id,
    )?;

    let filled_amount = expected_cancel_size - leaf_node_quantity;
    // note that order.max_base_lots is checked to be > 0 inside `place_order`
    if filled_amount > 0 && order.max_base_lots > filled_amount {
        // Do not reduce max_quote_lots_including_fees as implicitly it's limited by max_base_lots.
        order.max_base_lots -= filled_amount;
        return crate::instructions::place_order(ctx, order, limit);
    }
    Ok(None)
}


// File: openbook-v2/programs/openbook-v2/src/instructions/mod.rs
pub use cancel_all_and_place_orders::*;
pub use cancel_all_orders::*;
pub use cancel_order::*;
pub use cancel_order_by_client_order_id::*;
pub use close_market::*;
pub use close_open_orders_account::*;
pub use close_open_orders_indexer::*;
pub use consume_events::*;
pub use create_market::*;
pub use create_open_orders_account::*;
pub use create_open_orders_indexer::*;
pub use deposit::*;
pub use edit_order::*;
pub use place_order::*;
pub use place_take_order::*;
pub use prune_orders::*;
pub use set_delegate::*;
pub use set_market_expired::*;
pub use settle_funds::*;
pub use settle_funds_expired::*;
pub use stub_oracle_close::*;
pub use stub_oracle_create::*;
pub use stub_oracle_set::*;
pub use sweep_fees::*;

mod cancel_all_and_place_orders;
mod cancel_all_orders;
mod cancel_order;
mod cancel_order_by_client_order_id;
mod close_market;
mod close_open_orders_account;
mod close_open_orders_indexer;
mod consume_events;
mod create_market;
mod create_open_orders_account;
mod create_open_orders_indexer;
mod deposit;
mod edit_order;
mod place_order;
mod place_take_order;
mod prune_orders;
mod set_delegate;
mod set_market_expired;
mod settle_funds;
mod settle_funds_expired;
mod stub_oracle_close;
mod stub_oracle_create;
mod stub_oracle_set;
mod sweep_fees;


// File: openbook-v2/programs/openbook-v2/src/instructions/place_order.rs
use anchor_lang::prelude::*;
use std::cmp;

use crate::accounts_ix::*;
use crate::accounts_zerocopy::AccountInfoRef;
use crate::error::*;
use crate::state::*;
use crate::token_utils::*;

#[allow(clippy::too_many_arguments)]
pub fn place_order<'c: 'info, 'info>(
    ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
    order: Order,
    limit: u8,
) -> Result<Option<u128>> {
    require_gte!(order.max_base_lots, 0, OpenBookError::InvalidInputLots);
    require_gte!(
        order.max_quote_lots_including_fees,
        0,
        OpenBookError::InvalidInputLots
    );

    let mut open_orders_account = ctx.accounts.open_orders_account.load_mut()?;
    let open_orders_account_pk = ctx.accounts.open_orders_account.key();

    let clock = Clock::get()?;

    let mut market = ctx.accounts.market.load_mut()?;
    require_keys_eq!(
        market.get_vault_by_side(order.side),
        ctx.accounts.market_vault.key(),
        OpenBookError::InvalidMarketVault
    );
    require!(
        !market.is_expired(clock.unix_timestamp),
        OpenBookError::MarketHasExpired
    );

    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };
    let mut event_heap = ctx.accounts.event_heap.load_mut()?;
    let event_heap_size_before = event_heap.len();

    let now_ts: u64 = clock.unix_timestamp.try_into().unwrap();

    let oracle_price_lots = market.oracle_price_lots(
        AccountInfoRef::borrow_some(ctx.accounts.oracle_a.as_ref())?.as_ref(),
        AccountInfoRef::borrow_some(ctx.accounts.oracle_b.as_ref())?.as_ref(),
        clock.slot,
    )?;

    let OrderWithAmounts {
        order_id,
        total_base_taken_native,
        total_quote_taken_native,
        posted_base_native,
        posted_quote_native,
        taker_fees,
        maker_fees,
        ..
    } = book.new_order(
        &order,
        &mut market,
        &ctx.accounts.market.key(),
        &mut event_heap,
        oracle_price_lots,
        Some(&mut open_orders_account),
        &open_orders_account_pk,
        now_ts,
        limit,
        ctx.remaining_accounts,
    )?;

    let position = &mut open_orders_account.position;
    let deposit_amount = match order.side {
        Side::Bid => {
            let free_quote = position.quote_free_native;
            let max_quote_including_fees =
                total_quote_taken_native + posted_quote_native + taker_fees + maker_fees;

            let free_qty_to_lock = cmp::min(max_quote_including_fees, free_quote);
            let deposit_amount = max_quote_including_fees - free_qty_to_lock;

            // Update market deposit total
            position.quote_free_native -= free_qty_to_lock;
            market.quote_deposit_total += deposit_amount;

            deposit_amount
        }

        Side::Ask => {
            let free_base = position.base_free_native;
            let max_base_native = total_base_taken_native + posted_base_native;

            let free_qty_to_lock = cmp::min(max_base_native, free_base);
            let deposit_amount = max_base_native - free_qty_to_lock;

            // Update market deposit total
            position.base_free_native -= free_qty_to_lock;
            market.base_deposit_total += deposit_amount;

            deposit_amount
        }
    };

    if event_heap.len() > event_heap_size_before {
        position.penalty_heap_count += 1;
    }

    token_transfer(
        deposit_amount,
        &ctx.accounts.token_program,
        &ctx.accounts.user_token_account,
        &ctx.accounts.market_vault,
        &ctx.accounts.signer,
    )?;

    Ok(order_id)
}


// File: openbook-v2/programs/openbook-v2/src/instructions/place_take_order.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::accounts_zerocopy::AccountInfoRef;
use crate::error::*;
use crate::state::*;
use crate::token_utils::*;

#[allow(clippy::too_many_arguments)]
pub fn place_take_order<'c: 'info, 'info>(
    ctx: Context<'_, '_, 'c, 'info, PlaceTakeOrder<'info>>,
    order: Order,
    limit: u8,
) -> Result<()> {
    require_gte!(order.max_base_lots, 0, OpenBookError::InvalidInputLots);
    require_gte!(
        order.max_quote_lots_including_fees,
        0,
        OpenBookError::InvalidInputLots
    );

    let clock = Clock::get()?;

    let mut market = ctx.accounts.market.load_mut()?;
    require!(
        !market.is_expired(clock.unix_timestamp),
        OpenBookError::MarketHasExpired
    );

    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };

    let mut event_heap = ctx.accounts.event_heap.load_mut()?;
    let event_heap_size_before = event_heap.len();

    let now_ts: u64 = clock.unix_timestamp.try_into().unwrap();

    let oracle_price_lots = market.oracle_price_lots(
        AccountInfoRef::borrow_some(ctx.accounts.oracle_a.as_ref())?.as_ref(),
        AccountInfoRef::borrow_some(ctx.accounts.oracle_b.as_ref())?.as_ref(),
        clock.slot,
    )?;

    let side = order.side;

    let OrderWithAmounts {
        total_base_taken_native,
        total_quote_taken_native,
        referrer_amount,
        taker_fees,
        ..
    } = book.new_order(
        &order,
        &mut market,
        &ctx.accounts.market.key(),
        &mut event_heap,
        oracle_price_lots,
        None,
        &ctx.accounts.signer.key(),
        now_ts,
        limit,
        ctx.remaining_accounts,
    )?;

    // place_take_orders doesnt pay to referrers
    let makers_rebates = taker_fees - referrer_amount;

    let (deposit_amount, withdraw_amount) = match side {
        Side::Bid => {
            let total_quote_including_fees = total_quote_taken_native + makers_rebates;
            market.base_deposit_total -= total_base_taken_native;
            market.quote_deposit_total += total_quote_including_fees;
            (total_quote_including_fees, total_base_taken_native)
        }
        Side::Ask => {
            let total_quote_discounting_fees = total_quote_taken_native - makers_rebates;
            market.base_deposit_total += total_base_taken_native;
            market.quote_deposit_total -= total_quote_discounting_fees;
            (total_base_taken_native, total_quote_discounting_fees)
        }
    };

    let seeds = market_seeds!(market, ctx.accounts.market.key());

    drop(market);

    if event_heap.len() > event_heap_size_before {
        system_program_transfer(
            PENALTY_EVENT_HEAP,
            &ctx.accounts.system_program,
            &ctx.accounts.penalty_payer,
            &ctx.accounts.market,
        )?;
    }

    let (user_deposit_acc, user_withdraw_acc, market_deposit_acc, market_withdraw_acc) = match side
    {
        Side::Bid => (
            &ctx.accounts.user_quote_account,
            &ctx.accounts.user_base_account,
            &ctx.accounts.market_quote_vault,
            &ctx.accounts.market_base_vault,
        ),
        Side::Ask => (
            &ctx.accounts.user_base_account,
            &ctx.accounts.user_quote_account,
            &ctx.accounts.market_base_vault,
            &ctx.accounts.market_quote_vault,
        ),
    };

    token_transfer(
        deposit_amount,
        &ctx.accounts.token_program,
        user_deposit_acc.as_ref(),
        market_deposit_acc,
        &ctx.accounts.signer,
    )?;

    token_transfer_signed(
        withdraw_amount,
        &ctx.accounts.token_program,
        market_withdraw_acc,
        user_withdraw_acc.as_ref(),
        &ctx.accounts.market_authority,
        seeds,
    )?;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/prune_orders.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::error::*;
use crate::state::*;

pub fn prune_orders(ctx: Context<PruneOrders>, limit: u8) -> Result<()> {
    let mut account = ctx.accounts.open_orders_account.load_mut()?;
    let market = ctx.accounts.market.load()?;

    require!(
        market.is_expired(Clock::get()?.unix_timestamp),
        OpenBookError::MarketHasNotExpired
    );

    let mut book = Orderbook {
        bids: ctx.accounts.bids.load_mut()?,
        asks: ctx.accounts.asks.load_mut()?,
    };

    book.cancel_all_orders(&mut account, *market, limit, None, None)?;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/set_delegate.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::logs::{emit_stack, SetDelegateLog};
use crate::pubkey_option::NonZeroPubkeyOption;

pub fn set_delegate(ctx: Context<SetDelegate>) -> Result<()> {
    let mut account = ctx.accounts.open_orders_account.load_mut()?;

    let delegate_account: NonZeroPubkeyOption = ctx
        .accounts
        .delegate_account
        .as_ref()
        .map(|account| account.key())
        .into();

    account.delegate = delegate_account;

    emit_stack(SetDelegateLog {
        open_orders_account: ctx.accounts.open_orders_account.key(),
        delegate: delegate_account.into(),
    });

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/set_market_expired.rs
use crate::accounts_ix::*;
use crate::error::OpenBookError;
use anchor_lang::prelude::*;

pub fn set_market_expired(ctx: Context<SetMarketExpired>) -> Result<()> {
    let mut market = ctx.accounts.market.load_mut()?;
    require!(
        !market.is_expired(Clock::get()?.unix_timestamp),
        OpenBookError::MarketHasExpired
    );

    market.time_expiry = -1;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/settle_funds.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::logs::emit_stack;
use crate::logs::SettleFundsLog;
use crate::state::*;
use crate::token_utils::*;

pub fn settle_funds<'info>(ctx: Context<'_, '_, '_, 'info, SettleFunds<'info>>) -> Result<()> {
    let mut open_orders_account = ctx.accounts.open_orders_account.load_mut()?;
    let mut market = ctx.accounts.market.load_mut()?;

    let mut roundoff_maker_fees = 0;

    if market.maker_fee.is_positive() && open_orders_account.position.bids_base_lots == 0 {
        roundoff_maker_fees = open_orders_account.position.locked_maker_fees;
        open_orders_account.position.locked_maker_fees = 0;
    }

    let pa = &mut open_orders_account.position;
    let referrer_rebate = pa.referrer_rebates_available + roundoff_maker_fees;

    if ctx.accounts.referrer_account.is_some() {
        market.fees_to_referrers += referrer_rebate as u128;
        market.quote_deposit_total -= referrer_rebate;
    } else {
        market.fees_available += referrer_rebate;
    }

    market.base_deposit_total -= pa.base_free_native;
    market.quote_deposit_total -= pa.quote_free_native;
    market.referrer_rebates_accrued -= pa.referrer_rebates_available;

    let seeds = market_seeds!(market, ctx.accounts.market.key());

    drop(market);

    if pa.penalty_heap_count > 0 {
        system_program_transfer(
            pa.penalty_heap_count * PENALTY_EVENT_HEAP,
            &ctx.accounts.system_program,
            &ctx.accounts.penalty_payer,
            &ctx.accounts.market,
        )?;
        pa.penalty_heap_count = 0;
    }

    if let Some(referrer_account) = &ctx.accounts.referrer_account {
        token_transfer_signed(
            referrer_rebate,
            &ctx.accounts.token_program,
            &ctx.accounts.market_quote_vault,
            referrer_account,
            &ctx.accounts.market_authority,
            seeds,
        )?;
    }

    token_transfer_signed(
        pa.base_free_native,
        &ctx.accounts.token_program,
        &ctx.accounts.market_base_vault,
        &ctx.accounts.user_base_account,
        &ctx.accounts.market_authority,
        seeds,
    )?;

    token_transfer_signed(
        pa.quote_free_native,
        &ctx.accounts.token_program,
        &ctx.accounts.market_quote_vault,
        &ctx.accounts.user_quote_account,
        &ctx.accounts.market_authority,
        seeds,
    )?;

    emit_stack(SettleFundsLog {
        open_orders_account: ctx.accounts.open_orders_account.key(),
        base_native: pa.base_free_native,
        quote_native: pa.quote_free_native,
        referrer_rebate,
        referrer: ctx.accounts.referrer_account.as_ref().map(|acc| acc.key()),
    });

    pa.base_free_native = 0;
    pa.quote_free_native = 0;
    pa.referrer_rebates_available = 0;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/settle_funds_expired.rs
use crate::accounts_ix::*;
use crate::error::OpenBookError;
use anchor_lang::prelude::*;

pub fn settle_funds_expired<'info>(
    ctx: Context<'_, '_, '_, 'info, SettleFundsExpired<'info>>,
) -> Result<()> {
    {
        let market = ctx.accounts.market.load()?;
        require!(
            market.is_expired(Clock::get()?.unix_timestamp),
            OpenBookError::MarketHasNotExpired
        );
    }

    crate::instructions::settle_funds(Context::new(
        ctx.program_id,
        &mut ctx.accounts.to_settle_funds(),
        ctx.remaining_accounts,
        ctx.bumps.to_settle_funds(),
    ))
}


// File: openbook-v2/programs/openbook-v2/src/instructions/stub_oracle_close.rs
use crate::accounts_ix::*;
use anchor_lang::prelude::*;

pub fn stub_oracle_close(_ctx: Context<StubOracleClose>) -> Result<()> {
    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/stub_oracle_create.rs
use anchor_lang::prelude::*;

use crate::accounts_ix::*;

pub fn stub_oracle_create(ctx: Context<StubOracleCreate>, price: f64) -> Result<()> {
    let clock = Clock::get()?;
    let mut oracle = ctx.accounts.oracle.load_init()?;

    oracle.owner = ctx.accounts.owner.key();
    oracle.mint = ctx.accounts.mint.key();
    oracle.price = price;
    oracle.last_update_ts = clock.unix_timestamp;
    oracle.last_update_slot = clock.slot;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/stub_oracle_set.rs
use crate::accounts_ix::*;
use anchor_lang::prelude::*;

pub fn stub_oracle_set(ctx: Context<StubOracleSet>, price: f64) -> Result<()> {
    let clock = Clock::get()?;
    let mut oracle = ctx.accounts.oracle.load_mut()?;

    oracle.price = price;
    oracle.last_update_ts = clock.unix_timestamp;
    oracle.last_update_slot = clock.slot;

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/instructions/sweep_fees.rs
use crate::state::market_seeds;
use anchor_lang::prelude::*;

use crate::accounts_ix::*;
use crate::logs::{emit_stack, SweepFeesLog};
use crate::token_utils::*;

pub fn sweep_fees(ctx: Context<SweepFees>) -> Result<()> {
    let mut market = ctx.accounts.market.load_mut()?;

    let amount = market.fees_available;
    market.fees_available = 0;
    market.quote_deposit_total -= amount;

    let seeds = market_seeds!(market, ctx.accounts.market.key());
    drop(market);

    token_transfer_signed(
        amount,
        &ctx.accounts.token_program,
        &ctx.accounts.market_quote_vault,
        &ctx.accounts.token_receiver_account,
        &ctx.accounts.market_authority,
        seeds,
    )?;

    emit_stack(SweepFeesLog {
        market: ctx.accounts.market.key(),
        amount,
        receiver: ctx.accounts.token_receiver_account.key(),
    });

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/lib.rs
//! A central-limit order book (CLOB) program that targets the Sealevel runtime.

use anchor_lang::prelude::{
    borsh::{BorshDeserialize, BorshSerialize},
    *,
};

declare_id!("opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb");

#[macro_use]
pub mod util;

pub mod accounts_ix;
pub mod accounts_zerocopy;
pub mod error;
pub mod logs;
pub mod pubkey_option;
pub mod state;
pub mod token_utils;
pub mod types;

mod i80f48;

#[cfg(feature = "enable-gpl")]
pub mod instructions;

use accounts_ix::*;
use accounts_ix::{StubOracleCreate, StubOracleSet};
use error::*;
use state::{OracleConfigParams, Order, OrderParams, PlaceOrderType, SelfTradeBehavior, Side};
use std::cmp;

#[cfg(all(not(feature = "no-entrypoint"), not(feature = "enable-gpl")))]
compile_error!("compiling the program entrypoint without 'enable-gpl' makes no sense, enable it or use the 'cpi' or 'client' features");

#[program]
pub mod openbook_v2 {
    use super::*;

    /// Create a [`Market`](crate::state::Market) for a given token pair.
    #[allow(clippy::too_many_arguments)]
    pub fn create_market(
        ctx: Context<CreateMarket>,
        name: String,
        oracle_config: OracleConfigParams,
        quote_lot_size: i64,
        base_lot_size: i64,
        maker_fee: i64,
        taker_fee: i64,
        time_expiry: i64,
    ) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::create_market(
            ctx,
            name,
            oracle_config,
            quote_lot_size,
            base_lot_size,
            maker_fee,
            taker_fee,
            time_expiry,
        )?;
        Ok(())
    }

    /// Close a [`Market`](crate::state::Market) (only
    /// [`close_market_admin`](crate::state::Market::close_market_admin)).
    pub fn close_market(ctx: Context<CloseMarket>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::close_market(ctx)?;
        Ok(())
    }

    /// Create an [`OpenOrdersIndexer`](crate::state::OpenOrdersIndexer) account.
    pub fn create_open_orders_indexer(ctx: Context<CreateOpenOrdersIndexer>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::create_open_orders_indexer(ctx)?;
        Ok(())
    }

    /// Close an [`OpenOrdersIndexer`](crate::state::OpenOrdersIndexer) account.
    pub fn close_open_orders_indexer(ctx: Context<CloseOpenOrdersIndexer>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::close_open_orders_indexer(ctx)?;
        Ok(())
    }

    /// Create an [`OpenOrdersAccount`](crate::state::OpenOrdersAccount).
    pub fn create_open_orders_account(
        ctx: Context<CreateOpenOrdersAccount>,
        name: String,
    ) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::create_open_orders_account(ctx, name)?;
        Ok(())
    }

    /// Close an [`OpenOrdersAccount`](crate::state::OpenOrdersAccount).
    pub fn close_open_orders_account(ctx: Context<CloseOpenOrdersAccount>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::close_open_orders_account(ctx)?;
        Ok(())
    }

    /// Place an order.
    ///
    /// Different types of orders have different effects on the order book,
    /// as described in [`PlaceOrderType`](crate::state::PlaceOrderType).
    ///
    /// `price_lots` refers to the price in lots: the number of quote lots
    /// per base lot. It is ignored for `PlaceOrderType::Market` orders.
    ///
    /// `expiry_timestamp` is a unix timestamp for when this order should
    /// expire. If 0 is passed in, the order will never expire. If the time
    /// is in the past, the instruction is skipped. Timestamps in the future
    /// are reduced to now + 65,535s.
    ///
    /// `limit` determines the maximum number of orders from the book to fill,
    /// and can be used to limit CU spent. When the limit is reached, processing
    /// stops and the instruction succeeds.
    pub fn place_order<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
        args: PlaceOrderArgs,
    ) -> Result<Option<u128>> {
        require_gte!(args.price_lots, 1, OpenBookError::InvalidInputPriceLots);

        let time_in_force = match Order::tif_from_expiry(args.expiry_timestamp) {
            Some(t) => t,
            None => {
                msg!("Order is already expired");
                return Ok(None);
            }
        };
        let order = Order {
            side: args.side,
            max_base_lots: args.max_base_lots,
            max_quote_lots_including_fees: args.max_quote_lots_including_fees,
            client_order_id: args.client_order_id,
            time_in_force,
            self_trade_behavior: args.self_trade_behavior,
            params: match args.order_type {
                PlaceOrderType::Market => OrderParams::Market,
                PlaceOrderType::ImmediateOrCancel => OrderParams::ImmediateOrCancel {
                    price_lots: args.price_lots,
                },
                PlaceOrderType::FillOrKill => OrderParams::FillOrKill {
                    price_lots: args.price_lots,
                },
                _ => OrderParams::Fixed {
                    price_lots: args.price_lots,
                    order_type: args.order_type.to_post_order_type()?,
                },
            },
        };
        #[cfg(feature = "enable-gpl")]
        return instructions::place_order(ctx, order, args.limit);

        #[cfg(not(feature = "enable-gpl"))]
        Ok(None)
    }

    /// Edit an order.
    pub fn edit_order<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
        client_order_id: u64,
        expected_cancel_size: i64,
        place_order: PlaceOrderArgs,
    ) -> Result<Option<u128>> {
        require_gte!(
            place_order.price_lots,
            1,
            OpenBookError::InvalidInputPriceLots
        );

        let time_in_force = match Order::tif_from_expiry(place_order.expiry_timestamp) {
            Some(t) => t,
            None => {
                msg!("Order is already expired");
                return Ok(None);
            }
        };
        let order = Order {
            side: place_order.side,
            max_base_lots: place_order.max_base_lots,
            max_quote_lots_including_fees: place_order.max_quote_lots_including_fees,
            client_order_id: place_order.client_order_id,
            time_in_force,
            self_trade_behavior: place_order.self_trade_behavior,
            params: match place_order.order_type {
                PlaceOrderType::Market => OrderParams::Market,
                PlaceOrderType::ImmediateOrCancel => OrderParams::ImmediateOrCancel {
                    price_lots: place_order.price_lots,
                },
                PlaceOrderType::FillOrKill => OrderParams::FillOrKill {
                    price_lots: place_order.price_lots,
                },
                _ => OrderParams::Fixed {
                    price_lots: place_order.price_lots,
                    order_type: place_order.order_type.to_post_order_type()?,
                },
            },
        };
        #[cfg(feature = "enable-gpl")]
        return instructions::edit_order(
            ctx,
            client_order_id,
            expected_cancel_size,
            order,
            place_order.limit,
        );

        #[cfg(not(feature = "enable-gpl"))]
        Ok(None)
    }

    /// Edit an order pegged.
    pub fn edit_order_pegged<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
        client_order_id: u64,
        expected_cancel_size: i64,
        place_order: PlaceOrderPeggedArgs,
    ) -> Result<Option<u128>> {
        require!(
            ctx.accounts.oracle_a.is_some(),
            OpenBookError::DisabledOraclePeg
        );

        require_gt!(
            place_order.peg_limit,
            0,
            OpenBookError::InvalidInputPegLimit
        );

        let time_in_force = match Order::tif_from_expiry(place_order.expiry_timestamp) {
            Some(t) => t,
            None => {
                msg!("Order is already expired");
                return Ok(None);
            }
        };

        let order = Order {
            side: place_order.side,
            max_base_lots: place_order.max_base_lots,
            max_quote_lots_including_fees: place_order.max_quote_lots_including_fees,
            client_order_id: place_order.client_order_id,
            time_in_force,
            self_trade_behavior: place_order.self_trade_behavior,
            params: OrderParams::OraclePegged {
                price_offset_lots: place_order.price_offset_lots,
                order_type: place_order.order_type.to_post_order_type()?,
                peg_limit: place_order.peg_limit,
            },
        };
        #[cfg(feature = "enable-gpl")]
        return instructions::edit_order(
            ctx,
            client_order_id,
            expected_cancel_size,
            order,
            place_order.limit,
        );

        #[cfg(not(feature = "enable-gpl"))]
        Ok(None)
    }

    /// Place multiple orders
    pub fn place_orders<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, CancelAllAndPlaceOrders<'info>>,
        orders_type: PlaceOrderType,
        bids: Vec<PlaceMultipleOrdersArgs>,
        asks: Vec<PlaceMultipleOrdersArgs>,
        limit: u8,
    ) -> Result<Vec<Option<u128>>> {
        let n_bids = bids.len();

        let mut orders = vec![];
        for (i, order) in bids.into_iter().chain(asks).enumerate() {
            require_gte!(order.price_lots, 1, OpenBookError::InvalidInputPriceLots);

            let time_in_force = match Order::tif_from_expiry(order.expiry_timestamp) {
                Some(t) => t,
                None => {
                    msg!("Order is already expired");
                    continue;
                }
            };
            orders.push(Order {
                side: if i < n_bids { Side::Bid } else { Side::Ask },
                max_base_lots: i64::MIN, // this will be overriden to max_base_lots
                max_quote_lots_including_fees: order.max_quote_lots_including_fees,
                client_order_id: i as u64,
                time_in_force,
                self_trade_behavior: SelfTradeBehavior::CancelProvide,
                params: match orders_type {
                    PlaceOrderType::Market => OrderParams::Market,
                    PlaceOrderType::ImmediateOrCancel => OrderParams::ImmediateOrCancel {
                        price_lots: order.price_lots,
                    },
                    PlaceOrderType::FillOrKill => OrderParams::FillOrKill {
                        price_lots: order.price_lots,
                    },
                    _ => OrderParams::Fixed {
                        price_lots: order.price_lots,
                        order_type: orders_type.to_post_order_type()?,
                    },
                },
            });
        }

        #[cfg(feature = "enable-gpl")]
        return instructions::cancel_all_and_place_orders(ctx, false, orders, limit);

        #[cfg(not(feature = "enable-gpl"))]
        Ok(vec![])
    }

    /// Cancel orders and place multiple orders.
    pub fn cancel_all_and_place_orders<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, CancelAllAndPlaceOrders<'info>>,
        orders_type: PlaceOrderType,
        bids: Vec<PlaceMultipleOrdersArgs>,
        asks: Vec<PlaceMultipleOrdersArgs>,
        limit: u8,
    ) -> Result<Vec<Option<u128>>> {
        let n_bids = bids.len();

        let mut orders = vec![];
        for (i, order) in bids.into_iter().chain(asks).enumerate() {
            require_gte!(order.price_lots, 1, OpenBookError::InvalidInputPriceLots);

            let time_in_force = match Order::tif_from_expiry(order.expiry_timestamp) {
                Some(t) => t,
                None => {
                    msg!("Order is already expired");
                    continue;
                }
            };
            orders.push(Order {
                side: if i < n_bids { Side::Bid } else { Side::Ask },
                max_base_lots: i64::MIN, // this will be overriden to max_base_lots
                max_quote_lots_including_fees: order.max_quote_lots_including_fees,
                client_order_id: i as u64,
                time_in_force,
                self_trade_behavior: SelfTradeBehavior::CancelProvide,
                params: match orders_type {
                    PlaceOrderType::Market => OrderParams::Market,
                    PlaceOrderType::ImmediateOrCancel => OrderParams::ImmediateOrCancel {
                        price_lots: order.price_lots,
                    },
                    PlaceOrderType::FillOrKill => OrderParams::FillOrKill {
                        price_lots: order.price_lots,
                    },
                    _ => OrderParams::Fixed {
                        price_lots: order.price_lots,
                        order_type: orders_type.to_post_order_type()?,
                    },
                },
            });
        }

        #[cfg(feature = "enable-gpl")]
        return instructions::cancel_all_and_place_orders(ctx, true, orders, limit);

        #[cfg(not(feature = "enable-gpl"))]
        Ok(vec![])
    }

    /// Place an oracle-peg order.
    pub fn place_order_pegged<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, PlaceOrder<'info>>,
        args: PlaceOrderPeggedArgs,
    ) -> Result<Option<u128>> {
        require!(
            ctx.accounts.oracle_a.is_some(),
            OpenBookError::DisabledOraclePeg
        );

        require_gt!(args.peg_limit, 0, OpenBookError::InvalidInputPegLimit);

        let time_in_force = match Order::tif_from_expiry(args.expiry_timestamp) {
            Some(t) => t,
            None => {
                msg!("Order is already expired");
                return Ok(None);
            }
        };

        let order = Order {
            side: args.side,
            max_base_lots: args.max_base_lots,
            max_quote_lots_including_fees: args.max_quote_lots_including_fees,
            client_order_id: args.client_order_id,
            time_in_force,
            self_trade_behavior: args.self_trade_behavior,
            params: OrderParams::OraclePegged {
                price_offset_lots: args.price_offset_lots,
                order_type: args.order_type.to_post_order_type()?,
                peg_limit: args.peg_limit,
            },
        };
        #[cfg(feature = "enable-gpl")]
        return instructions::place_order(ctx, order, args.limit);

        #[cfg(not(feature = "enable-gpl"))]
        Ok(None)
    }

    /// Place an order that shall take existing liquidity off of the book, not
    /// add a new order off the book.
    ///
    /// This type of order allows for instant token settlement for the taker.
    pub fn place_take_order<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, PlaceTakeOrder<'info>>,
        args: PlaceTakeOrderArgs,
    ) -> Result<()> {
        require_gte!(args.price_lots, 1, OpenBookError::InvalidInputPriceLots);

        let order = Order {
            side: args.side,
            max_base_lots: args.max_base_lots,
            max_quote_lots_including_fees: args.max_quote_lots_including_fees,
            client_order_id: 0,
            time_in_force: 0,
            self_trade_behavior: SelfTradeBehavior::default(),
            params: match args.order_type {
                PlaceOrderType::Market => OrderParams::Market,
                PlaceOrderType::ImmediateOrCancel => OrderParams::ImmediateOrCancel {
                    price_lots: args.price_lots,
                },
                PlaceOrderType::FillOrKill => OrderParams::FillOrKill {
                    price_lots: args.price_lots,
                },
                _ => return Err(OpenBookError::InvalidInputOrderType.into()),
            },
        };

        #[cfg(feature = "enable-gpl")]
        instructions::place_take_order(ctx, order, args.limit)?;
        Ok(())
    }

    /// Process up to `limit` [events](crate::state::AnyEvent).
    ///
    /// When a user places a 'take' order, they do not know beforehand which
    /// market maker will have placed the 'make' order that they get executed
    /// against. This prevents them from passing in a market maker's
    /// [`OpenOrdersAccount`](crate::state::OpenOrdersAccount), which is needed
    /// to credit/debit the relevant tokens to/from the maker. As such, Openbook
    /// uses a 'crank' system, where `place_order` only emits events, and
    /// `consume_events` handles token settlement.
    ///
    /// Currently, there are two types of events: [`FillEvent`](crate::state::FillEvent)s
    /// and [`OutEvent`](crate::state::OutEvent)s.
    ///
    /// A `FillEvent` is emitted when an order is filled, and it is handled by
    /// debiting whatever the taker is selling from the taker and crediting
    /// it to the maker, and debiting whatever the taker is buying from the
    /// maker and crediting it to the taker. Note that *no tokens are moved*,
    /// these are just debits and credits to each party's [`Position`](crate::state::Position).
    ///
    /// An `OutEvent` is emitted when a limit order needs to be removed from
    /// the book during a `place_order` invocation, and it is handled by
    /// crediting whatever the maker would have sold (quote token in a bid,
    /// base token in an ask) back to the maker.
    pub fn consume_events<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, ConsumeEvents>,
        limit: usize,
    ) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::consume_events(ctx, limit, None)?;
        Ok(())
    }

    /// Process the [events](crate::state::AnyEvent) at the given positions.
    pub fn consume_given_events<'c: 'info, 'info>(
        ctx: Context<'_, '_, 'c, 'info, ConsumeEvents>,
        slots: Vec<usize>,
    ) -> Result<()> {
        require!(
            slots
                .iter()
                .all(|slot| *slot < crate::state::MAX_NUM_EVENTS as usize),
            OpenBookError::InvalidInputHeapSlots
        );
        #[cfg(feature = "enable-gpl")]
        instructions::consume_events(ctx, slots.len(), Some(slots))?;
        Ok(())
    }

    /// Cancel an order by its `order_id`.
    ///
    /// Note that this doesn't emit an [`OutEvent`](crate::state::OutEvent) because a
    /// maker knows that they will be passing in their own [`OpenOrdersAccount`](crate::state::OpenOrdersAccount).
    pub fn cancel_order(ctx: Context<CancelOrder>, order_id: u128) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::cancel_order(ctx, order_id)?;
        Ok(())
    }

    /// Cancel an order by its `client_order_id`.
    ///
    /// Note that this doesn't emit an [`OutEvent`](crate::state::OutEvent) because a
    /// maker knows that they will be passing in their own [`OpenOrdersAccount`](crate::state::OpenOrdersAccount).
    pub fn cancel_order_by_client_order_id(
        ctx: Context<CancelOrder>,
        client_order_id: u64,
    ) -> Result<i64> {
        #[cfg(feature = "enable-gpl")]
        return instructions::cancel_order_by_client_order_id(ctx, client_order_id);

        #[cfg(not(feature = "enable-gpl"))]
        Ok(0)
    }

    /// Cancel up to `limit` orders, optionally filtering by side
    pub fn cancel_all_orders(
        ctx: Context<CancelOrder>,
        side_option: Option<Side>,
        limit: u8,
    ) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::cancel_all_orders(ctx, side_option, limit)?;
        Ok(())
    }

    /// Deposit a certain amount of `base` and `quote` lamports into one's
    /// [`Position`](crate::state::Position).
    ///
    /// Makers might wish to `deposit`, rather than have actual tokens moved for
    /// each trade, in order to reduce CUs.
    pub fn deposit(ctx: Context<Deposit>, base_amount: u64, quote_amount: u64) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::deposit(ctx, base_amount, quote_amount)?;
        Ok(())
    }

    /// Refill a certain amount of `base` and `quote` lamports. The amount being passed is the
    /// total lamports that the [`Position`](crate::state::Position) will have.
    ///
    /// Makers might wish to `refill`, rather than have actual tokens moved for
    /// each trade, in order to reduce CUs.
    pub fn refill(ctx: Context<Deposit>, base_amount: u64, quote_amount: u64) -> Result<()> {
        let (quote_amount, base_amount) = {
            let open_orders_account = ctx.accounts.open_orders_account.load()?;
            (
                quote_amount
                    - cmp::min(quote_amount, open_orders_account.position.quote_free_native),
                base_amount - cmp::min(base_amount, open_orders_account.position.base_free_native),
            )
        };
        #[cfg(feature = "enable-gpl")]
        instructions::deposit(ctx, base_amount, quote_amount)?;
        Ok(())
    }

    /// Withdraw any available tokens.
    pub fn settle_funds<'info>(ctx: Context<'_, '_, '_, 'info, SettleFunds<'info>>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::settle_funds(ctx)?;
        Ok(())
    }

    /// Withdraw any available tokens when the market is expired (only
    /// [`close_market_admin`](crate::state::Market::close_market_admin)).
    pub fn settle_funds_expired<'info>(
        ctx: Context<'_, '_, '_, 'info, SettleFundsExpired<'info>>,
    ) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::settle_funds_expired(ctx)?;
        Ok(())
    }

    /// Sweep fees, as a [`Market`](crate::state::Market)'s admin.
    pub fn sweep_fees(ctx: Context<SweepFees>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::sweep_fees(ctx)?;
        Ok(())
    }

    /// Update the [`delegate`](crate::state::OpenOrdersAccount::delegate) of an open orders account.
    pub fn set_delegate(ctx: Context<SetDelegate>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::set_delegate(ctx)?;
        Ok(())
    }

    /// Set market to expired before pruning orders and closing the market (only
    /// [`close_market_admin`](crate::state::Market::close_market_admin)).
    pub fn set_market_expired(ctx: Context<SetMarketExpired>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::set_market_expired(ctx)?;
        Ok(())
    }

    /// Remove orders from the book when the market is expired (only
    /// [`close_market_admin`](crate::state::Market::close_market_admin)).
    pub fn prune_orders(ctx: Context<PruneOrders>, limit: u8) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::prune_orders(ctx, limit)?;
        Ok(())
    }

    pub fn stub_oracle_create(ctx: Context<StubOracleCreate>, price: f64) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::stub_oracle_create(ctx, price)?;
        Ok(())
    }

    pub fn stub_oracle_close(ctx: Context<StubOracleClose>) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::stub_oracle_close(ctx)?;
        Ok(())
    }

    pub fn stub_oracle_set(ctx: Context<StubOracleSet>, price: f64) -> Result<()> {
        #[cfg(feature = "enable-gpl")]
        instructions::stub_oracle_set(ctx, price)?;
        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Debug, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlaceOrderArgs {
    pub side: Side,
    pub price_lots: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub client_order_id: u64,
    pub order_type: PlaceOrderType,
    pub expiry_timestamp: u64,
    pub self_trade_behavior: SelfTradeBehavior,
    // Maximum number of orders from the book to fill.
    //
    // Use this to limit compute used during order matching.
    // When the limit is reached, processing stops and the instruction succeeds.
    pub limit: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Debug, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlaceMultipleOrdersArgs {
    pub price_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub expiry_timestamp: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Debug, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlaceOrderPeggedArgs {
    pub side: Side,

    // The adjustment from the oracle price, in lots (quote lots per base lots).
    // Orders on the book may be filled at oracle + adjustment (depends on order type).
    pub price_offset_lots: i64,

    // The limit at which the pegged order shall expire.
    //
    // Example: An bid pegged to -20 with peg_limit 100 would expire if the oracle hits 121.
    pub peg_limit: i64,

    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub client_order_id: u64,
    pub order_type: PlaceOrderType,

    // Timestamp of when order expires
    //
    // Send 0 if you want the order to never expire.
    // Timestamps in the past mean the instruction is skipped.
    // Timestamps in the future are reduced to now + 65535s.
    pub expiry_timestamp: u64,

    pub self_trade_behavior: SelfTradeBehavior,
    // Maximum number of orders from the book to fill.
    //
    // Use this to limit compute used during order matching.
    // When the limit is reached, processing stops and the instruction succeeds.
    pub limit: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Debug, Copy, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PlaceTakeOrderArgs {
    pub side: Side,
    pub price_lots: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub order_type: PlaceOrderType,
    // Maximum number of orders from the book to fill.
    //
    // Use this to limit compute used during order matching.
    // When the limit is reached, processing stops and the instruction succeeds.
    pub limit: u8,
}

// Add security details to explorer.solana.com
#[cfg(not(feature = "no-entrypoint"))]
use {default_env::default_env, solana_security_txt::security_txt};

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "OpenBook V2",
    project_url: "https://www.openbook-solana.com/",
    contacts: "email:contact@openbook-solana.com,discord:https://discord.com/invite/pX3n5Sercb",
    policy: "https://github.com/openbook-dex/openbook-v2/blob/master/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/openbook-dex/openbook-v2",
    auditors: "https://github.com/openbook-dex/openbook-v2/blob/master/audit/openbook_audit.pdf",
    source_revision: default_env!("GITHUB_SHA", "Unknown source revision"),
    source_release: default_env!("GITHUB_REF_NAME", "Unknown source release")
}


// File: openbook-v2/programs/openbook-v2/src/logs.rs
use anchor_lang::prelude::*;
use borsh::BorshSerialize;

#[inline(never)] // ensure fresh stack frame
pub fn emit_stack<T: anchor_lang::Event>(e: T) {
    use std::io::{Cursor, Write};

    // stack buffer, stack frames are 4kb
    let mut buffer = [0u8; 3000];

    let mut cursor = Cursor::new(&mut buffer[..]);
    cursor.write_all(&T::DISCRIMINATOR).unwrap();
    e.serialize(&mut cursor)
        .expect("event must fit into stack buffer");

    let pos = cursor.position() as usize;
    anchor_lang::solana_program::log::sol_log_data(&[&buffer[..pos]]);
}

#[event]
pub struct DepositLog {
    pub open_orders_account: Pubkey,
    pub signer: Pubkey,
    pub base_amount: u64,
    pub quote_amount: u64,
}

#[event]
pub struct FillLog {
    pub market: Pubkey,
    pub taker_side: u8, // side from the taker's POV
    pub maker_slot: u8,
    pub maker_out: bool, // true if maker order quantity == 0
    pub timestamp: u64,
    pub seq_num: u64, // note: usize same as u64

    pub maker: Pubkey,
    pub maker_client_order_id: u64,
    pub maker_fee: u64, // native quote

    // Timestamp of when the maker order was placed; copied over from the LeafNode
    pub maker_timestamp: u64,

    pub taker: Pubkey,
    pub taker_client_order_id: u64,
    pub taker_fee_ceil: u64, // native quote

    pub price: i64,
    pub quantity: i64, // number of base lots
}

#[event]
pub struct TakerSignatureLog {
    pub market: Pubkey,
    pub seq_num: u64,
}

#[event]
pub struct MarketMetaDataLog {
    pub market: Pubkey,
    pub name: String,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub base_lot_size: i64,
    pub quote_lot_size: i64,
}

#[event]
pub struct TotalOrderFillEvent {
    pub side: u8,
    pub taker: Pubkey,
    pub total_quantity_paid: u64,
    pub total_quantity_received: u64,
    pub fees: u64,
}

#[event]
pub struct SetDelegateLog {
    pub open_orders_account: Pubkey,
    pub delegate: Option<Pubkey>,
}

#[event]
pub struct SettleFundsLog {
    pub open_orders_account: Pubkey,
    pub base_native: u64,
    pub quote_native: u64,
    pub referrer_rebate: u64,
    pub referrer: Option<Pubkey>,
}

#[event]
pub struct SweepFeesLog {
    pub market: Pubkey,
    pub amount: u64,
    pub receiver: Pubkey,
}

#[event]
pub struct OpenOrdersPositionLog {
    pub owner: Pubkey,
    pub open_orders_account_num: u32,
    pub market: Pubkey,
    /// Base lots in open bids
    pub bids_base_lots: i64,
    /// Quote lots in open bids
    pub bids_quote_lots: i64,
    /// Base lots in open asks
    pub asks_base_lots: i64,
    pub base_free_native: u64,
    pub quote_free_native: u64,
    pub locked_maker_fees: u64,
    pub referrer_rebates_available: u64,
    /// Cumulative maker volume in quote native units (display only)
    pub maker_volume: u128,
    /// Cumulative taker volume in quote native units (display only)
    pub taker_volume: u128,
}


// File: openbook-v2/programs/openbook-v2/src/pubkey_option.rs
use anchor_lang::prelude::*;
use bytemuck::Zeroable;
use std::convert::From;

/// Like `Option`, but implemented for `Pubkey` to be used with `zero_copy`
#[zero_copy]
#[derive(AnchorSerialize, AnchorDeserialize, Debug, Default, PartialEq)]
pub struct NonZeroPubkeyOption {
    key: Pubkey,
}

pub trait NonZeroKey {
    fn non_zero_key(&self) -> NonZeroPubkeyOption;
}

impl<T> NonZeroKey for Option<T>
where
    T: Key,
{
    fn non_zero_key(&self) -> NonZeroPubkeyOption {
        self.as_ref().map(|this| this.key()).into()
    }
}

impl PartialEq<NonZeroPubkeyOption> for Pubkey {
    fn eq(&self, other: &NonZeroPubkeyOption) -> bool {
        other.is_some() && *self == other.key
    }
}

impl PartialEq<Pubkey> for NonZeroPubkeyOption {
    fn eq(&self, other: &Pubkey) -> bool {
        self.is_some() && self.key == *other
    }
}

impl From<NonZeroPubkeyOption> for Option<Pubkey> {
    fn from(pubkey_option: NonZeroPubkeyOption) -> Self {
        if pubkey_option.is_some() {
            Some(pubkey_option.key)
        } else {
            None
        }
    }
}

impl From<Option<Pubkey>> for NonZeroPubkeyOption {
    fn from(normal_option: Option<Pubkey>) -> Self {
        match normal_option {
            Some(key) => Self { key },
            None => Self::zeroed(),
        }
    }
}

impl NonZeroPubkeyOption {
    pub fn is_some(&self) -> bool {
        *self != Self::zeroed()
    }

    pub fn is_none(&self) -> bool {
        *self == Self::zeroed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_some() {
        let foo: NonZeroPubkeyOption = Some(crate::ID).into();
        assert!(foo.is_some());
        assert_eq!(Option::<Pubkey>::from(foo), Some(crate::ID));
    }

    #[test]
    pub fn test_none() {
        let foo: NonZeroPubkeyOption = None.into();
        assert!(foo.is_none());
        assert_eq!(Option::<Pubkey>::from(foo), None);

        // the default pubkey also matches none
        assert_eq!(Pubkey::default(), Pubkey::zeroed());
        let foo: NonZeroPubkeyOption = Some(Pubkey::default()).into();
        assert!(foo.is_none());
        assert_eq!(Option::<Pubkey>::from(foo), None);
    }

    #[test]
    pub fn test_partial_eq() {
        let foo: NonZeroPubkeyOption = Some(crate::ID).into();
        let bar: NonZeroPubkeyOption = None.into();
        assert_eq!(foo, crate::ID);
        assert_ne!(bar, Pubkey::zeroed());

        assert_eq!(crate::ID, foo);
        assert_ne!(Pubkey::zeroed(), bar);
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/market.rs
use anchor_lang::prelude::*;
use fixed::types::I80F48;
use static_assertions::const_assert_eq;
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;

use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroPubkeyOption;
use crate::state::oracle;
use crate::{accounts_zerocopy::KeyedAccountReader, state::orderbook::Side};

use super::{orderbook, OracleConfig};

// For a 1bps taker fee, set taker_fee to 100, so taker_fee/FEES_SCALE_FACTOR = 10e-4
pub const FEES_SCALE_FACTOR: i128 = 1_000_000;
// taker pays 500 lamports penalty for every transaction that adds to the event heap
pub const PENALTY_EVENT_HEAP: u64 = 500;

#[account(zero_copy)]
#[derive(Debug)]
pub struct Market {
    /// PDA bump
    pub bump: u8,

    /// Number of decimals used for the base token.
    ///
    /// Used to convert the oracle's price into a native/native price.
    pub base_decimals: u8,
    pub quote_decimals: u8,

    pub padding1: [u8; 5],

    // Pda for signing vault txs
    pub market_authority: Pubkey,

    /// No expiry = 0. Market will expire and no trading allowed after time_expiry
    pub time_expiry: i64,

    /// Admin who can collect fees from the market
    pub collect_fee_admin: Pubkey,
    /// Admin who must sign off on all order creations
    pub open_orders_admin: NonZeroPubkeyOption,
    /// Admin who must sign off on all event consumptions
    pub consume_events_admin: NonZeroPubkeyOption,
    /// Admin who can set market expired, prune orders and close the market
    pub close_market_admin: NonZeroPubkeyOption,

    /// Name. Trailing zero bytes are ignored.
    pub name: [u8; 16],

    /// Address of the BookSide account for bids
    pub bids: Pubkey,
    /// Address of the BookSide account for asks
    pub asks: Pubkey,
    /// Address of the EventHeap account
    pub event_heap: Pubkey,

    /// Oracles account address
    pub oracle_a: NonZeroPubkeyOption,
    pub oracle_b: NonZeroPubkeyOption,
    /// Oracle configuration
    pub oracle_config: OracleConfig,

    /// Number of quote native in a quote lot. Must be a power of 10.
    ///
    /// Primarily useful for increasing the tick size on the market: A lot price
    /// of 1 becomes a native price of quote_lot_size/base_lot_size becomes a
    /// ui price of quote_lot_size*base_decimals/base_lot_size/quote_decimals.
    pub quote_lot_size: i64,

    /// Number of base native in a base lot. Must be a power of 10.
    ///
    /// Example: If base decimals for the underlying asset is 6, base lot size
    /// is 100 and and base position lots is 10_000 then base position native is
    /// 1_000_000 and base position ui is 1.
    pub base_lot_size: i64,

    /// Total number of orders seen
    pub seq_num: u64,

    /// Timestamp in seconds that the market was registered at.
    pub registration_time: i64,

    /// Fees
    ///
    /// Fee (in 10^-6) when matching maker orders.
    /// maker_fee < 0 it means some of the taker_fees goes to the maker
    /// maker_fee > 0, it means no taker_fee to the maker, and maker fee goes to the referral
    pub maker_fee: i64,
    /// Fee (in 10^-6) for taker orders, always >= 0.
    pub taker_fee: i64,

    /// Total fees accrued in native quote
    pub fees_accrued: u128,
    /// Total fees settled in native quote
    pub fees_to_referrers: u128,

    /// Referrer rebates to be distributed
    pub referrer_rebates_accrued: u64,

    /// Fees generated and available to withdraw via sweep_fees
    pub fees_available: u64,

    /// Cumulative maker volume (same as taker volume) in quote native units
    pub maker_volume: u128,

    /// Cumulative taker volume in quote native units due to place take orders
    pub taker_volume_wo_oo: u128,

    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,

    pub market_base_vault: Pubkey,
    pub base_deposit_total: u64,

    pub market_quote_vault: Pubkey,
    pub quote_deposit_total: u64,

    pub reserved: [u8; 128],
}

const_assert_eq!(
    size_of::<Market>(),
    32 +                        // market_authority
    32 +                        // collect_fee_admin
    32 +                        // open_order_admin
    32 +                        // consume_event_admin
    32 +                        // close_market_admin
    1 +                         // bump
    1 +                         // base_decimals
    1 +                         // quote_decimals
    5 +                         // padding1
    8 +                         // time_expiry
    16 +                        // name
    3 * 32 +                    // bids, asks, and event_heap
    32 +                        // oracle_a
    32 +                        // oracle_b
    size_of::<OracleConfig>() + // oracle_config
    8 +                         // quote_lot_size
    8 +                         // base_lot_size
    8 +                         // seq_num
    8 +                         // registration_time
    8 +                         // maker_fee
    8 +                         // taker_fee
    16 +                        // fees_accrued
    16 +                        // fees_to_referrers
    16 +                        // maker_volume
    16 +                        // taker_volume_wo_oo
    4 * 32 +                    // base_mint, quote_mint, market_base_vault, and market_quote_vault
    8 +                         // base_deposit_total
    8 +                         // quote_deposit_total
    8 +                         // base_fees_accrued
    8 +                         // referrer_rebates_accrued
    128 // reserved
);
const_assert_eq!(size_of::<Market>(), 840);
const_assert_eq!(size_of::<Market>() % 8, 0);

impl Market {
    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.name)
            .unwrap()
            .trim_matches(char::from(0))
    }

    pub fn is_expired(&self, timestamp: i64) -> bool {
        self.time_expiry != 0 && self.time_expiry < timestamp
    }

    pub fn is_empty(&self) -> bool {
        self.base_deposit_total == 0
            && self.quote_deposit_total == 0
            && self.fees_available == 0
            && self.referrer_rebates_accrued == 0
    }

    pub fn is_market_vault(&self, pubkey: Pubkey) -> bool {
        pubkey == self.market_quote_vault || pubkey == self.market_base_vault
    }

    pub fn get_vault_by_side(&self, side: Side) -> Pubkey {
        match side {
            Side::Ask => self.market_base_vault,
            Side::Bid => self.market_quote_vault,
        }
    }

    pub fn gen_order_id(&mut self, side: Side, price_data: u64) -> u128 {
        self.seq_num += 1;
        orderbook::new_node_key(side, price_data, self.seq_num)
    }

    pub fn max_base_lots(&self) -> i64 {
        i64::MAX / self.base_lot_size
    }

    pub fn max_quote_lots(&self) -> i64 {
        i64::MAX / self.quote_lot_size
    }

    pub fn max_base_lots_from_lamports(&self, lamports: u64) -> i64 {
        let base_lots = lamports / self.base_lot_size as u64;
        std::cmp::min(self.max_base_lots() as u64, base_lots)
            .try_into()
            .unwrap()
    }

    pub fn max_quote_lots_from_lamports(&self, lamports: u64) -> i64 {
        let quote_lots = lamports / self.quote_lot_size as u64;
        std::cmp::min(self.max_quote_lots() as u64, quote_lots)
            .try_into()
            .unwrap()
    }

    /// Convert from the price stored on the book to the price used in value calculations
    pub fn lot_to_native_price(&self, price: i64) -> I80F48 {
        I80F48::from_num(price) * I80F48::from_num(self.quote_lot_size)
            / I80F48::from_num(self.base_lot_size)
    }

    pub fn native_price_to_lot(&self, price: I80F48) -> Result<i64> {
        price
            .checked_mul(I80F48::from_num(self.base_lot_size))
            .and_then(|x| x.checked_div(I80F48::from_num(self.quote_lot_size)))
            .and_then(|x| x.checked_to_num())
            .ok_or_else(|| OpenBookError::InvalidOraclePrice.into())
    }

    pub fn oracle_price_lots(
        &self,
        oracle_a_acc: Option<&impl KeyedAccountReader>,
        oracle_b_acc: Option<&impl KeyedAccountReader>,
        slot: u64,
    ) -> Result<Option<i64>> {
        let oracle_price = self.oracle_price(oracle_a_acc, oracle_b_acc, slot)?;
        match oracle_price {
            Some(p) => Ok(Some(self.native_price_to_lot(p)?)),
            None => Ok(None),
        }
    }

    pub fn oracle_price(
        &self,
        oracle_a_acc: Option<&impl KeyedAccountReader>,
        oracle_b_acc: Option<&impl KeyedAccountReader>,
        slot: u64,
    ) -> Result<Option<I80F48>> {
        if self.oracle_a.is_some() && self.oracle_b.is_some() {
            self.oracle_price_from_a_and_b(oracle_a_acc.unwrap(), oracle_b_acc.unwrap(), slot)
        } else if self.oracle_a.is_some() {
            self.oracle_price_from_a(oracle_a_acc.unwrap(), slot)
        } else {
            Ok(None)
        }
    }

    fn oracle_price_from_a(
        &self,
        oracle_acc: &impl KeyedAccountReader,
        now_slot: u64,
    ) -> Result<Option<I80F48>> {
        assert_eq!(self.oracle_a, *oracle_acc.key());
        let oracle = oracle::oracle_state_unchecked(oracle_acc)?;

        if oracle.is_stale(oracle_acc.key(), &self.oracle_config, now_slot)
            || !oracle.has_valid_confidence(oracle_acc.key(), &self.oracle_config)
        {
            Ok(None)
        } else {
            let decimals = (self.quote_decimals as i8) - (self.base_decimals as i8);
            let decimal_adj = oracle::power_of_ten_float(decimals);
            Ok(I80F48::checked_from_num(oracle.price * decimal_adj))
        }
    }

    fn oracle_price_from_a_and_b(
        &self,
        oracle_a_acc: &impl KeyedAccountReader,
        oracle_b_acc: &impl KeyedAccountReader,
        now_slot: u64,
    ) -> Result<Option<I80F48>> {
        assert_eq!(self.oracle_a, *oracle_a_acc.key());
        assert_eq!(self.oracle_b, *oracle_b_acc.key());

        let oracle_a = oracle::oracle_state_unchecked(oracle_a_acc)?;
        let oracle_b = oracle::oracle_state_unchecked(oracle_b_acc)?;

        if oracle_a.is_stale(oracle_a_acc.key(), &self.oracle_config, now_slot)
            || oracle_b.is_stale(oracle_b_acc.key(), &self.oracle_config, now_slot)
            || !oracle_a.has_valid_combined_confidence(&oracle_b, &self.oracle_config)
        {
            Ok(None)
        } else {
            let price = oracle_a.price / oracle_b.price;
            let decimals = (self.quote_decimals as i8) - (self.base_decimals as i8);
            let decimal_adj = oracle::power_of_ten_float(decimals);
            Ok(I80F48::checked_from_num(price * decimal_adj))
        }
    }

    pub fn subtract_taker_fees(&self, quote: i64) -> i64 {
        ((quote as i128) * FEES_SCALE_FACTOR / (FEES_SCALE_FACTOR + (self.taker_fee as i128)))
            .try_into()
            .unwrap()
    }

    pub fn maker_fees_floor(self, amount: u64) -> u64 {
        if self.maker_fee.is_positive() {
            self.unsigned_maker_fees_floor(amount)
        } else {
            0
        }
    }

    pub fn maker_rebate_floor(self, amount: u64) -> u64 {
        if self.maker_fee.is_positive() {
            0
        } else {
            self.unsigned_maker_fees_floor(amount)
        }
    }

    pub fn maker_fees_ceil<T>(self, amount: T) -> T
    where
        T: Into<i128> + TryFrom<i128> + From<u8>,
        <T as TryFrom<i128>>::Error: std::fmt::Debug,
    {
        if self.maker_fee.is_positive() {
            self.ceil_fee_division(amount.into() * (self.maker_fee.abs() as i128))
                .try_into()
                .unwrap()
        } else {
            T::from(0)
        }
    }

    pub fn taker_fees_ceil<T>(self, amount: T) -> T
    where
        T: Into<i128> + TryFrom<i128>,
        <T as TryFrom<i128>>::Error: std::fmt::Debug,
    {
        self.ceil_fee_division(amount.into() * (self.taker_fee as i128))
            .try_into()
            .unwrap()
    }

    fn ceil_fee_division(self, numerator: i128) -> i128 {
        (numerator + (FEES_SCALE_FACTOR - 1_i128)) / FEES_SCALE_FACTOR
    }

    fn unsigned_maker_fees_floor(self, amount: u64) -> u64 {
        (i128::from(amount) * i128::from(self.maker_fee.abs()) / FEES_SCALE_FACTOR)
            .try_into()
            .unwrap()
    }
}

/// Generate signed seeds for the market
macro_rules! market_seeds {
    ($market:expr,$key:expr) => {
        &[b"Market".as_ref(), &$key.to_bytes(), &[$market.bump]]
    };
}
pub(crate) use market_seeds;


// File: openbook-v2/programs/openbook-v2/src/state/mod.rs
pub use market::*;
pub use open_orders_account::*;
pub use open_orders_indexer::*;
pub use oracle::*;
pub use orderbook::*;

mod market;
mod open_orders_account;
mod open_orders_indexer;
mod orderbook;

pub mod oracle;
mod raydium_internal;


// File: openbook-v2/programs/openbook-v2/src/state/open_orders_account.rs
use anchor_lang::prelude::*;
use derivative::Derivative;
use static_assertions::const_assert_eq;
use std::mem::size_of;

use crate::logs::{emit_stack, FillLog};
use crate::pubkey_option::NonZeroPubkeyOption;
use crate::{error::*, logs::OpenOrdersPositionLog};

use super::{BookSideOrderTree, FillEvent, LeafNode, Market, Side, SideAndOrderTree};

pub const MAX_OPEN_ORDERS: usize = 24;

#[account(zero_copy)]
#[derive(Debug)]
pub struct OpenOrdersAccount {
    pub owner: Pubkey,
    pub market: Pubkey,

    pub name: [u8; 32],

    // Alternative authority/signer of transactions for a openbook account
    pub delegate: NonZeroPubkeyOption,

    pub account_num: u32,

    pub bump: u8,

    // Introducing a version as we are adding a new field bids_quote_lots
    pub version: u8,

    pub padding: [u8; 2],

    pub position: Position,

    pub open_orders: [OpenOrder; MAX_OPEN_ORDERS],
}

const_assert_eq!(
    size_of::<OpenOrdersAccount>(),
    size_of::<Pubkey>() * 2
        + 32
        + 32
        + 4
        + 1
        + 3
        + size_of::<Position>()
        + MAX_OPEN_ORDERS * size_of::<OpenOrder>()
);
const_assert_eq!(size_of::<OpenOrdersAccount>(), 1256);
const_assert_eq!(size_of::<OpenOrdersAccount>() % 8, 0);

impl OpenOrdersAccount {
    /// Number of bytes needed for the OpenOrdersAccount, including the discriminator
    pub fn space() -> usize {
        8 + size_of::<OpenOrdersAccount>()
    }

    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.name)
            .unwrap()
            .trim_matches(char::from(0))
    }

    pub fn default_for_tests() -> Box<OpenOrdersAccount> {
        Box::new(OpenOrdersAccount {
            owner: Pubkey::default(),
            market: Pubkey::default(),
            name: [0; 32],
            delegate: NonZeroPubkeyOption::default(),
            account_num: 0,
            bump: 0,
            version: 1,
            padding: [0; 2],
            position: Position::default(),
            open_orders: [OpenOrder::default(); MAX_OPEN_ORDERS],
        })
    }

    pub fn is_owner_or_delegate(&self, ix_signer: Pubkey) -> bool {
        let delegate_option: Option<Pubkey> = Option::from(self.delegate);
        if let Some(delegate) = delegate_option {
            return self.owner == ix_signer || delegate == ix_signer;
        }
        self.owner == ix_signer
    }

    pub fn is_settle_destination_allowed(&self, ix_signer: Pubkey, account_owner: Pubkey) -> bool {
        // delegate can withdraw to owner accounts
        let delegate_option: Option<Pubkey> = Option::from(self.delegate);
        if Some(ix_signer) == delegate_option {
            return self.owner == account_owner;
        }

        // owner can withdraw to anywhere
        ix_signer == self.owner
    }

    pub fn all_orders(&self) -> impl Iterator<Item = &OpenOrder> {
        self.open_orders.iter()
    }

    pub fn has_no_orders(&self) -> bool {
        self.open_orders.iter().count() == 0
    }

    pub fn all_orders_in_use(&self) -> impl Iterator<Item = &OpenOrder> {
        self.all_orders().filter(|oo| !oo.is_free())
    }

    pub fn next_order_slot(&self) -> Result<usize> {
        self.all_orders()
            .position(|&oo| oo.is_free())
            .ok_or_else(|| error!(OpenBookError::OpenOrdersFull))
    }

    pub fn find_order_with_client_order_id(&self, client_order_id: u64) -> Option<&OpenOrder> {
        self.all_orders_in_use()
            .find(|&oo| oo.client_id == client_order_id)
    }

    pub fn find_order_with_order_id(&self, order_id: u128) -> Option<&OpenOrder> {
        self.all_orders_in_use().find(|&oo| oo.id == order_id)
    }

    pub fn open_order_by_raw_index(&self, raw_index: usize) -> &OpenOrder {
        &self.open_orders[raw_index]
    }

    pub fn open_order_mut_by_raw_index(&mut self, raw_index: usize) -> &mut OpenOrder {
        &mut self.open_orders[raw_index]
    }

    pub fn execute_maker(&mut self, market: &mut Market, fill: &FillEvent) {
        let is_self_trade = fill.maker == fill.taker;

        let side = fill.taker_side().invert_side();
        let quote_native = (fill.quantity * fill.price * market.quote_lot_size) as u64;

        let (maker_fees, maker_rebate) = if is_self_trade {
            (0, 0)
        } else {
            (
                market.maker_fees_floor(quote_native),
                market.maker_rebate_floor(quote_native),
            )
        };

        let mut locked_maker_fees = maker_fees;
        let mut locked_amount_above_fill_price = 0;

        let locked_price = if fill.peg_limit != -1 && side == Side::Bid {
            let quote_at_lock_price =
                (fill.quantity * fill.peg_limit * market.quote_lot_size) as u64;
            let quote_to_free = quote_at_lock_price - quote_native;

            let fees_at_lock_price = market.maker_fees_floor(quote_at_lock_price);
            let fees_at_fill_price = maker_fees;
            let maker_fees_to_free = fees_at_lock_price - fees_at_fill_price;

            locked_maker_fees = fees_at_lock_price;
            locked_amount_above_fill_price = quote_to_free + maker_fees_to_free;
            fill.peg_limit
        } else {
            fill.price
        };

        {
            let pa = &mut self.position;

            match side {
                Side::Bid => {
                    pa.base_free_native += (fill.quantity * market.base_lot_size) as u64;
                    pa.quote_free_native += maker_rebate + locked_amount_above_fill_price;
                    pa.locked_maker_fees -= locked_maker_fees;
                }
                Side::Ask => {
                    pa.quote_free_native += quote_native + maker_rebate - maker_fees;
                }
            };

            pa.maker_volume += quote_native as u128;
            pa.referrer_rebates_available += maker_fees;
            market.referrer_rebates_accrued += maker_fees;
            market.maker_volume += quote_native as u128;
            market.fees_accrued += maker_fees as u128;

            if fill.maker_out() {
                self.remove_order(fill.maker_slot as usize, fill.quantity, locked_price);
            } else {
                match side {
                    Side::Bid => {
                        pa.bids_base_lots -= fill.quantity;
                        pa.bids_quote_lots -= fill.quantity * locked_price;
                    }
                    Side::Ask => pa.asks_base_lots -= fill.quantity,
                };
            }
        }

        // Calculate taker fee, ignoring self trades
        let taker_fee_ceil = if quote_native > 0 && fill.maker != fill.taker {
            market.taker_fees_ceil(quote_native)
        } else {
            0
        };

        emit_stack(FillLog {
            market: self.market,
            taker_side: fill.taker_side,
            maker_slot: fill.maker_slot,
            maker_out: fill.maker_out(),
            timestamp: fill.timestamp,
            seq_num: fill.market_seq_num,
            maker: fill.maker,
            maker_client_order_id: fill.maker_client_order_id,
            maker_fee: maker_fees,
            maker_timestamp: fill.maker_timestamp,
            taker: fill.taker,
            taker_client_order_id: fill.taker_client_order_id,
            taker_fee_ceil,
            price: fill.price,
            quantity: fill.quantity,
        });

        let pa = &self.position;
        emit_stack(OpenOrdersPositionLog {
            owner: self.owner,
            open_orders_account_num: self.account_num,
            market: self.market,
            bids_base_lots: pa.bids_base_lots,
            bids_quote_lots: pa.bids_quote_lots,
            asks_base_lots: pa.asks_base_lots,
            base_free_native: pa.base_free_native,
            quote_free_native: pa.quote_free_native,
            locked_maker_fees: pa.locked_maker_fees,
            referrer_rebates_available: pa.referrer_rebates_available,
            maker_volume: pa.maker_volume,
            taker_volume: pa.taker_volume,
        })
    }

    /// Release funds and apply taker fees to the taker account. Account fees for referrer
    pub fn execute_taker(
        &mut self,
        market: &mut Market,
        taker_side: Side,
        base_native: u64,
        quote_native: u64,
        taker_fees: u64,
        referrer_amount: u64,
    ) {
        let pa = &mut self.position;
        match taker_side {
            Side::Bid => pa.base_free_native += base_native,
            Side::Ask => pa.quote_free_native += quote_native - taker_fees,
        };

        pa.taker_volume += quote_native as u128;
        pa.referrer_rebates_available += referrer_amount;
        market.referrer_rebates_accrued += referrer_amount;

        emit_stack(OpenOrdersPositionLog {
            owner: self.owner,
            open_orders_account_num: self.account_num,
            market: self.market,
            bids_base_lots: pa.bids_base_lots,
            bids_quote_lots: pa.bids_quote_lots,
            asks_base_lots: pa.asks_base_lots,
            base_free_native: pa.base_free_native,
            quote_free_native: pa.quote_free_native,
            locked_maker_fees: pa.locked_maker_fees,
            referrer_rebates_available: pa.referrer_rebates_available,
            maker_volume: pa.maker_volume,
            taker_volume: pa.taker_volume,
        })
    }

    pub fn add_order(
        &mut self,
        side: Side,
        order_tree: BookSideOrderTree,
        order: &LeafNode,
        client_order_id: u64,
        locked_price: i64,
    ) {
        let position = &mut self.position;
        match side {
            Side::Bid => {
                position.bids_base_lots += order.quantity;
                position.bids_quote_lots += order.quantity * locked_price;
            }
            Side::Ask => position.asks_base_lots += order.quantity,
        };
        let slot = order.owner_slot as usize;

        let oo = self.open_order_mut_by_raw_index(slot);
        oo.is_free = false.into();
        oo.side_and_tree = SideAndOrderTree::new(side, order_tree).into();
        oo.id = order.key;
        oo.client_id = client_order_id;
        oo.locked_price = locked_price;
    }

    pub fn remove_order(&mut self, slot: usize, base_quantity: i64, locked_price: i64) {
        let oo = self.open_order_by_raw_index(slot);
        assert!(!oo.is_free());

        let order_side = oo.side_and_tree().side();
        let position = &mut self.position;

        // accounting
        match order_side {
            Side::Bid => {
                position.bids_base_lots -= base_quantity;
                position.bids_quote_lots -= base_quantity * locked_price;
            }
            Side::Ask => position.asks_base_lots -= base_quantity,
        }

        // release space
        *self.open_order_mut_by_raw_index(slot) = OpenOrder::default();
    }

    pub fn cancel_order(&mut self, slot: usize, base_quantity: i64, market: Market) {
        let oo = self.open_order_by_raw_index(slot);
        let price = oo.locked_price;
        let order_side = oo.side_and_tree().side();

        let base_quantity_native = (base_quantity * market.base_lot_size) as u64;
        let quote_quantity_native = (base_quantity * price * market.quote_lot_size) as u64;
        let fees = market.maker_fees_ceil(quote_quantity_native);

        let position = &mut self.position;
        match order_side {
            Side::Bid => {
                position.quote_free_native += quote_quantity_native + fees;
                position.locked_maker_fees -= fees;
            }
            Side::Ask => position.base_free_native += base_quantity_native,
        }

        self.remove_order(slot, base_quantity, price);
    }
}

#[zero_copy]
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Position {
    /// Base lots in open bids
    pub bids_base_lots: i64,
    /// Base lots in open asks
    pub asks_base_lots: i64,

    pub base_free_native: u64,
    pub quote_free_native: u64,

    pub locked_maker_fees: u64,
    pub referrer_rebates_available: u64,
    /// Count of ixs when events are added to the heap
    /// To avoid this, send remaining accounts in order to process the events
    pub penalty_heap_count: u64,

    /// Cumulative maker volume in quote native units (display only)
    pub maker_volume: u128,
    /// Cumulative taker volume in quote native units (display only)
    pub taker_volume: u128,

    /// Quote lots in open bids
    pub bids_quote_lots: i64,

    #[derivative(Debug = "ignore")]
    pub reserved: [u8; 64],
}

const_assert_eq!(
    size_of::<Position>(),
    8 + 8 + 8 + 8 + 8 + 8 + 8 + 16 + 16 + 8 + 64
);
const_assert_eq!(size_of::<Position>(), 160);
const_assert_eq!(size_of::<Position>() % 8, 0);

impl Default for Position {
    fn default() -> Self {
        Self {
            bids_base_lots: 0,
            asks_base_lots: 0,
            base_free_native: 0,
            quote_free_native: 0,
            locked_maker_fees: 0,
            referrer_rebates_available: 0,
            penalty_heap_count: 0,
            maker_volume: 0,
            taker_volume: 0,
            bids_quote_lots: 0,
            reserved: [0; 64],
        }
    }
}

impl Position {
    /// Does the user have any orders on the book?
    ///
    /// Note that it's possible they were matched already: This only becomes
    /// false when the fill event is processed or the orders are cancelled.
    pub fn has_open_orders(&self) -> bool {
        self.asks_base_lots != 0 || self.bids_base_lots != 0
    }

    pub fn is_empty(&self, version: u8) -> bool {
        self.bids_base_lots == 0
            && self.asks_base_lots == 0
            && self.base_free_native == 0
            && self.quote_free_native == 0
            && self.locked_maker_fees == 0
            && self.referrer_rebates_available == 0
            && self.penalty_heap_count == 0
            // For version 0, bids_quote_lots was not properly tracked
            && (version == 0 || self.bids_quote_lots == 0)
    }
}

#[zero_copy]
#[derive(Debug)]
pub struct OpenOrder {
    pub id: u128,
    pub client_id: u64,
    /// Price at which user's assets were locked
    pub locked_price: i64,

    pub is_free: u8,
    pub side_and_tree: u8, // SideAndOrderTree -- enums aren't POD
    pub padding: [u8; 6],
}
const_assert_eq!(size_of::<OpenOrder>(), 16 + 8 + 8 + 1 + 1 + 6);
const_assert_eq!(size_of::<OpenOrder>(), 40);
const_assert_eq!(size_of::<OpenOrder>() % 8, 0);

impl Default for OpenOrder {
    fn default() -> Self {
        Self {
            is_free: true.into(),
            side_and_tree: SideAndOrderTree::BidFixed.into(),
            client_id: 0,
            locked_price: 0,
            id: 0,
            padding: [0; 6],
        }
    }
}

impl OpenOrder {
    pub fn is_free(&self) -> bool {
        self.is_free == u8::from(true)
    }

    pub fn side_and_tree(&self) -> SideAndOrderTree {
        SideAndOrderTree::try_from(self.side_and_tree).unwrap()
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/open_orders_indexer.rs
use anchor_lang::prelude::*;

#[account]
#[derive(Default)]
pub struct OpenOrdersIndexer {
    pub bump: u8,
    pub created_counter: u32,
    pub addresses: Vec<Pubkey>,
}

impl OpenOrdersIndexer {
    pub fn space(len: usize) -> usize {
        8 + 1 + 4 + (4 + (len * 32))
    }

    pub fn has_active_open_orders_accounts(&self) -> bool {
        !self.addresses.is_empty()
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/oracle.rs
use anchor_lang::prelude::*;
use anchor_lang::Discriminator;
use fixed::types::U64F64;
use static_assertions::const_assert_eq;
use std::mem::size_of;
use switchboard_program::FastRoundResultAccountData;
use switchboard_solana::AggregatorAccountData;

use crate::accounts_zerocopy::*;
use crate::error::*;
use crate::state::raydium_internal;
use crate::state::raydium_internal::PoolState;

const DECIMAL_CONSTANT_ZERO_INDEX: i8 = 12;
const DECIMAL_CONSTANTS_F64: [f64; 25] = [
    1e-12, 1e-11, 1e-10, 1e-9, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1e0, 1e1, 1e2, 1e3,
    1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12,
];

pub const fn power_of_ten_float(decimals: i8) -> f64 {
    DECIMAL_CONSTANTS_F64[(decimals + DECIMAL_CONSTANT_ZERO_INDEX) as usize]
}

pub mod switchboard_v1_devnet_oracle {
    use solana_program::declare_id;
    declare_id!("7azgmy1pFXHikv36q1zZASvFq5vFa39TT9NweVugKKTU");
}
pub mod switchboard_v2_mainnet_oracle {
    use solana_program::declare_id;
    declare_id!("DtmE9D2CSB4L5D6A15mraeEjrGMm6auWVzgaD8hK2tZM");
}

#[zero_copy]
#[derive(AnchorDeserialize, AnchorSerialize, Debug)]
pub struct OracleConfig {
    pub conf_filter: f64,
    pub max_staleness_slots: i64,
    pub reserved: [u8; 72],
}
const_assert_eq!(size_of::<OracleConfig>(), 8 + 8 + 72);
const_assert_eq!(size_of::<OracleConfig>(), 88);
const_assert_eq!(size_of::<OracleConfig>() % 8, 0);

#[derive(AnchorDeserialize, AnchorSerialize, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OracleConfigParams {
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub conf_filter: f32,
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub max_staleness_slots: Option<u32>,
}

impl OracleConfigParams {
    pub fn to_oracle_config(&self) -> OracleConfig {
        OracleConfig {
            conf_filter: self.conf_filter as f64,
            max_staleness_slots: self.max_staleness_slots.map(|v| v as i64).unwrap_or(-1),
            reserved: [0; 72],
        }
    }
}

#[derive(Clone, Copy, PartialEq, AnchorSerialize, AnchorDeserialize)]
pub enum OracleType {
    Pyth,
    Stub,
    SwitchboardV1,
    SwitchboardV2,
    RaydiumCLMM,
}

pub struct OracleState {
    pub price: f64,
    pub deviation: f64,
    pub last_update_slot: u64,
    pub oracle_type: OracleType,
}

impl OracleState {
    pub fn is_stale(&self, oracle_pk: &Pubkey, config: &OracleConfig, now_slot: u64) -> bool {
        if config.max_staleness_slots >= 0
            && self
                .last_update_slot
                .saturating_add(config.max_staleness_slots as u64)
                < now_slot
        {
            msg!(
                "Oracle is stale; pubkey {}, price: {}, last_update_slot: {}, now_slot: {}",
                oracle_pk,
                self.price,
                self.last_update_slot,
                now_slot,
            );
            true
        } else {
            false
        }
    }

    pub fn has_valid_confidence(&self, oracle_pk: &Pubkey, config: &OracleConfig) -> bool {
        if self.deviation > config.conf_filter * self.price {
            msg!(
                "Oracle confidence not good enough: pubkey {}, price: {}, deviation: {}, conf_filter: {}",
                oracle_pk,
                self.price,
                self.deviation,
                config.conf_filter,
            );
            false
        } else {
            true
        }
    }

    pub fn has_valid_combined_confidence(&self, other: &Self, config: &OracleConfig) -> bool {
        // target uncertainty reads
        //   $ \sigma \approx \frac{A}{B} * \sqrt{(\sigma_A/A)^2 + (\sigma_B/B)^2} $
        // but alternatively, to avoid costly operations, we compute the square
        // Also note that the relative scaled var, i.e. without the \frac{A}{B} factor, is computed
        let relative_var =
            (self.deviation / self.price).powi(2) + (other.deviation / other.price).powi(2);

        let relative_target_var = config.conf_filter.powi(2);

        if relative_var > relative_target_var {
            msg!(
                "Combined confidence too high: computed^2: {}, conf_filter^2: {}",
                relative_var,
                relative_target_var
            );
            false
        } else {
            true
        }
    }
}

#[account(zero_copy)]
pub struct StubOracle {
    pub owner: Pubkey,
    pub mint: Pubkey,
    pub price: f64,
    pub last_update_ts: i64,
    pub last_update_slot: u64,
    pub deviation: f64,
    pub reserved: [u8; 104],
}
const_assert_eq!(size_of::<StubOracle>(), 32 + 32 + 8 + 8 + 8 + 8 + 104);
const_assert_eq!(size_of::<StubOracle>(), 200);
const_assert_eq!(size_of::<StubOracle>() % 8, 0);

pub fn determine_oracle_type(acc_info: &impl KeyedAccountReader) -> Result<OracleType> {
    let data = acc_info.data();

    if u32::from_le_bytes(data[0..4].try_into().unwrap()) == pyth_sdk_solana::state::MAGIC {
        return Ok(OracleType::Pyth);
    } else if data[0..8] == StubOracle::discriminator() {
        return Ok(OracleType::Stub);
    }
    // https://github.com/switchboard-xyz/switchboard-v2/blob/main/libraries/rs/src/aggregator.rs#L114
    // note: disc is not public, hence the copy pasta
    else if data[0..8] == [217, 230, 65, 101, 201, 162, 27, 125] {
        return Ok(OracleType::SwitchboardV2);
    }
    // note: this is the only known way of checking this
    else if acc_info.owner() == &switchboard_v1_devnet_oracle::ID
        || acc_info.owner() == &switchboard_v2_mainnet_oracle::ID
    {
        return Ok(OracleType::SwitchboardV1);
    } else if acc_info.owner() == &raydium_internal::ID {
        return Ok(OracleType::RaydiumCLMM);
    }

    Err(OpenBookError::UnknownOracleType.into())
}

/// Get the pyth agg price if it's available, otherwise take the prev price.
///
/// Returns the publish slot in addition to the price info.
///
/// Also see pyth's PriceAccount::get_price_no_older_than().
fn pyth_get_price(
    account: &pyth_sdk_solana::state::SolanaPriceAccount,
) -> (pyth_sdk_solana::Price, u64) {
    use pyth_sdk_solana::*;
    if account.agg.status == state::PriceStatus::Trading {
        (
            Price {
                conf: account.agg.conf,
                expo: account.expo,
                price: account.agg.price,
                publish_time: account.timestamp,
            },
            account.agg.pub_slot,
        )
    } else {
        (
            Price {
                conf: account.prev_conf,
                expo: account.expo,
                price: account.prev_price,
                publish_time: account.prev_timestamp,
            },
            account.prev_slot,
        )
    }
}

/// Returns the price of one native base token, in native quote tokens
///
/// Example: The for SOL at 40 USDC/SOL it would return 0.04 (the unit is USDC-native/SOL-native)
///
/// The staleness and confidence of the oracle is not checked. Use the functions on
/// OracleState to validate them if needed. That's why this function is called _unchecked.
pub fn oracle_state_unchecked(acc_info: &impl KeyedAccountReader) -> Result<OracleState> {
    let data = &acc_info.data();
    let oracle_type = determine_oracle_type(acc_info)?;

    Ok(match oracle_type {
        OracleType::Stub => {
            let stub = acc_info.load::<StubOracle>()?;
            let last_update_slot = if stub.last_update_slot == 0 {
                // ensure staleness checks will never fail
                u64::MAX
            } else {
                stub.last_update_slot
            };
            OracleState {
                price: stub.price,
                last_update_slot,
                deviation: stub.deviation,
                oracle_type: OracleType::Stub,
            }
        }
        OracleType::Pyth => {
            let price_account = pyth_sdk_solana::state::load_price_account(data).unwrap();
            let (price_data, last_update_slot) = pyth_get_price(price_account);

            let decimals = price_account.expo as i8;
            let decimal_adj = power_of_ten_float(decimals);
            let price = price_data.price as f64 * decimal_adj;
            let deviation = price_data.conf as f64 * decimal_adj;
            require_gte!(price, 0f64);
            OracleState {
                price,
                last_update_slot,
                deviation,
                oracle_type: OracleType::Pyth,
            }
        }
        OracleType::SwitchboardV2 => {
            fn from_foreign_error(e: impl std::fmt::Display) -> Error {
                error_msg!("{}", e)
            }

            let feed = bytemuck::from_bytes::<AggregatorAccountData>(&data[8..]);
            let feed_result = feed.get_result().map_err(from_foreign_error)?;
            let price: f64 = feed_result.try_into().map_err(from_foreign_error)?;
            let deviation: f64 = feed
                .latest_confirmed_round
                .std_deviation
                .try_into()
                .map_err(from_foreign_error)?;

            // The round_open_slot is an underestimate of the last update slot: Reporters will see
            // the round opening and only then start executing the price tasks.
            let last_update_slot = feed.latest_confirmed_round.round_open_slot;

            require_gte!(price, 0f64);
            OracleState {
                price,
                last_update_slot,
                deviation,
                oracle_type: OracleType::SwitchboardV2,
            }
        }
        OracleType::SwitchboardV1 => {
            let result = FastRoundResultAccountData::deserialize(data).unwrap();
            let price = result.result.result;

            let deviation = result.result.max_response - result.result.min_response;
            let last_update_slot = result.result.round_open_slot;
            require_gte!(price, 0f64);
            OracleState {
                price,
                last_update_slot,
                deviation,
                oracle_type: OracleType::SwitchboardV1,
            }
        }
        OracleType::RaydiumCLMM => {
            let pool = bytemuck::from_bytes::<PoolState>(&data[8..]);

            let sqrt_price = U64F64::from_bits(pool.sqrt_price_x64);

            let decimals: i8 = (pool.mint_decimals_0 as i8) - (pool.mint_decimals_1 as i8);
            let price: f64 =
                (sqrt_price * sqrt_price).to_num::<f64>() * power_of_ten_float(decimals);

            require_gte!(price, 0f64);
            OracleState {
                price,
                last_update_slot: u64::MAX, // ensure staleness slot will never fail
                deviation: 0f64,
                oracle_type: OracleType::RaydiumCLMM,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program_test::{find_file, read_file};
    use std::{cell::RefCell, path::PathBuf, str::FromStr};

    #[test]
    pub fn test_oracles() -> Result<()> {
        // add ability to find fixtures
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test");

        let fixtures = vec![
            (
                "J83w4HKfqxwcq3BEMMkPFSppX3gqekLyLJBexebFVkix",
                OracleType::Pyth,
                Pubkey::default(),
            ),
            (
                "8k7F9Xb36oFJsjpCKpsXvg4cgBRoZtwNTc3EzG5Ttd2o",
                OracleType::SwitchboardV1,
                switchboard_v1_devnet_oracle::ID,
            ),
            (
                "GvDMxPzN1sCj7L26YDK2HnMRXEQmQ2aemov8YBtPS7vR",
                OracleType::SwitchboardV2,
                Pubkey::default(),
            ),
            (
                "2QdhepnKRTLjjSqPL1PtKNwqrUkoLee5Gqs8bvZhRdMv",
                OracleType::RaydiumCLMM,
                raydium_internal::ID,
            ),
        ];

        for fixture in fixtures {
            let filename = format!("resources/test/{}.bin", fixture.0);
            let mut file_data = read_file(find_file(&filename).unwrap());
            let data = RefCell::new(&mut file_data[..]);
            let ai = &AccountInfoRef {
                key: &Pubkey::from_str(fixture.0).unwrap(),
                owner: &fixture.2,
                data: data.borrow(),
            };
            assert!(determine_oracle_type(ai).unwrap() == fixture.1);
        }

        Ok(())
    }

    #[test]
    pub fn test_raydium_price() -> Result<()> {
        let filename = format!(
            "resources/test/{}.bin",
            "2QdhepnKRTLjjSqPL1PtKNwqrUkoLee5Gqs8bvZhRdMv"
        );

        let mut file_data = read_file(find_file(&filename).unwrap());
        let data = RefCell::new(&mut file_data[..]);
        let ai = &AccountInfoRef {
            key: &Pubkey::default(),
            owner: &raydium_internal::ID,
            data: data.borrow(),
        };

        let oracle = oracle_state_unchecked(ai)?;

        let price_from_raydium_sdk = 24.470_087_964_273_85f64;
        println!("{:?}", oracle.price);
        assert!((oracle.price - price_from_raydium_sdk).abs() < 1e-10);

        Ok(())
    }

    #[test]
    pub fn lookup_test() {
        for idx in -12..0_i8 {
            let s = format!("0.{}1", str::repeat("0", (idx.unsigned_abs() as usize) - 1));
            assert_eq!(power_of_ten_float(idx), f64::from_str(&s).unwrap());
        }

        assert_eq!(power_of_ten_float(0), 1.);

        for idx in 1..=12_i8 {
            let s = format!("1{}", str::repeat("0", idx.unsigned_abs() as usize));
            assert_eq!(power_of_ten_float(idx), f64::from_str(&s).unwrap());
        }
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/book.rs
use crate::logs::*;
use crate::state::MAX_OPEN_ORDERS;
use crate::{
    error::*,
    state::{orderbook::bookside::*, EventHeap, Market, OpenOrdersAccount},
};
use anchor_lang::prelude::*;
use bytemuck::cast;
use std::cell::RefMut;

use super::*;

/// Drop at most this many expired orders from a BookSide when trying to match orders.
/// This exists as a guard against excessive compute use.
pub const DROP_EXPIRED_ORDER_LIMIT: usize = 5;

/// Process up to this remaining accounts in the fill event
pub const FILL_EVENT_REMAINING_LIMIT: usize = 15;

pub struct Orderbook<'a> {
    pub bids: RefMut<'a, BookSide>,
    pub asks: RefMut<'a, BookSide>,
}

pub struct OrderWithAmounts {
    pub order_id: Option<u128>,
    pub posted_base_native: u64,
    pub posted_quote_native: u64,
    pub total_base_taken_native: u64,
    pub total_quote_taken_native: u64,
    pub taker_fees: u64,
    pub maker_fees: u64,
    pub referrer_amount: u64,
}

impl<'a> Orderbook<'a> {
    pub fn init(&mut self) {
        self.bids.nodes.order_tree_type = OrderTreeType::Bids.into();
        self.asks.nodes.order_tree_type = OrderTreeType::Asks.into();
    }

    pub fn is_empty(&self) -> bool {
        self.bids.is_empty() && self.asks.is_empty()
    }

    pub fn bookside_mut(&mut self, side: Side) -> &mut BookSide {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }

    pub fn bookside(&self, side: Side) -> &BookSide {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_order<'c: 'info, 'info>(
        &mut self,
        order: &Order,
        open_book_market: &mut Market,
        market_pk: &Pubkey,
        event_heap: &mut EventHeap,
        oracle_price_lots: Option<i64>,
        mut open_orders_account: Option<&mut OpenOrdersAccount>,
        owner: &Pubkey,
        now_ts: u64,
        mut limit: u8,
        remaining_accs: &'c [AccountInfo<'info>],
    ) -> std::result::Result<OrderWithAmounts, Error> {
        let market = open_book_market;

        let side = order.side;

        let other_side = side.invert_side();
        let post_only = order.is_post_only();
        let fill_or_kill = order.is_fill_or_kill();
        let mut post_target = order.post_target();
        let (price_lots, price_data) = order.price(now_ts, oracle_price_lots, self)?;

        // generate new order id
        let order_id = market.gen_order_id(side, price_data);

        // Iterate through book and match against this new order.
        //
        // Any changes to matching orders on the other side of the book are collected in
        // matched_changes/matched_deletes and then applied after this loop.

        let order_max_base_lots = order.max_base_lots;
        let order_max_quote_lots = if side == Side::Bid && !post_only {
            market.subtract_taker_fees(order.max_quote_lots_including_fees)
        } else {
            order.max_quote_lots_including_fees
        };

        require_gte!(
            market.max_base_lots(),
            order_max_base_lots,
            OpenBookError::InvalidInputLotsSize
        );

        require_gte!(
            market.max_quote_lots(),
            order_max_quote_lots,
            OpenBookError::InvalidInputLotsSize
        );

        let mut remaining_base_lots = order_max_base_lots;
        let mut remaining_quote_lots = order_max_quote_lots;
        let mut decremented_quote_lots = 0_i64;

        let mut referrer_amount = 0_u64;
        let mut maker_rebates_acc = 0_u64;

        let mut matched_order_changes: Vec<(BookSideOrderHandle, i64)> = vec![];
        let mut matched_order_deletes: Vec<(BookSideOrderTree, u128)> = vec![];
        let mut number_of_dropped_expired_orders = 0;
        let mut number_of_processed_fill_events = 0;

        let opposing_bookside = self.bookside_mut(other_side);
        for best_opposing in opposing_bookside.iter_all_including_invalid(now_ts, oracle_price_lots)
        {
            if remaining_base_lots == 0 || remaining_quote_lots == 0 {
                break;
            }

            if !best_opposing.is_valid() {
                // Remove the order from the book unless we've done that enough
                if number_of_dropped_expired_orders < DROP_EXPIRED_ORDER_LIMIT {
                    number_of_dropped_expired_orders += 1;
                    let event = OutEvent::new(
                        other_side,
                        best_opposing.node.owner_slot,
                        now_ts,
                        event_heap.header.seq_num,
                        best_opposing.node.owner,
                        best_opposing.node.quantity,
                    );

                    process_out_event(
                        event,
                        market,
                        event_heap,
                        open_orders_account.as_deref_mut(),
                        owner,
                        remaining_accs,
                    )?;
                    matched_order_deletes
                        .push((best_opposing.handle.order_tree, best_opposing.node.key));
                }
                continue;
            }

            let best_opposing_price = best_opposing.price_lots;

            if !side.is_price_within_limit(best_opposing_price, price_lots) {
                break;
            }
            if post_only {
                msg!("Order could not be placed due to PostOnly");
                post_target = None;
                break; // return silently to not fail other instructions in tx
            }
            if limit == 0 {
                msg!("Order matching limit reached");
                post_target = None;
                break;
            }

            let max_match_by_quote = remaining_quote_lots / best_opposing_price;
            // Do not post orders in the book due to bad pricing and negative spread
            if max_match_by_quote == 0 {
                post_target = None;
                break;
            }

            let match_base_lots = remaining_base_lots
                .min(best_opposing.node.quantity)
                .min(max_match_by_quote);
            let match_quote_lots = match_base_lots * best_opposing_price;

            // Self-trade behaviour
            if open_orders_account.is_some() && owner == &best_opposing.node.owner {
                match order.self_trade_behavior {
                    SelfTradeBehavior::DecrementTake => {
                        // remember all decremented quote lots to only charge fees on not-self-trades
                        decremented_quote_lots += match_quote_lots;
                    }
                    SelfTradeBehavior::CancelProvide => {
                        // The open orders acc is always present in this case, no need event_heap
                        open_orders_account.as_mut().unwrap().cancel_order(
                            best_opposing.node.owner_slot as usize,
                            best_opposing.node.quantity,
                            *market,
                        );
                        matched_order_deletes
                            .push((best_opposing.handle.order_tree, best_opposing.node.key));

                        // skip actual matching
                        continue;
                    }
                    SelfTradeBehavior::AbortTransaction => {
                        return err!(OpenBookError::WouldSelfTrade)
                    }
                }
                assert!(order.self_trade_behavior == SelfTradeBehavior::DecrementTake);
            } else {
                maker_rebates_acc +=
                    market.maker_rebate_floor((match_quote_lots * market.quote_lot_size) as u64);
            }

            remaining_base_lots -= match_base_lots;
            remaining_quote_lots -= match_quote_lots;
            assert!(remaining_quote_lots >= 0);

            let new_best_opposing_quantity = best_opposing.node.quantity - match_base_lots;
            let maker_out = new_best_opposing_quantity == 0;
            if maker_out {
                matched_order_deletes
                    .push((best_opposing.handle.order_tree, best_opposing.node.key));
            } else {
                matched_order_changes.push((best_opposing.handle, new_best_opposing_quantity));
            }

            let fill = FillEvent::new(
                side,
                maker_out,
                best_opposing.node.owner_slot,
                now_ts,
                market.seq_num,
                best_opposing.node.owner,
                best_opposing.node.client_order_id,
                best_opposing.node.timestamp,
                *owner,
                order.client_order_id,
                best_opposing_price,
                best_opposing.node.peg_limit,
                match_base_lots,
            );

            emit_stack(TakerSignatureLog {
                market: *market_pk,
                seq_num: market.seq_num,
            });

            process_fill_event(
                fill,
                market,
                event_heap,
                remaining_accs,
                &mut number_of_processed_fill_events,
            )?;

            limit -= 1;
        }

        let total_quote_lots_taken = order_max_quote_lots - remaining_quote_lots;
        let total_base_lots_taken = order.max_base_lots - remaining_base_lots;
        assert!(total_quote_lots_taken >= 0);
        assert!(total_base_lots_taken >= 0);

        let total_base_taken_native = (total_base_lots_taken * market.base_lot_size) as u64;
        let total_quote_taken_native = (total_quote_lots_taken * market.quote_lot_size) as u64;

        // Record the taker trade in the account already, even though it will only be
        // realized when the fill event gets executed
        let mut taker_fees_native = 0_u64;
        if total_quote_lots_taken > 0 || total_base_lots_taken > 0 {
            let total_quote_taken_native_wo_self =
                ((total_quote_lots_taken - decremented_quote_lots) * market.quote_lot_size) as u64;

            if total_quote_taken_native_wo_self > 0 {
                taker_fees_native = market.taker_fees_ceil(total_quote_taken_native_wo_self);

                // Only account taker fees now. Maker fees accounted once processing the event
                referrer_amount = taker_fees_native - maker_rebates_acc;
                market.fees_accrued += referrer_amount as u128;
            };

            if let Some(open_orders_account) = &mut open_orders_account {
                open_orders_account.execute_taker(
                    market,
                    side,
                    total_base_taken_native,
                    total_quote_taken_native,
                    taker_fees_native,
                    referrer_amount,
                );
            } else {
                market.taker_volume_wo_oo += total_quote_taken_native as u128;
            }

            let (total_quantity_paid, total_quantity_received) = match side {
                Side::Bid => (
                    total_quote_taken_native + taker_fees_native,
                    total_base_taken_native,
                ),
                Side::Ask => (
                    total_base_taken_native,
                    total_quote_taken_native - taker_fees_native,
                ),
            };

            emit_stack(TotalOrderFillEvent {
                side: side.into(),
                taker: *owner,
                total_quantity_paid,
                total_quantity_received,
                fees: taker_fees_native,
            });
        }

        // The native taker fees in lots, rounded up.
        //
        // Imagine quote_lot_size = 10. A new bid comes in with max_quote lots = 10. It matches against
        // other orders for 5 quote lots total. The taker_fees_native is 15, taker_fees_lots is 2. That
        // means only up the 3 quote lots may be placed on the book.
        let taker_fees_lots =
            (taker_fees_native as i64 + market.quote_lot_size - 1) / market.quote_lot_size;

        // Update remaining based on quote_lots taken. If nothing taken, same as the beginning
        remaining_quote_lots =
            order.max_quote_lots_including_fees - total_quote_lots_taken - taker_fees_lots;

        // Apply changes to matched asks (handles invalidate on delete!)
        for (handle, new_quantity) in matched_order_changes {
            opposing_bookside
                .node_mut(handle.node)
                .unwrap()
                .as_leaf_mut()
                .unwrap()
                .quantity = new_quantity;
        }
        for (component, key) in matched_order_deletes {
            let _removed_leaf = opposing_bookside.remove_by_key(component, key).unwrap();
        }

        //
        // Place remainder on the book if requested
        //

        // To calculate max quantity to post, for oracle peg orders & bids take the peg_limit as
        // it's the upper price limitation
        let is_oracle_peg = order.peg_limit() != -1;
        let price = if is_oracle_peg && order.side == Side::Bid {
            order.peg_limit()
        } else {
            price_lots
        };

        // If there are still quantity unmatched, place on the book
        let book_base_quantity_lots = {
            remaining_quote_lots -= market.maker_fees_ceil(remaining_quote_lots);
            remaining_base_lots.min(remaining_quote_lots / price)
        };

        if book_base_quantity_lots <= 0 {
            post_target = None;
        }

        if is_oracle_peg && side.is_price_better(price_lots, order.peg_limit()) {
            msg!(
                "Posting on book disallowed due to peg_limit, order price {:?}, limit {:?}",
                price_lots,
                order.peg_limit(),
            );
            post_target = None;
        }

        // There is still quantity, but it's a fill or kill order -> kill
        if fill_or_kill && remaining_base_lots > 0 {
            return err!(OpenBookError::WouldExecutePartially);
        }

        let mut maker_fees_native = 0;
        let mut posted_base_native = 0;
        let mut posted_quote_native = 0;

        if let Some(order_tree_target) = post_target {
            require_gte!(
                market.max_quote_lots(),
                book_base_quantity_lots * price,
                OpenBookError::InvalidPostAmount
            );

            posted_base_native = book_base_quantity_lots * market.base_lot_size;
            posted_quote_native = book_base_quantity_lots * price * market.quote_lot_size;

            // Open orders always exists in this case
            let open_orders = open_orders_account.as_mut().unwrap();

            // Subtract maker fees in bid.
            if side == Side::Bid {
                maker_fees_native = market
                    .maker_fees_ceil(posted_quote_native)
                    .try_into()
                    .unwrap();

                open_orders.position.locked_maker_fees += maker_fees_native;
            }

            let bookside = self.bookside_mut(side);
            // Drop an expired order if possible
            if let Some(expired_order) = bookside.remove_one_expired(order_tree_target, now_ts) {
                let event = OutEvent::new(
                    side,
                    expired_order.owner_slot,
                    now_ts,
                    event_heap.header.seq_num,
                    expired_order.owner,
                    expired_order.quantity,
                );
                process_out_event(
                    event,
                    market,
                    event_heap,
                    Some(open_orders),
                    owner,
                    remaining_accs,
                )?;
            }

            if bookside.is_full() {
                // If this bid is higher than lowest bid, boot that bid and insert this one
                let (worst_order, worst_price) =
                    bookside.remove_worst(now_ts, oracle_price_lots).unwrap();
                // OpenBookErrorCode::OutOfSpace
                require!(
                    side.is_price_better(price_lots, worst_price),
                    OpenBookError::SomeError
                );
                let event = OutEvent::new(
                    side,
                    worst_order.owner_slot,
                    now_ts,
                    event_heap.header.seq_num,
                    worst_order.owner,
                    worst_order.quantity,
                );
                process_out_event(
                    event,
                    market,
                    event_heap,
                    Some(open_orders),
                    owner,
                    remaining_accs,
                )?;
            }

            let owner_slot = open_orders.next_order_slot()?;
            let new_order = LeafNode::new(
                owner_slot as u8,
                order_id,
                *owner,
                book_base_quantity_lots,
                now_ts,
                order.time_in_force,
                order.peg_limit(),
                order.client_order_id,
            );
            let _result = bookside.insert_leaf(order_tree_target, &new_order)?;

            open_orders.add_order(
                side,
                order_tree_target,
                &new_order,
                order.client_order_id,
                price,
            );
        }

        let placed_order_id = if post_target.is_some() {
            Some(order_id)
        } else {
            None
        };

        Ok(OrderWithAmounts {
            order_id: placed_order_id,
            posted_base_native: posted_base_native as u64,
            posted_quote_native: posted_quote_native as u64,
            total_base_taken_native,
            total_quote_taken_native,
            referrer_amount,
            taker_fees: taker_fees_native,
            maker_fees: maker_fees_native,
        })
    }

    /// Cancels up to `limit` orders that are listed on the openorders account for the given market.
    /// Optionally filters by `side_to_cancel_option`.
    /// The orders are removed from the book and from the openorders account open order list.
    pub fn cancel_all_orders(
        &mut self,
        open_orders_account: &mut OpenOrdersAccount,
        market: Market,
        mut limit: u8,
        side_to_cancel_option: Option<Side>,
        client_id_option: Option<u64>,
    ) -> Result<i64> {
        let mut total_quantity = 0_i64;
        for i in 0..MAX_OPEN_ORDERS {
            let oo = open_orders_account.open_orders[i];
            if oo.is_free() {
                continue;
            }

            let order_side_and_tree = oo.side_and_tree();
            if let Some(side_to_cancel) = side_to_cancel_option {
                if side_to_cancel != order_side_and_tree.side() {
                    continue;
                }
            }

            if let Some(client_id) = client_id_option {
                if client_id != oo.client_id {
                    continue;
                }
            }

            if limit == 0 {
                msg!("Cancel orders limit reached");
                break;
            }

            let order_id = oo.id;

            let cancel_result = self.cancel_order(
                open_orders_account,
                order_id,
                order_side_and_tree,
                market,
                None,
            );
            if cancel_result.is_anchor_error_with_code(OpenBookError::OrderIdNotFound.into()) {
                // It's possible for the order to be filled or expired already.
                // There will be an event on the heap, the perp order slot is freed once
                // it is processed.
                msg!(
                    "order {} was not found on orderbook, expired or filled already",
                    order_id
                );
            } else {
                total_quantity += cancel_result?.quantity;
            }

            limit -= 1;
        }
        Ok(total_quantity)
    }

    /// Cancels an order on a side, removing it from the book and the openorders account orders list
    pub fn cancel_order(
        &mut self,
        open_orders_account: &mut OpenOrdersAccount,
        order_id: u128,
        side_and_tree: SideAndOrderTree,
        market: Market,
        expected_owner: Option<Pubkey>,
    ) -> Result<LeafNode> {
        let side = side_and_tree.side();
        let book_component = side_and_tree.order_tree();
        let leaf_node = self.bookside_mut(side).
        remove_by_key(book_component, order_id).ok_or_else(|| {
            // possibly already filled or expired?
            error_msg_typed!(OpenBookError::OrderIdNotFound, "no order with id {order_id}, side {side:?}, component {book_component:?} found on the orderbook")
        })?;
        if let Some(owner) = expected_owner {
            require_keys_eq!(leaf_node.owner, owner);
        }
        open_orders_account.cancel_order(leaf_node.owner_slot as usize, leaf_node.quantity, market);

        Ok(leaf_node)
    }
}

pub fn process_out_event<'c: 'info, 'info>(
    event: OutEvent,
    market: &Market,
    event_heap: &mut EventHeap,
    open_orders_account: Option<&mut OpenOrdersAccount>,
    owner: &Pubkey,
    remaining_accs: &'c [AccountInfo<'info>],
) -> Result<()> {
    if let Some(acc) = open_orders_account {
        if owner == &event.owner {
            acc.cancel_order(event.owner_slot as usize, event.quantity, *market);
            return Ok(());
        }
    }

    if let Some(acc) = remaining_accs.iter().find(|ai| ai.key == &event.owner) {
        let ooa: AccountLoader<OpenOrdersAccount> = AccountLoader::try_from(acc)?;
        let mut acc = ooa.load_mut()?;
        acc.cancel_order(event.owner_slot as usize, event.quantity, *market);
    } else {
        event_heap.push_back(cast(event));
    }

    Ok(())
}

pub fn process_fill_event<'c: 'info, 'info>(
    event: FillEvent,
    market: &mut Market,
    event_heap: &mut EventHeap,
    remaining_accs: &'c [AccountInfo<'info>],
    number_of_processed_fill_events: &mut usize,
) -> Result<()> {
    let mut is_processed = false;
    if *number_of_processed_fill_events < FILL_EVENT_REMAINING_LIMIT {
        if let Some(acc) = remaining_accs.iter().find(|ai| ai.key == &event.maker) {
            let ooa: AccountLoader<OpenOrdersAccount> = AccountLoader::try_from(acc)?;
            let mut maker = ooa.load_mut()?;
            maker.execute_maker(market, &event);
            is_processed = true;
            *number_of_processed_fill_events += 1;
        }
    }

    if !is_processed {
        event_heap.push_back(cast(event));
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/bookside.rs
use anchor_lang::prelude::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use static_assertions::const_assert_eq;

use super::*;

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[repr(u8)]
pub enum BookSideOrderTree {
    Fixed = 0,
    OraclePegged = 1,
}

/// Reference to a node in a book side component
pub struct BookSideOrderHandle {
    pub node: NodeHandle,
    pub order_tree: BookSideOrderTree,
}

#[account(zero_copy)]
pub struct BookSide {
    pub roots: [OrderTreeRoot; 2],
    pub reserved_roots: [OrderTreeRoot; 4],
    pub reserved: [u8; 256],
    pub nodes: OrderTreeNodes,
}
const_assert_eq!(
    std::mem::size_of::<BookSide>(),
    std::mem::size_of::<OrderTreeNodes>() + 6 * std::mem::size_of::<OrderTreeRoot>() + 256
);
const_assert_eq!(std::mem::size_of::<BookSide>(), 90944);
const_assert_eq!(std::mem::size_of::<BookSide>() % 8, 0);

impl BookSide {
    /// Iterate over all entries in the book filtering out invalid orders
    ///
    /// smallest to highest for asks
    /// highest to smallest for bids
    pub fn iter_valid(
        &self,
        now_ts: u64,
        oracle_price_lots: Option<i64>,
    ) -> impl Iterator<Item = BookSideIterItem> {
        BookSideIter::new(self, now_ts, oracle_price_lots).filter(|it| it.is_valid())
    }

    /// Iterate over all entries, including invalid orders
    pub fn iter_all_including_invalid(
        &self,
        now_ts: u64,
        oracle_price_lots: Option<i64>,
    ) -> BookSideIter {
        BookSideIter::new(self, now_ts, oracle_price_lots)
    }

    pub fn node(&self, handle: NodeHandle) -> Option<&AnyNode> {
        self.nodes.node(handle)
    }

    pub fn node_mut(&mut self, handle: NodeHandle) -> Option<&mut AnyNode> {
        self.nodes.node_mut(handle)
    }

    pub fn root(&self, component: BookSideOrderTree) -> &OrderTreeRoot {
        &self.roots[component as usize]
    }

    pub fn root_mut(&mut self, component: BookSideOrderTree) -> &mut OrderTreeRoot {
        &mut self.roots[component as usize]
    }

    pub fn is_full(&self) -> bool {
        self.nodes.is_full()
    }

    pub fn is_empty(&self) -> bool {
        [BookSideOrderTree::Fixed, BookSideOrderTree::OraclePegged]
            .into_iter()
            .all(|component| self.nodes.iter(self.root(component)).count() == 0)
    }

    pub fn insert_leaf(
        &mut self,
        component: BookSideOrderTree,
        new_leaf: &LeafNode,
    ) -> Result<(NodeHandle, Option<LeafNode>)> {
        let root = &mut self.roots[component as usize];
        self.nodes.insert_leaf(root, new_leaf)
    }

    /// Remove the overall worst-price order.
    pub fn remove_worst(
        &mut self,
        now_ts: u64,
        oracle_price_lots: Option<i64>,
    ) -> Option<(LeafNode, i64)> {
        let worst_fixed = self.nodes.find_worst(&self.roots[0]);
        let worst_pegged = self.nodes.find_worst(&self.roots[1]);
        let side = self.nodes.order_tree_type().side();
        let worse = rank_orders(
            side,
            worst_fixed,
            worst_pegged,
            true,
            now_ts,
            oracle_price_lots,
        )?;
        let price = worse.price_lots;
        let key = worse.node.key;
        let order_tree = worse.handle.order_tree;
        let n = self.remove_by_key(order_tree, key)?;
        Some((n, price))
    }

    /// Remove the order with the lowest expiry timestamp in the component, if that's < now_ts.
    /// If there is none, try to remove the lowest expiry one from the other component.
    pub fn remove_one_expired(
        &mut self,
        component: BookSideOrderTree,
        now_ts: u64,
    ) -> Option<LeafNode> {
        let root = &mut self.roots[component as usize];
        if let Some(n) = self.nodes.remove_one_expired(root, now_ts) {
            return Some(n);
        }

        let other_component = match component {
            BookSideOrderTree::Fixed => BookSideOrderTree::OraclePegged,
            BookSideOrderTree::OraclePegged => BookSideOrderTree::Fixed,
        };
        let other_root = &mut self.roots[other_component as usize];
        self.nodes.remove_one_expired(other_root, now_ts)
    }

    pub fn remove_by_key(
        &mut self,
        component: BookSideOrderTree,
        search_key: u128,
    ) -> Option<LeafNode> {
        let root = &mut self.roots[component as usize];
        self.nodes.remove_by_key(root, search_key)
    }

    pub fn side(&self) -> Side {
        self.nodes.order_tree_type().side()
    }

    /// Return the quantity of orders that can be matched by an order at `limit_price_lots`
    pub fn quantity_at_price(
        &self,
        limit_price_lots: i64,
        now_ts: u64,
        oracle_price_lots: i64,
    ) -> i64 {
        let side = self.side();
        let mut sum = 0;
        for item in self.iter_valid(now_ts, Some(oracle_price_lots)) {
            if side.is_price_better(limit_price_lots, item.price_lots) {
                break;
            }
            sum += item.node.quantity;
        }
        sum
    }

    /// Return the price of the order closest to the spread
    pub fn best_price(&self, now_ts: u64, oracle_price_lots: Option<i64>) -> Option<i64> {
        Some(
            self.iter_valid(now_ts, oracle_price_lots)
                .next()?
                .price_lots,
        )
    }

    /// Walk up the book `quantity` units and return the price at that level. If `quantity` units
    /// not on book, return None
    pub fn impact_price(&self, quantity: i64, now_ts: u64, oracle_price_lots: i64) -> Option<i64> {
        let mut sum: i64 = 0;
        for order in self.iter_valid(now_ts, Some(oracle_price_lots)) {
            sum += order.node.quantity;
            if sum >= quantity {
                return Some(order.price_lots);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;

    fn new_order_tree(order_tree_type: OrderTreeType) -> OrderTreeNodes {
        let mut ot = OrderTreeNodes::zeroed();
        ot.order_tree_type = order_tree_type.into();
        ot
    }

    fn bookside_iteration_random_helper(side: Side) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let order_tree_type = match side {
            Side::Bid => OrderTreeType::Bids,
            Side::Ask => OrderTreeType::Asks,
        };

        let mut order_tree = new_order_tree(order_tree_type);
        let mut root_fixed = OrderTreeRoot::zeroed();
        let mut root_pegged = OrderTreeRoot::zeroed();
        let new_leaf = |key: u128| LeafNode::new(0, key, Pubkey::default(), 0, 1, 0, -1, 0);

        // add 100 leaves to each BookSide, mostly random
        let mut keys = vec![];

        // ensure at least one oracle pegged order visible even at oracle price 1
        let key = new_node_key(side, oracle_pegged_price_data(20), 0);
        keys.push(key);
        order_tree
            .insert_leaf(&mut root_pegged, &new_leaf(key))
            .unwrap();

        while root_pegged.leaf_count < 100 {
            let price_data: u64 = oracle_pegged_price_data(rng.gen_range(-20..20));
            let seq_num: u64 = rng.gen_range(0..1000);
            let key = new_node_key(side, price_data, seq_num);
            if keys.contains(&key) {
                continue;
            }
            keys.push(key);
            order_tree
                .insert_leaf(&mut root_pegged, &new_leaf(key))
                .unwrap();
        }

        while root_fixed.leaf_count < 100 {
            let price_data: u64 = rng.gen_range(1..50);
            let seq_num: u64 = rng.gen_range(0..1000);
            let key = new_node_key(side, price_data, seq_num);
            if keys.contains(&key) {
                continue;
            }
            keys.push(key);
            order_tree
                .insert_leaf(&mut root_fixed, &new_leaf(key))
                .unwrap();
        }

        let bookside = BookSide {
            roots: [root_fixed, root_pegged],
            reserved_roots: [OrderTreeRoot::zeroed(); 4],
            reserved: [0; 256],
            nodes: order_tree,
        };

        // verify iteration order for different oracle prices
        for oracle_price_lots in 1..40 {
            let mut total = 0;
            let ascending = order_tree_type == OrderTreeType::Asks;
            let mut last_price = if ascending { 0 } else { i64::MAX };
            for order in bookside.iter_all_including_invalid(0, Some(oracle_price_lots)) {
                let price = order.price_lots;
                println!("{} {:?} {price}", order.node.key, order.handle.order_tree);
                if ascending {
                    assert!(price >= last_price);
                } else {
                    assert!(price <= last_price);
                }
                last_price = price;
                total += 1;
            }
            assert!(total >= 101); // some oracle peg orders could be skipped
            if oracle_price_lots > 20 {
                assert_eq!(total, 200);
            }
        }
    }

    #[test]
    fn bookside_iteration_random() {
        bookside_iteration_random_helper(Side::Bid);
        bookside_iteration_random_helper(Side::Ask);
    }

    fn bookside_setup() -> BookSide {
        use std::cell::RefCell;

        let side = Side::Bid;
        let order_tree_type = OrderTreeType::Bids;

        let order_tree = RefCell::new(new_order_tree(order_tree_type));
        let mut root_fixed = OrderTreeRoot::zeroed();
        let mut root_pegged = OrderTreeRoot::zeroed();
        let new_node = |key: u128, tif: u16, peg_limit: i64| {
            LeafNode::new(0, key, Pubkey::default(), 0, 1000, tif, peg_limit, 0)
        };
        let mut add_fixed = |price: i64, tif: u16| {
            let key = new_node_key(side, fixed_price_data(price).unwrap(), 0);
            order_tree
                .borrow_mut()
                .insert_leaf(&mut root_fixed, &new_node(key, tif, -1))
                .unwrap();
        };
        let mut add_pegged = |price_offset: i64, tif: u16, peg_limit: i64| {
            let key = new_node_key(side, oracle_pegged_price_data(price_offset), 0);
            order_tree
                .borrow_mut()
                .insert_leaf(&mut root_pegged, &new_node(key, tif, peg_limit))
                .unwrap();
        };

        add_fixed(100, 0);
        add_fixed(120, 5);
        add_pegged(-10, 0, 100);
        add_pegged(-15, 0, -1);
        add_pegged(-20, 7, 95);

        BookSide {
            roots: [root_fixed, root_pegged],
            reserved_roots: [OrderTreeRoot::zeroed(); 4],
            reserved: [0; 256],
            nodes: order_tree.into_inner(),
        }
    }

    #[test]
    fn bookside_order_filtering() {
        let bookside = bookside_setup();

        let order_prices = |now_ts: u64, oracle: i64| -> Vec<i64> {
            bookside
                .iter_valid(now_ts, Some(oracle))
                .map(|it| it.price_lots)
                .collect()
        };

        assert_eq!(order_prices(0, 100), vec![120, 100, 90, 85, 80]);
        assert_eq!(order_prices(1004, 100), vec![120, 100, 90, 85, 80]);
        assert_eq!(order_prices(1005, 100), vec![100, 90, 85, 80]);
        assert_eq!(order_prices(1006, 100), vec![100, 90, 85, 80]);
        assert_eq!(order_prices(1007, 100), vec![100, 90, 85]);
        assert_eq!(order_prices(0, 110), vec![120, 100, 100, 95, 90]);
        assert_eq!(order_prices(0, 111), vec![120, 100, 96, 91]);
        assert_eq!(order_prices(0, 115), vec![120, 100, 100, 95]);
        assert_eq!(order_prices(0, 116), vec![120, 101, 100]);
        assert_eq!(order_prices(0, 2015), vec![2000, 120, 100]);
        assert_eq!(order_prices(1010, 2015), vec![2000, 100]);
    }

    #[test]
    fn bookside_remove_worst() {
        use std::cell::RefCell;

        let bookside = RefCell::new(bookside_setup());

        let order_prices = |now_ts: u64, oracle: i64| -> Vec<i64> {
            bookside
                .borrow()
                .iter_valid(now_ts, Some(oracle))
                .map(|it| it.price_lots)
                .collect()
        };

        // remove pegged order
        assert_eq!(order_prices(0, 100), vec![120, 100, 90, 85, 80]);
        let (_, p) = bookside.borrow_mut().remove_worst(0, Some(100)).unwrap();
        assert_eq!(p, 80);
        assert_eq!(order_prices(0, 100), vec![120, 100, 90, 85]);

        // remove fixed order (order at 190=200-10 hits the peg limit)
        assert_eq!(order_prices(0, 200), vec![185, 120, 100]);
        let (_, p) = bookside.borrow_mut().remove_worst(0, Some(200)).unwrap();
        assert_eq!(p, 100);
        assert_eq!(order_prices(0, 200), vec![185, 120]);

        // remove until end

        assert_eq!(order_prices(0, 100), vec![120, 90, 85]);
        let (_, p) = bookside.borrow_mut().remove_worst(0, Some(100)).unwrap();
        assert_eq!(p, 85);
        assert_eq!(order_prices(0, 100), vec![120, 90]);
        let (_, p) = bookside.borrow_mut().remove_worst(0, Some(100)).unwrap();
        assert_eq!(p, 90);
        assert_eq!(order_prices(0, 100), vec![120]);
        let (_, p) = bookside.borrow_mut().remove_worst(0, Some(100)).unwrap();
        assert_eq!(p, 120);
        assert_eq!(order_prices(0, 100), Vec::<i64>::new());
    }

    // add test for oracle expired
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/bookside_iterator.rs
use super::*;

pub struct BookSideIterItem<'a> {
    pub handle: BookSideOrderHandle,
    pub node: &'a LeafNode,
    pub price_lots: i64,
    pub state: OrderState,
}

impl<'a> BookSideIterItem<'a> {
    pub fn is_valid(&self) -> bool {
        self.state == OrderState::Valid
    }
}

/// Iterates the fixed and oracle_pegged OrderTrees simultaneously, allowing users to
/// walk the orderbook without caring about where an order came from.
///
/// This will skip over orders that are not currently matchable, but might be valid
/// in the future.
///
/// This may return invalid orders (tif expired, peg_limit exceeded; see is_valid) which
/// users are supposed to remove from the orderbook if they can.
pub struct BookSideIter<'a> {
    fixed_iter: OrderTreeIter<'a>,
    oracle_pegged_iter: OrderTreeIter<'a>,
    now_ts: u64,
    oracle_price_lots: Option<i64>,
}

impl<'a> BookSideIter<'a> {
    pub fn new(book_side: &'a BookSide, now_ts: u64, oracle_price_lots: Option<i64>) -> Self {
        Self {
            fixed_iter: book_side
                .nodes
                .iter(book_side.root(BookSideOrderTree::Fixed)),
            oracle_pegged_iter: book_side
                .nodes
                .iter(book_side.root(BookSideOrderTree::OraclePegged)),
            now_ts,
            oracle_price_lots,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum OrderState {
    Valid,
    Invalid,
    Skipped,
}

/// Returns the state and current price of an oracle pegged order.
///
/// For pegged orders with offsets that let the price escape the 1..i64::MAX range,
/// this function returns Skipped and clamps `price` to that range.
///
/// Orders that exceed their peg_limit will have Invalid state.
pub fn oracle_pegged_price(
    oracle_price_lots: i64,
    node: &LeafNode,
    side: Side,
) -> (OrderState, i64) {
    let price_data = node.price_data();
    let price_offset = oracle_pegged_price_offset(price_data);
    let price = oracle_price_lots.saturating_add(price_offset);
    if (1..i64::MAX).contains(&price) {
        if node.peg_limit != -1 && side.is_price_better(price, node.peg_limit) {
            return (OrderState::Invalid, price);
        } else {
            return (OrderState::Valid, price);
        }
    }
    (OrderState::Skipped, price.max(1))
}

/// Replace the price data in a binary tree `key` with the fixed order price data at `price_lots`.
///
/// Used to convert oracle pegged keys into a form that allows comparison with fixed order keys.
fn key_for_fixed_price(key: u128, price_lots: i64) -> u128 {
    // We know this can never fail, because oracle pegged price will always be >= 1
    assert!(price_lots >= 1);
    let price_data = fixed_price_data(price_lots).unwrap();
    let upper = (price_data as u128) << 64;
    let lower = (key as u64) as u128;
    upper | lower
}

/// Helper for the iterator returning a fixed order
fn fixed_to_result(fixed: (NodeHandle, &LeafNode), now_ts: u64) -> BookSideIterItem {
    let (handle, node) = fixed;
    let expired = node.is_expired(now_ts);
    BookSideIterItem {
        handle: BookSideOrderHandle {
            order_tree: BookSideOrderTree::Fixed,
            node: handle,
        },
        node,
        price_lots: fixed_price_lots(node.price_data()),
        state: if expired {
            OrderState::Invalid
        } else {
            OrderState::Valid
        },
    }
}

/// Helper for the iterator returning a pegged order
fn oracle_pegged_to_result(
    pegged: (NodeHandle, &LeafNode, i64, OrderState),
    now_ts: u64,
) -> BookSideIterItem {
    let (handle, node, price_lots, state) = pegged;
    let expired = node.is_expired(now_ts);
    BookSideIterItem {
        handle: BookSideOrderHandle {
            order_tree: BookSideOrderTree::OraclePegged,
            node: handle,
        },
        node,
        price_lots,
        state: if expired { OrderState::Invalid } else { state },
    }
}

/// Compares the `fixed` and `oracle_pegged` order and returns the one that would match first.
///
/// (or the worse one, if `return_worse` is set)
pub fn rank_orders<'a>(
    side: Side,
    fixed: Option<(NodeHandle, &'a LeafNode)>,
    oracle_pegged: Option<(NodeHandle, &'a LeafNode)>,
    return_worse: bool,
    now_ts: u64,
    oracle_price_lots: Option<i64>,
) -> Option<BookSideIterItem<'a>> {
    // Enrich with data that'll always be needed
    let oracle_pegged = if let Some(oracle_price_lots) = oracle_price_lots {
        oracle_pegged.map(|(handle, node)| {
            let (state, price_lots) = oracle_pegged_price(oracle_price_lots, node, side);
            (handle, node, price_lots, state)
        })
    } else {
        None
    };

    match (fixed, oracle_pegged) {
        (Some(f), Some(o)) => {
            let is_better = if side == Side::Bid {
                |a, b| a > b
            } else {
                |a, b| a < b
            };

            if is_better(f.1.key, key_for_fixed_price(o.1.key, o.2)) ^ return_worse {
                Some(fixed_to_result(f, now_ts))
            } else {
                Some(oracle_pegged_to_result(o, now_ts))
            }
        }
        (None, Some(o)) => Some(oracle_pegged_to_result(o, now_ts)),
        (Some(f), None) => Some(fixed_to_result(f, now_ts)),
        (None, None) => None,
    }
}

impl<'a> Iterator for BookSideIter<'a> {
    type Item = BookSideIterItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let side = self.fixed_iter.side();

        // Skip all the oracle pegged orders that aren't representable with the current oracle
        // price. Example: iterating asks, but the best ask is at offset -100 with the oracle at 50.
        // We need to skip asks until we find the first that has a price >= 1.
        let o_peek = if let Some(oracle_price_lots) = self.oracle_price_lots {
            let mut o_peek = self.oracle_pegged_iter.peek();
            while let Some((_, o_node)) = o_peek {
                if oracle_pegged_price(oracle_price_lots, o_node, side).0 != OrderState::Skipped {
                    break;
                }
                o_peek = self.oracle_pegged_iter.next()
            }
            o_peek
        } else {
            None
        };

        let f_peek = self.fixed_iter.peek();

        let better = rank_orders(
            side,
            f_peek,
            o_peek,
            false,
            self.now_ts,
            self.oracle_price_lots,
        )?;
        match better.handle.order_tree {
            BookSideOrderTree::Fixed => self.fixed_iter.next(),
            BookSideOrderTree::OraclePegged => self.oracle_pegged_iter.next(),
        };

        Some(better)
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/heap.rs
use crate::error::OpenBookError;
use anchor_lang::prelude::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use static_assertions::const_assert_eq;
use std::mem::size_of;

use super::Side;

pub const MAX_NUM_EVENTS: u16 = 600;
pub const NO_NODE: u16 = u16::MAX;

/// Container for the different EventTypes.
///
/// Events are stored in a fixed-array of nodes. Free nodes are connected by a single-linked list
/// starting at free_head while used nodes form a circular doubly-linked list starting at
/// used_head.
#[account(zero_copy)]
pub struct EventHeap {
    pub header: EventHeapHeader,
    pub nodes: [EventNode; MAX_NUM_EVENTS as usize],
    pub reserved: [u8; 64],
}
const_assert_eq!(
    std::mem::size_of::<EventHeap>(),
    16 + MAX_NUM_EVENTS as usize * (EVENT_SIZE + 8) + 64
);
// Costs 0.636 SOL to create this account
const_assert_eq!(std::mem::size_of::<EventHeap>(), 91280);
const_assert_eq!(std::mem::size_of::<EventHeap>() % 8, 0);

impl EventHeap {
    pub fn init(&mut self) {
        self.header = EventHeapHeader {
            free_head: 0,
            used_head: NO_NODE,
            count: 0,
            seq_num: 0,
            _padd: Default::default(),
        };

        for i in 0..MAX_NUM_EVENTS {
            self.nodes[i as usize].next = i + 1;
            self.nodes[i as usize].prev = NO_NODE;
        }
        self.nodes[MAX_NUM_EVENTS as usize - 1].next = NO_NODE;
    }

    pub fn len(&self) -> usize {
        self.header.count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.nodes.len()
    }

    pub fn front(&self) -> Option<&AnyEvent> {
        if self.is_empty() {
            None
        } else {
            Some(&self.nodes[self.header.used_head()].event)
        }
    }

    pub fn at_slot(&self, slot: usize) -> Option<&AnyEvent> {
        if slot >= self.nodes.len() || self.nodes[slot].is_free() {
            None
        } else {
            Some(&self.nodes[slot].event)
        }
    }

    pub fn push_back(&mut self, value: AnyEvent) {
        assert!(!self.is_full());

        let slot = self.header.free_head;
        self.header.free_head = self.nodes[slot as usize].next;

        let new_next: u16;
        let new_prev: u16;

        if self.is_empty() {
            new_next = slot;
            new_prev = slot;

            self.header.used_head = slot;
        } else {
            new_next = self.header.used_head;
            new_prev = self.nodes[new_next as usize].prev;

            self.nodes[new_prev as usize].next = slot;
            self.nodes[new_next as usize].prev = slot;
        }

        self.header.incr_count();
        self.header.incr_event_id();
        self.nodes[slot as usize].event = value;
        self.nodes[slot as usize].next = new_next;
        self.nodes[slot as usize].prev = new_prev;
    }

    pub fn pop_front(&mut self) -> Result<AnyEvent> {
        self.delete_slot(self.header.used_head())
    }

    pub fn delete_slot(&mut self, slot: usize) -> Result<AnyEvent> {
        if slot >= self.nodes.len() || self.is_empty() || self.nodes[slot].is_free() {
            return Err(OpenBookError::SomeError.into());
        }

        let prev_slot = self.nodes[slot].prev;
        let next_slot = self.nodes[slot].next;
        let next_free = self.header.free_head;

        self.nodes[prev_slot as usize].next = next_slot;
        self.nodes[next_slot as usize].prev = prev_slot;

        if self.header.count() == 1 {
            self.header.used_head = NO_NODE;
        } else if self.header.used_head() == slot {
            self.header.used_head = next_slot;
        };

        self.header.decr_count();
        self.header.free_head = slot.try_into().unwrap();
        self.nodes[slot].next = next_free;
        self.nodes[slot].prev = NO_NODE;

        Ok(self.nodes[slot].event)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AnyEvent, usize)> {
        EventHeapIterator {
            heap: self,
            index: 0,
            slot: self.header.used_head(),
        }
    }
}

struct EventHeapIterator<'a> {
    heap: &'a EventHeap,
    index: usize,
    slot: usize,
}

impl<'a> Iterator for EventHeapIterator<'a> {
    type Item = (&'a AnyEvent, usize);
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.heap.len() {
            None
        } else {
            let current_slot = self.slot;
            self.slot = self.heap.nodes[current_slot].next as usize;
            self.index += 1;
            Some((&self.heap.nodes[current_slot].event, current_slot))
        }
    }
}

#[zero_copy]
pub struct EventHeapHeader {
    free_head: u16,
    used_head: u16,
    count: u16,
    _padd: u16,
    pub seq_num: u64,
}
const_assert_eq!(std::mem::size_of::<EventHeapHeader>(), 16);
const_assert_eq!(std::mem::size_of::<EventHeapHeader>() % 8, 0);

impl EventHeapHeader {
    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn free_head(&self) -> usize {
        self.free_head as usize
    }

    pub fn used_head(&self) -> usize {
        self.used_head as usize
    }

    fn incr_count(&mut self) {
        self.count += 1;
    }

    fn decr_count(&mut self) {
        self.count -= 1;
    }

    fn incr_event_id(&mut self) {
        self.seq_num += 1;
    }
}

#[zero_copy]
#[derive(Debug)]
pub struct EventNode {
    next: u16,
    prev: u16,
    _pad: [u8; 4],
    pub event: AnyEvent,
}
const_assert_eq!(std::mem::size_of::<EventNode>(), 8 + EVENT_SIZE);
const_assert_eq!(std::mem::size_of::<EventNode>() % 8, 0);

impl EventNode {
    pub fn is_free(&self) -> bool {
        self.prev == NO_NODE
    }
}

const EVENT_SIZE: usize = 144;
#[zero_copy]
#[derive(Debug)]
pub struct AnyEvent {
    pub event_type: u8,
    pub padding: [u8; 143],
}

const_assert_eq!(size_of::<AnyEvent>(), EVENT_SIZE);

#[derive(Copy, Clone, IntoPrimitive, TryFromPrimitive, Eq, PartialEq)]
#[repr(u8)]
pub enum EventType {
    Fill,
    Out,
}

#[derive(
    Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable, AnchorSerialize, AnchorDeserialize,
)]
#[repr(C)]
pub struct FillEvent {
    pub event_type: u8,
    pub taker_side: u8, // Side, from the taker's POV
    pub maker_out: u8,  // 1 if maker order quantity == 0
    pub maker_slot: u8,
    pub padding: [u8; 4],
    pub timestamp: u64,
    pub market_seq_num: u64,

    pub maker: Pubkey,

    // Timestamp of when the maker order was placed; copied over from the LeafNode
    pub maker_timestamp: u64,

    pub taker: Pubkey,
    pub taker_client_order_id: u64,

    pub price: i64,
    pub peg_limit: i64,
    pub quantity: i64, // number of base lots
    pub maker_client_order_id: u64,
    pub reserved: [u8; 8],
}
const_assert_eq!(size_of::<FillEvent>() % 8, 0);
const_assert_eq!(size_of::<FillEvent>(), EVENT_SIZE);

impl FillEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        taker_side: Side,
        maker_out: bool,
        maker_slot: u8,
        timestamp: u64,
        market_seq_num: u64,
        maker: Pubkey,
        maker_client_order_id: u64,
        maker_timestamp: u64,
        taker: Pubkey,
        taker_client_order_id: u64,
        price: i64,
        peg_limit: i64,
        quantity: i64,
    ) -> FillEvent {
        Self {
            event_type: EventType::Fill as u8,
            taker_side: taker_side.into(),
            maker_out: maker_out.into(),
            maker_slot,
            timestamp,
            market_seq_num,
            maker,
            maker_client_order_id,
            maker_timestamp,
            taker,
            taker_client_order_id,
            price,
            peg_limit,
            quantity,
            padding: Default::default(),
            reserved: [0; 8],
        }
    }

    pub fn taker_side(&self) -> Side {
        self.taker_side.try_into().unwrap()
    }
    pub fn maker_out(&self) -> bool {
        self.maker_out == 1
    }
}

#[derive(
    Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable, AnchorSerialize, AnchorDeserialize,
)]
#[repr(C)]
pub struct OutEvent {
    pub event_type: u8,
    pub side: u8, // Side
    pub owner_slot: u8,
    padding0: [u8; 5],
    pub timestamp: u64,
    pub seq_num: u64,
    pub owner: Pubkey,
    pub quantity: i64,
    padding1: [u8; 80],
}
const_assert_eq!(size_of::<OutEvent>() % 8, 0);
const_assert_eq!(size_of::<OutEvent>(), EVENT_SIZE);

impl OutEvent {
    pub fn new(
        side: Side,
        owner_slot: u8,
        timestamp: u64,
        seq_num: u64,
        owner: Pubkey,
        quantity: i64,
    ) -> Self {
        Self {
            event_type: EventType::Out.into(),
            side: side.into(),
            owner_slot,
            padding0: [0; 5],
            timestamp,
            seq_num,
            owner,
            quantity,
            padding1: [0; EVENT_SIZE - 64],
        }
    }

    pub fn side(&self) -> Side {
        self.side.try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;

    const LAST_SLOT: u16 = MAX_NUM_EVENTS - 1;

    fn count_free_nodes(event_heap: &EventHeap) -> usize {
        event_heap.nodes.iter().filter(|n| n.is_free()).count()
    }

    fn dummy_event_with_number(number: u8) -> AnyEvent {
        let mut dummy_event = AnyEvent::zeroed();
        dummy_event.event_type = number;
        dummy_event
    }

    #[test]
    fn init() {
        let mut eq = EventHeap::zeroed();
        eq.init();

        assert_eq!(eq.header.count(), 0);
        assert_eq!(eq.header.free_head(), 0);
        assert_eq!(eq.header.used_head(), NO_NODE as usize);
        assert_eq!(count_free_nodes(&eq), MAX_NUM_EVENTS as usize);
    }

    #[test]
    #[should_panic]
    fn cannot_insert_if_full() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        for _ in 0..MAX_NUM_EVENTS + 1 {
            eq.push_back(AnyEvent::zeroed());
        }
    }

    #[test]
    #[should_panic]
    fn cannot_delete_if_empty() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        eq.pop_front().unwrap();
    }

    #[test]
    fn insert_until_full() {
        let mut eq = EventHeap::zeroed();
        eq.init();

        // insert one event in the first slot; the single used node should point to himself
        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.used_head, 0);
        assert_eq!(eq.header.free_head, 1);
        assert_eq!(eq.nodes[0].prev, 0);
        assert_eq!(eq.nodes[0].next, 0);
        assert_eq!(eq.nodes[1].next, 2);

        for i in 1..MAX_NUM_EVENTS - 2 {
            eq.push_back(AnyEvent::zeroed());
            assert_eq!(eq.header.used_head, 0);
            assert_eq!(eq.header.free_head, i + 1);
            assert_eq!(eq.nodes[0].prev, i);
            assert_eq!(eq.nodes[0].next, 1);
            assert_eq!(eq.nodes[i as usize + 1].next, i + 2);
        }

        // insert another one, afterwards only one free node pointing to null should be left
        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.used_head, 0);
        assert_eq!(eq.header.free_head, LAST_SLOT);
        assert_eq!(eq.nodes[0].prev, LAST_SLOT - 1);
        assert_eq!(eq.nodes[0].next, 1);
        assert_eq!(eq.nodes[LAST_SLOT as usize].next, NO_NODE);

        // insert last available event
        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.used_head, 0);
        assert_eq!(eq.header.free_head, NO_NODE);
        assert_eq!(eq.nodes[0].prev, LAST_SLOT);
        assert_eq!(eq.nodes[0].next, 1);
    }

    #[test]
    fn delete_full() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        for _ in 0..MAX_NUM_EVENTS {
            eq.push_back(AnyEvent::zeroed());
        }

        eq.pop_front().unwrap();
        assert_eq!(eq.header.free_head, 0);
        assert_eq!(eq.header.used_head, 1);
        assert_eq!(eq.nodes[0].next, NO_NODE);
        assert_eq!(eq.nodes[1].prev, LAST_SLOT);
        assert_eq!(eq.nodes[1].next, 2);

        for i in 1..MAX_NUM_EVENTS - 2 {
            eq.pop_front().unwrap();
            assert_eq!(eq.header.free_head, i);
            assert_eq!(eq.header.used_head, i + 1);
            assert_eq!(eq.nodes[i as usize].next, i - 1);
            assert_eq!(eq.nodes[i as usize + 1].prev, LAST_SLOT);
            assert_eq!(eq.nodes[i as usize + 1].next, i + 2);
        }

        eq.pop_front().unwrap();
        assert_eq!(eq.header.free_head, LAST_SLOT - 1);
        assert_eq!(eq.header.used_head, LAST_SLOT);
        assert_eq!(eq.nodes[LAST_SLOT as usize - 1].next, LAST_SLOT - 2);
        assert_eq!(eq.nodes[LAST_SLOT as usize].prev, LAST_SLOT);
        assert_eq!(eq.nodes[LAST_SLOT as usize].next, LAST_SLOT);

        eq.pop_front().unwrap();
        assert_eq!(eq.header.used_head, NO_NODE);
        assert_eq!(eq.header.free_head, LAST_SLOT);
        assert_eq!(eq.nodes[LAST_SLOT as usize].next, LAST_SLOT - 1);

        assert_eq!(eq.header.count(), 0);
        assert_eq!(count_free_nodes(&eq), MAX_NUM_EVENTS as usize);
    }

    #[test]
    fn delete_at_given_position() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        for _ in 0..5 {
            eq.push_back(AnyEvent::zeroed());
        }
        eq.delete_slot(2).unwrap();
        assert_eq!(eq.header.free_head(), 2);
        assert_eq!(eq.header.used_head(), 0);
    }

    #[test]
    #[should_panic]
    fn cannot_delete_twice_same() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        for _ in 0..5 {
            eq.push_back(AnyEvent::zeroed());
        }
        eq.delete_slot(2).unwrap();
        eq.delete_slot(2).unwrap();
    }

    #[test]
    fn read_front() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        eq.push_back(dummy_event_with_number(1));
        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.front().unwrap().event_type, 1);
    }

    #[test]
    fn read_at_slot() {
        let mut eq = EventHeap::zeroed();
        eq.init();
        eq.push_back(AnyEvent::zeroed());
        eq.push_back(AnyEvent::zeroed());
        eq.push_back(dummy_event_with_number(1));
        assert_eq!(eq.at_slot(2).unwrap().event_type, 1);
    }

    #[test]
    fn fifo_event_processing() {
        // [ | | | | ] init
        // [1| | | | ] push_back
        // [1|2| | | ] push_back
        // [ |2| | | ] pop_front
        // [3|2| | | ] push_back
        // [3| | | | ] pop_front

        let mut eq = EventHeap::zeroed();
        eq.init();
        assert!(eq.nodes[0].is_free());
        assert!(eq.nodes[1].is_free());
        assert!(eq.nodes[2].is_free());

        eq.push_back(dummy_event_with_number(1));
        assert_eq!(eq.nodes[0].event.event_type, 1);
        assert!(eq.nodes[1].is_free());
        assert!(eq.nodes[2].is_free());

        eq.push_back(dummy_event_with_number(2));
        assert_eq!(eq.nodes[0].event.event_type, 1);
        assert_eq!(eq.nodes[1].event.event_type, 2);
        assert!(eq.nodes[2].is_free());

        eq.pop_front().unwrap();
        assert!(eq.nodes[0].is_free());
        assert_eq!(eq.nodes[1].event.event_type, 2);
        assert!(eq.nodes[2].is_free());

        eq.push_back(dummy_event_with_number(3));
        assert_eq!(eq.nodes[0].event.event_type, 3);
        assert_eq!(eq.nodes[1].event.event_type, 2);
        assert!(eq.nodes[2].is_free());

        eq.pop_front().unwrap();
        assert_eq!(eq.nodes[0].event.event_type, 3);
        assert!(eq.nodes[1].is_free());
        assert!(eq.nodes[2].is_free());
    }

    #[test]
    fn lifo_free_available_slots() {
        // [0|1|2|3|4] init
        // [ |0|1|2|3] push_back
        // [ | |0|1|2] push_back
        // [0| |1|2|3] pop_front
        // [1|0|2|3|4] pop_front
        // [0| |1|2|3] push_back
        // [ | |0|1|2] push_back

        let mut eq = EventHeap::zeroed();
        eq.init();
        assert_eq!(eq.header.free_head(), 0);
        assert_eq!(eq.nodes[0].next, 1);

        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.free_head(), 1);
        assert_eq!(eq.nodes[1].next, 2);

        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.free_head(), 2);
        assert_eq!(eq.nodes[2].next, 3);

        eq.pop_front().unwrap();
        assert_eq!(eq.header.free_head(), 0);
        assert_eq!(eq.nodes[0].next, 2);

        eq.pop_front().unwrap();
        assert_eq!(eq.header.free_head(), 1);
        assert_eq!(eq.nodes[1].next, 0);

        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.free_head(), 0);
        assert_eq!(eq.nodes[0].next, 2);

        eq.push_back(AnyEvent::zeroed());
        assert_eq!(eq.header.free_head(), 2);
        assert_eq!(eq.nodes[2].next, 3);
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/mod.rs
pub use book::*;
pub use bookside::*;
pub use bookside_iterator::*;
pub use heap::*;
pub use nodes::*;
pub use order::*;
pub use order_type::*;
pub use ordertree::*;
pub use ordertree_iterator::*;

mod book;
mod bookside;
mod bookside_iterator;
mod heap;
mod nodes;
mod order;
mod order_type;
mod ordertree;
mod ordertree_iterator;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Market, OpenOrdersAccount, FEES_SCALE_FACTOR};
    use bytemuck::Zeroable;
    use fixed::types::I80F48;
    use solana_program::pubkey::Pubkey;
    use std::cell::RefCell;

    fn order_tree_leaf_by_key(bookside: &BookSide, key: u128) -> Option<&LeafNode> {
        for component in [BookSideOrderTree::Fixed, BookSideOrderTree::OraclePegged] {
            for (_, leaf) in bookside.nodes.iter(bookside.root(component)) {
                if leaf.key == key {
                    return Some(leaf);
                }
            }
        }
        None
    }

    fn order_tree_contains_key(bookside: &BookSide, key: u128) -> bool {
        order_tree_leaf_by_key(bookside, key).is_some()
    }

    fn order_tree_contains_price(bookside: &BookSide, price_data: u64) -> bool {
        for component in [BookSideOrderTree::Fixed, BookSideOrderTree::OraclePegged] {
            for (_, leaf) in bookside.nodes.iter(bookside.root(component)) {
                if leaf.price_data() == price_data {
                    return true;
                }
            }
        }
        false
    }

    struct OrderbookAccounts {
        bids: Box<RefCell<BookSide>>,
        asks: Box<RefCell<BookSide>>,
    }

    impl OrderbookAccounts {
        fn new() -> Self {
            let s = Self {
                bids: Box::new(RefCell::new(BookSide::zeroed())),
                asks: Box::new(RefCell::new(BookSide::zeroed())),
            };
            s.bids.borrow_mut().nodes.order_tree_type = OrderTreeType::Bids.into();
            s.asks.borrow_mut().nodes.order_tree_type = OrderTreeType::Asks.into();
            s
        }

        fn orderbook(&self) -> Orderbook {
            Orderbook {
                bids: self.bids.borrow_mut(),
                asks: self.asks.borrow_mut(),
            }
        }
    }

    fn test_setup(price: f64) -> (Market, Option<i64>, EventHeap, OrderbookAccounts) {
        let book = OrderbookAccounts::new();

        let event_heap = EventHeap::zeroed();

        let mut openbook_market = Market::zeroed();
        openbook_market.quote_lot_size = 1;
        openbook_market.base_lot_size = 1;

        let oracle_price_lots = openbook_market
            .native_price_to_lot(I80F48::from_num(price))
            .ok();

        (openbook_market, oracle_price_lots, event_heap, book)
    }

    // Check what happens when one side of the book fills up
    #[test]
    fn book_bids_full() {
        let (mut openbook_market, oracle_price_lots, mut event_heap, book_accs) =
            test_setup(5000.0);
        let mut book = book_accs.orderbook();
        let market_pk = Pubkey::new_unique();

        let mut new_order =
            |book: &mut Orderbook, event_heap: &mut EventHeap, side, price_lots, now_ts| -> u128 {
                let mut account = OpenOrdersAccount::default_for_tests();

                let max_base_lots = 1;
                let time_in_force = 100;

                book.new_order(
                    &Order {
                        side,
                        max_base_lots,
                        max_quote_lots_including_fees: i64::MAX / openbook_market.quote_lot_size,
                        client_order_id: 0,
                        time_in_force,
                        params: OrderParams::Fixed {
                            price_lots,
                            order_type: PostOrderType::Limit,
                        },
                        self_trade_behavior: SelfTradeBehavior::DecrementTake,
                    },
                    &mut openbook_market,
                    &market_pk,
                    event_heap,
                    oracle_price_lots,
                    Some(&mut account),
                    &Pubkey::new_unique(),
                    now_ts,
                    u8::MAX,
                    &[],
                )
                .unwrap();
                account.open_order_by_raw_index(0).id
            };

        // insert bids until book side is full
        for i in 1..10 {
            new_order(
                &mut book,
                &mut event_heap,
                Side::Bid,
                1000 + i as i64,
                1000000 + i as u64,
            );
        }
        for i in 10..1000 {
            new_order(
                &mut book,
                &mut event_heap,
                Side::Bid,
                1000 + i as i64,
                1000011_u64,
            );
            if book.bids.is_full() {
                break;
            }
        }
        assert!(book.bids.is_full());
        assert_eq!(
            book.bids
                .nodes
                .min_leaf(&book.bids.roots[0])
                .unwrap()
                .1
                .price_data(),
            1001
        );
        assert_eq!(
            fixed_price_lots(
                book.bids
                    .nodes
                    .max_leaf(&book.bids.roots[0])
                    .unwrap()
                    .1
                    .price_data()
            ),
            (1000 + book.bids.roots[0].leaf_count) as i64
        );

        // add another bid at a higher price before expiry, replacing the lowest-price one (1001)
        new_order(&mut book, &mut event_heap, Side::Bid, 1005, 1000000 - 1);
        assert_eq!(
            book.bids
                .nodes
                .min_leaf(&book.bids.roots[0])
                .unwrap()
                .1
                .price_data(),
            1002
        );
        assert_eq!(event_heap.len(), 1);

        // adding another bid after expiry removes the soonest-expiring order (1005)
        new_order(&mut book, &mut event_heap, Side::Bid, 999, 2000000);
        assert_eq!(
            book.bids
                .nodes
                .min_leaf(&book.bids.roots[0])
                .unwrap()
                .1
                .price_data(),
            999
        );
        assert!(!order_tree_contains_key(&book.bids, 1005));
        assert_eq!(event_heap.len(), 2);

        // adding an ask will wipe up to three expired bids at the top of the book
        let bids_max = book
            .bids
            .nodes
            .max_leaf(&book.bids.roots[0])
            .unwrap()
            .1
            .price_data();
        let bids_count = book.bids.roots[0].leaf_count;
        new_order(&mut book, &mut event_heap, Side::Ask, 6000, 1500000);
        assert_eq!(book.bids.roots[0].leaf_count, bids_count - 5);
        assert_eq!(book.asks.roots[0].leaf_count, 1);
        assert_eq!(event_heap.len(), 2 + 5);
        assert!(!order_tree_contains_price(&book.bids, bids_max));
        assert!(!order_tree_contains_price(&book.bids, bids_max - 1));
        assert!(!order_tree_contains_price(&book.bids, bids_max - 2));
        assert!(!order_tree_contains_price(&book.bids, bids_max - 3));
        assert!(!order_tree_contains_price(&book.bids, bids_max - 4));
        assert!(order_tree_contains_price(&book.bids, bids_max - 5));
    }

    #[test]
    fn book_new_order() {
        let (mut market, oracle_price_lots, mut event_heap, book_accs) = test_setup(1000.0);
        let mut book = book_accs.orderbook();
        let market_pk = Pubkey::new_unique();

        // Add lots and fees to make sure to exercise unit conversion
        market.base_lot_size = 10;
        market.quote_lot_size = 100;
        let maker_fee = 100;
        let taker_fee = 1000;
        market.maker_fee = maker_fee;
        market.taker_fee = taker_fee;

        let mut maker = OpenOrdersAccount::default_for_tests();
        let mut taker = OpenOrdersAccount::default_for_tests();

        let maker_pk = Pubkey::new_unique();
        let taker_pk = Pubkey::new_unique();
        let now_ts = 1000000;

        // Place a maker-bid
        let price_lots = 1000 * market.base_lot_size / market.quote_lot_size;
        let bid_quantity = 10;
        book.new_order(
            &Order {
                side: Side::Bid,
                max_base_lots: bid_quantity,
                max_quote_lots_including_fees: i64::MAX / market.quote_lot_size,
                client_order_id: 42,
                time_in_force: 0,
                params: OrderParams::Fixed {
                    price_lots,
                    order_type: PostOrderType::Limit,
                },
                self_trade_behavior: SelfTradeBehavior::DecrementTake,
            },
            &mut market,
            &market_pk,
            &mut event_heap,
            oracle_price_lots,
            Some(&mut maker),
            &maker_pk,
            now_ts,
            u8::MAX,
            &[],
        )
        .unwrap();
        let order =
            order_tree_leaf_by_key(&book.bids, maker.open_order_by_raw_index(0).id).unwrap();
        assert_eq!(order.client_order_id, 42);
        assert_eq!(order.quantity, bid_quantity);
        assert!(maker.open_order_by_raw_index(1).is_free());
        assert_ne!(maker.open_order_by_raw_index(0).id, 0);
        assert_eq!(maker.open_order_by_raw_index(0).client_id, 42);
        assert_eq!(
            maker.open_order_by_raw_index(0).side_and_tree(),
            SideAndOrderTree::BidFixed
        );
        assert!(order_tree_contains_key(
            &book.bids,
            maker.open_order_by_raw_index(0).id
        ));
        assert!(order_tree_contains_price(&book.bids, price_lots as u64));
        assert_eq!(maker.position.bids_base_lots, bid_quantity);
        assert_eq!(maker.position.bids_quote_lots, bid_quantity * price_lots);
        assert_eq!(maker.position.asks_base_lots, 0);
        assert_eq!(event_heap.len(), 0);

        // Take the order partially
        let match_quantity = 5;
        book.new_order(
            &Order {
                side: Side::Ask,
                max_base_lots: match_quantity,
                max_quote_lots_including_fees: i64::MAX / market.quote_lot_size,
                client_order_id: 43,
                time_in_force: 0,
                params: OrderParams::Fixed {
                    price_lots,
                    order_type: PostOrderType::Limit,
                },
                self_trade_behavior: SelfTradeBehavior::DecrementTake,
            },
            &mut market,
            &market_pk,
            &mut event_heap,
            oracle_price_lots,
            Some(&mut taker),
            &taker_pk,
            now_ts,
            u8::MAX,
            &[],
        )
        .unwrap();
        // the remainder of the maker order is still on the book
        // (the maker account is unchanged: it was not even passed in)
        let order =
            order_tree_leaf_by_key(&book.bids, maker.open_order_by_raw_index(0).id).unwrap();
        assert_eq!(fixed_price_lots(order.price_data()), price_lots);
        assert_eq!(order.quantity, bid_quantity - match_quantity);

        // fees were immediately accrued
        let match_quote = match_quantity * price_lots * market.quote_lot_size;
        assert_eq!(
            market.fees_accrued as i64,
            match_quote * (taker_fee) / (FEES_SCALE_FACTOR as i64)
        );

        // the taker account is updated
        assert!(taker.open_order_by_raw_index(1).is_free());
        assert_eq!(taker.position.bids_base_lots, 0);
        assert_eq!(taker.position.bids_quote_lots, 0);
        assert_eq!(taker.position.asks_base_lots, 0);
        // the fill gets added to the event heap
        assert_eq!(event_heap.len(), 1);
        let event = event_heap.front().unwrap();
        assert_eq!(event.event_type, EventType::Fill as u8);
        let fill: &FillEvent = bytemuck::cast_ref(event);
        assert_eq!(fill.quantity, match_quantity);
        assert_eq!(fill.price, price_lots);
        assert_eq!(fill.taker_client_order_id, 43);
        assert_eq!(fill.maker, maker_pk);
        assert_eq!(fill.taker, taker_pk);

        // simulate event heap processing
        maker.execute_maker(&mut market, fill);
        taker.execute_taker(&mut market, Side::Ask, 0, 0, 0, 0);

        assert_eq!(maker.position.bids_base_lots, bid_quantity - match_quantity);
        assert_eq!(maker.position.asks_base_lots, 0);

        assert_eq!(taker.position.bids_base_lots, 0);
        assert_eq!(taker.position.bids_quote_lots, 0);
        assert_eq!(taker.position.asks_base_lots, 0);
        // Maker fee is accrued now
        assert_eq!(
            market.fees_accrued as i64,
            match_quote * (maker_fee + taker_fee) / (FEES_SCALE_FACTOR as i64)
        );
    }

    // Check that there are no zero-quantity fills when max_quote_lots is not
    // enough for a single lot
    #[test]
    fn book_max_quote_lots() {
        let (mut market, oracle_price_lots, mut event_heap, book_accs) = test_setup(5000.0);
        let quote_lot_size = market.quote_lot_size;
        let mut book = book_accs.orderbook();
        let market_pk = Pubkey::new_unique();

        let mut new_order = |book: &mut Orderbook,
                             event_heap: &mut EventHeap,
                             side,
                             price_lots,
                             max_base_lots: i64,
                             max_quote_lots_including_fees: i64|
         -> u128 {
            let mut account = OpenOrdersAccount::default_for_tests();

            book.new_order(
                &Order {
                    side,
                    max_base_lots,
                    max_quote_lots_including_fees,
                    client_order_id: 0,
                    time_in_force: 0,
                    params: OrderParams::Fixed {
                        price_lots,
                        order_type: PostOrderType::Limit,
                    },
                    self_trade_behavior: SelfTradeBehavior::DecrementTake,
                },
                &mut market,
                &market_pk,
                event_heap,
                oracle_price_lots,
                Some(&mut account),
                &Pubkey::default(),
                0, // now_ts
                u8::MAX,
                &[],
            )
            .unwrap();
            account.open_order_by_raw_index(0).id
        };

        // Setup
        new_order(
            &mut book,
            &mut event_heap,
            Side::Ask,
            5000,
            5,
            i64::MAX / quote_lot_size,
        );
        new_order(
            &mut book,
            &mut event_heap,
            Side::Ask,
            5001,
            5,
            i64::MAX / quote_lot_size,
        );
        new_order(
            &mut book,
            &mut event_heap,
            Side::Ask,
            5002,
            5,
            i64::MAX / quote_lot_size,
        );

        // Try taking: the quote limit allows only one base lot to be taken.
        new_order(&mut book, &mut event_heap, Side::Bid, 5005, 30, 6000);
        // Only one fill event is generated, the matching aborts even though neither the base nor quote limit
        // is exhausted.
        assert_eq!(event_heap.len(), 1);

        // Try taking: the quote limit allows no fills
        new_order(&mut book, &mut event_heap, Side::Bid, 5005, 30, 1);
        assert_eq!(event_heap.len(), 1);
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/nodes.rs
use std::mem::{align_of, size_of};

use anchor_lang::prelude::*;
use bytemuck::{cast_mut, cast_ref};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use static_assertions::const_assert_eq;

use super::order_type::Side;

pub type NodeHandle = u32;
const NODE_SIZE: usize = 88;

#[derive(IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum NodeTag {
    Uninitialized = 0,
    InnerNode = 1,
    LeafNode = 2,
    FreeNode = 3,
    LastFreeNode = 4,
}

/// Creates a binary tree node key.
///
/// It's used for sorting nodes (ascending for asks, descending for bids)
/// and encodes price data in the top 64 bits followed by an ordering number
/// in the lower bits.
///
/// The `seq_num` that's passed should monotonically increase. It's used to choose
/// the ordering number such that orders placed later for the same price data
/// are ordered after earlier orders.
pub fn new_node_key(side: Side, price_data: u64, seq_num: u64) -> u128 {
    let seq_num = if side == Side::Bid { !seq_num } else { seq_num };

    let upper = (price_data as u128) << 64;
    upper | (seq_num as u128)
}

/// Creates price data for an oracle pegged order from the price offset
///
/// Reverse of oracle_pegged_price_offset()
pub fn oracle_pegged_price_data(price_offset_lots: i64) -> u64 {
    // Price data is used for ordering in the bookside's top bits of the u128 key.
    // Map i64::MIN to be 0 and i64::MAX to u64::MAX, that way comparisons on the
    // u64 produce the same result as on the source i64.
    // Equivalent: (price_offset_lots as i128 - (i64::MIN as i128) as u64
    (price_offset_lots as u64).wrapping_add(u64::MAX / 2 + 1)
}

/// Retrieves the price offset (in lots) from an oracle pegged order's price data
///
/// Reverse of oracle_pegged_price_data()
pub fn oracle_pegged_price_offset(price_data: u64) -> i64 {
    price_data.wrapping_sub(u64::MAX / 2 + 1) as i64
}

/// Creates price data for a fixed order's price
///
/// Reverse of fixed_price_lots()
pub fn fixed_price_data(price_lots: i64) -> Result<u64> {
    require_gte!(price_lots, 1);
    Ok(price_lots as u64)
}

/// Retrieves the price (in lots) from a fixed order's price data
///
/// Reverse of fixed_price_data().
pub fn fixed_price_lots(price_data: u64) -> i64 {
    assert!(price_data <= i64::MAX as u64);
    price_data as i64
}

/// InnerNodes and LeafNodes compose the binary tree of orders.
///
/// Each InnerNode has exactly two children, which are either InnerNodes themselves,
/// or LeafNodes. The children share the top `prefix_len` bits of `key`. The left
/// child has a 0 in the next bit, and the right a 1.
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable, AnchorSerialize, AnchorDeserialize)]
#[repr(C)]
pub struct InnerNode {
    pub tag: u8, // NodeTag
    pub padding: [u8; 3],
    /// number of highest `key` bits that all children share
    /// e.g. if it's 2, the two highest bits of `key` will be the same on all children
    pub prefix_len: u32,

    /// only the top `prefix_len` bits of `key` are relevant
    pub key: u128,

    /// indexes into `BookSide::nodes`
    pub children: [NodeHandle; 2],

    /// The earliest expiry timestamp for the left and right subtrees.
    ///
    /// Needed to be able to find and remove expired orders without having to
    /// iterate through the whole bookside.
    pub child_earliest_expiry: [u64; 2],

    pub reserved: [u8; 40],
}
const_assert_eq!(size_of::<InnerNode>(), 4 + 4 + 16 + 4 * 2 + 8 * 2 + 40);
const_assert_eq!(size_of::<InnerNode>(), NODE_SIZE);
const_assert_eq!(size_of::<InnerNode>() % 8, 0);

impl InnerNode {
    pub fn new(prefix_len: u32, key: u128) -> Self {
        Self {
            tag: NodeTag::InnerNode.into(),
            padding: Default::default(),
            prefix_len,
            key,
            children: [0; 2],
            child_earliest_expiry: [u64::MAX; 2],
            reserved: [0; NODE_SIZE - 48],
        }
    }

    /// Returns the handle of the child that may contain the search key
    /// and 0 or 1 depending on which child it was.
    pub(crate) fn walk_down(&self, search_key: u128) -> (NodeHandle, bool) {
        let crit_bit_mask = 1u128 << (127 - self.prefix_len);
        let crit_bit = (search_key & crit_bit_mask) != 0;
        (self.children[crit_bit as usize], crit_bit)
    }

    /// The lowest timestamp at which one of the contained LeafNodes expires.
    #[inline(always)]
    pub fn earliest_expiry(&self) -> u64 {
        std::cmp::min(self.child_earliest_expiry[0], self.child_earliest_expiry[1])
    }
}

/// LeafNodes represent an order in the binary tree
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    bytemuck::Pod,
    bytemuck::Zeroable,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[repr(C)]
pub struct LeafNode {
    /// NodeTag
    pub tag: u8,

    /// Index into the owning OpenOrdersAccount's OpenOrders
    pub owner_slot: u8,

    /// Time in seconds after `timestamp` at which the order expires.
    /// A value of 0 means no expiry.
    pub time_in_force: u16,

    pub padding: [u8; 4],

    /// The binary tree key, see new_node_key()
    pub key: u128,

    /// Address of the owning OpenOrdersAccount
    pub owner: Pubkey,

    /// Number of base lots to buy or sell, always >=1
    pub quantity: i64,

    /// The time the order was placed
    pub timestamp: u64,

    /// If the effective price of an oracle pegged order exceeds this limit,
    /// it will be considered invalid and may be removed.
    ///
    /// Only applicable in the oracle_pegged OrderTree
    pub peg_limit: i64,

    /// User defined id for this order, used in FillEvents
    pub client_order_id: u64,
}
const_assert_eq!(
    size_of::<LeafNode>(),
    4 + 1 + 1 + 1 + 1 + 16 + 32 + 8 + 8 + 8 + 8
);
const_assert_eq!(size_of::<LeafNode>(), NODE_SIZE);
const_assert_eq!(size_of::<LeafNode>() % 8, 0);

impl LeafNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_slot: u8,
        key: u128,
        owner: Pubkey,
        quantity: i64,
        timestamp: u64,
        time_in_force: u16,
        peg_limit: i64,
        client_order_id: u64,
    ) -> Self {
        Self {
            tag: NodeTag::LeafNode.into(),
            owner_slot,
            time_in_force,
            padding: Default::default(),
            key,
            owner,
            quantity,
            timestamp,
            peg_limit,
            client_order_id,
        }
    }

    /// The order's price_data as stored in the key
    ///
    /// Needs to be unpacked differently for fixed and oracle pegged orders.
    #[inline(always)]
    pub fn price_data(&self) -> u64 {
        (self.key >> 64) as u64
    }

    /// Time at which this order will expire, u64::MAX if never
    #[inline(always)]
    pub fn expiry(&self) -> u64 {
        if self.time_in_force == 0 {
            u64::MAX
        } else {
            self.timestamp + self.time_in_force as u64
        }
    }

    /// Returns if the order is expired at `now_ts`
    #[inline(always)]
    pub fn is_expired(&self, now_ts: u64) -> bool {
        self.time_in_force > 0 && now_ts >= self.timestamp + self.time_in_force as u64
    }
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct FreeNode {
    pub(crate) tag: u8, // NodeTag
    pub(crate) padding: [u8; 3],
    pub(crate) next: NodeHandle,
    pub(crate) reserved: [u8; NODE_SIZE - 16],
    // essential to make AnyNode alignment the same as other node types
    pub(crate) force_align: u64,
}
const_assert_eq!(size_of::<FreeNode>(), NODE_SIZE);
const_assert_eq!(size_of::<FreeNode>() % 8, 0);

#[zero_copy]
pub struct AnyNode {
    pub tag: u8,
    pub data: [u8; 79],
    // essential to make AnyNode alignment the same as other node types
    pub force_align: u64,
}
const_assert_eq!(size_of::<AnyNode>(), NODE_SIZE);
const_assert_eq!(size_of::<AnyNode>() % 8, 0);
const_assert_eq!(align_of::<AnyNode>(), 8);
const_assert_eq!(size_of::<AnyNode>(), size_of::<InnerNode>());
const_assert_eq!(align_of::<AnyNode>(), align_of::<InnerNode>());
const_assert_eq!(size_of::<AnyNode>(), size_of::<LeafNode>());
const_assert_eq!(align_of::<AnyNode>(), align_of::<LeafNode>());
const_assert_eq!(size_of::<AnyNode>(), size_of::<FreeNode>());
const_assert_eq!(align_of::<AnyNode>(), align_of::<FreeNode>());

pub(crate) enum NodeRef<'a> {
    Inner(&'a InnerNode),
    Leaf(&'a LeafNode),
}

pub(crate) enum NodeRefMut<'a> {
    Inner(&'a mut InnerNode),
    Leaf(&'a mut LeafNode),
}

impl AnyNode {
    pub fn key(&self) -> Option<u128> {
        match self.case()? {
            NodeRef::Inner(inner) => Some(inner.key),
            NodeRef::Leaf(leaf) => Some(leaf.key),
        }
    }

    pub(crate) fn children(&self) -> Option<[NodeHandle; 2]> {
        match self.case().unwrap() {
            NodeRef::Inner(&InnerNode { children, .. }) => Some(children),
            NodeRef::Leaf(_) => None,
        }
    }

    pub(crate) fn case(&self) -> Option<NodeRef> {
        match NodeTag::try_from(self.tag) {
            Ok(NodeTag::InnerNode) => Some(NodeRef::Inner(cast_ref(self))),
            Ok(NodeTag::LeafNode) => Some(NodeRef::Leaf(cast_ref(self))),
            _ => None,
        }
    }

    fn case_mut(&mut self) -> Option<NodeRefMut> {
        match NodeTag::try_from(self.tag) {
            Ok(NodeTag::InnerNode) => Some(NodeRefMut::Inner(cast_mut(self))),
            Ok(NodeTag::LeafNode) => Some(NodeRefMut::Leaf(cast_mut(self))),
            _ => None,
        }
    }

    #[inline]
    pub fn as_leaf(&self) -> Option<&LeafNode> {
        match self.case() {
            Some(NodeRef::Leaf(leaf_ref)) => Some(leaf_ref),
            _ => None,
        }
    }

    #[inline]
    pub fn as_leaf_mut(&mut self) -> Option<&mut LeafNode> {
        match self.case_mut() {
            Some(NodeRefMut::Leaf(leaf_ref)) => Some(leaf_ref),
            _ => None,
        }
    }

    #[inline]
    pub fn as_inner(&self) -> Option<&InnerNode> {
        match self.case() {
            Some(NodeRef::Inner(inner_ref)) => Some(inner_ref),
            _ => None,
        }
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> Option<&mut InnerNode> {
        match self.case_mut() {
            Some(NodeRefMut::Inner(inner_ref)) => Some(inner_ref),
            _ => None,
        }
    }

    #[inline]
    pub fn earliest_expiry(&self) -> u64 {
        match self.case().unwrap() {
            NodeRef::Inner(inner) => inner.earliest_expiry(),
            NodeRef::Leaf(leaf) => leaf.expiry(),
        }
    }
}

impl AsRef<AnyNode> for InnerNode {
    fn as_ref(&self) -> &AnyNode {
        cast_ref(self)
    }
}

impl AsRef<AnyNode> for LeafNode {
    #[inline]
    fn as_ref(&self) -> &AnyNode {
        cast_ref(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn order_tree_price_data() {
        for price in [1, 42, i64::MAX] {
            assert_eq!(price, fixed_price_lots(fixed_price_data(price).unwrap()));
        }

        let seq = [-i64::MAX, -i64::MAX + 1, 0, i64::MAX - 1, i64::MAX];
        for price_offset in seq {
            assert_eq!(
                price_offset,
                oracle_pegged_price_offset(oracle_pegged_price_data(price_offset))
            );
        }
        for (lhs, rhs) in seq.iter().tuple_windows() {
            let l_price_data = oracle_pegged_price_data(*lhs);
            let r_price_data = oracle_pegged_price_data(*rhs);
            assert!(l_price_data < r_price_data);
        }

        assert_eq!(oracle_pegged_price_data(i64::MIN), 0);
        assert_eq!(oracle_pegged_price_data(i64::MAX), u64::MAX);
        assert_eq!(oracle_pegged_price_data(0), -(i64::MIN as i128) as u64); // remember -i64::MIN is not a valid i64
    }

    #[test]
    fn order_tree_key_ordering() {
        let bid_seq: Vec<(i64, u64)> = vec![
            (-5, 15),
            (-5, 10),
            (-4, 6),
            (-4, 5),
            (0, 20),
            (0, 1),
            (4, 6),
            (4, 5),
            (5, 3),
        ];
        for (lhs, rhs) in bid_seq.iter().tuple_windows() {
            let l_price_data = oracle_pegged_price_data(lhs.0);
            let r_price_data = oracle_pegged_price_data(rhs.0);
            let l_key = new_node_key(Side::Bid, l_price_data, lhs.1);
            let r_key = new_node_key(Side::Bid, r_price_data, rhs.1);
            assert!(l_key < r_key);
        }

        let ask_seq: Vec<(i64, u64)> = vec![
            (-5, 10),
            (-5, 15),
            (-4, 6),
            (-4, 7),
            (0, 1),
            (0, 20),
            (4, 5),
            (4, 6),
            (5, 3),
        ];
        for (lhs, rhs) in ask_seq.iter().tuple_windows() {
            let l_price_data = oracle_pegged_price_data(lhs.0);
            let r_price_data = oracle_pegged_price_data(rhs.0);
            let l_key = new_node_key(Side::Ask, l_price_data, lhs.1);
            let r_key = new_node_key(Side::Ask, r_price_data, rhs.1);
            assert!(l_key < r_key);
        }
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/order.rs
use anchor_lang::prelude::*;

use super::*;
use crate::error::*;

///  order parameters
pub struct Order {
    pub side: Side,

    /// Max base lots to buy/sell.
    pub max_base_lots: i64,

    /// Max quote lots to pay/receive including fees.
    pub max_quote_lots_including_fees: i64,

    /// Arbitrary user-controlled order id.
    pub client_order_id: u64,

    /// Number of seconds the order shall live, 0 meaning forever
    pub time_in_force: u16,

    /// Configure how matches with order of the same owner are handled
    pub self_trade_behavior: SelfTradeBehavior,

    /// Order type specific params
    pub params: OrderParams,
}

pub enum OrderParams {
    Market,
    ImmediateOrCancel {
        price_lots: i64,
    },
    Fixed {
        price_lots: i64,
        order_type: PostOrderType,
    },
    OraclePegged {
        price_offset_lots: i64,
        order_type: PostOrderType,
        peg_limit: i64,
    },
    FillOrKill {
        price_lots: i64,
    },
}

impl Order {
    /// Convert an input expiry timestamp to a time_in_force value
    pub fn tif_from_expiry(expiry_timestamp: u64) -> Option<u16> {
        let now_ts: u64 = Clock::get().unwrap().unix_timestamp.try_into().unwrap();
        if expiry_timestamp != 0 {
            // If expiry is far in the future, clamp to u16::MAX seconds
            let tif = expiry_timestamp.saturating_sub(now_ts).min(u16::MAX.into());
            if tif == 0 {
                // If expiry is in the past, ignore the order
                return None;
            }
            Some(tif as u16)
        } else {
            // Never expire
            Some(0)
        }
    }

    /// Is this order required to be posted to the orderbook? It will fail if it would take.
    pub fn is_post_only(&self) -> bool {
        let order_type = match self.params {
            OrderParams::Fixed { order_type, .. } => order_type,
            OrderParams::OraclePegged { order_type, .. } => order_type,
            _ => return false,
        };
        order_type == PostOrderType::PostOnly || order_type == PostOrderType::PostOnlySlide
    }

    /// Is this order required to be executed completely? It will fail if it would do a partial execution.
    pub fn is_fill_or_kill(&self) -> bool {
        matches!(self.params, OrderParams::FillOrKill { .. })
    }

    /// Order tree that this order should be added to
    pub fn post_target(&self) -> Option<BookSideOrderTree> {
        match self.params {
            OrderParams::Fixed { .. } => Some(BookSideOrderTree::Fixed),
            OrderParams::OraclePegged { .. } => Some(BookSideOrderTree::OraclePegged),
            _ => None,
        }
    }

    /// Some order types (PostOnlySlide) may override the price that is passed in,
    /// this function computes the order-type-adjusted price.
    fn price_for_order_type(
        &self,
        now_ts: u64,
        oracle_price_lots: Option<i64>,
        price_lots: i64,
        order_type: PostOrderType,
        order_book: &Orderbook,
    ) -> i64 {
        if order_type == PostOrderType::PostOnlySlide {
            if let Some(best_other_price) = order_book
                .bookside(self.side.invert_side())
                .best_price(now_ts, oracle_price_lots)
            {
                post_only_slide_limit(self.side, best_other_price, price_lots)
            } else {
                price_lots
            }
        } else {
            price_lots
        }
    }

    /// Compute the price_lots this order is currently at, as well as the price_data that
    /// would be stored in its OrderTree node if the order is posted to the orderbook.
    /// Will fail for oracle peg if there is no oracle price passed.
    pub fn price(
        &self,
        now_ts: u64,
        oracle_price_lots: Option<i64>,
        order_book: &Orderbook,
    ) -> Result<(i64, u64)> {
        let price_lots = match self.params {
            OrderParams::Market => market_order_limit_for_side(self.side),
            OrderParams::ImmediateOrCancel { price_lots } => price_lots,
            OrderParams::FillOrKill { price_lots } => price_lots,
            OrderParams::Fixed {
                price_lots,
                order_type,
            } => self.price_for_order_type(
                now_ts,
                oracle_price_lots,
                price_lots,
                order_type,
                order_book,
            ),
            OrderParams::OraclePegged {
                price_offset_lots,
                order_type,
                ..
            } => {
                let price_lots = oracle_price_lots
                    .ok_or(OpenBookError::OraclePegInvalidOracleState)?
                    .checked_add(price_offset_lots)
                    .ok_or(OpenBookError::InvalidPriceLots)?;

                self.price_for_order_type(
                    now_ts,
                    oracle_price_lots,
                    price_lots,
                    order_type,
                    order_book,
                )
            }
        };
        require_gte!(price_lots, 1, OpenBookError::InvalidPriceLots);
        let price_data = match self.params {
            OrderParams::OraclePegged { .. } => {
                // unwrap cannot fail (already handled above)
                oracle_pegged_price_data(price_lots - oracle_price_lots.unwrap())
            }
            _ => fixed_price_data(price_lots)?,
        };
        Ok((price_lots, price_data))
    }

    /// pegging limit for oracle peg orders, otherwise -1
    pub fn peg_limit(&self) -> i64 {
        match self.params {
            OrderParams::OraclePegged { peg_limit, .. } => peg_limit,
            _ => -1,
        }
    }
}

/// The implicit limit price to use for market orders
fn market_order_limit_for_side(side: Side) -> i64 {
    match side {
        Side::Bid => i64::MAX,
        Side::Ask => 1,
    }
}

/// The limit to use for PostOnlySlide orders: the tinyest bit better than
/// the best opposing order
fn post_only_slide_limit(side: Side, best_other_side: i64, limit: i64) -> i64 {
    match side {
        Side::Bid => limit.min(best_other_side - 1),
        Side::Ask => limit.max(best_other_side + 1),
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/order_type.rs
use anchor_lang::prelude::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::*;
use crate::error::*;

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum PlaceOrderType {
    /// Take existing orders up to price, max_base_quantity and max_quote_quantity.
    /// If any base_quantity or quote_quantity remains, place an order on the book
    Limit = 0,

    /// Take existing orders up to price, max_base_quantity and max_quote_quantity.
    /// Never place an order on the book.
    ImmediateOrCancel = 1,

    /// Never take any existing orders, post the order on the book if possible.
    /// If existing orders can match with this order, do nothing.
    PostOnly = 2,

    /// Ignore price and take orders up to max_base_quantity and max_quote_quantity.
    /// Never place an order on the book.
    ///
    /// Equivalent to ImmediateOrCancel with price=i64::MAX.
    Market = 3,

    /// If existing orders match with this order, adjust the price to just barely
    /// not match. Always places an order on the book.
    PostOnlySlide = 4,

    /// Take existing orders up to price, max_base_quantity and max_quote_quantity.
    /// Abort if partially executed, never place an order on the book.
    FillOrKill = 5,
}

impl PlaceOrderType {
    pub fn to_post_order_type(&self) -> Result<PostOrderType> {
        match *self {
            Self::Market => Err(OpenBookError::InvalidOrderPostMarket.into()),
            Self::ImmediateOrCancel => Err(OpenBookError::InvalidOrderPostIOC.into()),
            Self::FillOrKill => Err(OpenBookError::InvalidOrderPostIOC.into()),
            Self::Limit => Ok(PostOrderType::Limit),
            Self::PostOnly => Ok(PostOrderType::PostOnly),
            Self::PostOnlySlide => Ok(PostOrderType::PostOnlySlide),
        }
    }
}

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[repr(u8)]
pub enum PostOrderType {
    /// Take existing orders up to price, max_base_quantity and max_quote_quantity.
    /// If any base_quantity or quote_quantity remains, place an order on the book
    Limit = 0,

    /// Never take any existing orders, post the order on the book if possible.
    /// If existing orders can match with this order, do nothing.
    PostOnly = 2,

    /// If existing orders match with this order, adjust the price to just barely
    /// not match. Always places an order on the book.
    PostOnlySlide = 4,
}

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    Default,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
/// Self trade behavior controls how taker orders interact with resting limit orders of the same account.
/// This setting has no influence on placing a resting or oracle pegged limit order that does not match
/// immediately, instead it's the responsibility of the user to correctly configure his taker orders.
pub enum SelfTradeBehavior {
    /// Both the maker and taker sides of the matched orders are decremented.
    /// This is equivalent to a normal order match, except for the fact that no fees are applied.
    #[default]
    DecrementTake = 0,

    /// Cancels the maker side of the trade, the taker side gets matched with other maker's orders.
    CancelProvide = 1,

    /// Cancels the whole transaction as soon as a self-matching scenario is encountered.
    AbortTransaction = 2,
}

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum Side {
    Bid = 0,
    Ask = 1,
}

impl Side {
    pub fn invert_side(self: &Side) -> Side {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }

    /// Is `lhs` is a better order for `side` than `rhs`?
    pub fn is_price_data_better(self: &Side, lhs: u64, rhs: u64) -> bool {
        match self {
            Side::Bid => lhs > rhs,
            Side::Ask => lhs < rhs,
        }
    }

    /// Is `lhs` is a better order for `side` than `rhs`?
    pub fn is_price_better(self: &Side, lhs: i64, rhs: i64) -> bool {
        match self {
            Side::Bid => lhs > rhs,
            Side::Ask => lhs < rhs,
        }
    }

    /// Is `price` acceptable for a `limit` order on `side`?
    pub fn is_price_within_limit(self: &Side, price: i64, limit: i64) -> bool {
        match self {
            Side::Bid => price <= limit,
            Side::Ask => price >= limit,
        }
    }
}

/// SideAndOrderTree is a storage optimization, so we don't need two bytes for the data
#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[repr(u8)]
pub enum SideAndOrderTree {
    BidFixed = 0,
    AskFixed = 1,
    BidOraclePegged = 2,
    AskOraclePegged = 3,
}

impl SideAndOrderTree {
    pub fn new(side: Side, order_tree: BookSideOrderTree) -> Self {
        match (side, order_tree) {
            (Side::Bid, BookSideOrderTree::Fixed) => Self::BidFixed,
            (Side::Ask, BookSideOrderTree::Fixed) => Self::AskFixed,
            (Side::Bid, BookSideOrderTree::OraclePegged) => Self::BidOraclePegged,
            (Side::Ask, BookSideOrderTree::OraclePegged) => Self::AskOraclePegged,
        }
    }

    pub fn side(&self) -> Side {
        match self {
            Self::BidFixed | Self::BidOraclePegged => Side::Bid,
            Self::AskFixed | Self::AskOraclePegged => Side::Ask,
        }
    }

    pub fn order_tree(&self) -> BookSideOrderTree {
        match self {
            Self::BidFixed | Self::AskFixed => BookSideOrderTree::Fixed,
            Self::BidOraclePegged | Self::AskOraclePegged => BookSideOrderTree::OraclePegged,
        }
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/ordertree.rs
use anchor_lang::prelude::*;
use bytemuck::{cast, cast_mut, cast_ref};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use static_assertions::const_assert_eq;

use super::*;
use crate::error::OpenBookError;

pub const MAX_ORDERTREE_NODES: usize = 1024;

#[derive(
    Eq,
    PartialEq,
    Copy,
    Clone,
    TryFromPrimitive,
    IntoPrimitive,
    Debug,
    AnchorSerialize,
    AnchorDeserialize,
)]
#[repr(u8)]
pub enum OrderTreeType {
    Bids,
    Asks,
}

impl OrderTreeType {
    pub fn side(&self) -> Side {
        match *self {
            Self::Bids => Side::Bid,
            Self::Asks => Side::Ask,
        }
    }
}

#[zero_copy]
pub struct OrderTreeRoot {
    pub maybe_node: NodeHandle,
    pub leaf_count: u32,
}
const_assert_eq!(std::mem::size_of::<OrderTreeRoot>(), 8);
const_assert_eq!(std::mem::size_of::<OrderTreeRoot>() % 8, 0);

impl OrderTreeRoot {
    pub fn node(&self) -> Option<NodeHandle> {
        if self.leaf_count == 0 {
            None
        } else {
            Some(self.maybe_node)
        }
    }
}

/// A binary tree on AnyNode::key()
///
/// The key encodes the price in the top 64 bits.
#[zero_copy]
pub struct OrderTreeNodes {
    pub order_tree_type: u8, // OrderTreeType, but that's not POD
    pub padding: [u8; 3],
    pub bump_index: u32,
    pub free_list_len: u32,
    pub free_list_head: NodeHandle,
    pub reserved: [u8; 512],
    pub nodes: [AnyNode; MAX_ORDERTREE_NODES],
}
const_assert_eq!(
    std::mem::size_of::<OrderTreeNodes>(),
    1 + 3 + 4 * 2 + 4 + 512 + 88 * 1024
);
const_assert_eq!(std::mem::size_of::<OrderTreeNodes>(), 90640);
const_assert_eq!(std::mem::size_of::<OrderTreeNodes>() % 8, 0);

impl OrderTreeNodes {
    pub fn order_tree_type(&self) -> OrderTreeType {
        OrderTreeType::try_from(self.order_tree_type).unwrap()
    }

    /// Iterate over all entries, including invalid orders
    ///
    /// smallest to highest for asks
    /// highest to smallest for bids
    pub fn iter(&self, root: &OrderTreeRoot) -> OrderTreeIter {
        OrderTreeIter::new(self, root)
    }

    pub fn node_mut(&mut self, handle: NodeHandle) -> Option<&mut AnyNode> {
        let node = &mut self.nodes[handle as usize];
        let tag = NodeTag::try_from(node.tag);
        match tag {
            Ok(NodeTag::InnerNode) | Ok(NodeTag::LeafNode) => Some(node),
            _ => None,
        }
    }
    pub fn node(&self, handle: NodeHandle) -> Option<&AnyNode> {
        let node = &self.nodes[handle as usize];
        let tag = NodeTag::try_from(node.tag);
        match tag {
            Ok(NodeTag::InnerNode) | Ok(NodeTag::LeafNode) => Some(node),
            _ => None,
        }
    }

    pub fn remove_worst(&mut self, root: &mut OrderTreeRoot) -> Option<LeafNode> {
        self.remove_by_key(root, self.find_worst(root)?.1.key)
    }

    pub fn find_worst(&self, root: &OrderTreeRoot) -> Option<(NodeHandle, &LeafNode)> {
        match self.order_tree_type() {
            OrderTreeType::Bids => self.min_leaf(root),
            OrderTreeType::Asks => self.max_leaf(root),
        }
    }

    /// Remove the order with the lowest expiry timestamp, if that's < now_ts.
    pub fn remove_one_expired(
        &mut self,
        root: &mut OrderTreeRoot,
        now_ts: u64,
    ) -> Option<LeafNode> {
        let (handle, expires_at) = self.find_earliest_expiry(root)?;
        if expires_at < now_ts {
            self.remove_by_key(root, self.node(handle)?.key()?)
        } else {
            None
        }
    }

    // only for fixed-price ordertrees
    #[cfg(test)]
    #[allow(dead_code)]
    fn as_price_quantity_vec(&self, root: &OrderTreeRoot, reverse: bool) -> Vec<(i64, i64)> {
        let mut pqs = vec![];
        let mut current: NodeHandle = match root.node() {
            None => return pqs,
            Some(node_handle) => node_handle,
        };

        let left = reverse as usize;
        let right = !reverse as usize;
        let mut stack = vec![];
        loop {
            let root_contents = self.node(current).unwrap(); // should never fail unless book is already fucked
            match root_contents.case().unwrap() {
                NodeRef::Inner(inner) => {
                    stack.push(inner);
                    current = inner.children[left];
                }
                NodeRef::Leaf(leaf) => {
                    // if you hit leaf then pop stack and go right
                    // all inner nodes on stack have already been visited to the left
                    pqs.push((fixed_price_lots(leaf.price_data()), leaf.quantity));
                    match stack.pop() {
                        None => return pqs,
                        Some(inner) => {
                            current = inner.children[right];
                        }
                    }
                }
            }
        }
    }

    pub fn min_leaf(&self, root: &OrderTreeRoot) -> Option<(NodeHandle, &LeafNode)> {
        self.leaf_min_max(false, root)
    }

    pub fn max_leaf(&self, root: &OrderTreeRoot) -> Option<(NodeHandle, &LeafNode)> {
        self.leaf_min_max(true, root)
    }
    fn leaf_min_max(
        &self,
        find_max: bool,
        root: &OrderTreeRoot,
    ) -> Option<(NodeHandle, &LeafNode)> {
        let mut node_handle: NodeHandle = root.node()?;

        let i = usize::from(find_max);
        loop {
            let node_contents = self.node(node_handle)?;
            match node_contents.case()? {
                NodeRef::Inner(inner) => {
                    node_handle = inner.children[i];
                }
                NodeRef::Leaf(leaf) => {
                    return Some((node_handle, leaf));
                }
            }
        }
    }

    pub fn remove_by_key(
        &mut self,
        root: &mut OrderTreeRoot,
        search_key: u128,
    ) -> Option<LeafNode> {
        // path of InnerNode handles that lead to the removed leaf
        let mut stack: Vec<(NodeHandle, bool)> = vec![];

        // special case potentially removing the root
        let mut parent_h = root.node()?;
        let (mut child_h, mut crit_bit) = match self.node(parent_h).unwrap().case().unwrap() {
            NodeRef::Leaf(&leaf) if leaf.key == search_key => {
                assert_eq!(root.leaf_count, 1);
                root.maybe_node = 0;
                root.leaf_count = 0;
                let _old_root = self.remove(parent_h).unwrap();
                return Some(leaf);
            }
            NodeRef::Leaf(_) => return None,
            NodeRef::Inner(inner) => inner.walk_down(search_key),
        };
        stack.push((parent_h, crit_bit));

        // walk down the tree until finding the key
        loop {
            match self.node(child_h).unwrap().case().unwrap() {
                NodeRef::Inner(inner) => {
                    parent_h = child_h;
                    let (new_child_h, new_crit_bit) = inner.walk_down(search_key);
                    child_h = new_child_h;
                    crit_bit = new_crit_bit;
                    stack.push((parent_h, crit_bit));
                }
                NodeRef::Leaf(leaf) => {
                    if leaf.key != search_key {
                        return None;
                    }
                    break;
                }
            }
        }

        // replace parent with its remaining child node
        // free child_h, replace *parent_h with *other_child_h, free other_child_h
        let other_child_h = self.node(parent_h).unwrap().children().unwrap()[!crit_bit as usize];
        let other_child_node_contents = self.remove(other_child_h).unwrap();
        let new_expiry = other_child_node_contents.earliest_expiry();
        *self.node_mut(parent_h).unwrap() = other_child_node_contents;
        root.leaf_count -= 1;
        let removed_leaf: LeafNode = cast(self.remove(child_h).unwrap());

        // update child min expiry back up to the root
        let outdated_expiry = removed_leaf.expiry();
        stack.pop(); // the final parent has been replaced by the remaining leaf
        self.update_parent_earliest_expiry(&stack, outdated_expiry, new_expiry);

        Some(removed_leaf)
    }

    /// Internal: Removes only the node, does not remove any links etc, use remove_key()
    fn remove(&mut self, key: NodeHandle) -> Option<AnyNode> {
        let val = *self.node(key)?;

        self.nodes[key as usize] = cast(FreeNode {
            tag: if self.free_list_len == 0 {
                NodeTag::LastFreeNode.into()
            } else {
                NodeTag::FreeNode.into()
            },
            padding: Default::default(),
            next: self.free_list_head,
            reserved: [0; 72],
            force_align: 0,
        });

        self.free_list_len += 1;
        self.free_list_head = key;
        Some(val)
    }

    /// Internal: Adds only the node, does not add parent links etc, use insert_leaf()
    fn insert(&mut self, val: &AnyNode) -> Result<NodeHandle> {
        match NodeTag::try_from(val.tag) {
            Ok(NodeTag::InnerNode) | Ok(NodeTag::LeafNode) => (),
            _ => unreachable!(),
        };

        if self.free_list_len == 0 {
            require!(
                (self.bump_index as usize) < self.nodes.len() && self.bump_index < u32::MAX,
                OpenBookError::SomeError
            );

            self.nodes[self.bump_index as usize] = *val;
            let key = self.bump_index;
            self.bump_index += 1;
            return Ok(key);
        }

        let key = self.free_list_head;
        let node = &mut self.nodes[key as usize];

        match NodeTag::try_from(node.tag) {
            Ok(NodeTag::FreeNode) => assert!(self.free_list_len > 1),
            Ok(NodeTag::LastFreeNode) => assert_eq!(self.free_list_len, 1),
            _ => unreachable!(),
        };

        self.free_list_head = cast_ref::<AnyNode, FreeNode>(node).next;
        self.free_list_len -= 1;
        *node = *val;
        Ok(key)
    }

    pub fn insert_leaf(
        &mut self,
        root: &mut OrderTreeRoot,
        new_leaf: &LeafNode,
    ) -> Result<(NodeHandle, Option<LeafNode>)> {
        // path of InnerNode handles that lead to the new leaf
        let mut stack: Vec<(NodeHandle, bool)> = vec![];

        // deal with inserts into an empty tree
        let mut parent_handle: NodeHandle = match root.node() {
            Some(h) => h,
            None => {
                // create a new root if none exists
                let handle = self.insert(new_leaf.as_ref())?;
                root.maybe_node = handle;
                root.leaf_count = 1;
                return Ok((handle, None));
            }
        };

        // walk down the tree until we find the insert location
        loop {
            // require if the new node will be a child of the root
            let parent_contents = *self.node(parent_handle).unwrap();
            let parent_key = parent_contents.key().unwrap();
            if parent_key == new_leaf.key {
                // This should never happen because key should never match
                if let Some(NodeRef::Leaf(&old_parent_as_leaf)) = parent_contents.case() {
                    // clobber the existing leaf
                    *self.node_mut(parent_handle).unwrap() = *new_leaf.as_ref();
                    self.update_parent_earliest_expiry(
                        &stack,
                        old_parent_as_leaf.expiry(),
                        new_leaf.expiry(),
                    );
                    return Ok((parent_handle, Some(old_parent_as_leaf)));
                }
                // InnerNodes have a random child's key, so matching can happen and is fine
            }
            let shared_prefix_len: u32 = (parent_key ^ new_leaf.key).leading_zeros();
            match parent_contents.case() {
                None => unreachable!(),
                Some(NodeRef::Inner(inner)) => {
                    let keep_old_parent = shared_prefix_len >= inner.prefix_len;
                    if keep_old_parent {
                        let (child, crit_bit) = inner.walk_down(new_leaf.key);
                        stack.push((parent_handle, crit_bit));
                        parent_handle = child;
                        continue;
                    };
                }
                _ => (),
            };
            // implies parent is a Leaf or Inner where shared_prefix_len < prefix_len
            // we'll replace parent with a new InnerNode that has new_leaf and parent as children

            // change the parent in place to represent the LCA of [new_leaf] and [parent]
            let crit_bit_mask: u128 = 1u128 << (127 - shared_prefix_len);
            let new_leaf_crit_bit = (crit_bit_mask & new_leaf.key) != 0;
            let old_parent_crit_bit = !new_leaf_crit_bit;

            let new_leaf_handle = self.insert(new_leaf.as_ref())?;
            let moved_parent_handle = match self.insert(&parent_contents) {
                Ok(h) => h,
                Err(e) => {
                    self.remove(new_leaf_handle).unwrap();
                    return Err(e);
                }
            };

            let new_parent: &mut InnerNode = cast_mut(self.node_mut(parent_handle).unwrap());
            *new_parent = InnerNode::new(shared_prefix_len, new_leaf.key);

            new_parent.children[new_leaf_crit_bit as usize] = new_leaf_handle;
            new_parent.children[old_parent_crit_bit as usize] = moved_parent_handle;

            let new_leaf_expiry = new_leaf.expiry();
            let old_parent_expiry = parent_contents.earliest_expiry();
            new_parent.child_earliest_expiry[new_leaf_crit_bit as usize] = new_leaf_expiry;
            new_parent.child_earliest_expiry[old_parent_crit_bit as usize] = old_parent_expiry;

            // walk up the stack and fix up the new min if needed
            if new_leaf_expiry < old_parent_expiry {
                self.update_parent_earliest_expiry(&stack, old_parent_expiry, new_leaf_expiry);
            }

            root.leaf_count += 1;
            return Ok((new_leaf_handle, None));
        }
    }

    pub fn is_full(&self) -> bool {
        self.free_list_len <= 1 && (self.bump_index as usize) >= self.nodes.len() - 1
    }

    /// When a node changes, the parents' child_earliest_expiry may need to be updated.
    ///
    /// This function walks up the `stack` of parents and applies the change where the
    /// previous child's `outdated_expiry` is replaced by `new_expiry`.
    pub fn update_parent_earliest_expiry(
        &mut self,
        stack: &[(NodeHandle, bool)],
        mut outdated_expiry: u64,
        mut new_expiry: u64,
    ) {
        // Walk from the top of the stack to the root of the tree.
        // Since the stack grows by appending, we need to iterate the slice in reverse order.
        for (parent_h, crit_bit) in stack.iter().rev() {
            let parent = self.node_mut(*parent_h).unwrap().as_inner_mut().unwrap();
            if parent.child_earliest_expiry[*crit_bit as usize] != outdated_expiry {
                break;
            }
            outdated_expiry = parent.earliest_expiry();
            parent.child_earliest_expiry[*crit_bit as usize] = new_expiry;
            new_expiry = parent.earliest_expiry();
        }
    }

    /// Returns the handle of the node with the lowest expiry timestamp, and this timestamp
    pub fn find_earliest_expiry(&self, root: &OrderTreeRoot) -> Option<(NodeHandle, u64)> {
        let mut current: NodeHandle = match root.node() {
            Some(h) => h,
            None => return None,
        };

        loop {
            let contents = *self.node(current).unwrap();
            match contents.case() {
                None => unreachable!(),
                Some(NodeRef::Inner(inner)) => {
                    current = inner.children[(inner.child_earliest_expiry[0]
                        > inner.child_earliest_expiry[1])
                        as usize];
                }
                _ => {
                    return Some((current, contents.earliest_expiry()));
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use bytemuck::Zeroable;

    fn new_order_tree(order_tree_type: OrderTreeType) -> OrderTreeNodes {
        let mut ot = OrderTreeNodes::zeroed();
        ot.order_tree_type = order_tree_type.into();
        ot
    }

    fn verify_order_tree(order_tree: &OrderTreeNodes, root: &OrderTreeRoot) {
        verify_order_tree_invariant(order_tree, root);
        verify_order_tree_iteration(order_tree, root);
        verify_order_tree_expiry(order_tree, root);
    }

    // check that BookSide binary tree key invariant holds
    fn verify_order_tree_invariant(order_tree: &OrderTreeNodes, root: &OrderTreeRoot) {
        fn recursive_check(order_tree: &OrderTreeNodes, h: NodeHandle) {
            if let NodeRef::Inner(&inner) = order_tree.node(h).unwrap().case().unwrap() {
                let left = order_tree.node(inner.children[0]).unwrap().key().unwrap();
                let right = order_tree.node(inner.children[1]).unwrap().key().unwrap();

                // the left and right keys share the InnerNode's prefix
                assert!((inner.key ^ left).leading_zeros() >= inner.prefix_len);
                assert!((inner.key ^ right).leading_zeros() >= inner.prefix_len);

                // the left and right node key have the critbit unset and set respectively
                let crit_bit_mask: u128 = 1u128 << (127 - inner.prefix_len);
                assert!(left & crit_bit_mask == 0);
                assert!(right & crit_bit_mask != 0);

                recursive_check(order_tree, inner.children[0]);
                recursive_check(order_tree, inner.children[1]);
            }
        }

        if let Some(r) = root.node() {
            recursive_check(order_tree, r);
        }
    }

    // check that iteration of order tree has the right order and misses no leaves
    fn verify_order_tree_iteration(order_tree: &OrderTreeNodes, root: &OrderTreeRoot) {
        let mut total = 0;
        let ascending = order_tree.order_tree_type() == OrderTreeType::Asks;
        let mut last_key = if ascending { 0 } else { u128::MAX };
        for (_, node) in order_tree.iter(root) {
            let key = node.key;
            if ascending {
                assert!(key >= last_key);
            } else {
                assert!(key <= last_key);
            }
            last_key = key;
            total += 1;
        }
        assert_eq!(root.leaf_count, total);
    }

    // check that BookSide::child_expiry invariant holds
    fn verify_order_tree_expiry(order_tree: &OrderTreeNodes, root: &OrderTreeRoot) {
        fn recursive_check(order_tree: &OrderTreeNodes, h: NodeHandle) {
            if let NodeRef::Inner(&inner) = order_tree.node(h).unwrap().case().unwrap() {
                let left = order_tree
                    .node(inner.children[0])
                    .unwrap()
                    .earliest_expiry();
                let right = order_tree
                    .node(inner.children[1])
                    .unwrap()
                    .earliest_expiry();

                // child_expiry must hold the expiry of the children
                assert_eq!(inner.child_earliest_expiry[0], left);
                assert_eq!(inner.child_earliest_expiry[1], right);

                recursive_check(order_tree, inner.children[0]);
                recursive_check(order_tree, inner.children[1]);
            }
        }
        if let Some(r) = root.node() {
            recursive_check(order_tree, r);
        }
    }

    #[test]
    fn order_tree_expiry_manual() {
        let mut bids = new_order_tree(OrderTreeType::Bids);
        let new_expiring_leaf = |key: u128, expiry: u64| {
            LeafNode::new(0, key, Pubkey::default(), 0, expiry - 1, 1, -1, 0)
        };

        let mut root = OrderTreeRoot::zeroed();

        assert!(bids.find_earliest_expiry(&root).is_none());

        bids.insert_leaf(&mut root, &new_expiring_leaf(0, 5000))
            .unwrap();
        assert_eq!(
            bids.find_earliest_expiry(&root).unwrap(),
            (root.maybe_node, 5000)
        );
        verify_order_tree(&bids, &root);

        let (new4000_h, _) = bids
            .insert_leaf(&mut root, &new_expiring_leaf(1, 4000))
            .unwrap();
        assert_eq!(bids.find_earliest_expiry(&root).unwrap(), (new4000_h, 4000));
        verify_order_tree(&bids, &root);

        let (_new4500_h, _) = bids
            .insert_leaf(&mut root, &new_expiring_leaf(2, 4500))
            .unwrap();
        assert_eq!(bids.find_earliest_expiry(&root).unwrap(), (new4000_h, 4000));
        verify_order_tree(&bids, &root);

        let (new3500_h, _) = bids
            .insert_leaf(&mut root, &new_expiring_leaf(3, 3500))
            .unwrap();
        assert_eq!(bids.find_earliest_expiry(&root).unwrap(), (new3500_h, 3500));
        verify_order_tree(&bids, &root);
        // the first two levels of the tree are innernodes, with 0;1 on one side and 2;3 on the other
        assert_eq!(
            bids.node_mut(root.maybe_node)
                .unwrap()
                .as_inner_mut()
                .unwrap()
                .child_earliest_expiry,
            [4000, 3500]
        );

        bids.remove_by_key(&mut root, 3).unwrap();
        verify_order_tree(&bids, &root);
        assert_eq!(
            bids.node_mut(root.maybe_node)
                .unwrap()
                .as_inner_mut()
                .unwrap()
                .child_earliest_expiry,
            [4000, 4500]
        );
        assert_eq!(bids.find_earliest_expiry(&root).unwrap().1, 4000);

        bids.remove_by_key(&mut root, 0).unwrap();
        verify_order_tree(&bids, &root);
        assert_eq!(
            bids.node_mut(root.maybe_node)
                .unwrap()
                .as_inner_mut()
                .unwrap()
                .child_earliest_expiry,
            [4000, 4500]
        );
        assert_eq!(bids.find_earliest_expiry(&root).unwrap().1, 4000);

        bids.remove_by_key(&mut root, 1).unwrap();
        verify_order_tree(&bids, &root);
        assert_eq!(bids.find_earliest_expiry(&root).unwrap().1, 4500);

        bids.remove_by_key(&mut root, 2).unwrap();
        verify_order_tree(&bids, &root);
        assert!(bids.find_earliest_expiry(&root).is_none());
    }

    #[test]
    fn order_tree_expiry_random() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut root = OrderTreeRoot::zeroed();
        let mut bids = new_order_tree(OrderTreeType::Bids);
        let new_expiring_leaf = |key: u128, expiry: u64| {
            LeafNode::new(0, key, Pubkey::default(), 0, expiry - 1, 1, -1, 0)
        };

        // add 200 random leaves
        let mut keys = vec![];
        for _ in 0..200 {
            let key: u128 = rng.gen_range(0..10000); // overlap in key bits
            if keys.contains(&key) {
                continue;
            }
            let expiry = rng.gen_range(1..200); // give good chance of duplicate expiry times
            keys.push(key);
            bids.insert_leaf(&mut root, &new_expiring_leaf(key, expiry))
                .unwrap();
            verify_order_tree(&bids, &root);
        }

        // remove 50 at random
        for _ in 0..50 {
            if keys.is_empty() {
                break;
            }
            let k = keys[rng.gen_range(0..keys.len())];
            bids.remove_by_key(&mut root, k).unwrap();
            keys.retain(|v| *v != k);
            verify_order_tree(&bids, &root);
        }
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/orderbook/ordertree_iterator.rs
use super::*;

/// Iterate over orders in order (bids=descending, asks=ascending)
pub struct OrderTreeIter<'a> {
    order_tree: &'a OrderTreeNodes,
    /// InnerNodes where the right side still needs to be iterated on
    stack: Vec<&'a InnerNode>,
    /// To be returned on `next()`
    next_leaf: Option<(NodeHandle, &'a LeafNode)>,

    /// either 0, 1 to iterate low-to-high, or 1, 0 to iterate high-to-low
    left: usize,
    right: usize,
}

impl<'a> OrderTreeIter<'a> {
    pub fn new(order_tree: &'a OrderTreeNodes, root: &OrderTreeRoot) -> Self {
        let (left, right) = if order_tree.order_tree_type() == OrderTreeType::Bids {
            (1, 0)
        } else {
            (0, 1)
        };
        let stack = vec![];

        let mut iter = Self {
            order_tree,
            stack,
            next_leaf: None,
            left,
            right,
        };
        if let Some(r) = root.node() {
            iter.next_leaf = iter.find_leftmost_leaf(r);
        }
        iter
    }

    pub fn side(&self) -> Side {
        if self.left == 1 {
            Side::Bid
        } else {
            Side::Ask
        }
    }

    pub fn peek(&self) -> Option<(NodeHandle, &'a LeafNode)> {
        self.next_leaf
    }

    fn find_leftmost_leaf(&mut self, start: NodeHandle) -> Option<(NodeHandle, &'a LeafNode)> {
        let mut current = start;
        loop {
            match self.order_tree.node(current).unwrap().case().unwrap() {
                NodeRef::Inner(inner) => {
                    self.stack.push(inner);
                    current = inner.children[self.left];
                }
                NodeRef::Leaf(leaf) => {
                    return Some((current, leaf));
                }
            }
        }
    }
}

impl<'a> Iterator for OrderTreeIter<'a> {
    type Item = (NodeHandle, &'a LeafNode);

    fn next(&mut self) -> Option<Self::Item> {
        // no next leaf? done
        self.next_leaf?;

        // start popping from stack and get the other child
        let current_leaf = self.next_leaf;
        self.next_leaf = match self.stack.pop() {
            None => None,
            Some(inner) => {
                let start = inner.children[self.right];
                // go down the left branch as much as possible until reaching a leaf
                self.find_leftmost_leaf(start)
            }
        };

        current_leaf
    }
}


// File: openbook-v2/programs/openbook-v2/src/state/raydium_internal.rs
use anchor_lang::{account, declare_id, zero_copy};
use solana_program::pubkey::Pubkey;

#[cfg(feature = "devnet")]
declare_id!("devi51mZmdwUJGU9hjN27vEz64Gps7uUefqxg27EAtH");
#[cfg(not(feature = "devnet"))]
declare_id!("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK");

pub const REWARD_NUM: usize = 3;

/// The pool state
///
/// PDA of `[POOL_SEED, config, token_mint_0, token_mint_1]`
///
#[account(zero_copy(unsafe))]
#[repr(packed)]
#[derive(Default, Debug)]
pub struct PoolState {
    /// Bump to identify PDA
    pub bump: [u8; 1],
    // Which config the pool belongs
    pub amm_config: Pubkey,
    // Pool creator
    pub owner: Pubkey,

    /// Token pair of the pool, where token_mint_0 address < token_mint_1 address
    pub token_mint_0: Pubkey,
    pub token_mint_1: Pubkey,

    /// Token pair vault
    pub token_vault_0: Pubkey,
    pub token_vault_1: Pubkey,

    /// observation account key
    pub observation_key: Pubkey,

    /// mint0 and mint1 decimals
    pub mint_decimals_0: u8,
    pub mint_decimals_1: u8,

    /// The minimum number of ticks between initialized ticks
    pub tick_spacing: u16,
    /// The currently in range liquidity available to the pool.
    pub liquidity: u128,
    /// The current price of the pool as a sqrt(token_1/token_0) Q64.64 value
    pub sqrt_price_x64: u128,
    /// The current tick of the pool, i.e. according to the last tick transition that was run.
    pub tick_current: i32,

    /// the most-recently updated index of the observations array
    pub observation_index: u16,
    pub observation_update_duration: u16,

    /// The fee growth as a Q64.64 number, i.e. fees of token_0 and token_1 collected per
    /// unit of liquidity for the entire life of the pool.
    pub fee_growth_global_0_x64: u128,
    pub fee_growth_global_1_x64: u128,

    /// The amounts of token_0 and token_1 that are owed to the protocol.
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,

    /// The amounts in and out of swap token_0 and token_1
    pub swap_in_amount_token_0: u128,
    pub swap_out_amount_token_1: u128,
    pub swap_in_amount_token_1: u128,
    pub swap_out_amount_token_0: u128,

    /// Bitwise representation of the state of the pool
    /// bit0, 1: disable open position and increase liquidity, 0: normal
    /// bit1, 1: disable decrease liquidity, 0: normal
    /// bit2, 1: disable collect fee, 0: normal
    /// bit3, 1: disable collect reward, 0: normal
    /// bit4, 1: disable swap, 0: normal
    pub status: u8,
    /// Leave blank for future use
    pub padding: [u8; 7],

    pub reward_infos: [RewardInfo; REWARD_NUM],

    /// Packed initialized tick array state
    pub tick_array_bitmap: [u64; 16],

    /// except protocol_fee and fund_fee
    pub total_fees_token_0: u64,
    /// except protocol_fee and fund_fee
    pub total_fees_claimed_token_0: u64,
    pub total_fees_token_1: u64,
    pub total_fees_claimed_token_1: u64,

    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,

    // The timestamp allowed for swap in the pool.
    pub open_time: u64,

    // Unused bytes for future upgrades.
    pub padding1: [u64; 25],
    pub padding2: [u64; 32],
}

#[zero_copy(unsafe)]
#[repr(packed)]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RewardInfo {
    /// Reward state
    pub reward_state: u8,
    /// Reward open time
    pub open_time: u64,
    /// Reward end time
    pub end_time: u64,
    /// Reward last update time
    pub last_update_time: u64,
    /// Q64.64 number indicates how many tokens per second are earned per unit of liquidity.
    pub emissions_per_second_x64: u128,
    /// The total amount of reward emissioned
    pub reward_total_emissioned: u64,
    /// The total amount of claimed reward
    pub reward_claimed: u64,
    /// Reward token mint.
    pub token_mint: Pubkey,
    /// Reward vault token account.
    pub token_vault: Pubkey,
    /// The owner that has permission to set reward param
    pub authority: Pubkey,
    /// Q64.64 number that tracks the total tokens earned per unit of liquidity since the reward
    /// emissions were turned on.
    pub reward_growth_global_x64: u128,
}


// File: openbook-v2/programs/openbook-v2/src/token_utils.rs
use super::*;
use anchor_lang::system_program;
use anchor_spl::token;

pub fn token_transfer<
    'info,
    P: ToAccountInfo<'info>,
    A: ToAccountInfo<'info>,
    S: ToAccountInfo<'info>,
>(
    amount: u64,
    token_program: &P,
    from: &A,
    to: &A,
    authority: &S,
) -> Result<()> {
    if amount > 0 {
        token::transfer(
            CpiContext::new(
                token_program.to_account_info(),
                token::Transfer {
                    from: from.to_account_info(),
                    to: to.to_account_info(),
                    authority: authority.to_account_info(),
                },
            ),
            amount,
        )
    } else {
        Ok(())
    }
}

pub fn token_transfer_signed<
    'info,
    P: ToAccountInfo<'info>,
    A: ToAccountInfo<'info>,
    L: ToAccountInfo<'info>,
>(
    amount: u64,
    token_program: &P,
    from: &A,
    to: &A,
    authority: &L,
    seeds: &[&[u8]],
) -> Result<()> {
    if amount > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                token_program.to_account_info(),
                token::Transfer {
                    from: from.to_account_info(),
                    to: to.to_account_info(),
                    authority: authority.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    } else {
        Ok(())
    }
}

pub fn system_program_transfer<
    'info,
    S: ToAccountInfo<'info>,
    A: ToAccountInfo<'info>,
    L: ToAccountInfo<'info>,
>(
    amount: u64,
    system_program: &S,
    from: &A,
    to: &L,
) -> Result<()> {
    if amount > 0 {
        system_program::transfer(
            CpiContext::new(
                system_program.to_account_info(),
                system_program::Transfer {
                    from: from.to_account_info(),
                    to: to.to_account_info(),
                },
            ),
            amount,
        )
    } else {
        Ok(())
    }
}


// File: openbook-v2/programs/openbook-v2/src/types.rs
use anchor_lang::prelude::*;
/// Nothing in Rust shall use these types. They only exist so that the Anchor IDL
/// knows about them and typescript can deserialize it.

#[derive(AnchorSerialize, AnchorDeserialize, Default)]
pub struct I80F48 {
    val: i128,
}


// File: openbook-v2/programs/openbook-v2/src/util.rs
use crate::error::OpenBookError;
use anchor_lang::prelude::*;

pub fn fill_from_str<const N: usize>(name: &str) -> Result<[u8; N]> {
    let name_bytes = name.as_bytes();
    require!(name_bytes.len() <= N, OpenBookError::InvalidInputNameLength);
    let mut name_ = [0u8; N];
    name_[..name_bytes.len()].copy_from_slice(name_bytes);
    Ok(name_)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_from_str() {
        assert_eq!(fill_from_str::<4>(""), Ok([0, 0, 0, 0]));
        assert_eq!(fill_from_str::<4>("abc"), Ok([b'a', b'b', b'c', 0]));
        assert_eq!(fill_from_str::<4>("abcd"), Ok([b'a', b'b', b'c', b'd']));
        assert!(fill_from_str::<4>("abcde").is_err());
    }
}


// File: openbook-v2/programs/openbook-v2/tests/cases/mod.rs
pub use anchor_lang::prelude::Pubkey;
pub use anchor_spl::token::TokenAccount;
pub use fixed::types::I80F48;
pub use solana_program_test::*;
pub use solana_sdk::transport::TransportError;

pub use openbook_v2::{error::OpenBookError, state::*};
pub use program_test::*;
pub use setup::*;

pub use super::program_test;

pub use utils::assert_equal_fixed_f64 as assert_equal;

mod test;
mod test_crank;
mod test_create_market;
mod test_edit_order;
mod test_fees;
mod test_fill_or_kill_order;
mod test_indexer;
mod test_multiple_orders;
mod test_oracle_peg;
mod test_order_types;
mod test_permissioned;
mod test_place_order_remaining;
mod test_self_trade;
mod test_take_order;


// File: openbook-v2/programs/openbook-v2/tests/cases/test.rs
use super::*;

#[tokio::test]
async fn test_simple_settle() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        payer,
        mints,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        close_market_admin_bool: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    //
    // TEST: Create another market
    //

    let market_2 = TestKeypair::new();

    send_tx(
        solana,
        CreateMarketInstruction {
            collect_fee_admin: collect_fee_admin.pubkey(),
            open_orders_admin: None,
            close_market_admin: None,
            payer,
            market: market_2,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, None, None).await
        },
    )
    .await
    .unwrap();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 20);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_delegate_settle() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        payer,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        close_market_admin_bool: true,
        payer_as_delegate: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();
    let payer_token_0 = context.users[1].token_accounts[0];
    let payer_token_1 = context.users[1].token_accounts[1];

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    // delegate settle to own account fails
    assert!(send_tx(
        solana,
        SettleFundsInstruction {
            owner: payer,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: payer_token_0,
            user_quote_account: payer_token_1,
            referrer_account: None,
        },
    )
    .await
    .is_err());

    // delegate settle to owner succeeds
    send_tx(
        solana,
        SettleFundsInstruction {
            owner: payer,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    // owner settle to payer account succeeds
    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: payer_token_0,
            user_quote_account: payer_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_cancel_orders() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -100,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 10);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        DepositInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            base_amount: 10000,
            quote_amount: 0,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(open_orders_account_1.position.base_free_native, 10100);
        assert_eq!(open_orders_account_1.position.quote_free_native, 10);
    }

    let balance = solana.token_account_balance(owner_token_0).await;

    // Assets should be free, let's post the opposite orders
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        assert_eq!(balance, solana.token_account_balance(owner_token_0).await);
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 10000);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 10);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    let order_id_to_cancel = solana
        .get_account::<OpenOrdersAccount>(account_1)
        .await
        .open_orders[0]
        .id;

    send_tx(
        solana,
        CancelOrderInstruction {
            signer: owner,
            market,
            open_orders_account: account_1,
            order_id: order_id_to_cancel,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    // Post and cancel Bid
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    let order_id_to_cancel = solana
        .get_account::<OpenOrdersAccount>(account_1)
        .await
        .open_orders[0]
        .id;

    send_tx(
        solana,
        CancelOrderInstruction {
            signer: owner,
            market,
            open_orders_account: account_1,
            order_id: order_id_to_cancel,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_1.position.quote_free_native, 100000);
    }

    Ok(())
}

#[tokio::test]
async fn test_expired_orders() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Order with expiry time of 2s
    let now_ts: u64 = solana.get_clock().await.unix_timestamp as u64;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: now_ts + 2,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    // Advance clock
    solana.advance_clock(2).await;
    // Bid isn't available anymore, shouldn't be matched. Introduces event on the event_heap
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    {
        let market_acc = solana.get_account_boxed::<Market>(market).await;
        let event_heap = solana
            .get_account_boxed::<EventHeap>(market_acc.event_heap)
            .await;
        assert_eq!(event_heap.header.count(), 1);
    }
    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    // ConsumeEvents removes the bids_base_lots in the Out event
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();
    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 100000);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }
    // No more events on event_heap
    {
        let market_acc = solana.get_account::<Market>(market).await;
        let event_heap = solana.get_account::<EventHeap>(market_acc.event_heap).await;

        assert_eq!(event_heap.header.count(), 0);
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_crank.rs
use super::*;
use bytemuck::cast_ref;

#[tokio::test]
async fn test_skip_missing_accounts() -> Result<(), TransportError> {
    let context = TestContext::new().await;
    let solana = &context.solana.clone();

    let collect_fee_admin = TestKeypair::new();
    let close_market_admin = TestKeypair::new();
    let owner = context.users[0].key;
    let payer = context.users[1].key;
    let mints = &context.mints[0..=2];

    let owner_token_0 = context.users[0].token_accounts[0];
    let owner_token_1 = context.users[0].token_accounts[1];

    let tokens = Token::create(mints.to_vec(), solana, collect_fee_admin, payer).await;

    let market = TestKeypair::new();

    let openbook_v2::accounts::CreateMarket {
        market,
        market_base_vault,
        market_quote_vault,
        event_heap,
        ..
    } = send_tx(
        solana,
        CreateMarketInstruction {
            collect_fee_admin: collect_fee_admin.pubkey(),
            open_orders_admin: None,
            close_market_admin: Some(close_market_admin.pubkey()),
            payer,
            market,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(tokens[1].oracle), None)
                .await
        },
    )
    .await
    .unwrap();

    let price_lots = {
        let market = solana.get_account::<Market>(market).await;
        market.native_price_to_lot(I80F48::ONE).unwrap()
    };

    let _indexer = create_open_orders_indexer(solana, &context.users[1], owner, market).await;
    let (maker_1, maker_2, maker_3) = {
        (
            create_open_orders_account(solana, owner, market, 1, &context.users[1], None).await,
            create_open_orders_account(solana, owner, market, 2, &context.users[1], None).await,
            create_open_orders_account(solana, owner, market, 3, &context.users[1], None).await,
        )
    };
    let taker = create_open_orders_account(solana, owner, market, 4, &context.users[1], None).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 2,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_3,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 3,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: taker,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 3,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let event_heap = solana.get_account_boxed::<EventHeap>(event_heap).await;
        assert_eq!(event_heap.header.count(), 3);
        assert_eq!(fill_maker(event_heap.at_slot(0).unwrap()), maker_1);
        assert_eq!(fill_maker(event_heap.at_slot(1).unwrap()), maker_2);
        assert_eq!(fill_maker(event_heap.at_slot(2).unwrap()), maker_3);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![maker_2, maker_3],
        },
    )
    .await
    .unwrap();

    {
        let event_heap = solana.get_account_boxed::<EventHeap>(event_heap).await;
        assert_eq!(event_heap.header.count(), 1);
        assert_eq!(fill_maker(event_heap.front().unwrap()), maker_1);
    }

    Ok(())
}

#[tokio::test]
async fn test_crank_given_events() -> Result<(), TransportError> {
    let context = TestContext::new().await;
    let solana = &context.solana.clone();

    let collect_fee_admin = TestKeypair::new();
    let close_market_admin = TestKeypair::new();
    let owner = context.users[0].key;
    let payer = context.users[1].key;
    let mints = &context.mints[0..=2];

    let owner_token_0 = context.users[0].token_accounts[0];
    let owner_token_1 = context.users[0].token_accounts[1];

    let tokens = Token::create(mints.to_vec(), solana, collect_fee_admin, payer).await;

    let market = TestKeypair::new();

    let openbook_v2::accounts::CreateMarket {
        market,
        market_base_vault,
        market_quote_vault,
        event_heap,
        ..
    } = send_tx(
        solana,
        CreateMarketInstruction {
            collect_fee_admin: collect_fee_admin.pubkey(),
            open_orders_admin: None,
            close_market_admin: Some(close_market_admin.pubkey()),
            payer,
            market,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(tokens[0].oracle), None)
                .await
        },
    )
    .await
    .unwrap();

    let price_lots = {
        let market = solana.get_account::<Market>(market).await;
        market.native_price_to_lot(I80F48::ONE).unwrap()
    };

    let _indexer = create_open_orders_indexer(solana, &context.users[1], owner, market).await;
    let (maker_1, maker_2, maker_3) = {
        (
            create_open_orders_account(solana, owner, market, 1, &context.users[1], None).await,
            create_open_orders_account(solana, owner, market, 2, &context.users[1], None).await,
            create_open_orders_account(solana, owner, market, 3, &context.users[1], None).await,
        )
    };
    let taker = create_open_orders_account(solana, owner, market, 4, &context.users[1], None).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 2,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: maker_3,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 3,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: taker,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 3,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let event_heap = solana.get_account_boxed::<EventHeap>(event_heap).await;
        assert_eq!(event_heap.header.count(), 3);
        assert_eq!(fill_maker(event_heap.at_slot(0).unwrap()), maker_1);
        assert_eq!(fill_maker(event_heap.at_slot(1).unwrap()), maker_2);
        assert_eq!(fill_maker(event_heap.at_slot(2).unwrap()), maker_3);
    }

    send_tx(
        solana,
        ConsumeGivenEventsInstruction {
            consume_events_admin: None,
            market,
            slots: vec![2, 0],
            open_orders_accounts: vec![maker_1, maker_3],
        },
    )
    .await
    .unwrap();

    {
        let event_heap = solana.get_account_boxed::<EventHeap>(event_heap).await;
        assert_eq!(event_heap.header.count(), 1);
        assert_eq!(fill_maker(event_heap.front().unwrap()), maker_2);
    }

    // is not possible to process slots > limit
    assert!(send_tx(
        solana,
        ConsumeGivenEventsInstruction {
            consume_events_admin: None,
            market,
            slots: vec![openbook_v2::state::MAX_NUM_EVENTS.into()],
            open_orders_accounts: vec![maker_2],
        },
    )
    .await
    .is_err());

    // but if non-valid free slots are sent, the crank is performed from the front
    send_tx(
        solana,
        ConsumeGivenEventsInstruction {
            consume_events_admin: None,
            market,
            slots: vec![100, 100, 200],
            open_orders_accounts: vec![maker_2],
        },
    )
    .await
    .unwrap();

    {
        let event_heap = solana.get_account_boxed::<EventHeap>(event_heap).await;
        assert_eq!(event_heap.header.count(), 0);
    }

    Ok(())
}

fn fill_maker(anyevent: &AnyEvent) -> Pubkey {
    let event: &FillEvent = cast_ref(anyevent);
    event.maker
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_create_market.rs
use super::*;

#[tokio::test]
async fn test_with_single_oracle() -> Result<(), TransportError> {
    let context = TestContextBuilder::new().start_default().await;
    let solana = &context.solana.clone();

    let payer = context.users[0].key;
    let mints = &context.mints[0..=2];
    let tokens = Token::create(mints.to_vec(), solana, payer, payer).await;

    let market_a = TestKeypair::new();
    let market_b = TestKeypair::new();

    assert!(send_tx(
        solana,
        CreateMarketInstruction {
            payer,
            market: market_a,
            quote_lot_size: 100,
            base_lot_size: 100,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(tokens[0].oracle), None,)
                .await
        },
    )
    .await
    .is_ok());

    assert_eq!(
        send_tx_and_get_ix_custom_error(
            solana,
            CreateMarketInstruction {
                payer,
                market: market_b,
                quote_lot_size: 100,
                base_lot_size: 100,
                base_mint: mints[0].pubkey,
                quote_mint: mints[1].pubkey,
                ..CreateMarketInstruction::with_new_book_and_heap(
                    solana,
                    None,
                    Some(tokens[1].oracle)
                )
                .await
            },
        )
        .await,
        Some(openbook_v2::error::OpenBookError::InvalidSecondOracle.into())
    );

    Ok(())
}

#[tokio::test]
async fn test_with_same_oracles() -> Result<(), TransportError> {
    let context = TestContextBuilder::new().start_default().await;
    let solana = &context.solana.clone();

    let payer = context.users[0].key;
    let mints = &context.mints[0..=2];

    let market = TestKeypair::new();
    let fake_oracle_a = solana.create_account_from_len(&payer.pubkey(), 100).await;

    assert_eq!(
        send_tx_and_get_ix_custom_error(
            solana,
            CreateMarketInstruction {
                payer,
                market,
                quote_lot_size: 100,
                base_lot_size: 100,
                base_mint: mints[0].pubkey,
                quote_mint: mints[1].pubkey,
                ..CreateMarketInstruction::with_new_book_and_heap(
                    solana,
                    Some(fake_oracle_a),
                    Some(fake_oracle_a),
                )
                .await
            },
        )
        .await,
        Some(anchor_lang::error::ErrorCode::RequireKeysNeqViolated.into())
    );

    Ok(())
}

#[tokio::test]
async fn test_with_wrong_oracle_types() -> Result<(), TransportError> {
    let context = TestContextBuilder::new().start_default().await;
    let solana = &context.solana.clone();

    let payer = context.users[0].key;
    let mints = &context.mints[0..=2];

    let market_a = TestKeypair::new();
    let market_ab = TestKeypair::new();

    let fake_oracle_a = solana.create_account_from_len(&payer.pubkey(), 100).await;
    let fake_oracle_b = solana.create_account_from_len(&payer.pubkey(), 100).await;

    assert_eq!(
        send_tx_and_get_ix_custom_error(
            solana,
            CreateMarketInstruction {
                payer,
                market: market_a,
                quote_lot_size: 100,
                base_lot_size: 100,
                base_mint: mints[0].pubkey,
                quote_mint: mints[1].pubkey,
                ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(fake_oracle_a), None)
                    .await
            },
        )
        .await,
        Some(openbook_v2::error::OpenBookError::UnknownOracleType.into())
    );

    assert_eq!(
        send_tx_and_get_ix_custom_error(
            solana,
            CreateMarketInstruction {
                payer,
                market: market_ab,
                quote_lot_size: 100,
                base_lot_size: 100,
                base_mint: mints[0].pubkey,
                quote_mint: mints[1].pubkey,
                ..CreateMarketInstruction::with_new_book_and_heap(
                    solana,
                    Some(fake_oracle_a),
                    Some(fake_oracle_b)
                )
                .await
            },
        )
        .await,
        Some(openbook_v2::error::OpenBookError::UnknownOracleType.into())
    );

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_edit_order.rs
use super::*;

#[tokio::test]
async fn test_edit_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -100,
        taker_fee: 200,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 2,
            max_quote_lots_including_fees: 20004,
            client_order_id: 12,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(open_orders_account_1.position.bids_base_lots, 2);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
    }

    // No client Id found, is treated as if order was fully filled
    send_tx(
        solana,
        EditOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10002,
            client_order_id: 11,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
            expected_cancel_size: 1,
        },
    )
    .await
    .unwrap();

    // take 1. send remaining to crank and remove 1 bids_base_lots
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 12,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![account_1],
        },
    )
    .await
    .unwrap();

    // 1 base_lot has been taken, post only 1
    send_tx(
        solana,
        EditOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 2,
            max_quote_lots_including_fees: 20004,
            client_order_id: 12,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
            expected_cancel_size: 2,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_fees.rs
use super::*;

#[tokio::test]
async fn test_fees_accrued() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -100,
        taker_fee: 200,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99980);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 10);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99980);
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 10);
        assert_eq!(market.fees_accrued, 10);
        assert_eq!(market.fees_to_referrers, 0);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
        assert_eq!(market.fees_accrued, 10);
        assert_eq!(market.fees_to_referrers, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_maker_fees() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: 200,
        taker_fee: 400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10020,
            client_order_id: 30,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        CancelOrderByClientOrderIdInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            client_order_id: 30,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 100020);
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10020,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 40);
        assert_eq!(market.fees_accrued, 60);
        assert_eq!(market.fees_to_referrers, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: Some(owner_token_1),
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 40);
        assert_eq!(market.fees_accrued, 60);
        assert_eq!(market.fees_to_referrers, 20);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
    }

    Ok(())
}

// Real simulation. Market maker pays fees but get them back on referral. Jupiter users don't pay fees.
// Only users paying fees are users using a UI limit orders.
#[tokio::test]
async fn test_market_maker_fees() -> Result<(), TransportError> {
    let market_base_lot_size = 100;
    let market_quote_lot_size = 10;
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        account_1,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size: market_quote_lot_size,
        base_lot_size: market_base_lot_size,
        maker_fee: 400,
        taker_fee: 400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let balance_owner_0_before = solana.token_account_balance(owner_token_0).await;
    let balance_owner_1_before = solana.token_account_balance(owner_token_1).await;

    // Account_1 is a MM and pays fee which will get back later
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10040,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let balance_owner_0_after = solana.token_account_balance(owner_token_0).await;
        let balance_owner_1_after = solana.token_account_balance(owner_token_1).await;
        assert_eq!(balance_owner_0_before, balance_owner_0_after);
        assert_eq!(
            balance_owner_1_before,
            balance_owner_1_after + 10000 * (market_quote_lot_size as u64) + 40
        );
    }

    let jup_user = context.users[2].key;
    let jup_user_token_0 = context.users[2].token_accounts[0];
    let jup_user_token_1 = context.users[2].token_accounts[1];

    let balance_jup_0_before = solana.token_account_balance(jup_user_token_0).await;
    let balance_jup_1_before = solana.token_account_balance(jup_user_token_1).await;

    // Jupiter user, takes and don't pay fees
    send_tx(
        solana,
        PlaceTakeOrderInstruction {
            market,
            signer: jup_user,
            user_base_account: jup_user_token_0,
            user_quote_account: jup_user_token_1,
            market_base_vault,
            market_quote_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10040,
            open_orders_admin: None,
        },
    )
    .await
    .unwrap();

    {
        let balance_jup_0_after = solana.token_account_balance(jup_user_token_0).await;
        let balance_jup_1_after = solana.token_account_balance(jup_user_token_1).await;
        assert_eq!(
            balance_jup_0_before,
            balance_jup_0_after + (market_base_lot_size as u64)
        );
        assert_eq!(
            balance_jup_1_before + 10000 * (market_quote_lot_size as u64),
            balance_jup_1_after
        );
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1],
        },
    )
    .await
    .unwrap();
    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: Some(owner_token_1),
        },
    )
    .await
    .unwrap();

    // MM gets back the fee
    {
        let balance_owner_0_after = solana.token_account_balance(owner_token_0).await;
        let balance_owner_1_after = solana.token_account_balance(owner_token_1).await;
        assert_eq!(
            balance_owner_0_before + (market_base_lot_size as u64),
            balance_owner_0_after
        );
        assert_eq!(
            balance_owner_1_before,
            balance_owner_1_after + 10000 * (market_quote_lot_size as u64)
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_no_maker_fees_ask() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -200,
        taker_fee: 400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10004,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 100020);
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
        assert_eq!(market.fees_accrued, 20);
        assert_eq!(market.fees_to_referrers, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: Some(owner_token_1),
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
        assert_eq!(market.fees_accrued, 20);
        assert_eq!(market.fees_to_referrers, 20);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_maker_fees_ask() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: 200,
        taker_fee: 400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10020,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10004,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99980);
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 20);
        assert_eq!(market.fees_accrued, 60);
        assert_eq!(market.fees_to_referrers, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: Some(owner_token_1),
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 20);
        assert_eq!(market.fees_accrued, 60);
        assert_eq!(market.fees_to_referrers, 40);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.fees_available, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_fees_half() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -3700,
        taker_fee: 7400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;
    let initial_quote_amount = 10000;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: initial_quote_amount,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: initial_quote_amount,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;
        let market = solana.get_account::<Market>(market).await;

        assert_eq!(open_orders_account_1.position.quote_free_native, 370);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99260);
        assert_eq!(market.referrer_rebates_accrued, 370);

        assert_eq!(
            (market.referrer_rebates_accrued
                + open_orders_account_2.position.quote_free_native
                + open_orders_account_1.position.quote_free_native) as i64,
            initial_quote_amount * 10 // as it's in native quote
        );
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let balance_quote = solana.token_account_balance(market_quote_vault).await;
        assert_eq!(balance_quote, 370);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let balance_quote = solana.token_account_balance(market_quote_vault).await;
        assert_eq!(balance_quote, 0);
    }

    // Different fees

    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: -3200,
        taker_fee: 6400,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;
    let initial_quote_amount = 10000;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: initial_quote_amount,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: initial_quote_amount,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;
        let market = solana.get_account::<Market>(market).await;

        assert_eq!(open_orders_account_1.position.quote_free_native, 320);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99360);
        assert_eq!(market.referrer_rebates_accrued, 320);

        assert_eq!(
            (market.referrer_rebates_accrued
                + open_orders_account_2.position.quote_free_native
                + open_orders_account_1.position.quote_free_native) as i64,
            initial_quote_amount * 10 // as it's in native quote
        );
    }

    let admin_token_1 = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let balance_quote = solana.token_account_balance(market_quote_vault).await;
        assert_eq!(balance_quote, 320);
    }

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: admin_token_1,
        },
    )
    .await
    .unwrap();

    {
        let balance_quote = solana.token_account_balance(market_quote_vault).await;
        assert_eq!(balance_quote, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_locked_maker_fees() -> Result<(), TransportError> {
    let maker_fee = 350;
    let taker_fee = 0;

    let TestInitialize {
        context,
        owner,
        owner_token_0: owner_base_ata,
        owner_token_1: owner_quote_ata,
        market,

        market_base_vault,
        market_quote_vault,
        account_1: maker,
        account_2: taker,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee,
        taker_fee,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let place_maker_bid = PlaceOrderInstruction {
        open_orders_account: maker,
        open_orders_admin: None,
        market,
        signer: owner,
        user_token_account: owner_quote_ata,
        market_vault: market_quote_vault,
        side: Side::Bid,
        price_lots: 1_000,
        max_base_lots: 5,
        max_quote_lots_including_fees: 1_000_000_000,
        client_order_id: 0,
        expiry_timestamp: 0,
        order_type: PlaceOrderType::Limit,
        self_trade_behavior: SelfTradeBehavior::default(),
        remainings: vec![],
    };

    let place_taker_ask = PlaceOrderInstruction {
        side: Side::Ask,
        market_vault: market_base_vault,
        open_orders_account: taker,
        user_token_account: owner_base_ata,
        max_base_lots: 3,
        ..place_maker_bid.clone()
    };

    let cancel_maker_orders_ix = CancelAllOrdersInstruction {
        open_orders_account: maker,
        signer: owner,
        market,
    };

    let settle_maker_funds_ix = SettleFundsInstruction {
        owner,
        market,
        open_orders_account: maker,
        market_base_vault,
        market_quote_vault,
        user_base_account: owner_base_ata,
        user_quote_account: owner_quote_ata,
        referrer_account: None,
    };

    send_tx(solana, place_maker_bid.clone()).await.unwrap();
    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 18);
    }

    send_tx(solana, place_taker_ask).await.unwrap();
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![maker],
        },
    )
    .await
    .unwrap();

    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 8);
    }

    send_tx(solana, cancel_maker_orders_ix.clone())
        .await
        .unwrap();

    // one lamport is still locked due rounding
    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 1);
    }

    send_tx(solana, place_maker_bid.clone()).await.unwrap();
    send_tx(solana, settle_maker_funds_ix.clone())
        .await
        .unwrap();

    // which cannot be claimed yet because there're still bids on the book
    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 1 + 18);
    }

    // but now if we don't have any pending bid order
    send_tx(solana, cancel_maker_orders_ix.clone())
        .await
        .unwrap();

    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 1);
    }

    // it's gone!
    send_tx(solana, settle_maker_funds_ix.clone())
        .await
        .unwrap();
    {
        let oo = solana.get_account::<OpenOrdersAccount>(maker).await;
        assert_eq!(oo.position.locked_maker_fees, 0);
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_fill_or_kill_order.rs
use super::*;
use std::sync::Arc;

#[tokio::test]
async fn test_fill_or_kill_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: 0,
        taker_fee: 0,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let default = PlaceOrderInstruction {
        open_orders_account: Default::default(),
        open_orders_admin: None,
        market,
        signer: owner,
        market_vault: Default::default(),
        user_token_account: Default::default(),
        side: Side::Bid,
        price_lots,
        max_base_lots: 0,
        max_quote_lots_including_fees: 0,
        client_order_id: 0,
        expiry_timestamp: 0,
        order_type: PlaceOrderType::Limit,
        self_trade_behavior: Default::default(),
        remainings: vec![],
    };
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    let initial_balance_base = solana.token_account_balance(owner_token_0).await;
    let initial_balance_quote = solana.token_account_balance(owner_token_1).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            max_base_lots: 5,
            max_quote_lots_including_fees: 50_000,
            order_type: PlaceOrderType::Limit,
            ..default.clone()
        },
    )
    .await
    .unwrap();

    assert_open_orders(account_1, solana, 5, 0).await;
    assert_open_orders(account_2, solana, 0, 0).await;

    // small order -> no problem
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10_000,
            order_type: PlaceOrderType::FillOrKill,
            ..default.clone()
        },
    )
    .await
    .unwrap();

    consume_and_settle(
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        solana,
    )
    .await;

    assert_open_orders(account_1, solana, 4, 0).await;
    assert_open_orders(account_2, solana, 0, 0).await;

    assert_balance(owner_token_0, solana, initial_balance_base).await;
    assert_balance(owner_token_1, solana, initial_balance_quote - 400_000).await;

    // big order -> should fail
    let result = send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            max_base_lots: 6,
            max_quote_lots_including_fees: 60_000,
            order_type: PlaceOrderType::FillOrKill,
            ..default.clone()
        },
    )
    .await;

    assert_openbook_error(
        &result,
        OpenBookError::WouldExecutePartially.error_code(),
        "Should kill order".into(),
    );
    Ok(())
}

async fn assert_open_orders(
    account: Pubkey,
    solana: &Arc<SolanaCookie>,
    bids_base_lots: i64,
    asks_base_lots: i64,
) {
    let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account).await;
    assert_eq!(
        open_orders_account_1.position.bids_base_lots,
        bids_base_lots
    );
    assert_eq!(
        open_orders_account_1.position.asks_base_lots,
        asks_base_lots
    );
}

async fn assert_balance(token: Pubkey, solana: &Arc<SolanaCookie>, expected_balance: u64) {
    let balance_base = solana.token_account_balance(token).await;
    assert_eq!(balance_base, expected_balance);
}

#[allow(clippy::too_many_arguments)]
async fn consume_and_settle(
    owner: TestKeypair,
    owner_token_0: Pubkey,
    owner_token_1: Pubkey,
    market: Pubkey,
    market_base_vault: Pubkey,
    market_quote_vault: Pubkey,
    account_1: Pubkey,
    account_2: Pubkey,
    solana: &Arc<SolanaCookie>,
) {
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_2,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_indexer.rs
use super::*;

#[tokio::test]
async fn test_indexer() -> Result<(), TransportError> {
    let context = TestContext::new().await;
    let solana = &context.solana.clone();

    let collect_fee_admin = TestKeypair::new();
    let close_market_admin = TestKeypair::new();
    let owner = context.users[0].key;
    let payer = context.users[1].key;
    let mints = &context.mints[0..=2];

    let tokens = Token::create(mints.to_vec(), solana, collect_fee_admin, payer).await;

    let market = TestKeypair::new();

    let openbook_v2::accounts::CreateMarket { market, .. } = send_tx(
        solana,
        CreateMarketInstruction {
            collect_fee_admin: collect_fee_admin.pubkey(),
            open_orders_admin: None,
            close_market_admin: Some(close_market_admin.pubkey()),
            payer,
            market,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(tokens[1].oracle), None)
                .await
        },
    )
    .await
    .unwrap();

    let indexer = create_open_orders_indexer(solana, &context.users[1], owner, market).await;
    let maker_1 =
        create_open_orders_account(solana, owner, market, 1, &context.users[1], None).await;

    {
        let indexer = solana.get_account::<OpenOrdersIndexer>(indexer).await;
        assert_eq!(indexer.created_counter, 1);
        assert!(indexer.addresses.contains(&maker_1));
    }

    let (maker_2, maker_3) = {
        (
            create_open_orders_account(solana, owner, market, 2, &context.users[1], None).await,
            create_open_orders_account(solana, owner, market, 3, &context.users[1], None).await,
        )
    };

    {
        let indexer = solana.get_account::<OpenOrdersIndexer>(indexer).await;

        assert_eq!(indexer.created_counter, 3);
        assert_eq!(indexer.addresses.len(), 3);
        assert!(indexer.addresses.contains(&maker_1));
        assert!(indexer.addresses.contains(&maker_2));
        assert!(indexer.addresses.contains(&maker_3));
    }

    send_tx(
        solana,
        CloseOpenOrdersAccountInstruction {
            account_num: 2,
            market,
            owner,
            sol_destination: owner.pubkey(),
        },
    )
    .await
    .unwrap();

    {
        let indexer = solana.get_account::<OpenOrdersIndexer>(indexer).await;

        assert_eq!(indexer.created_counter, 3);
        assert_eq!(indexer.addresses.len(), 2);
        assert!(indexer.addresses.contains(&maker_1));
        assert!(indexer.addresses.contains(&maker_3));
    }

    let maker_4 =
        create_open_orders_account(solana, owner, market, 4, &context.users[1], None).await;

    {
        let indexer = solana.get_account::<OpenOrdersIndexer>(indexer).await;
        assert_eq!(indexer.created_counter, 4);
        assert_eq!(indexer.addresses.len(), 3);
        assert!(indexer.addresses.contains(&maker_1));
        assert!(indexer.addresses.contains(&maker_3));
        assert!(indexer.addresses.contains(&maker_4));
    }

    Ok(())
}

#[tokio::test]
async fn test_size_vector() -> Result<(), TransportError> {
    let context = TestContext::new().await;
    let solana = &context.solana.clone();

    let collect_fee_admin = TestKeypair::new();
    let close_market_admin = TestKeypair::new();
    let owner = context.users[0].key;
    let payer = context.users[1].key;
    let mints = &context.mints[0..=2];

    let tokens = Token::create(mints.to_vec(), solana, collect_fee_admin, payer).await;

    let market = TestKeypair::new();

    let openbook_v2::accounts::CreateMarket { market, .. } = send_tx(
        solana,
        CreateMarketInstruction {
            collect_fee_admin: collect_fee_admin.pubkey(),
            open_orders_admin: None,
            close_market_admin: Some(close_market_admin.pubkey()),
            payer,
            market,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            base_mint: mints[0].pubkey,
            quote_mint: mints[1].pubkey,
            ..CreateMarketInstruction::with_new_book_and_heap(solana, Some(tokens[1].oracle), None)
                .await
        },
    )
    .await
    .unwrap();

    let indexer = create_open_orders_indexer(solana, &context.users[1], owner, market).await;

    let mut makers = vec![];
    let max = 256;
    for n in 0..max {
        makers.push(
            create_open_orders_account(solana, owner, market, n + 1, &context.users[1], None).await,
        )
    }

    {
        let indexer = solana.get_account::<OpenOrdersIndexer>(indexer).await;

        assert_eq!(indexer.created_counter, max);
        assert_eq!(indexer.addresses.len(), max as usize);
        assert!(indexer.addresses.contains(&makers[(max - 1) as usize]));
        assert!(indexer.addresses.contains(&makers[(max / 2) as usize]));
        assert!(indexer.addresses.contains(&makers[1]));
    }

    // Can't create more than 256
    assert!(send_tx(
        solana,
        CreateOpenOrdersAccountInstruction {
            account_num: 257,
            market,
            owner,
            payer: context.users[1].key,
            delegate: None,
        },
    )
    .await
    .is_err());

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_ioc.rs
use super::*;

#[tokio::test]
async fn test_ioc() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        payer,
        mints,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        maker_fee: 200,
        taker_fee: 200,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            reduce_only: false,
            client_order_id: 0,
            expiry_timestamp: 0,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            reduce_only: false,
            client_order_id: 0,
            expiry_timestamp: 0,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_position_lots(), 0);
        assert_eq!(open_orders_account_2.position.base_position_lots(), 0);
        assert_eq!(open_orders_account_1.position.quote_position_native(), 0);
        // assert_eq!(open_orders_account_2.position.quote_position_native(), 0);
        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.taker_base_lots, 0);
        assert_eq!(open_orders_account_2.position.taker_quote_lots, 10000);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_multiple_orders.rs
use super::*;

#[tokio::test]
async fn insufficient_funds() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        account_1,
        account_2,
        market,
        market_base_vault,
        market_quote_vault,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;

    let solana = &context.solana.clone();

    let max_quote_lots_including_fees = 104;

    // there's an ask on the book
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1,
            max_base_lots: i64::MAX / 1_000,
            max_quote_lots_including_fees,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    solana.set_account_balance(owner_token_0, 2_500).await;
    solana.set_account_balance(owner_token_1, 110).await;

    // some lamports are already deposited
    send_tx(
        solana,
        DepositInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            base_amount: 1_200,
            quote_amount: 0,
        },
    )
    .await
    .unwrap();

    // note that a priori, we only have enough lamports to place 2.5 Ask. But as the bid will be
    // filled & the taker executed immediately, we will have 10 extra base lots available
    let order = openbook_v2::PlaceMultipleOrdersArgs {
        price_lots: 1,
        max_quote_lots_including_fees,
        expiry_timestamp: 0,
    };

    let bids = vec![order];
    let asks = vec![order; 4];

    send_tx(
        solana,
        CancelAllAndPlaceOrdersInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            orders_type: PlaceOrderType::Limit,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            bids,
            asks,
        },
    )
    .await
    .unwrap();

    let position = solana
        .get_account::<OpenOrdersAccount>(account_1)
        .await
        .position;

    assert_eq!(position.asks_base_lots, 35);
    assert_eq!(position.bids_base_lots, 0);

    assert_eq!(position.base_free_native, 0);
    assert_eq!(position.quote_free_native, 0);

    assert_eq!(position.referrer_rebates_available, 1);
    assert_eq!(solana.token_account_balance(owner_token_1).await, 9);
    assert_eq!(solana.token_account_balance(owner_token_0).await, 0);

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_oracle_peg.rs
use super::*;

#[tokio::test]
async fn test_oracle_peg_enabled() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_1,
        market,
        market_quote_vault,
        account_1,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        with_oracle: false,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    assert!(send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -1,
            peg_limit: 100,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 0,
        },
    )
    .await
    .is_err());

    Ok(())
}

#[tokio::test]
async fn test_oracle_peg_invalid_oracle() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_1,
        market,
        market_quote_vault,
        account_1,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    solana.advance_clock(200).await;

    assert!(send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -1,
            peg_limit: 100,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 0,
        },
    )
    .await
    .is_err());

    Ok(())
}

#[tokio::test]
async fn test_oracle_peg() -> Result<(), TransportError> {
    let market_base_lot_size = 10000;
    let market_quote_lot_size = 10;

    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        tokens,
        collect_fee_admin,
        bids,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size: market_quote_lot_size,
        base_lot_size: market_base_lot_size,
        maker_fee: -0,
        taker_fee: 0,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let price_lots = {
        let market = solana.get_account::<Market>(market).await;
        market.native_price_to_lot(I80F48::ONE).unwrap()
    };
    assert_eq!(price_lots, market_base_lot_size / market_quote_lot_size);

    let place_pegged_ix = PlaceOrderPeggedInstruction {
        open_orders_account: account_1,
        market,
        signer: owner,
        user_token_account: owner_token_1,
        market_vault: market_quote_vault,
        side: Side::Bid,
        price_offset: -1,
        peg_limit: 1,
        max_base_lots: 1,
        max_quote_lots_including_fees: 100_000,
        client_order_id: 0,
    };

    // posting invalid orderes by peg_limit are skipped
    send_tx(solana, place_pegged_ix.clone()).await.unwrap();

    let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
    assert_eq!(bids_data.roots[1].leaf_count, 0);

    // but not if they are inside the peg_limit
    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            peg_limit: 1000,
            ..place_pegged_ix
        },
    )
    .await
    .unwrap();

    let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
    assert_eq!(bids_data.roots[1].leaf_count, 1);

    let order = solana
        .get_account::<OpenOrdersAccount>(account_1)
        .await
        .open_orders[0];
    assert_eq!(order.side_and_tree(), SideAndOrderTree::BidOraclePegged);

    send_tx(
        solana,
        CancelOrderInstruction {
            signer: owner,
            market,
            open_orders_account: account_1,
            order_id: order.id,
        },
    )
    .await
    .unwrap();

    assert_no_orders(solana, account_1).await;

    let balance_before = solana.token_account_balance(owner_token_1).await;
    let max_quote_lots_including_fees = 100_000;

    // TEST: Place a pegged bid, take it with a direct and pegged ask, and consume events
    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: 0,
            peg_limit: price_lots,
            max_base_lots: 2,
            max_quote_lots_including_fees,
            client_order_id: 5,
        },
    )
    .await
    .unwrap();

    let balance_after = solana.token_account_balance(owner_token_1).await;

    // Max quantity being subtracted from owner is max_quote_lots_including_fees
    {
        assert!(
            balance_before
                - ((max_quote_lots_including_fees as u64) * (market_quote_lot_size as u64))
                <= balance_after
        );
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 6,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_2,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_offset: 0,
            peg_limit: price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 7,
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    assert_no_orders(solana, account_1).await;

    // TEST: an ask at current oracle price does not match
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,

            client_order_id: 60,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    send_tx(
        solana,
        CancelOrderByClientOrderIdInstruction {
            open_orders_account: account_2,
            market,
            signer: owner,
            client_order_id: 60,
        },
    )
    .await
    .unwrap();

    // TEST: Change the oracle, now the ask matches
    set_stub_oracle_price(solana, &tokens[0], collect_fee_admin, 1.002).await;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 2,
            max_quote_lots_including_fees: 100_000,

            client_order_id: 61,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();
    assert_no_orders(solana, account_1).await;

    // restore the oracle to default
    set_stub_oracle_price(solana, &tokens[0], collect_fee_admin, 1.0).await;

    // TEST: order is cancelled when the price exceeds the peg limit
    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -1,
            peg_limit: price_lots + 2,
            max_base_lots: 2,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 5,
        },
    )
    .await
    .unwrap();

    // order is still matchable when exactly at the peg limit
    set_stub_oracle_price(solana, &tokens[0], collect_fee_admin, 1.003).await;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: price_lots + 2,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,

            client_order_id: 62,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let oo = solana.get_account::<OpenOrdersAccount>(account_2).await;
        assert!(oo.find_order_with_client_order_id(62).is_none());
    }

    // but once the adjusted price is > the peg limit, it's gone
    set_stub_oracle_price(solana, &tokens[0], collect_fee_admin, 1.004).await;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: price_lots + 3,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,

            client_order_id: 63,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    send_tx(
        solana,
        CancelOrderByClientOrderIdInstruction {
            open_orders_account: account_2,
            market,
            signer: owner,
            client_order_id: 63,
        },
    )
    .await
    .unwrap();
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();
    assert_no_orders(solana, account_1).await;

    Ok(())
}

#[tokio::test]
async fn test_take_peg_invalid_oracle() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        price_lots,
        tokens,
        collect_fee_admin,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -1,
            peg_limit: 100,
            max_base_lots: 1,
            max_quote_lots_including_fees: 100_000,
            client_order_id: 0,
        },
    )
    .await
    .unwrap();

    {
        let oo = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(oo.position.bids_base_lots, 1);
    }

    let take_order_ix = PlaceOrderInstruction {
        open_orders_account: account_2,
        open_orders_admin: None,
        market,
        signer: owner,
        user_token_account: owner_token_0,
        market_vault: market_base_vault,
        side: Side::Ask,
        price_lots,
        max_base_lots: 1,
        max_quote_lots_including_fees: 100_000,
        client_order_id: 6,
        expiry_timestamp: 0,
        order_type: PlaceOrderType::Limit,
        self_trade_behavior: SelfTradeBehavior::default(),
        remainings: vec![account_1],
    };

    solana.advance_clock(200).await;

    // stale oracle, order will be posted since matching with the oracle peg component of the book
    // is not possible
    send_tx(solana, take_order_ix.clone()).await.unwrap();
    {
        let oo_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let oo_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;
        assert_eq!(oo_1.position.bids_base_lots, 1);
        assert_eq!(oo_2.position.asks_base_lots, 1);
    }

    // but once the oracle is back, the match will be made
    set_stub_oracle_price(solana, &tokens[0], collect_fee_admin, 1000.0).await;
    send_tx(solana, take_order_ix.clone()).await.unwrap();
    {
        let oo = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(oo.position.bids_base_lots, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_oracle_peg_limit() -> Result<(), TransportError> {
    let market_base_lot_size = 10000;
    let market_quote_lot_size = 10;

    let TestInitialize {
        context,
        owner,
        owner_token_1,
        market,
        market_quote_vault,
        account_1,
        bids,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size: market_quote_lot_size,
        base_lot_size: market_base_lot_size,
        maker_fee: -0,
        taker_fee: 0,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let price_lots = {
        let market = solana.get_account::<Market>(market).await;
        market.native_price_to_lot(I80F48::ONE).unwrap()
    };
    assert_eq!(price_lots, market_base_lot_size / market_quote_lot_size);

    let balance_before = solana.token_account_balance(owner_token_1).await;
    let max_quote_lots_including_fees = 100_000;

    // TEST: Place a pegged bid, can't post in book due insufficient funds
    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -100,
            peg_limit: price_lots + 100_000,
            max_base_lots: 2,
            max_quote_lots_including_fees,
            client_order_id: 5,
        },
    )
    .await
    .unwrap();
    assert_no_orders(solana, account_1).await;

    // Upgrade max quantity
    let max_quote_lots_including_fees = 101_000;

    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: -100,
            peg_limit: price_lots + 100_000,
            max_base_lots: 2,
            max_quote_lots_including_fees,
            client_order_id: 5,
        },
    )
    .await
    .unwrap();

    let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
    assert_eq!(bids_data.roots[1].leaf_count, 1);

    let balance_after = solana.token_account_balance(owner_token_1).await;

    // Max quantity being subtracted from owner is max_quote_lots_including_fees
    {
        assert_eq!(
            balance_before
                - ((max_quote_lots_including_fees as u64) * (market_quote_lot_size as u64)),
            balance_after
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_locked_amounts() -> Result<(), TransportError> {
    let quote_lot_size = 10;
    let base_lot_size = 100;
    let maker_fee = 200;
    let taker_fee = 400;

    let TestInitialize {
        context,
        owner,
        owner_token_0: owner_base_ata,
        owner_token_1: owner_quote_ata,
        market,

        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size,
        base_lot_size,
        maker_fee,
        taker_fee,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let place_bid_0_ix = PlaceOrderPeggedInstruction {
        open_orders_account: account_1,
        market,
        signer: owner,
        user_token_account: owner_quote_ata,
        market_vault: market_quote_vault,
        side: Side::Bid,
        price_offset: 0,
        peg_limit: 30,
        max_base_lots: 1_000,
        max_quote_lots_including_fees: 100_000_000,
        client_order_id: 0,
    };

    let place_ask_1_ix = PlaceOrderPeggedInstruction {
        side: Side::Ask,
        peg_limit: 10,
        market_vault: market_base_vault,
        user_token_account: owner_base_ata,
        open_orders_account: account_2,
        ..place_bid_0_ix.clone()
    };

    let settle_funds_0_ix = SettleFundsInstruction {
        owner,
        market,
        open_orders_account: account_1,
        market_base_vault,
        market_quote_vault,
        user_base_account: owner_base_ata,
        user_quote_account: owner_quote_ata,
        referrer_account: None,
    };

    let settle_funds_1_ix = SettleFundsInstruction {
        open_orders_account: account_2,
        ..settle_funds_0_ix.clone()
    };

    let consume_events_ix = ConsumeEventsInstruction {
        consume_events_admin: None,
        market,
        open_orders_accounts: vec![account_1, account_2],
    };

    let init_balances = (
        solana.token_account_balance(owner_base_ata).await,
        solana.token_account_balance(owner_quote_ata).await,
    );

    // Cancel bid order
    {
        send_tx(solana, place_bid_0_ix.clone()).await.unwrap();

        let balances = (
            solana.token_account_balance(owner_base_ata).await,
            solana.token_account_balance(owner_quote_ata).await + 300_000 + 60,
        );

        assert_eq!(init_balances, balances);

        send_tx(
            solana,
            CancelAllOrdersInstruction {
                open_orders_account: account_1,
                market,
                signer: owner,
            },
        )
        .await
        .unwrap();
        send_tx(solana, settle_funds_0_ix.clone()).await.unwrap();

        let balances = (
            solana.token_account_balance(owner_base_ata).await,
            solana.token_account_balance(owner_quote_ata).await,
        );

        assert_eq!(init_balances, balances);
    }

    // Cancel ask order
    {
        send_tx(solana, place_ask_1_ix.clone()).await.unwrap();

        let balances = (
            solana.token_account_balance(owner_base_ata).await + 100_000,
            solana.token_account_balance(owner_quote_ata).await,
        );

        assert_eq!(init_balances, balances);

        send_tx(
            solana,
            CancelAllOrdersInstruction {
                open_orders_account: account_2,
                market,
                signer: owner,
            },
        )
        .await
        .unwrap();
        send_tx(solana, settle_funds_1_ix.clone()).await.unwrap();

        let balances = (
            solana.token_account_balance(owner_base_ata).await,
            solana.token_account_balance(owner_quote_ata).await,
        );

        assert_eq!(init_balances, balances);
    }

    // Place & take a bid
    {
        send_tx(solana, place_bid_0_ix.clone()).await.unwrap();
        send_tx(solana, place_ask_1_ix.clone()).await.unwrap();
        send_tx(solana, consume_events_ix.clone()).await.unwrap();

        let (position_0, position_1) = {
            let oo_0 = solana.get_account::<OpenOrdersAccount>(account_1).await;
            let oo_1 = solana.get_account::<OpenOrdersAccount>(account_2).await;
            (oo_0.position, oo_1.position)
        };

        assert_eq!(position_0.quote_free_native, 200_000 + 40);
        assert_eq!(position_0.base_free_native, 100_000);

        assert_eq!(position_1.quote_free_native, 100_000 - 40);
        assert_eq!(position_1.base_free_native, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_bids_quote_lots() -> Result<(), TransportError> {
    let quote_lot_size = 10;
    let base_lot_size = 100;
    let maker_fee = 200;
    let taker_fee = 400;

    let TestInitialize {
        context,
        owner,
        owner_token_0: owner_base_ata,
        owner_token_1: owner_quote_ata,
        market,

        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size,
        base_lot_size,
        maker_fee,
        taker_fee,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_1,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_offset: 0,
            peg_limit: 20,
            max_base_lots: 100,
            max_quote_lots_including_fees: 100_000_000,
            client_order_id: 0,
        },
    )
    .await
    .unwrap();

    // first partial match with another oracle peg order
    send_tx(
        solana,
        PlaceOrderPeggedInstruction {
            open_orders_account: account_2,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_offset: 0,
            peg_limit: 20,
            max_base_lots: 30,
            max_quote_lots_including_fees: 100_000_000,
            client_order_id: 0,
        },
    )
    .await
    .unwrap();

    // not yet unlocked!
    let oo_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
    assert_eq!(oo_1.position.bids_quote_lots, 2_000);

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    let oo_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
    assert_eq!(oo_1.position.bids_quote_lots, 1_400);

    // and fill the rest of the order with a normal ask
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1,
            max_base_lots: 70,
            max_quote_lots_including_fees: 100_000_000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    let oo_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
    assert_eq!(oo_1.position.bids_quote_lots, 0);

    Ok(())
}

async fn assert_no_orders(solana: &SolanaCookie, account_1: Pubkey) {
    let open_orders_account = solana.get_account::<OpenOrdersAccount>(account_1).await;

    for oo in open_orders_account.open_orders.iter() {
        assert!(oo.id == 0);
        assert!(oo.side_and_tree() == SideAndOrderTree::BidFixed);
        assert!(oo.client_id == 0);
    }
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_order_types.rs
use super::*;

#[tokio::test]
async fn test_immediate_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let balance_base = solana.token_account_balance(owner_token_0).await;
    let balance_quote = solana.token_account_balance(owner_token_1).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 2,
            max_quote_lots_including_fees: 20000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::ImmediateOrCancel,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
        assert_eq!(
            balance_base - 100,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote,
            solana.token_account_balance(owner_token_1).await
        );
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 20);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let balance_base = solana.token_account_balance(owner_token_0).await;
    let balance_quote = solana.token_account_balance(owner_token_1).await;

    // There is a bid in the book, post only doesn't do anything since there is a match
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::PostOnly,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(
            balance_base,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote,
            solana.token_account_balance(owner_token_1).await
        );
    }

    // Change the price, so no matching and order posts
    let price_lots_2 = price_lots - 100;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: price_lots_2,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::PostOnly,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(
            balance_base,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote,
            solana.token_account_balance(owner_token_1).await
        );
    }

    // PostOnlySlide always post on book
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10040,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::PostOnlySlide,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(
            balance_base - 100,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote,
            solana.token_account_balance(owner_token_1).await
        );
    }

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_permissioned.rs
use super::*;

#[tokio::test]
async fn test_permissioned_open_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_1,
        market,
        market_quote_vault,
        tokens,
        account_1,
        open_orders_admin,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        open_orders_admin_bool: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let price_lots = {
        let market = solana.get_account::<Market>(market).await;
        market.native_price_to_lot(I80F48::from(1000)).unwrap()
    };

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    // First, send in an order w/o the signature of the open order authority, expect failure
    let result = send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await;

    assert!(result.is_err());

    // Second, send in an order w/ the signature of the open order authority, expect success
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: Some(open_orders_admin),
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    Ok(())
}

#[tokio::test]
async fn test_permissioned_open_take_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        open_orders_admin,
        owner,
        owner_token_1,
        market,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        open_orders_admin_bool: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    let result = send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await;

    assert!(result.is_err());

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: Some(open_orders_admin),
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    Ok(())
}

#[tokio::test]
async fn test_consume_events_admin() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        consume_events_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        consume_events_admin_bool: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let result = send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await;

    assert!(result.is_err());

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: Some(consume_events_admin),
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    Ok(())
}

#[tokio::test]
async fn test_close_market_admin() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        close_market_admin,
        collect_fee_admin,
        owner,
        mints,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        account_1,
        account_2,
        payer,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        close_market_admin_bool: true,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let fee_admin_ata = solana
        .create_associated_token_account(&collect_fee_admin.pubkey(), mints[1].pubkey)
        .await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // Place an order that matches
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // Place another order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let close_ix = CloseMarketInstruction {
        close_market_admin,
        market,
        sol_destination: owner.pubkey(),
    };

    let settle_funds_expired_ix = SettleFundsExpiredInstruction {
        close_market_admin,
        market,
        owner: payer,
        open_orders_account: account_2,
        market_base_vault,
        market_quote_vault,
        user_base_account: owner_token_0,
        user_quote_account: owner_token_1,
        referrer_account: None,
    };

    // Can't close yet, market not market as expired
    assert!(send_tx(solana, close_ix.clone()).await.is_err());

    // also not possible to settle in behalf of the users
    assert!(send_tx(solana, settle_funds_expired_ix.clone())
        .await
        .is_err());

    send_tx(
        solana,
        SetMarketExpiredInstruction {
            close_market_admin,
            market,
        },
    )
    .await
    .unwrap();

    {
        let market = solana.get_account::<Market>(market).await;
        assert_eq!(market.time_expiry, -1);
    }

    // Can't post orders anymore
    let result = send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await;
    assert!(result.is_err());

    // Consume events
    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    // Can't close, have to prune orders first
    assert!(send_tx(solana, close_ix.clone()).await.is_err());

    send_tx(
        solana,
        PruneOrdersInstruction {
            close_market_admin,
            market,
            open_orders_account: account_1,
        },
    )
    .await
    .unwrap();

    // and wait until users settle funds
    {
        let market = solana.get_account::<Market>(market).await;
        assert!(market.base_deposit_total != 0);
        assert!(market.quote_deposit_total != 0);
    }
    assert!(send_tx(solana, close_ix.clone()).await.is_err());

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    // which can be even be called by the close_market_admin once the market is expired so it
    // doesn't have to wait for the users!
    send_tx(solana, settle_funds_expired_ix).await.unwrap();

    // but wait! the're still pending fees
    {
        let market = solana.get_account::<Market>(market).await;
        assert!(market.fees_available != 0);
    }
    assert!(send_tx(solana, close_ix.clone()).await.is_err());

    send_tx(
        solana,
        SweepFeesInstruction {
            collect_fee_admin,
            market,
            market_quote_vault,
            token_receiver_account: fee_admin_ata,
        },
    )
    .await
    .unwrap();

    // Boom
    send_tx(solana, close_ix.clone()).await.unwrap();

    Ok(())
}

#[tokio::test]
async fn test_delegate() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        market,
        market_quote_vault,
        price_lots,
        tokens,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    let account_3_delegate = context.users[2].key;
    let account_3 = create_open_orders_account(
        solana,
        owner,
        market,
        3,
        &context.users[0],
        Some(account_3_delegate.pubkey()),
    )
    .await;
    let delegate_token_1 = context.users[2].token_accounts[1];

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_3,
            open_orders_admin: None,
            market,
            signer: account_3_delegate,
            user_token_account: delegate_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 23,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        CancelOrderByClientOrderIdInstruction {
            signer: account_3_delegate,
            market,
            open_orders_account: account_3,
            client_order_id: 23,
        },
    )
    .await
    .unwrap();

    send_tx(
        solana,
        SetDelegateInstruction {
            owner,
            open_orders_account: account_3,
            delegate_account: None,
        },
    )
    .await
    .unwrap();

    // No delegate anymore
    let result = send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_3,
            open_orders_admin: None,
            market,
            signer: account_3_delegate,
            user_token_account: delegate_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 23,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await;
    assert!(result.is_err());

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_place_order_remaining.rs
use super::*;

#[tokio::test]
async fn test_place_cancel_order_remaining() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        bids,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 1);
    }

    // Add remainings, no event on event_heap
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10004,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![account_1],
        },
    )
    .await
    .unwrap();

    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 0);
    }

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 20);
        assert_eq!(open_orders_account_2.position.quote_free_native, 99960);
    }

    // No events on event_heap
    {
        let market_acc = solana.get_account::<Market>(market).await;
        let event_heap = solana.get_account::<EventHeap>(market_acc.event_heap).await;

        assert_eq!(event_heap.header.count(), 0);
    }

    // Order with expiry time of 10s
    let now_ts: u64 = solana.get_clock().await.unix_timestamp as u64;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 35,
            expiry_timestamp: now_ts + 10,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 1);
    }

    // Advance clock
    solana.advance_clock(11).await;

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
    }

    // Add remainings, no event on event_heap. previous order is canceled
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 36,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![account_1],
        },
    )
    .await
    .unwrap();
    // bid has been canceled
    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 0);
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
    }

    // No events on event_heap
    {
        let market_acc = solana.get_account_boxed::<Market>(market).await;
        let event_heap = solana
            .get_account_boxed::<EventHeap>(market_acc.event_heap)
            .await;

        assert_eq!(event_heap.header.count(), 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_cancel_order_yourself() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        bids,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    // Order with expiry time of 10s
    let now_ts: u64 = solana.get_clock().await.unix_timestamp as u64;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: now_ts + 10,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 1);
    }

    // Advance clock
    solana.advance_clock(11).await;

    // No remainings, same account, previos bid is canceled
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10004,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![account_1],
        },
    )
    .await
    .unwrap();

    {
        let bids_data = solana.get_account_boxed::<BookSide>(bids).await;
        assert_eq!(bids_data.roots[0].leaf_count, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_place_order_taker_fees() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        bids,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        taker_fee: 11000, // 1.1%
        maker_fee: 0,
        quote_lot_size: 1000,
        base_lot_size: 1,
        ..Default::default()
    })
    .await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 500,
            max_quote_lots_including_fees: 500,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // Now place place a bid that fills the ask fully and has some remainder go to the book
    let before_quote_balance = solana.token_account_balance(owner_token_1).await;
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 9999999, // unlimited
            max_quote_lots_including_fees: 1000,
            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();
    let after_quote_balance = solana.token_account_balance(owner_token_1).await;

    // What should have happened is:
    // - match against the ask, paying 500 quote lots for 500 base lots
    // - taker fee native is 1.1% * 500 * 1000 = 5500 native
    // - which is 5.5 quote lots, so only 500 - 6 = 494 quote lots can be placed on the book

    let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;
    assert_eq!(open_orders_account_2.position.bids_quote_lots, 494);
    assert_eq!(open_orders_account_2.position.base_free_native, 500);

    assert_eq!(
        before_quote_balance - after_quote_balance,
        // cost of buying 500 base lots
        500 * 1000
        // taker fee
        + 5500
        // order on the book
        + 494 * 1000
    );

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_self_trade.rs
use super::*;

#[tokio::test]
async fn test_self_trade_decrement_take() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();
    let owner_quote_ata = context.users[0].token_accounts[1];
    let owner_base_ata = context.users[0].token_accounts[0];

    // maker (which will be the taker) limit order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1000,
            max_base_lots: 2,
            max_quote_lots_including_fees: 10000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // maker limit order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1000,
            max_base_lots: 2,
            max_quote_lots_including_fees: 10000,
            client_order_id: 2,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // taker full self-trade IOC
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 3,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::ImmediateOrCancel,
            self_trade_behavior: SelfTradeBehavior::DecrementTake,
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
    }

    // taker partial self-trade limit
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 1000,
            max_base_lots: 2,
            max_quote_lots_including_fees: 10002,
            client_order_id: 4,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::DecrementTake,
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_1.position.base_free_native, 200);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 200);
        assert_eq!(open_orders_account_1.position.quote_free_native, 20000);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 10002);
    }

    Ok(())
}

#[tokio::test]
async fn test_self_trade_cancel_provide() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();
    let owner_quote_ata = context.users[0].token_accounts[1];
    let owner_base_ata = context.users[0].token_accounts[0];

    // maker (which will be the taker) limit order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // maker limit order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1000,
            max_base_lots: 2,
            max_quote_lots_including_fees: 10000,
            client_order_id: 2,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    // taker partial self-trade
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 3,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::ImmediateOrCancel,
            self_trade_behavior: SelfTradeBehavior::CancelProvide,
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 200);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    // taker with another maker
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10004,
            client_order_id: 4,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::DecrementTake,
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 300);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 2);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1, account_2],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 300);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);

        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 20004);
    }

    Ok(())
}

#[tokio::test]
async fn test_self_abort_transaction() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();
    let owner_quote_ata = context.users[0].token_accounts[1];
    let owner_base_ata = context.users[0].token_accounts[0];

    // taker limit order
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_base_ata,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // taker failing self-trade
    assert!(send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_quote_ata,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 1000,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            client_order_id: 2,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::AbortTransaction,
            remainings: vec![],
        },
    )
    .await
    .is_err());

    Ok(())
}

#[tokio::test]
async fn test_self_trade_no_fees() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0: owner_base_ata,
        owner_token_1: owner_quote_ata,
        market,

        market_base_vault,
        market_quote_vault,
        account_1: open_orders_account,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    let place_bid_ix = PlaceOrderInstruction {
        open_orders_account,
        open_orders_admin: None,
        market,
        signer: owner,
        user_token_account: owner_quote_ata,
        market_vault: market_quote_vault,
        side: Side::Bid,
        price_lots: 1000,
        max_base_lots: 1,
        max_quote_lots_including_fees: 10000,
        client_order_id: 1,
        expiry_timestamp: 0,
        order_type: PlaceOrderType::Limit,
        self_trade_behavior: SelfTradeBehavior::default(),
        remainings: vec![],
    };

    let place_ask_ix = PlaceOrderInstruction {
        side: Side::Ask,
        market_vault: market_base_vault,
        user_token_account: owner_base_ata,
        ..place_bid_ix.clone()
    };

    let consume_events_ix = ConsumeEventsInstruction {
        consume_events_admin: None,
        market,
        open_orders_accounts: vec![open_orders_account],
    };

    let settle_funds_ix = SettleFundsInstruction {
        owner,
        market,
        open_orders_account,
        market_base_vault,
        market_quote_vault,
        user_base_account: owner_base_ata,
        user_quote_account: owner_quote_ata,
        referrer_account: None,
    };

    let balances_before = (
        solana.token_account_balance(owner_base_ata).await,
        solana.token_account_balance(owner_quote_ata).await,
    );

    send_tx(solana, place_bid_ix.clone()).await.unwrap();
    send_tx(solana, place_ask_ix.clone()).await.unwrap();
    send_tx(solana, consume_events_ix.clone()).await.unwrap();
    send_tx(solana, settle_funds_ix.clone()).await.unwrap();

    let balances_after = (
        solana.token_account_balance(owner_base_ata).await,
        solana.token_account_balance(owner_quote_ata).await,
    );

    assert_eq!(balances_before, balances_after);

    send_tx(solana, place_ask_ix).await.unwrap();
    send_tx(solana, place_bid_ix).await.unwrap();
    send_tx(solana, consume_events_ix).await.unwrap();
    send_tx(solana, settle_funds_ix).await.unwrap();

    let balances_after = (
        solana.token_account_balance(owner_base_ata).await,
        solana.token_account_balance(owner_quote_ata).await,
    );

    assert_eq!(balances_before, balances_after);

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/cases/test_take_order.rs
use super::*;

#[tokio::test]
async fn test_take_ask_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,

        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let balance_base = solana.token_account_balance(owner_token_0).await;
    let balance_quote = solana.token_account_balance(owner_token_1).await;

    send_tx(
        solana,
        PlaceTakeOrderInstruction {
            market,
            signer: owner,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            market_base_vault,
            market_quote_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,
            open_orders_admin: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 1);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
        assert_eq!(
            balance_base - 100,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote + 99980,
            solana.token_account_balance(owner_token_1).await
        );
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 100);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 20);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_take_bid_order() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        collect_fee_admin,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        price_lots,
        tokens,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize::default()).await?;
    let solana = &context.solana.clone();

    // Set the initial oracle price
    set_stub_oracle_price(solana, &tokens[1], collect_fee_admin, 1000.0).await;

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10000,

            client_order_id: 0,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let balance_base = solana.token_account_balance(owner_token_0).await;
    let balance_quote = solana.token_account_balance(owner_token_1).await;

    send_tx(
        solana,
        PlaceTakeOrderInstruction {
            market,
            signer: owner,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            market_base_vault,
            market_quote_vault,
            side: Side::Bid,
            price_lots,
            max_base_lots: 1,
            max_quote_lots_including_fees: 10040,
            open_orders_admin: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 1);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
        assert_eq!(
            balance_base + 100,
            solana.token_account_balance(owner_token_0).await
        );
        assert_eq!(
            balance_quote - 100020,
            solana.token_account_balance(owner_token_1).await
        );
    }

    send_tx(
        solana,
        ConsumeEventsInstruction {
            consume_events_admin: None,
            market,
            open_orders_accounts: vec![account_1],
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_2.position.bids_base_lots, 0);
        assert_eq!(open_orders_account_1.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_2.position.asks_base_lots, 0);
        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 100020);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    send_tx(
        solana,
        SettleFundsInstruction {
            owner,
            market,
            open_orders_account: account_1,
            market_base_vault,
            market_quote_vault,
            user_base_account: owner_token_0,
            user_quote_account: owner_token_1,
            referrer_account: None,
        },
    )
    .await
    .unwrap();

    {
        let open_orders_account_1 = solana.get_account::<OpenOrdersAccount>(account_1).await;
        let open_orders_account_2 = solana.get_account::<OpenOrdersAccount>(account_2).await;

        assert_eq!(open_orders_account_1.position.base_free_native, 0);
        assert_eq!(open_orders_account_2.position.base_free_native, 0);
        assert_eq!(open_orders_account_1.position.quote_free_native, 0);
        assert_eq!(open_orders_account_2.position.quote_free_native, 0);
    }

    Ok(())
}

#[tokio::test]
async fn test_negative_spread_ask() -> Result<(), TransportError> {
    let TestInitialize {
        context,
        owner,
        owner_token_0,
        owner_token_1,
        market,
        market_base_vault,
        market_quote_vault,
        account_1,
        account_2,
        ..
    } = TestContext::new_with_market(TestNewMarketInitialize {
        quote_lot_size: 100,
        base_lot_size: 1_000_000_000,
        ..TestNewMarketInitialize::default()
    })
    .await?;
    let solana = &context.solana.clone();

    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_1,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_1,
            market_vault: market_quote_vault,
            side: Side::Bid,
            price_lots: 10_000,     // $1
            max_base_lots: 1000000, // wahtever
            max_quote_lots_including_fees: 10_000,
            client_order_id: 1,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::default(),
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    // This order doesn't take any due max_quote_lots_including_fees but it's also don't post in on the book
    send_tx(
        solana,
        PlaceOrderInstruction {
            open_orders_account: account_2,
            open_orders_admin: None,
            market,
            signer: owner,
            user_token_account: owner_token_0,
            market_vault: market_base_vault,
            side: Side::Ask,
            price_lots: 7_500,
            max_base_lots: 1,
            max_quote_lots_including_fees: 7_500,
            client_order_id: 25,
            expiry_timestamp: 0,
            order_type: PlaceOrderType::Limit,
            self_trade_behavior: SelfTradeBehavior::AbortTransaction,
            remainings: vec![],
        },
    )
    .await
    .unwrap();

    let position = solana
        .get_account::<OpenOrdersAccount>(account_2)
        .await
        .position;

    assert_eq!(position.asks_base_lots, 0);
    assert_eq!(position.bids_base_lots, 0);

    Ok(())
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/client.rs
#![allow(dead_code)]

use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken, token::Token};
use solana_program::instruction::Instruction;
use solana_program_test::BanksClientError;
use solana_sdk::instruction;
use solana_sdk::transport::TransportError;
use std::sync::Arc;

use super::solana::SolanaCookie;
use super::utils::TestKeypair;
use openbook_v2::{
    state::*, PlaceMultipleOrdersArgs, PlaceOrderArgs, PlaceOrderPeggedArgs, PlaceTakeOrderArgs,
};

#[async_trait::async_trait(?Send)]
pub trait ClientAccountLoader {
    async fn load_bytes(&self, pubkey: &Pubkey) -> Option<Vec<u8>>;
    async fn load<T: AccountDeserialize>(&self, pubkey: &Pubkey) -> Option<T> {
        let bytes = self.load_bytes(pubkey).await?;
        AccountDeserialize::try_deserialize(&mut &bytes[..]).ok()
    }
}

#[async_trait::async_trait(?Send)]
impl ClientAccountLoader for &SolanaCookie {
    async fn load_bytes(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.get_account_data(*pubkey).await
    }
}

// TODO: report error outwards etc
pub async fn send_tx<CI: ClientInstruction>(
    solana: &SolanaCookie,
    ix: CI,
) -> std::result::Result<CI::Accounts, TransportError> {
    let (accounts, instruction) = ix.to_instruction(solana).await;
    let signers = ix.signers();
    let instructions = vec![instruction];
    solana
        .process_transaction(&instructions, Some(&signers[..]))
        .await?;
    Ok(accounts)
}

pub async fn send_tx_and_get_ix_custom_error<CI: ClientInstruction>(
    solana: &SolanaCookie,
    ix: CI,
) -> Option<u32> {
    let tx_result = send_tx(solana, ix).await;

    if let Err(TransportError::TransactionError(
        solana_sdk::transaction::TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(err_num),
        ),
    )) = tx_result
    {
        Some(err_num)
    } else {
        None
    }
}

/// Build a transaction from multiple instructions
pub struct ClientTransaction {
    solana: Arc<SolanaCookie>,
    instructions: Vec<instruction::Instruction>,
    signers: Vec<TestKeypair>,
}

impl<'a> ClientTransaction {
    pub fn new(solana: &Arc<SolanaCookie>) -> Self {
        Self {
            solana: solana.clone(),
            instructions: vec![],
            signers: vec![],
        }
    }

    pub async fn add_instruction<CI: ClientInstruction>(&mut self, ix: CI) -> CI::Accounts {
        let solana: &SolanaCookie = &self.solana;
        let (accounts, instruction) = ix.to_instruction(solana).await;
        self.instructions.push(instruction);
        self.signers.extend(ix.signers());
        accounts
    }

    pub fn add_instruction_direct(&mut self, ix: instruction::Instruction) {
        self.instructions.push(ix);
    }

    pub fn add_signer(&mut self, keypair: TestKeypair) {
        self.signers.push(keypair);
    }

    pub async fn send(&self) -> std::result::Result<(), BanksClientError> {
        self.solana
            .process_transaction(&self.instructions, Some(&self.signers))
            .await
    }
}

#[async_trait::async_trait(?Send)]
pub trait ClientInstruction {
    type Accounts: anchor_lang::ToAccountMetas;
    type Instruction: anchor_lang::InstructionData;

    async fn to_instruction(
        &self,
        loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction);
    fn signers(&self) -> Vec<TestKeypair>;
}

fn make_instruction(
    program_id: Pubkey,
    accounts: &impl anchor_lang::ToAccountMetas,
    data: impl anchor_lang::InstructionData,
) -> instruction::Instruction {
    instruction::Instruction {
        program_id,
        accounts: anchor_lang::ToAccountMetas::to_account_metas(accounts, None),
        data: anchor_lang::InstructionData::data(&data),
    }
}

pub fn get_market_address(market: TestKeypair) -> Pubkey {
    Pubkey::find_program_address(
        &[b"Market".as_ref(), market.pubkey().to_bytes().as_ref()],
        &openbook_v2::id(),
    )
    .0
}
pub async fn set_stub_oracle_price(
    solana: &SolanaCookie,
    token: &super::setup::Token,
    owner: TestKeypair,
    price: f64,
) {
    send_tx(
        solana,
        StubOracleSetInstruction {
            owner,
            mint: token.mint.pubkey,
            price,
        },
    )
    .await
    .unwrap();
}

pub struct CreateOpenOrdersIndexerInstruction {
    pub market: Pubkey,
    pub owner: TestKeypair,
    pub payer: TestKeypair,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CreateOpenOrdersIndexerInstruction {
    type Accounts = openbook_v2::accounts::CreateOpenOrdersIndexer;
    type Instruction = openbook_v2::instruction::CreateOpenOrdersIndexer;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = openbook_v2::instruction::CreateOpenOrdersIndexer {};

        let open_orders_indexer = Pubkey::find_program_address(
            &[b"OpenOrdersIndexer".as_ref(), self.owner.pubkey().as_ref()],
            &program_id,
        )
        .0;

        let accounts = openbook_v2::accounts::CreateOpenOrdersIndexer {
            payer: self.payer.pubkey(),
            owner: self.owner.pubkey(),
            open_orders_indexer,
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner, self.payer]
    }
}

pub struct CreateOpenOrdersAccountInstruction {
    pub account_num: u32,
    pub market: Pubkey,
    pub owner: TestKeypair,
    pub payer: TestKeypair,
    pub delegate: Option<Pubkey>,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CreateOpenOrdersAccountInstruction {
    type Accounts = openbook_v2::accounts::CreateOpenOrdersAccount;
    type Instruction = openbook_v2::instruction::CreateOpenOrdersAccount;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = openbook_v2::instruction::CreateOpenOrdersAccount {
            name: "test".to_string(),
        };

        let open_orders_indexer = Pubkey::find_program_address(
            &[b"OpenOrdersIndexer".as_ref(), self.owner.pubkey().as_ref()],
            &program_id,
        )
        .0;

        let open_orders_account = Pubkey::find_program_address(
            &[
                b"OpenOrders".as_ref(),
                self.owner.pubkey().as_ref(),
                &self.account_num.to_le_bytes(),
            ],
            &program_id,
        )
        .0;

        let accounts = openbook_v2::accounts::CreateOpenOrdersAccount {
            owner: self.owner.pubkey(),
            open_orders_indexer,
            open_orders_account,
            market: self.market,
            payer: self.payer.pubkey(),
            delegate_account: self.delegate,
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner, self.payer]
    }
}

pub struct CloseOpenOrdersAccountInstruction {
    pub account_num: u32,
    pub market: Pubkey,
    pub owner: TestKeypair,
    pub sol_destination: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CloseOpenOrdersAccountInstruction {
    type Accounts = openbook_v2::accounts::CloseOpenOrdersAccount;
    type Instruction = openbook_v2::instruction::CloseOpenOrdersAccount;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = openbook_v2::instruction::CloseOpenOrdersAccount {};

        let open_orders_indexer = Pubkey::find_program_address(
            &[b"OpenOrdersIndexer".as_ref(), self.owner.pubkey().as_ref()],
            &program_id,
        )
        .0;

        let open_orders_account = Pubkey::find_program_address(
            &[
                b"OpenOrders".as_ref(),
                self.owner.pubkey().as_ref(),
                &self.account_num.to_le_bytes(),
            ],
            &program_id,
        )
        .0;

        let accounts = openbook_v2::accounts::CloseOpenOrdersAccount {
            owner: self.owner.pubkey(),
            open_orders_indexer,
            open_orders_account,
            sol_destination: self.sol_destination,
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

#[derive(Default)]
pub struct CreateMarketInstruction {
    pub collect_fee_admin: Pubkey,
    pub open_orders_admin: Option<Pubkey>,
    pub consume_events_admin: Option<Pubkey>,
    pub close_market_admin: Option<Pubkey>,
    pub oracle_a: Option<Pubkey>,
    pub oracle_b: Option<Pubkey>,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub name: String,
    pub bids: Pubkey,
    pub asks: Pubkey,
    pub event_heap: Pubkey,
    pub market: TestKeypair,
    pub payer: TestKeypair,
    pub quote_lot_size: i64,
    pub base_lot_size: i64,
    pub maker_fee: i64,
    pub taker_fee: i64,
    pub fee_penalty: u64,
    pub settle_fee_flat: f32,
    pub settle_fee_amount_threshold: f32,
    pub time_expiry: i64,
}
impl CreateMarketInstruction {
    pub async fn with_new_book_and_heap(
        solana: &SolanaCookie,
        oracle_a: Option<Pubkey>,
        oracle_b: Option<Pubkey>,
    ) -> Self {
        CreateMarketInstruction {
            bids: solana
                .create_account_for_type::<BookSide>(&openbook_v2::id())
                .await,
            asks: solana
                .create_account_for_type::<BookSide>(&openbook_v2::id())
                .await,
            event_heap: solana
                .create_account_for_type::<EventHeap>(&openbook_v2::id())
                .await,
            oracle_a,
            oracle_b,
            ..CreateMarketInstruction::default()
        }
    }
}

#[async_trait::async_trait(?Send)]
impl ClientInstruction for CreateMarketInstruction {
    type Accounts = openbook_v2::accounts::CreateMarket;
    type Instruction = openbook_v2::instruction::CreateMarket;
    async fn to_instruction(
        &self,
        _loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            name: "ONE-TWO".to_string(),
            oracle_config: OracleConfigParams {
                conf_filter: 0.1,
                max_staleness_slots: Some(100),
            },
            quote_lot_size: self.quote_lot_size,
            base_lot_size: self.base_lot_size,
            maker_fee: self.maker_fee,
            taker_fee: self.taker_fee,
            time_expiry: self.time_expiry,
        };

        let event_authority =
            Pubkey::find_program_address(&[b"__event_authority".as_ref()], &openbook_v2::id()).0;

        let market_authority = Pubkey::find_program_address(
            &[b"Market".as_ref(), self.market.pubkey().to_bytes().as_ref()],
            &openbook_v2::id(),
        )
        .0;

        let market_base_vault = spl_associated_token_account::get_associated_token_address(
            &market_authority,
            &self.base_mint,
        );
        let market_quote_vault = spl_associated_token_account::get_associated_token_address(
            &market_authority,
            &self.quote_mint,
        );

        let accounts = Self::Accounts {
            market: self.market.pubkey(),
            market_authority,
            bids: self.bids,
            asks: self.asks,
            event_heap: self.event_heap,
            payer: self.payer.pubkey(),
            market_base_vault,
            market_quote_vault,
            quote_mint: self.quote_mint,
            base_mint: self.base_mint,
            system_program: System::id(),
            token_program: Token::id(),
            associated_token_program: AssociatedToken::id(),
            collect_fee_admin: self.collect_fee_admin,
            open_orders_admin: self.open_orders_admin,
            consume_events_admin: self.consume_events_admin,
            close_market_admin: self.close_market_admin,
            oracle_a: self.oracle_a,
            oracle_b: self.oracle_b,
            event_authority,
            program: openbook_v2::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.payer, self.market]
    }
}

#[derive(Clone)]
pub struct PlaceOrderInstruction {
    pub open_orders_account: Pubkey,
    pub open_orders_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub market_vault: Pubkey,
    pub user_token_account: Pubkey,
    pub side: Side,
    pub price_lots: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub client_order_id: u64,
    pub expiry_timestamp: u64,
    pub order_type: PlaceOrderType,
    pub self_trade_behavior: SelfTradeBehavior,
    pub remainings: Vec<Pubkey>,
}

#[async_trait::async_trait(?Send)]
impl ClientInstruction for PlaceOrderInstruction {
    type Accounts = openbook_v2::accounts::PlaceOrder;
    type Instruction = openbook_v2::instruction::PlaceOrder;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            args: PlaceOrderArgs {
                side: self.side,
                price_lots: self.price_lots,
                max_base_lots: self.max_base_lots,
                max_quote_lots_including_fees: self.max_quote_lots_including_fees,
                client_order_id: self.client_order_id,
                order_type: self.order_type,
                expiry_timestamp: self.expiry_timestamp,
                self_trade_behavior: self.self_trade_behavior,
                limit: 10,
            },
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            open_orders_admin: self.open_orders_admin.map(|kp| kp.pubkey()),
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            oracle_a: market.oracle_a.into(),
            oracle_b: market.oracle_b.into(),
            signer: self.signer.pubkey(),
            user_token_account: self.user_token_account,
            market_vault: self.market_vault,
            token_program: Token::id(),
        };
        let mut instruction = make_instruction(program_id, &accounts, instruction);
        let mut vec_remainings: Vec<AccountMeta> = Vec::new();
        for remaining in &self.remainings {
            vec_remainings.push(AccountMeta {
                pubkey: *remaining,
                is_signer: false,
                is_writable: true,
            })
        }
        instruction.accounts.append(&mut vec_remainings);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        let mut signers = vec![self.signer];
        if let Some(open_orders_admin) = self.open_orders_admin {
            signers.push(open_orders_admin);
        }

        signers
    }
}

#[derive(Clone)]
pub struct PlaceOrderPeggedInstruction {
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub user_token_account: Pubkey,
    pub market_vault: Pubkey,
    pub side: Side,
    pub price_offset: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub client_order_id: u64,
    pub peg_limit: i64,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for PlaceOrderPeggedInstruction {
    type Accounts = openbook_v2::accounts::PlaceOrder;
    type Instruction = openbook_v2::instruction::PlaceOrderPegged;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            args: PlaceOrderPeggedArgs {
                side: self.side,
                price_offset_lots: self.price_offset,
                peg_limit: self.peg_limit,
                max_base_lots: self.max_base_lots,
                max_quote_lots_including_fees: self.max_quote_lots_including_fees,
                client_order_id: self.client_order_id,
                order_type: PlaceOrderType::Limit,
                expiry_timestamp: 0,
                self_trade_behavior: SelfTradeBehavior::default(),
                limit: 10,
            },
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            open_orders_admin: None,
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            oracle_a: market.oracle_a.into(),
            oracle_b: market.oracle_b.into(),
            signer: self.signer.pubkey(),
            user_token_account: self.user_token_account,
            market_vault: self.market_vault,
            token_program: Token::id(),
        };
        let instruction = make_instruction(program_id, &accounts, instruction);

        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.signer]
    }
}

pub struct PlaceTakeOrderInstruction {
    pub open_orders_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub user_base_account: Pubkey,
    pub user_quote_account: Pubkey,
    pub side: Side,
    pub price_lots: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for PlaceTakeOrderInstruction {
    type Accounts = openbook_v2::accounts::PlaceTakeOrder;
    type Instruction = openbook_v2::instruction::PlaceTakeOrder;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            args: PlaceTakeOrderArgs {
                side: self.side,
                price_lots: self.price_lots,
                max_base_lots: self.max_base_lots,
                max_quote_lots_including_fees: self.max_quote_lots_including_fees,
                order_type: PlaceOrderType::ImmediateOrCancel,
                limit: 10,
            },
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            open_orders_admin: self.open_orders_admin.map(|kp| kp.pubkey()),
            market: self.market,
            market_authority: market.market_authority,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            oracle_a: market.oracle_a.into(),
            oracle_b: market.oracle_b.into(),
            signer: self.signer.pubkey(),
            penalty_payer: self.signer.pubkey(),
            user_base_account: self.user_base_account,
            user_quote_account: self.user_quote_account,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            token_program: Token::id(),
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        let mut signers = vec![self.signer];
        if let Some(open_orders_admin) = self.open_orders_admin {
            signers.push(open_orders_admin);
        }

        signers
    }
}

pub struct CancelOrderInstruction {
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub order_id: u128,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CancelOrderInstruction {
    type Accounts = openbook_v2::accounts::CancelOrder;
    type Instruction = openbook_v2::instruction::CancelOrder;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            order_id: self.order_id,
        };
        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            signer: self.signer.pubkey(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.signer]
    }
}

pub struct CancelOrderByClientOrderIdInstruction {
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub client_order_id: u64,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CancelOrderByClientOrderIdInstruction {
    type Accounts = openbook_v2::accounts::CancelOrder;
    type Instruction = openbook_v2::instruction::CancelOrderByClientOrderId;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            client_order_id: self.client_order_id,
        };
        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            signer: self.signer.pubkey(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.signer]
    }
}

#[derive(Clone)]
pub struct CancelAllOrdersInstruction {
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub signer: TestKeypair,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CancelAllOrdersInstruction {
    type Accounts = openbook_v2::accounts::CancelOrder;
    type Instruction = openbook_v2::instruction::CancelAllOrders;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            side_option: None,
            limit: 5,
        };
        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            signer: self.signer.pubkey(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.signer]
    }
}

#[derive(Clone)]
pub struct ConsumeEventsInstruction {
    pub consume_events_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub open_orders_accounts: Vec<Pubkey>,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for ConsumeEventsInstruction {
    type Accounts = openbook_v2::accounts::ConsumeEvents;
    type Instruction = openbook_v2::instruction::ConsumeEvents;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction { limit: 10 };

        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            consume_events_admin: self.consume_events_admin.map(|kp| kp.pubkey()),
            market: self.market,
            event_heap: market.event_heap,
        };

        let mut instruction = make_instruction(program_id, &accounts, instruction);
        instruction
            .accounts
            .extend(self.open_orders_accounts.iter().map(|ma| AccountMeta {
                pubkey: *ma,
                is_signer: false,
                is_writable: true,
            }));
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        match self.consume_events_admin {
            Some(consume_events_admin) => vec![consume_events_admin],
            None => vec![],
        }
    }
}

pub struct ConsumeGivenEventsInstruction {
    pub consume_events_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub open_orders_accounts: Vec<Pubkey>,
    pub slots: Vec<usize>,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for ConsumeGivenEventsInstruction {
    type Accounts = openbook_v2::accounts::ConsumeEvents;
    type Instruction = openbook_v2::instruction::ConsumeGivenEvents;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            slots: self.slots.clone(),
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            consume_events_admin: self.consume_events_admin.map(|kp| kp.pubkey()),
            market: self.market,
            event_heap: market.event_heap,
        };

        let mut instruction = make_instruction(program_id, &accounts, instruction);
        instruction
            .accounts
            .extend(self.open_orders_accounts.iter().map(|ma| AccountMeta {
                pubkey: *ma,
                is_signer: false,
                is_writable: true,
            }));
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        match self.consume_events_admin {
            Some(consume_events_admin) => vec![consume_events_admin],
            None => vec![],
        }
    }
}

#[derive(Clone)]
pub struct SettleFundsInstruction {
    pub owner: TestKeypair,
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub user_base_account: Pubkey,
    pub user_quote_account: Pubkey,
    pub referrer_account: Option<Pubkey>,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for SettleFundsInstruction {
    type Accounts = openbook_v2::accounts::SettleFunds;
    type Instruction = openbook_v2::instruction::SettleFunds;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};
        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            owner: self.owner.pubkey(),
            penalty_payer: self.owner.pubkey(),
            open_orders_account: self.open_orders_account,
            market: self.market,
            market_authority: market.market_authority,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            user_base_account: self.user_base_account,
            user_quote_account: self.user_quote_account,
            referrer_account: self.referrer_account,
            token_program: Token::id(),
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

#[derive(Clone)]
pub struct SettleFundsExpiredInstruction {
    pub close_market_admin: TestKeypair,
    pub owner: TestKeypair,
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub user_base_account: Pubkey,
    pub user_quote_account: Pubkey,
    pub referrer_account: Option<Pubkey>,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for SettleFundsExpiredInstruction {
    type Accounts = openbook_v2::accounts::SettleFundsExpired;
    type Instruction = openbook_v2::instruction::SettleFundsExpired;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};
        let market: Market = account_loader.load(&self.market).await.unwrap();
        let accounts = Self::Accounts {
            close_market_admin: self.close_market_admin.pubkey(),
            owner: self.owner.pubkey(),
            penalty_payer: self.owner.pubkey(),
            open_orders_account: self.open_orders_account,
            market: self.market,
            market_authority: market.market_authority,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            user_base_account: self.user_base_account,
            user_quote_account: self.user_quote_account,
            referrer_account: self.referrer_account,
            token_program: Token::id(),
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.close_market_admin, self.owner]
    }
}

pub struct SweepFeesInstruction {
    pub collect_fee_admin: TestKeypair,
    pub market: Pubkey,
    pub market_quote_vault: Pubkey,
    pub token_receiver_account: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for SweepFeesInstruction {
    type Accounts = openbook_v2::accounts::SweepFees;
    type Instruction = openbook_v2::instruction::SweepFees;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};
        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            collect_fee_admin: self.collect_fee_admin.pubkey(),
            market: self.market,
            market_authority: market.market_authority,
            market_quote_vault: self.market_quote_vault,
            token_receiver_account: self.token_receiver_account,
            token_program: Token::id(),
        };
        let instruction = make_instruction(program_id, &accounts, instruction);

        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.collect_fee_admin]
    }
}

pub struct DepositInstruction {
    pub open_orders_account: Pubkey,
    pub market: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub user_base_account: Pubkey,
    pub user_quote_account: Pubkey,
    pub owner: TestKeypair,
    pub base_amount: u64,
    pub quote_amount: u64,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for DepositInstruction {
    type Accounts = openbook_v2::accounts::Deposit;
    type Instruction = openbook_v2::instruction::Deposit;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            base_amount: self.base_amount,
            quote_amount: self.quote_amount,
        };

        let accounts = Self::Accounts {
            owner: self.owner.pubkey(),
            open_orders_account: self.open_orders_account,
            market: self.market,
            market_base_vault: self.market_base_vault,
            market_quote_vault: self.market_quote_vault,
            user_base_account: self.user_base_account,
            user_quote_account: self.user_quote_account,
            token_program: Token::id(),
        };
        let instruction = make_instruction(program_id, &accounts, instruction);

        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

pub struct StubOracleSetInstruction {
    pub mint: Pubkey,
    pub owner: TestKeypair,
    pub price: f64,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for StubOracleSetInstruction {
    type Accounts = openbook_v2::accounts::StubOracleSet;
    type Instruction = openbook_v2::instruction::StubOracleSet;

    async fn to_instruction(
        &self,
        _loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction { price: self.price };

        let oracle = Pubkey::find_program_address(
            &[
                b"StubOracle".as_ref(),
                self.owner.pubkey().as_ref(),
                self.mint.as_ref(),
            ],
            &program_id,
        )
        .0;

        let accounts = Self::Accounts {
            oracle,
            owner: self.owner.pubkey(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

pub struct StubOracleCreate {
    pub mint: Pubkey,
    pub owner: TestKeypair,
    pub payer: TestKeypair,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for StubOracleCreate {
    type Accounts = openbook_v2::accounts::StubOracleCreate;
    type Instruction = openbook_v2::instruction::StubOracleCreate;

    async fn to_instruction(
        &self,
        _loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction { price: 1.0 };

        let oracle = Pubkey::find_program_address(
            &[
                b"StubOracle".as_ref(),
                self.owner.pubkey().as_ref(),
                self.mint.as_ref(),
            ],
            &program_id,
        )
        .0;

        let accounts = Self::Accounts {
            oracle,
            mint: self.mint,
            owner: self.owner.pubkey(),
            payer: self.payer.pubkey(),
            system_program: System::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.payer, self.owner]
    }
}

pub struct StubOracleCloseInstruction {
    pub mint: Pubkey,
    pub owner: TestKeypair,
    pub sol_destination: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for StubOracleCloseInstruction {
    type Accounts = openbook_v2::accounts::StubOracleClose;
    type Instruction = openbook_v2::instruction::StubOracleClose;

    async fn to_instruction(
        &self,
        _loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};

        let oracle = Pubkey::find_program_address(
            &[
                b"StubOracle".as_ref(),
                self.owner.pubkey().as_ref(),
                self.mint.as_ref(),
            ],
            &program_id,
        )
        .0;

        let accounts = Self::Accounts {
            owner: self.owner.pubkey(),
            oracle,
            sol_destination: self.sol_destination,
            token_program: Token::id(),
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

#[derive(Clone)]
pub struct CloseMarketInstruction {
    pub close_market_admin: TestKeypair,
    pub market: Pubkey,
    pub sol_destination: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for CloseMarketInstruction {
    type Accounts = openbook_v2::accounts::CloseMarket;
    type Instruction = openbook_v2::instruction::CloseMarket;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};
        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            close_market_admin: self.close_market_admin.pubkey(),
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            token_program: Token::id(),
            sol_destination: self.sol_destination,
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.close_market_admin]
    }
}

pub struct SetMarketExpiredInstruction {
    pub close_market_admin: TestKeypair,
    pub market: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for SetMarketExpiredInstruction {
    type Accounts = openbook_v2::accounts::SetMarketExpired;
    type Instruction = openbook_v2::instruction::SetMarketExpired;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};

        let accounts = Self::Accounts {
            close_market_admin: self.close_market_admin.pubkey(),
            market: self.market,
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.close_market_admin]
    }
}

pub struct PruneOrdersInstruction {
    pub close_market_admin: TestKeypair,
    pub market: Pubkey,
    pub open_orders_account: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for PruneOrdersInstruction {
    type Accounts = openbook_v2::accounts::PruneOrders;
    type Instruction = openbook_v2::instruction::PruneOrders;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction { limit: 255 };
        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            close_market_admin: self.close_market_admin.pubkey(),
            market: self.market,
            open_orders_account: self.open_orders_account,
            bids: market.bids,
            asks: market.asks,
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.close_market_admin]
    }
}

pub struct SetDelegateInstruction {
    pub delegate_account: Option<Pubkey>,
    pub owner: TestKeypair,
    pub open_orders_account: Pubkey,
}
#[async_trait::async_trait(?Send)]
impl ClientInstruction for SetDelegateInstruction {
    type Accounts = openbook_v2::accounts::SetDelegate;
    type Instruction = openbook_v2::instruction::SetDelegate;
    async fn to_instruction(
        &self,
        _account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {};

        let accounts = Self::Accounts {
            owner: self.owner.pubkey(),
            open_orders_account: self.open_orders_account,
            delegate_account: self.delegate_account,
        };

        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        vec![self.owner]
    }
}

#[derive(Clone)]
pub struct EditOrderInstruction {
    pub open_orders_account: Pubkey,
    pub open_orders_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub market_vault: Pubkey,
    pub user_token_account: Pubkey,
    pub side: Side,
    pub price_lots: i64,
    pub max_base_lots: i64,
    pub max_quote_lots_including_fees: i64,
    pub client_order_id: u64,
    pub expiry_timestamp: u64,
    pub order_type: PlaceOrderType,
    pub self_trade_behavior: SelfTradeBehavior,
    pub remainings: Vec<Pubkey>,
    pub expected_cancel_size: i64,
}

#[async_trait::async_trait(?Send)]
impl ClientInstruction for EditOrderInstruction {
    type Accounts = openbook_v2::accounts::PlaceOrder;
    type Instruction = openbook_v2::instruction::EditOrder;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            expected_cancel_size: self.expected_cancel_size,
            client_order_id: self.client_order_id,
            place_order: PlaceOrderArgs {
                side: self.side,
                price_lots: self.price_lots,
                max_base_lots: self.max_base_lots,
                max_quote_lots_including_fees: self.max_quote_lots_including_fees,
                client_order_id: self.client_order_id,
                order_type: self.order_type,
                expiry_timestamp: self.expiry_timestamp,
                self_trade_behavior: self.self_trade_behavior,
                limit: 10,
            },
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            open_orders_admin: self.open_orders_admin.map(|kp| kp.pubkey()),
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            oracle_a: market.oracle_a.into(),
            oracle_b: market.oracle_b.into(),
            signer: self.signer.pubkey(),
            user_token_account: self.user_token_account,
            market_vault: self.market_vault,
            token_program: Token::id(),
        };
        let mut instruction = make_instruction(program_id, &accounts, instruction);
        let mut vec_remainings: Vec<AccountMeta> = Vec::new();
        for remaining in &self.remainings {
            vec_remainings.push(AccountMeta {
                pubkey: *remaining,
                is_signer: false,
                is_writable: true,
            })
        }
        instruction.accounts.append(&mut vec_remainings);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        let mut signers = vec![self.signer];
        if let Some(open_orders_admin) = self.open_orders_admin {
            signers.push(open_orders_admin);
        }

        signers
    }
}

#[derive(Clone)]
pub struct CancelAllAndPlaceOrdersInstruction {
    pub open_orders_account: Pubkey,
    pub open_orders_admin: Option<TestKeypair>,
    pub market: Pubkey,
    pub signer: TestKeypair,
    pub user_base_account: Pubkey,
    pub user_quote_account: Pubkey,
    pub orders_type: PlaceOrderType,
    pub bids: Vec<PlaceMultipleOrdersArgs>,
    pub asks: Vec<PlaceMultipleOrdersArgs>,
}

#[async_trait::async_trait(?Send)]
impl ClientInstruction for CancelAllAndPlaceOrdersInstruction {
    type Accounts = openbook_v2::accounts::CancelAllAndPlaceOrders;
    type Instruction = openbook_v2::instruction::CancelAllAndPlaceOrders;
    async fn to_instruction(
        &self,
        account_loader: impl ClientAccountLoader + 'async_trait,
    ) -> (Self::Accounts, instruction::Instruction) {
        let program_id = openbook_v2::id();
        let instruction = Self::Instruction {
            orders_type: self.orders_type,
            bids: self.bids.clone(),
            asks: self.asks.clone(),
            limit: 10,
        };

        let market: Market = account_loader.load(&self.market).await.unwrap();

        let accounts = Self::Accounts {
            open_orders_account: self.open_orders_account,
            open_orders_admin: self.open_orders_admin.map(|kp| kp.pubkey()),
            market: self.market,
            bids: market.bids,
            asks: market.asks,
            event_heap: market.event_heap,
            oracle_a: market.oracle_a.into(),
            oracle_b: market.oracle_b.into(),
            signer: self.signer.pubkey(),
            user_base_account: self.user_base_account,
            user_quote_account: self.user_quote_account,
            market_base_vault: market.market_base_vault,
            market_quote_vault: market.market_quote_vault,
            token_program: Token::id(),
        };
        let instruction = make_instruction(program_id, &accounts, instruction);
        (accounts, instruction)
    }

    fn signers(&self) -> Vec<TestKeypair> {
        let mut signers = vec![self.signer];
        if let Some(open_orders_admin) = self.open_orders_admin {
            signers.push(open_orders_admin);
        }

        signers
    }
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/cookies.rs
use solana_program::pubkey::*;

use super::utils::*;

#[derive(Debug, Clone, Copy)]
pub struct MintCookie {
    pub index: usize,
    pub decimals: u8,
    pub unit: f64,
    pub base_lot: f64,
    pub quote_lot: f64,
    pub pubkey: Pubkey,
    pub authority: TestKeypair,
}

#[derive(Debug, Clone)]
pub struct UserCookie {
    pub key: TestKeypair,
    pub token_accounts: Vec<Pubkey>,
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/mod.rs
#![allow(dead_code)]

use std::cell::RefCell;
use std::{sync::Arc, sync::RwLock};

use fixed::types::I80F48;
use log::*;
use openbook_v2::state::Market;
use solana_program::{program_option::COption, program_pack::Pack};
use solana_program_test::*;
use solana_sdk::pubkey::Pubkey;
pub use solana_sdk::transport::TransportError;
use spl_token::{state::*, *};

use crate::program_test::setup::{create_open_orders_account, create_open_orders_indexer, Token};

pub use client::*;
pub use cookies::*;
pub use solana::*;
pub use utils::*;

pub mod client;
pub mod cookies;
pub mod setup;
pub mod solana;
pub mod utils;

pub struct TestInitialize {
    pub context: TestContext,
    pub collect_fee_admin: TestKeypair,
    pub open_orders_admin: TestKeypair,
    pub close_market_admin: TestKeypair,
    pub consume_events_admin: TestKeypair,
    pub owner: TestKeypair,
    pub payer: TestKeypair,
    pub mints: Vec<MintCookie>,
    pub owner_token_0: Pubkey,
    pub owner_token_1: Pubkey,
    pub market: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub price_lots: i64,
    pub tokens: Vec<Token>,
    pub account_1: Pubkey,
    pub account_2: Pubkey,
    pub bids: Pubkey,
}

trait AddPacked {
    fn add_packable_account<T: Pack>(
        &mut self,
        pubkey: Pubkey,
        amount: u64,
        data: &T,
        owner: &Pubkey,
    );
}

impl AddPacked for ProgramTest {
    fn add_packable_account<T: Pack>(
        &mut self,
        pubkey: Pubkey,
        amount: u64,
        data: &T,
        owner: &Pubkey,
    ) {
        let mut account = solana_sdk::account::Account::new(amount, T::get_packed_len(), owner);
        data.pack_into_slice(&mut account.data);
        self.add_account(pubkey, account);
    }
}

struct LoggerWrapper {
    inner: env_logger::Logger,
    capture: Arc<RwLock<Vec<String>>>,
}

impl Log for LoggerWrapper {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if record
            .target()
            .starts_with("solana_runtime::message_processor")
        {
            let msg = record.args().to_string();
            if let Some(data) = msg.strip_prefix("Program log: ") {
                self.capture.write().unwrap().push(data.into());
            } else if let Some(data) = msg.strip_prefix("Program data: ") {
                self.capture.write().unwrap().push(data.into());
            }
        }
        self.inner.log(record);
    }

    fn flush(&self) {}
}

#[derive(Default)]
pub struct TestContextBuilder {
    test: ProgramTest,
    logger_capture: Arc<RwLock<Vec<String>>>,
    mint0: Pubkey,
}

lazy_static::lazy_static! {
    static ref LOGGER_CAPTURE: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(vec![]));
    static ref LOGGER_LOCK: Arc<RwLock<()>> = Arc::new(RwLock::new(()));
}

impl TestContextBuilder {
    pub fn new() -> Self {
        // We need to intercept logs to capture program log output
        let log_filter = "solana_rbpf=trace,\
                    solana_runtime::message_processor=debug,\
                    solana_runtime::system_instruction_processor=trace,\
                    solana_program_test=info";
        let env_logger =
            env_logger::Builder::from_env(env_logger::Env::new().default_filter_or(log_filter))
                .format_timestamp_nanos()
                .build();
        let _ = log::set_boxed_logger(Box::new(LoggerWrapper {
            inner: env_logger,
            capture: LOGGER_CAPTURE.clone(),
        }));

        // hack to fix https://github.com/coral-xyz/anchor/issues/2738
        pub fn fixed_entry(
            program_id: &Pubkey,
            accounts: &[anchor_lang::prelude::AccountInfo],
            data: &[u8],
        ) -> anchor_lang::solana_program::entrypoint::ProgramResult {
            let extended_lifetime_accs = unsafe {
                core::mem::transmute::<_, &[anchor_lang::prelude::AccountInfo<'_>]>(accounts)
            };
            openbook_v2::entry(program_id, extended_lifetime_accs, data)
        }

        let mut test = ProgramTest::new("openbook_v2", openbook_v2::id(), processor!(fixed_entry));

        // intentionally set to as tight as possible, to catch potential problems early
        test.set_compute_max_units(130000);

        Self {
            test,
            logger_capture: LOGGER_CAPTURE.clone(),
            mint0: Pubkey::new_unique(),
        }
    }

    pub fn test(&mut self) -> &mut ProgramTest {
        &mut self.test
    }

    pub fn create_mints(&mut self) -> Vec<MintCookie> {
        let mut mints: Vec<MintCookie> = vec![
            MintCookie {
                index: 0,
                decimals: 6,
                unit: 10u64.pow(6) as f64,
                base_lot: 100_f64,
                quote_lot: 10_f64,
                pubkey: self.mint0,
                authority: TestKeypair::new(),
            }, // symbol: "MNGO".to_string()
        ];
        for i in 1..10 {
            mints.push(MintCookie {
                index: i,
                decimals: 6,
                unit: 10u64.pow(6) as f64,
                base_lot: 100_f64,
                quote_lot: 10_f64,
                pubkey: Pubkey::default(),
                authority: TestKeypair::new(),
            });
        }
        // Add mints in loop
        for mint in &mut mints {
            let mint_pk = if mint.pubkey == Pubkey::default() {
                Pubkey::new_unique()
            } else {
                mint.pubkey
            };
            mint.pubkey = mint_pk;

            self.test.add_packable_account(
                mint_pk,
                u32::MAX as u64,
                &Mint {
                    is_initialized: true,
                    mint_authority: COption::Some(mint.authority.pubkey()),
                    decimals: mint.decimals,
                    ..Mint::default()
                },
                &spl_token::id(),
            );
        }

        mints
    }

    pub fn create_users(&mut self, mints: &[MintCookie]) -> Vec<UserCookie> {
        let num_users = 4;
        let mut users = Vec::new();
        for _ in 0..num_users {
            let user_key = TestKeypair::new();
            self.test.add_account(
                user_key.pubkey(),
                solana_sdk::account::Account::new(
                    u32::MAX as u64,
                    0,
                    &solana_sdk::system_program::id(),
                ),
            );

            // give every user 10^18 (< 2^60) of every token
            // ~~ 1 trillion in case of 6 decimals
            let mut token_accounts = Vec::new();
            for mint in mints {
                let token_key = Pubkey::new_unique();
                self.test.add_packable_account(
                    token_key,
                    u32::MAX as u64,
                    &spl_token::state::Account {
                        mint: mint.pubkey,
                        owner: user_key.pubkey(),
                        amount: 1_000_000_000_000_000_000,
                        state: spl_token::state::AccountState::Initialized,
                        ..spl_token::state::Account::default()
                    },
                    &spl_token::id(),
                );

                token_accounts.push(token_key);
            }
            users.push(UserCookie {
                key: user_key,
                token_accounts,
            });
        }

        users
    }

    pub async fn start_default(mut self) -> TestContext {
        let mints = self.create_mints();
        let users = self.create_users(&mints);

        let solana = self.start().await;

        TestContext {
            solana,
            mints,
            users,
        }
    }

    pub async fn start(self) -> Arc<SolanaCookie> {
        let mut context = self.test.start_with_context().await;
        let rent = context.banks_client.get_rent().await.unwrap();

        Arc::new(SolanaCookie {
            context: RefCell::new(context),
            rent,
            logger_capture: self.logger_capture.clone(),
            logger_lock: LOGGER_LOCK.clone(),
            last_transaction_log: RefCell::new(vec![]),
        })
    }
}

pub struct TestContext {
    pub solana: Arc<SolanaCookie>,
    pub mints: Vec<MintCookie>,
    pub users: Vec<UserCookie>,
}

pub struct TestNewMarketInitialize {
    pub fee_penalty: u64,
    pub quote_lot_size: i64,
    pub base_lot_size: i64,
    pub maker_fee: i64,
    pub taker_fee: i64,
    pub open_orders_admin_bool: bool,
    pub close_market_admin_bool: bool,
    pub consume_events_admin_bool: bool,
    pub time_expiry: i64,
    pub with_oracle: bool,
    pub payer_as_delegate: bool,
}

impl Default for TestNewMarketInitialize {
    fn default() -> TestNewMarketInitialize {
        TestNewMarketInitialize {
            fee_penalty: 0,
            quote_lot_size: 10,
            base_lot_size: 100,
            maker_fee: -200,
            taker_fee: 400,
            open_orders_admin_bool: false,
            close_market_admin_bool: false,
            consume_events_admin_bool: false,
            time_expiry: 0,
            with_oracle: true,
            payer_as_delegate: false,
        }
    }
}
impl TestContext {
    pub async fn new() -> Self {
        TestContextBuilder::new().start_default().await
    }

    pub async fn new_with_market(
        args: TestNewMarketInitialize,
    ) -> Result<TestInitialize, TransportError> {
        let context = TestContextBuilder::new().start_default().await;
        let solana = &context.solana.clone();

        let collect_fee_admin_acc = TestKeypair::new();
        let open_orders_admin_acc = TestKeypair::new();
        let open_orders_admin = if args.open_orders_admin_bool {
            Some(open_orders_admin_acc.pubkey())
        } else {
            None
        };
        let close_market_admin_acc = TestKeypair::new();
        let close_market_admin = if args.close_market_admin_bool {
            Some(close_market_admin_acc.pubkey())
        } else {
            None
        };
        let consume_events_admin_acc = TestKeypair::new();
        let consume_events_admin = if args.consume_events_admin_bool {
            Some(consume_events_admin_acc.pubkey())
        } else {
            None
        };

        let owner = context.users[0].key;
        let payer = context.users[1].key;
        let mints = &context.mints[0..=2];

        let owner_token_0 = context.users[0].token_accounts[0];
        let owner_token_1 = context.users[0].token_accounts[1];

        let tokens = Token::create(mints.to_vec(), solana, collect_fee_admin_acc, payer).await;

        // Create a market

        let market = TestKeypair::new();

        let oracle = if args.with_oracle {
            Some(tokens[0].oracle)
        } else {
            None
        };

        let openbook_v2::accounts::CreateMarket {
            market,
            market_base_vault,
            market_quote_vault,
            bids,
            ..
        } = send_tx(
            solana,
            CreateMarketInstruction {
                collect_fee_admin: collect_fee_admin_acc.pubkey(),
                open_orders_admin,
                close_market_admin,
                consume_events_admin,
                payer,
                market,
                quote_lot_size: args.quote_lot_size,
                base_lot_size: args.base_lot_size,
                maker_fee: args.maker_fee,
                taker_fee: args.taker_fee,
                base_mint: mints[0].pubkey,
                quote_mint: mints[1].pubkey,
                fee_penalty: args.fee_penalty,
                time_expiry: args.time_expiry,
                ..CreateMarketInstruction::with_new_book_and_heap(solana, oracle, None).await
            },
        )
        .await
        .unwrap();

        let _indexer = create_open_orders_indexer(solana, &context.users[1], owner, market).await;

        let delegate_opt = if args.payer_as_delegate {
            Some(payer.pubkey())
        } else {
            None
        };

        let account_1 =
            create_open_orders_account(solana, owner, market, 1, &context.users[1], delegate_opt)
                .await;
        let account_2 =
            create_open_orders_account(solana, owner, market, 2, &context.users[1], delegate_opt)
                .await;

        let price_lots = {
            let market = solana.get_account::<Market>(market).await;
            market.native_price_to_lot(I80F48::from(1000)).unwrap()
        };

        let mints = mints.to_vec();

        Ok(TestInitialize {
            context,
            collect_fee_admin: collect_fee_admin_acc,
            open_orders_admin: open_orders_admin_acc,
            close_market_admin: close_market_admin_acc,
            consume_events_admin: consume_events_admin_acc,
            owner,
            payer,
            mints,
            owner_token_0,
            owner_token_1,
            market,

            market_base_vault,
            market_quote_vault,
            price_lots,
            tokens,
            account_1,
            account_2,
            bids,
        })
    }
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/setup.rs
#![allow(dead_code)]

use anchor_lang::prelude::*;

use super::client::*;
use super::solana::SolanaCookie;
use super::{send_tx, MintCookie, TestKeypair, UserCookie};

#[derive(Clone)]
pub struct Token {
    pub index: u16,
    pub mint: MintCookie,
    pub oracle: Pubkey,
    pub mint_info: Pubkey,
}

impl Token {
    pub async fn create(
        mints: Vec<MintCookie>,
        solana: &SolanaCookie,
        owner: TestKeypair,
        payer: TestKeypair,
    ) -> Vec<Token> {
        let mut tokens = vec![];

        for (index, mint) in mints.iter().enumerate() {
            let create_stub_oracle_accounts = send_tx(
                solana,
                StubOracleCreate {
                    mint: mint.pubkey,
                    owner,
                    payer,
                },
            )
            .await
            .unwrap();
            let oracle = create_stub_oracle_accounts.oracle;
            send_tx(
                solana,
                StubOracleSetInstruction {
                    owner,
                    mint: mint.pubkey,
                    price: 1.0,
                },
            )
            .await
            .unwrap();
            let token_index = index as u16;
            tokens.push(Token {
                index: token_index,
                mint: *mint,
                oracle,
                mint_info: mint.pubkey,
            });
        }
        tokens
    }
}

pub async fn create_open_orders_indexer(
    solana: &SolanaCookie,
    payer: &UserCookie,
    owner: TestKeypair,
    market: Pubkey,
) -> Pubkey {
    send_tx(
        solana,
        CreateOpenOrdersIndexerInstruction {
            market,
            owner,
            payer: payer.key,
        },
    )
    .await
    .unwrap()
    .open_orders_indexer
}

pub async fn create_open_orders_account(
    solana: &SolanaCookie,
    owner: TestKeypair,
    market: Pubkey,
    account_num: u32,
    payer: &UserCookie,
    delegate: Option<Pubkey>,
) -> Pubkey {
    send_tx(
        solana,
        CreateOpenOrdersAccountInstruction {
            account_num,
            market,
            owner,
            payer: payer.key,
            delegate,
        },
    )
    .await
    .unwrap()
    .open_orders_account
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/solana.rs
#![allow(dead_code)]
#![allow(clippy::await_holding_refcell_ref)]

use std::cell::RefCell;
use std::sync::{Arc, RwLock};

use super::utils::TestKeypair;
use anchor_lang::AccountDeserialize;
use anchor_spl::token::TokenAccount;
use solana_program::{program_pack::Pack, rent::*, system_instruction};
use solana_program_test::*;
use solana_sdk::{
    account::ReadableAccount,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::*;

pub struct SolanaCookie {
    pub context: RefCell<ProgramTestContext>,
    pub rent: Rent,
    pub logger_capture: Arc<RwLock<Vec<String>>>,
    pub logger_lock: Arc<RwLock<()>>,
    pub last_transaction_log: RefCell<Vec<String>>,
}

impl SolanaCookie {
    pub async fn process_transaction(
        &self,
        instructions: &[Instruction],
        signers: Option<&[TestKeypair]>,
    ) -> Result<(), BanksClientError> {
        // The locking in this function is convoluted:
        // We capture the program log output by overriding the global logger and capturing
        // messages there. This logger is potentially shared among multiple tests that run
        // concurrently.
        // To allow each independent SolanaCookie to capture only the logs from the transaction
        // passed to process_transaction, wo globally hold the "program_log_lock" for the
        // duration that the tx needs to process. So only a single one can run at a time.
        let tx_log_lock = Arc::new(self.logger_lock.write().unwrap());
        self.logger_capture.write().unwrap().clear();

        let mut context = self.context.borrow_mut();

        let mut transaction =
            Transaction::new_with_payer(instructions, Some(&context.payer.pubkey()));

        let mut all_signers = vec![&context.payer];
        let signer_keypairs =
            signers.map(|signers| signers.iter().map(|s| s.into()).collect::<Vec<Keypair>>());
        let signer_keypair_refs = signer_keypairs
            .as_ref()
            .map(|kps| kps.iter().collect::<Vec<&Keypair>>());

        if let Some(signer_keypair_refs) = signer_keypair_refs {
            all_signers.extend(signer_keypair_refs.iter());
        }

        // This fails when warping is involved - https://gitmemory.com/issue/solana-labs/solana/18201/868325078
        // let recent_blockhash = self.context.banks_client.get_recent_blockhash().await.unwrap();

        transaction.sign(&all_signers, context.last_blockhash);

        let result = context
            .banks_client
            .process_transaction_with_commitment(
                transaction,
                solana_sdk::commitment_config::CommitmentLevel::Processed,
            )
            .await;

        *self.last_transaction_log.borrow_mut() = self.logger_capture.read().unwrap().clone();

        drop(tx_log_lock);
        drop(context);

        // This makes sure every transaction gets a new blockhash, avoiding issues where sending
        // the same transaction again would lead to it being skipped.
        self.advance_by_slots(1).await;

        result
    }

    pub async fn get_clock(&self) -> solana_program::clock::Clock {
        self.context
            .borrow_mut()
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
    }

    pub async fn advance_by_slots(&self, slots: u64) {
        let clock = self.get_clock().await;
        self.context
            .borrow_mut()
            .warp_to_slot(clock.slot + slots + 1)
            .unwrap();
    }

    pub async fn advance_clock_to(&self, target: i64) {
        let mut clock = self.get_clock().await;

        // just advance enough to ensure we get changes over last_updated in various ix
        // if this gets too slow for our tests, remove and replace with manual time offset
        // which is configurable
        while clock.unix_timestamp <= target {
            self.context
                .borrow_mut()
                .warp_to_slot(clock.slot + 50)
                .unwrap();
            clock = self.get_clock().await;
        }
    }

    pub async fn advance_clock_to_next_multiple(&self, window: i64) {
        let ts = self.get_clock().await.unix_timestamp;
        self.advance_clock_to(ts / window * window + window).await
    }

    pub async fn advance_clock(&self, seconds: i64) {
        let clock = self.get_clock().await;
        self.advance_clock_to(clock.unix_timestamp + seconds).await
    }

    pub async fn get_newest_slot_from_history(&self) -> u64 {
        self.context
            .borrow_mut()
            .banks_client
            .get_sysvar::<solana_program::slot_history::SlotHistory>()
            .await
            .unwrap()
            .newest()
    }

    pub async fn create_account_from_len(&self, owner: &Pubkey, len: usize) -> Pubkey {
        let key = TestKeypair::new();
        let rent = self.rent.minimum_balance(len);
        let create_account_instr = solana_sdk::system_instruction::create_account(
            &self.context.borrow().payer.pubkey(),
            &key.pubkey(),
            rent,
            len as u64,
            owner,
        );
        self.process_transaction(&[create_account_instr], Some(&[key]))
            .await
            .unwrap();
        key.pubkey()
    }

    pub async fn create_account_for_type<T>(&self, owner: &Pubkey) -> Pubkey {
        let key = TestKeypair::new();
        let len = 8 + std::mem::size_of::<T>();
        let rent = self.rent.minimum_balance(len);
        let create_account_instr = solana_sdk::system_instruction::create_account(
            &self.context.borrow().payer.pubkey(),
            &key.pubkey(),
            rent,
            len as u64,
            owner,
        );
        self.process_transaction(&[create_account_instr], Some(&[key]))
            .await
            .unwrap();
        key.pubkey()
    }

    pub async fn create_token_account(&self, owner: &Pubkey, mint: Pubkey) -> Pubkey {
        let keypair = TestKeypair::new();
        let rent = self.rent.minimum_balance(spl_token::state::Account::LEN);

        let instructions = [
            system_instruction::create_account(
                &self.context.borrow().payer.pubkey(),
                &keypair.pubkey(),
                rent,
                spl_token::state::Account::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account(
                &spl_token::id(),
                &keypair.pubkey(),
                &mint,
                owner,
            )
            .unwrap(),
        ];

        self.process_transaction(&instructions, Some(&[keypair]))
            .await
            .unwrap();
        keypair.pubkey()
    }

    pub async fn create_associated_token_account(&self, owner: &Pubkey, mint: Pubkey) -> Pubkey {
        let instruction =
            spl_associated_token_account::instruction::create_associated_token_account(
                &self.context.borrow().payer.pubkey(),
                owner,
                &mint,
                &spl_token::id(),
            );

        self.process_transaction(&[instruction], None)
            .await
            .unwrap();

        spl_associated_token_account::get_associated_token_address(owner, &mint)
    }

    // Note: Only one table can be created per authority per slot!
    // pub async fn create_address_lookup_table(
    //     &self,
    //     authority: TestKeypair,
    //     payer: TestKeypair,
    // ) -> Pubkey {
    //     let (instruction, alt_address) =
    //         solana_address_lookup_table_program::instruction::create_lookup_table(
    //             authority.pubkey(),
    //             payer.pubkey(),
    //             self.get_newest_slot_from_history().await,
    //         );
    //     self.process_transaction(&[instruction], Some(&[authority, payer]))
    //         .await
    //         .unwrap();
    //     alt_address
    // }

    pub async fn get_account_data(&self, address: Pubkey) -> Option<Vec<u8>> {
        Some(
            self.context
                .borrow_mut()
                .banks_client
                .get_account(address)
                .await
                .unwrap()?
                .data()
                .to_vec(),
        )
    }

    pub async fn get_account_opt<T: AccountDeserialize>(&self, address: Pubkey) -> Option<T> {
        let data = self.get_account_data(address).await?;
        let mut data_slice: &[u8] = &data;
        AccountDeserialize::try_deserialize(&mut data_slice).ok()
    }

    // Use when accounts are too big for the stack
    pub async fn get_account_boxed<T: AccountDeserialize>(&self, address: Pubkey) -> Box<T> {
        let data = self.get_account_data(address).await.unwrap();
        let mut data_slice: &[u8] = &data;
        Box::new(AccountDeserialize::try_deserialize(&mut data_slice).unwrap())
    }

    pub async fn get_account<T: AccountDeserialize>(&self, address: Pubkey) -> T {
        self.get_account_opt(address).await.unwrap()
    }

    pub async fn token_account_balance(&self, address: Pubkey) -> u64 {
        self.get_account::<TokenAccount>(address).await.amount
    }

    pub async fn set_account_balance(&self, address: Pubkey, amount: u64) {
        let mut account = self
            .context
            .borrow_mut()
            .banks_client
            .get_account(address)
            .await
            .unwrap()
            .unwrap();

        let mut account_data = spl_token::state::Account::unpack(&account.data).unwrap();
        account_data.amount = amount;
        spl_token::state::Account::pack(account_data, &mut account.data).unwrap();

        self.context
            .borrow_mut()
            .set_account(&address, &account.into());
    }

    pub fn program_log(&self) -> Vec<String> {
        self.last_transaction_log.borrow().clone()
    }

    pub fn program_log_events<T: anchor_lang::Event + anchor_lang::AnchorDeserialize>(
        &self,
    ) -> Vec<T> {
        self.program_log()
            .iter()
            .filter_map(|data| {
                let bytes = base64::decode(data).ok()?;
                if bytes[0..8] != T::discriminator() {
                    return None;
                }
                T::try_from_slice(&bytes[8..]).ok()
            })
            .collect()
    }
}


// File: openbook-v2/programs/openbook-v2/tests/program_test/utils.rs
#![allow(dead_code)]

use bytemuck::{bytes_of, Contiguous};
use fixed::types::I80F48;
use solana_program::instruction::InstructionError;
use solana_program::program_error::ProgramError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::TransactionError;
use solana_sdk::transport::TransportError;

pub fn gen_signer_seeds<'a>(nonce: &'a u64, acc_pk: &'a Pubkey) -> [&'a [u8]; 2] {
    [acc_pk.as_ref(), bytes_of(nonce)]
}

pub fn gen_signer_key(
    nonce: u64,
    acc_pk: &Pubkey,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let seeds = gen_signer_seeds(&nonce, acc_pk);
    Ok(Pubkey::create_program_address(&seeds, program_id)?)
}

pub fn create_signer_key_and_nonce(program_id: &Pubkey, acc_pk: &Pubkey) -> (Pubkey, u64) {
    for i in 0..=u64::MAX_VALUE {
        if let Ok(pk) = gen_signer_key(i, acc_pk, program_id) {
            return (pk, i);
        }
    }
    panic!("Could not generate signer key");
}

pub fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::from_base58_string(&keypair.to_base58_string())
}

// Add clone() to Keypair, totally safe in tests
pub trait ClonableKeypair {
    fn clone(&self) -> Self;
}
impl ClonableKeypair for Keypair {
    fn clone(&self) -> Self {
        clone_keypair(self)
    }
}

/// A Keypair-like struct that's Clone and Copy and can be into()ed to a Keypair
///
/// The regular Keypair is neither Clone nor Copy because the key data is sensitive
/// and should not be copied needlessly. That just makes things difficult for tests.
#[derive(Clone, Copy, Debug)]
pub struct TestKeypair([u8; 64]);
impl TestKeypair {
    pub fn new() -> Self {
        Keypair::new().into()
    }

    pub fn to_keypair(&self) -> Keypair {
        Keypair::from_bytes(&self.0).unwrap()
    }

    pub fn pubkey(&self) -> Pubkey {
        solana_sdk::signature::Signer::pubkey(&self.to_keypair())
    }
}
impl Default for TestKeypair {
    fn default() -> Self {
        Self([0; 64])
    }
}
impl<T: std::borrow::Borrow<Keypair>> From<T> for TestKeypair {
    fn from(k: T) -> Self {
        Self(k.borrow().to_bytes())
    }
}
#[allow(clippy::from_over_into)]
impl Into<Keypair> for &TestKeypair {
    fn into(self) -> Keypair {
        self.to_keypair()
    }
}

pub fn assert_openbook_error<T>(
    result: &Result<T, TransportError>,
    expected_error: u32,
    comment: String,
) {
    #[allow(clippy::collapsible_match)]
    match result {
        Ok(_) => panic!("No error returned"),
        Err(TransportError::TransactionError(tx_err)) => match tx_err {
            TransactionError::InstructionError(_, err) => match err {
                InstructionError::Custom(err_num) => {
                    assert_eq!(*err_num, expected_error, "{}", comment);
                }
                _ => panic!("Not an openbook error"),
            },
            _ => panic!("Not an openbook error"),
        },
        _ => panic!("Not an openbook error"),
    }
}

pub fn assert_equal_fixed_f64(value: I80F48, expected: f64, max_error: f64) -> bool {
    let ok = (value.to_num::<f64>() - expected).abs() < max_error;
    if !ok {
        println!("comparison failed: value: {value}, expected: {expected}");
    }
    ok
}

pub fn assert_equal_f64_f64(value: f64, expected: f64, max_error: f64) -> bool {
    let ok = (value - expected).abs() < max_error;
    if !ok {
        println!("comparison failed: value: {value}, expected: {expected}");
    }
    ok
}


// File: openbook-v2/programs/openbook-v2/tests/test_all.rs
#![cfg(feature = "test-bpf")]

mod cases;
pub mod program_test;


