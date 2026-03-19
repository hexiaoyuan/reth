use alloy_consensus::{transaction::TxHashRef, BlockHeader};
use alloy_eip7928::BlockAccessList;
use alloy_eips::{eip2718::Encodable2718, BlockId, BlockNumberOrTag};
use alloy_evm::env::BlockEnvironment;
use alloy_genesis::ChainConfig;
use alloy_primitives::{hex::decode, uint, Address, Bytes, B256, U64};
use alloy_rlp::{Decodable, Encodable};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_rpc_types_eth::{state::EvmOverrides, BlockError, Bundle, StateContext};
use alloy_rpc_types_trace::geth::{
    BlockTraceResult, GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, TraceResult,
};
use async_trait::async_trait;
use futures::Stream;
use jsonrpsee::core::RpcResult;
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_engine_primitives::ConsensusEngineEvent;
use reth_errors::RethError;
use reth_evm::{execute::Executor, ConfigureEvm, EvmEnvFor};
use reth_primitives_traits::{
    Block as BlockTrait, BlockBody, BlockTy, ReceiptWithBloom, RecoveredBlock,
};
use reth_revm::{db::State, witness::ExecutionWitnessRecord};
use reth_rpc_api::DebugApiServer;
use reth_rpc_convert::RpcTxReq;
use reth_rpc_eth_api::{
    helpers::{EthTransactions, TraceExt},
    FromEthApiError, RpcConvert, RpcNodeCore,
};
use reth_rpc_eth_types::EthApiError;
use reth_rpc_server_types::{result::internal_rpc_err, ToRpcResult};
use reth_storage_api::{
    BlockIdReader, BlockReaderIdExt, HeaderProvider, ProviderBlock, ReceiptProviderIdExt,
    StateProofProvider, StateProviderFactory, StateRootProvider, TransactionVariant,
};
use reth_tasks::{pool::BlockingTaskGuard, TaskSpawner};
use reth_trie_common::{updates::TrieUpdates, HashedPostState};
use revm::DatabaseCommit;
use revm_inspectors::tracing::{DebugInspector, TransactionContext};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{AcquireError, OwnedSemaphorePermit};
use tokio_stream::StreamExt;

use alloy_network::TransactionBuilder as _;
use alloy_primitives::U256;
use reth_evm::{Evm as _, TransactionEnv as _, TxEnvFor};
use reth_rpc_eth_types::error::api::{FromEvmError, FromEvmHalt};
use revm::{context::Block as _, context_interface::Transaction as _};
use tracing::info;

/// `debug` API implementation.
///
/// This type provides the functionality for handling `debug` related requests.
pub struct DebugApi<Eth: RpcNodeCore> {
    inner: Arc<DebugApiInner<Eth>>,
}

impl<Eth> DebugApi<Eth>
where
    Eth: RpcNodeCore,
{
    /// Create a new instance of the [`DebugApi`]
    pub fn new(
        eth_api: Eth,
        blocking_task_guard: BlockingTaskGuard,
        executor: impl TaskSpawner,
        mut stream: impl Stream<Item = ConsensusEngineEvent<Eth::Primitives>> + Send + Unpin + 'static,
    ) -> Self {
        let bad_block_store = BadBlockStore::default();
        let inner = Arc::new(DebugApiInner {
            eth_api,
            blocking_task_guard,
            bad_block_store: bad_block_store.clone(),
        });

        // Spawn a task caching bad blocks
        executor.spawn_task(Box::pin(async move {
            while let Some(event) = stream.next().await {
                if let ConsensusEngineEvent::InvalidBlock(block) = event &&
                    let Ok(recovered) =
                        RecoveredBlock::try_recover_sealed(block.as_ref().clone())
                {
                    bad_block_store.insert(recovered);
                }
            }
        }));

        Self { inner }
    }

    /// Access the underlying `Eth` API.
    pub fn eth_api(&self) -> &Eth {
        &self.inner.eth_api
    }

    /// Access the underlying provider.
    pub fn provider(&self) -> &Eth::Provider {
        self.inner.eth_api.provider()
    }
}

// === impl DebugApi ===

impl<Eth> DebugApi<Eth>
where
    Eth: TraceExt,
{
    /// Acquires a permit to execute a tracing call.
    async fn acquire_trace_permit(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        self.inner.blocking_task_guard.clone().acquire_owned().await
    }

    /// Trace the entire block asynchronously
    async fn trace_block(
        &self,
        block: Arc<RecoveredBlock<ProviderBlock<Eth::Provider>>>,
        evm_env: EvmEnvFor<Eth::Evm>,
        opts: GethDebugTracingOptions,
    ) -> Result<Vec<TraceResult>, Eth::Error> {
        self.eth_api()
            .spawn_with_state_at_block(block.parent_hash(), move |eth_api, mut db| {
                let mut results = Vec::with_capacity(block.body().transactions().len());

                eth_api.apply_pre_execution_changes(&block, &mut db, &evm_env)?;

                let mut transactions = block.transactions_recovered().enumerate().peekable();
                let mut inspector = DebugInspector::new(opts).map_err(Eth::Error::from_eth_err)?;
                while let Some((index, tx)) = transactions.next() {
                    let tx_hash = *tx.tx_hash();
                    let tx_env = eth_api.evm_config().tx_env(tx);

                    let res = eth_api.inspect(
                        &mut db,
                        evm_env.clone(),
                        tx_env.clone(),
                        &mut inspector,
                    )?;
                    let result = inspector
                        .get_result(
                            Some(TransactionContext {
                                block_hash: Some(block.hash()),
                                tx_hash: Some(tx_hash),
                                tx_index: Some(index),
                            }),
                            &tx_env,
                            &evm_env.block_env,
                            &res,
                            &mut db,
                        )
                        .map_err(Eth::Error::from_eth_err)?;

                    results.push(TraceResult::Success { result, tx_hash: Some(tx_hash) });
                    if transactions.peek().is_some() {
                        inspector.fuse().map_err(Eth::Error::from_eth_err)?;
                        // need to apply the state changes of this transaction before executing the
                        // next transaction
                        db.commit(res.state)
                    }
                }

                Ok(results)
            })
            .await
    }

    /// Replays the given block and returns the trace of each transaction.
    ///
    /// This expects a rlp encoded block
    ///
    /// Note, the parent of this block must be present, or it will fail.
    pub async fn debug_trace_raw_block(
        &self,
        rlp_block: Bytes,
        opts: GethDebugTracingOptions,
    ) -> Result<Vec<TraceResult>, Eth::Error> {
        let block: ProviderBlock<Eth::Provider> = Decodable::decode(&mut rlp_block.as_ref())
            .map_err(BlockError::RlpDecodeRawBlock)
            .map_err(Eth::Error::from_eth_err)?;

        let evm_env = self
            .eth_api()
            .evm_config()
            .evm_env(block.header())
            .map_err(RethError::other)
            .map_err(Eth::Error::from_eth_err)?;

        // Depending on EIP-2 we need to recover the transactions differently
        let senders =
            if self.provider().chain_spec().is_homestead_active_at_block(block.header().number()) {
                block.body().recover_signers()
            } else {
                block.body().recover_signers_unchecked()
            }
            .map_err(Eth::Error::from_eth_err)?;

        self.trace_block(Arc::new(block.into_recovered_with_signers(senders)), evm_env, opts).await
    }

    /// Replays a block and returns the trace of each transaction.
    pub async fn debug_trace_block(
        &self,
        block_id: BlockId,
        opts: GethDebugTracingOptions,
    ) -> Result<Vec<TraceResult>, Eth::Error> {
        let block_hash = self
            .provider()
            .block_hash_for_id(block_id)
            .map_err(Eth::Error::from_eth_err)?
            .ok_or(EthApiError::HeaderNotFound(block_id))?;

        let ((evm_env, _), block) = futures::try_join!(
            self.eth_api().evm_env_at(block_hash.into()),
            self.eth_api().recovered_block(block_hash.into()),
        )?;

        let block = block.ok_or(EthApiError::HeaderNotFound(block_id))?;

        self.trace_block(block, evm_env, opts).await
    }

    /// Trace the transaction according to the provided options.
    ///
    /// Ref: <https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers>
    pub async fn debug_trace_transaction(
        &self,
        tx_hash: B256,
        opts: GethDebugTracingOptions,
    ) -> Result<GethTrace, Eth::Error> {
        let (transaction, block) = match self.eth_api().transaction_and_block(tx_hash).await? {
            None => return Err(EthApiError::TransactionNotFound.into()),
            Some(res) => res,
        };
        let (evm_env, _) = self.eth_api().evm_env_at(block.hash().into()).await?;

        // we need to get the state of the parent block because we're essentially replaying the
        // block the transaction is included in
        let state_at: BlockId = block.parent_hash().into();
        let block_hash = block.hash();

        self.eth_api()
            .spawn_with_state_at_block(state_at, move |eth_api, mut db| {
                let block_txs = block.transactions_recovered();

                // configure env for the target transaction
                let tx = transaction.into_recovered();

                eth_api.apply_pre_execution_changes(&block, &mut db, &evm_env)?;

                // replay all transactions prior to the targeted transaction
                let index = eth_api.replay_transactions_until(
                    &mut db,
                    evm_env.clone(),
                    block_txs,
                    *tx.tx_hash(),
                )?;

                let tx_env = eth_api.evm_config().tx_env(&tx);

                let mut inspector = DebugInspector::new(opts).map_err(Eth::Error::from_eth_err)?;
                let res =
                    eth_api.inspect(&mut db, evm_env.clone(), tx_env.clone(), &mut inspector)?;
                let trace = inspector
                    .get_result(
                        Some(TransactionContext {
                            block_hash: Some(block_hash),
                            tx_index: Some(index),
                            tx_hash: Some(*tx.tx_hash()),
                        }),
                        &tx_env,
                        &evm_env.block_env,
                        &res,
                        &mut db,
                    )
                    .map_err(Eth::Error::from_eth_err)?;

                Ok(trace)
            })
            .await
    }

    /// The `debug_traceCall` method lets you run an `eth_call` within the context of the given
    /// block execution using the final state of parent block as the base.
    ///
    /// If `tx_index` is provided in opts, the call will be traced at the state after executing
    /// transactions up to the specified index within the block (0-indexed).
    /// If not provided, then uses the post-state (default behavior).
    ///
    /// Differences compare to `eth_call`:
    ///  - `debug_traceCall` executes with __enabled__ basefee check, `eth_call` does not: <https://github.com/paradigmxyz/reth/issues/6240>
    pub async fn debug_trace_call(
        &self,
        call: RpcTxReq<Eth::NetworkTypes>,
        block_id: Option<BlockId>,
        opts: GethDebugTracingCallOptions,
    ) -> Result<GethTrace, Eth::Error> {
        let at = block_id.unwrap_or_default();
        let GethDebugTracingCallOptions {
            tracing_options,
            state_overrides,
            block_overrides,
            tx_index,
        } = opts;
        let overrides = EvmOverrides::new(state_overrides, block_overrides.map(Box::new));

        // Check if we need to replay transactions for a specific tx_index
        if let Some(tx_idx) = tx_index {
            return self
                .debug_trace_call_at_tx_index(call, at, tx_idx as usize, tracing_options, overrides)
                .await;
        }

        let this = self.clone();
        self.eth_api()
            .spawn_with_call_at(call, at, overrides, move |db, evm_env, tx_env| {
                let mut inspector =
                    DebugInspector::new(tracing_options).map_err(Eth::Error::from_eth_err)?;
                let res = this.eth_api().inspect(
                    &mut *db,
                    evm_env.clone(),
                    tx_env.clone(),
                    &mut inspector,
                )?;
                let trace = inspector
                    .get_result(None, &tx_env, &evm_env.block_env, &res, db)
                    .map_err(Eth::Error::from_eth_err)?;
                Ok(trace)
            })
            .await
    }

    /// Helper method to execute `debug_trace_call` at a specific transaction index within a block.
    /// This replays transactions up to the specified index, then executes the trace call in that
    /// state.
    async fn debug_trace_call_at_tx_index(
        &self,
        call: RpcTxReq<Eth::NetworkTypes>,
        block_id: BlockId,
        tx_index: usize,
        tracing_options: GethDebugTracingOptions,
        overrides: EvmOverrides,
    ) -> Result<GethTrace, Eth::Error> {
        // Get the target block to check transaction count
        let block = self
            .eth_api()
            .recovered_block(block_id)
            .await?
            .ok_or(EthApiError::HeaderNotFound(block_id))?;

        if tx_index >= block.transaction_count() {
            // tx_index out of bounds
            return Err(EthApiError::InvalidParams(format!(
                "tx_index {} out of bounds for block with {} transactions",
                tx_index,
                block.transaction_count()
            ))
            .into())
        }

        let (evm_env, _) = self.eth_api().evm_env_at(block.hash().into()).await?;

        // execute after the parent block, replaying `tx_index` transactions
        let state_at = block.parent_hash();

        self.eth_api()
            .spawn_with_state_at_block(state_at, move |eth_api, mut db| {
                // 1. apply pre-execution changes
                eth_api.apply_pre_execution_changes(&block, &mut db, &evm_env)?;

                // 2. replay the required number of transactions
                for tx in block.transactions_recovered().take(tx_index) {
                    let tx_env = eth_api.evm_config().tx_env(tx);
                    let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                    db.commit(res.state);
                }

                // 3. now execute the trace call on this state
                let (evm_env, tx_env) =
                    eth_api.prepare_call_env(evm_env, call, &mut db, overrides)?;

                let mut inspector =
                    DebugInspector::new(tracing_options).map_err(Eth::Error::from_eth_err)?;
                let res =
                    eth_api.inspect(&mut db, evm_env.clone(), tx_env.clone(), &mut inspector)?;
                let trace = inspector
                    .get_result(None, &tx_env, &evm_env.block_env, &res, &mut db)
                    .map_err(Eth::Error::from_eth_err)?;

                Ok(trace)
            })
            .await
    }

    /// The `debug_traceCallMany` method lets you run an `eth_callMany` within the context of the
    /// given block execution using the first n transactions in the given block as base.
    /// Each following bundle increments block number by 1 and block timestamp by 12 seconds
    pub async fn debug_trace_call_many(
        &self,
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> Result<Vec<Vec<GethTrace>>, Eth::Error> {
        if bundles.is_empty() {
            return Err(EthApiError::InvalidParams(String::from("bundles are empty.")).into())
        }

        let StateContext { transaction_index, block_number } = state_context.unwrap_or_default();
        let transaction_index = transaction_index.unwrap_or_default();

        let target_block = block_number.unwrap_or_default();
        let ((mut evm_env, _), block) = futures::try_join!(
            self.eth_api().evm_env_at(target_block),
            self.eth_api().recovered_block(target_block),
        )?;

        let opts = opts.unwrap_or_default();
        let block = block.ok_or(EthApiError::HeaderNotFound(target_block))?;
        let GethDebugTracingCallOptions { tracing_options, mut state_overrides, .. } = opts;

        // we're essentially replaying the transactions in the block here, hence we need the state
        // that points to the beginning of the block, which is the state at the parent block
        let mut at = block.parent_hash();
        let mut replay_block_txs = true;

        // if a transaction index is provided, we need to replay the transactions until the index
        let num_txs =
            transaction_index.index().unwrap_or_else(|| block.body().transactions().len());
        // but if all transactions are to be replayed, we can use the state at the block itself
        // this works with the exception of the PENDING block, because its state might not exist if
        // built locally
        if !target_block.is_pending() && num_txs == block.body().transactions().len() {
            at = block.hash();
            replay_block_txs = false;
        }

        self.eth_api()
            .spawn_with_state_at_block(at, move |eth_api, mut db| {
                // the outer vec for the bundles
                let mut all_bundles = Vec::with_capacity(bundles.len());

                if replay_block_txs {
                    // only need to replay the transactions in the block if not all transactions are
                    // to be replayed
                    let transactions = block.transactions_recovered().take(num_txs);

                    // Execute all transactions until index
                    for tx in transactions {
                        let tx_env = eth_api.evm_config().tx_env(tx);
                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        db.commit(res.state);
                    }
                }

                // Trace all bundles
                let mut bundles = bundles.into_iter().peekable();
                let mut inspector = DebugInspector::new(tracing_options.clone())
                    .map_err(Eth::Error::from_eth_err)?;
                while let Some(bundle) = bundles.next() {
                    let mut results = Vec::with_capacity(bundle.transactions.len());
                    let Bundle { transactions, block_override } = bundle;

                    let block_overrides = block_override.map(Box::new);

                    let mut transactions = transactions.into_iter().peekable();
                    while let Some(tx) = transactions.next() {
                        // apply state overrides only once, before the first transaction
                        let state_overrides = state_overrides.take();
                        let overrides = EvmOverrides::new(state_overrides, block_overrides.clone());

                        let (evm_env, tx_env) =
                            eth_api.prepare_call_env(evm_env.clone(), tx, &mut db, overrides)?;

                        let res = eth_api.inspect(
                            &mut db,
                            evm_env.clone(),
                            tx_env.clone(),
                            &mut inspector,
                        )?;
                        let trace = inspector
                            .get_result(None, &tx_env, &evm_env.block_env, &res, &mut db)
                            .map_err(Eth::Error::from_eth_err)?;

                        // If there is more transactions, commit the database
                        // If there is no transactions, but more bundles, commit to the database too
                        if transactions.peek().is_some() || bundles.peek().is_some() {
                            inspector.fuse().map_err(Eth::Error::from_eth_err)?;
                            db.commit(res.state);
                        }
                        results.push(trace);
                    }
                    // Increment block_env number and timestamp for the next bundle
                    evm_env.block_env.inner_mut().number += uint!(1_U256);
                    evm_env.block_env.inner_mut().timestamp += uint!(12_U256);

                    all_bundles.push(results);
                }
                Ok(all_bundles)
            })
            .await
    }

    /// The `debug_traceCallMan2` method lets you run an `eth_callMan2` within the context of the
    /// given block execution using the first n transactions in the given block as base.
    /// 当前需求,针对flashblock的情况,想缓存cache的变化,以便节省大量的重复运算,在原本的call-many的基础上修改一个新的,
    /// 增加参数 raw_txs 传入后执行结果缓存之(配合参数 block_overrides 可覆盖区块参数).
    pub async fn debug_trace_call_man2(
        &self,
        raw_txs: Vec<Bytes>,
        block_overrides: Option<alloy_rpc_types_eth::BlockOverrides>, // NOTE: 这个参数只是针对raw_txs时用的;
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
        cm2_idx: Option<u8>,
        comments: String,
    ) -> Result<Vec<Vec<GethTrace>>, Eth::Error> {
        let StateContext { transaction_index, block_number } = state_context.unwrap_or_default();
        let transaction_index = transaction_index.unwrap_or_default();
        let cm2_idx = cm2_idx.unwrap_or(0);
        let mut cm2_bn_keep = false;

        let mut target_block = block_number.unwrap_or_default();
        if let Some(0) = target_block.as_u64() {
            // fix target_block 0 to cached block number
            let cached_bn = cm2_temp_cache_query_bn(cm2_idx).unwrap_or(0);
            //info!("callMan2: override bn={},i={},{}", cached_bn, cm2_idx, comments);
            target_block = cached_bn.into();
            cm2_bn_keep = true;
        }
        let ((mut evm_env, _), block) = futures::try_join!(
            self.eth_api().evm_env_at(target_block),
            self.eth_api().recovered_block(target_block),
        )?;

        let start_time = std::time::Instant::now();
        let bn = evm_env.block_env.number().to::<u64>();
        info!(
            "callMan2: bn={},raw={},n={},i={},{}",
            bn,
            raw_txs.len(),
            bundles.len(),
            cm2_idx,
            comments
        );
        let cm2_bn = if cm2_bn_keep { 0 } else { bn };

        let opts = opts.unwrap_or_default();
        let block = block.ok_or(EthApiError::HeaderNotFound(target_block))?;
        let GethDebugTracingCallOptions { tracing_options, mut state_overrides, .. } = opts;

        let mut at = block.parent_hash();
        let mut replay_block_txs = true;
        let num_txs = transaction_index.index().unwrap_or_else(|| block.body().transactions().len());
        if !target_block.is_pending() && num_txs == block.body().transactions().len() {
            at = block.hash();
            replay_block_txs = false;
        }

        self.eth_api()
            .spawn_with_state_at_block(at, move |eth_api, mut db| {
                db.cache = cm2_temp_cache_get(cm2_idx, cm2_bn);
                let mut all_bundles = Vec::with_capacity(bundles.len());
                if replay_block_txs {
                    let transactions = block.transactions_recovered().take(num_txs);
                    for tx in transactions {
                        let tx_env = eth_api.evm_config().tx_env(tx);
                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        db.commit(res.state);
                    }
                }

                // Execute all raw-transactions -- pt01
                if raw_txs.len() > 0 {
                    // NOTE: 这个参数只是针对raw_txs时用的;
                    if let Some(overrides) = block_overrides {
                        alloy_evm::overrides::apply_block_overrides(
                            overrides,
                            &mut db,
                            evm_env.block_env.inner_mut(),
                        );
                    }
                    let mut raw_txs = raw_txs.into_iter().peekable();
                    while let Some(tx) = raw_txs.next() {
                        // info!("xxxx.recover_raw_transaction.1");
                        // NOTE: `Consensus` → `Pooled`: May fail for transactions that cannot be pooled (e.g., OP deposit transactions, blob transactions without sidecars)
                        let tx = reth_rpc_eth_types::utils::recover_raw_transaction::<
                            reth_transaction_pool::PoolConsensusTx<Eth::Pool>,
                        >(&tx)?;
                        let tx_env = eth_api.evm_config().tx_env(tx);
                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        // info!("xxxx.db.commit");
                        db.commit(res.state);
                    }
                    cm2_temp_cache_extend(cm2_idx, bn, db.cache.clone());
                }

                // Trace all bundles
                let mut bundles = bundles.into_iter().peekable();
                let mut inspector = DebugInspector::new(tracing_options.clone())
                    .map_err(Eth::Error::from_eth_err)?;
                while let Some(bundle) = bundles.next() {
                    let mut results = Vec::with_capacity(bundle.transactions.len());
                    let Bundle { transactions, block_override } = bundle;

                    let block_overrides = block_override.map(Box::new);

                    let mut transactions = transactions.into_iter().peekable();
                    while let Some(tx) = transactions.next() {
                        // apply state overrides only once, before the first transaction
                        let state_overrides = state_overrides.take();
                        let overrides = EvmOverrides::new(state_overrides, block_overrides.clone());

                        let (evm_env, tx_env) =
                            eth_api.prepare_call_env(evm_env.clone(), tx, &mut db, overrides)?;

                        let res = eth_api.inspect(
                            &mut db,
                            evm_env.clone(),
                            tx_env.clone(),
                            &mut inspector,
                        )?;
                        let trace = inspector
                            .get_result(None, &tx_env, &evm_env.block_env, &res, &mut db)
                            .map_err(Eth::Error::from_eth_err)?;

                        // If there is more transactions, commit the database
                        // If there is no transactions, but more bundles, commit to the database too
                        if transactions.peek().is_some() || bundles.peek().is_some() {
                            db.commit(res.state);
                        }
                        results.push(trace);
                    }
                    // NOTE: 这里我们是用了适配fb的,因此不能修改,如有需要,外部自己通过override自己修改吧.
                    // // Increment block_env number and timestamp for the next bundle
                    // evm_env.block_env.inner_mut().number += uint!(1_U256);
                    // evm_env.block_env.inner_mut().timestamp += uint!(12_U256);

                    all_bundles.push(results);
                }
                info!("callMan2.ok: {:?},{}", start_time.elapsed(), comments);
                Ok(all_bundles)
            })
            .await
    }

    /// The `debug_traceCallMan3` method lets you run an `eth_callMan3` within the context of ...
    /// 在2的基础上修改,替代call-many的调用效果,看看是否有性能提升...
    pub async fn debug_trace_call_man3(
        &self,
        raw_txs: Vec<Bytes>,
        block_overrides: Option<alloy_rpc_types_eth::BlockOverrides>, // NOTE: 这个参数只是针对raw_txs时用的;
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
        cm2_idx: Option<u8>,
        comments: String,
    ) -> Result<Vec<Vec<(u64, alloy_rpc_types::EthCallResponse)>>, Eth::Error> {
        let StateContext { transaction_index, block_number } = state_context.unwrap_or_default();
        let transaction_index = transaction_index.unwrap_or_default();
        let cm2_idx = cm2_idx.unwrap_or(0);
        let mut cm2_bn_keep = false;

        let mut target_block = block_number.unwrap_or_default();
        if let Some(0) = target_block.as_u64() {
            // fix target_block 0 to cached block number
            let cached_bn = cm2_temp_cache_query_bn(cm2_idx).unwrap_or(0);
            //info!("callMan3: override bn={},i={},{}", cached_bn, cm2_idx, comments);
            target_block = cached_bn.into();
            cm2_bn_keep = true;
        }
        let ((mut evm_env, _), block) = futures::try_join!(
            self.eth_api().evm_env_at(target_block),
            self.eth_api().recovered_block(target_block),
        )?;

        let start_time = std::time::Instant::now();
        let bn = evm_env.block_env.number().to::<u64>();
        info!(
            "callMan3:bn={},raw={},n={},i={},{}",
            bn,
            raw_txs.len(),
            bundles.len(),
            cm2_idx,
            comments
        );
        let cm2_bn = if cm2_bn_keep { 0 } else { bn };

        let opts = opts.unwrap_or_default();
        let block = block.ok_or(EthApiError::HeaderNotFound(target_block))?;
        let GethDebugTracingCallOptions { tracing_options, mut state_overrides, .. } = opts;
        let _ = tracing_options;

        let mut at = block.parent_hash();
        let mut replay_block_txs = true;
        let num_txs = transaction_index.index().unwrap_or_else(|| block.body().transactions().len());
        if !target_block.is_pending() && num_txs == block.body().transactions().len() {
            at = block.hash();
            replay_block_txs = false;
        }

        self.eth_api()
            .spawn_with_state_at_block(at, move |eth_api, mut db| {
                db.cache = cm2_temp_cache_get(cm2_idx, cm2_bn);
                let mut all_bundles = Vec::with_capacity(bundles.len());
                if replay_block_txs {
                    let transactions = block.transactions_recovered().take(num_txs);
                    for tx in transactions {
                        let tx_env = eth_api.evm_config().tx_env(tx);
                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        db.commit(res.state);
                    }
                }

                // Execute all raw-transactions -- pt01
                if raw_txs.len() > 0 {
                    // NOTE: 这个参数只是针对raw_txs时用的;
                    if let Some(overrides) = block_overrides {
                        alloy_evm::overrides::apply_block_overrides(
                            overrides,
                            &mut db,
                            evm_env.block_env.inner_mut(),
                        );
                    }
                    let mut raw_txs = raw_txs.into_iter().peekable();
                    while let Some(tx) = raw_txs.next() {
                        // info!("xxxx.recover_raw_transaction.1");
                        // NOTE: `Consensus` → `Pooled`: May fail for transactions that cannot be pooled (e.g., OP deposit transactions, blob transactions without sidecars)
                        let tx = reth_rpc_eth_types::utils::recover_raw_transaction::<
                            reth_transaction_pool::PoolConsensusTx<Eth::Pool>,
                        >(&tx)?;
                        let tx_env = eth_api.evm_config().tx_env(tx);
                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        // info!("xxxx.db.commit");
                        db.commit(res.state);
                    }
                    cm2_temp_cache_extend(cm2_idx, bn, db.cache.clone());
                }

                // Trace all bundles
                let mut bundles = bundles.into_iter().peekable();
                while let Some(bundle) = bundles.next() {
                    let Bundle { transactions, block_override } = bundle;
                    if transactions.is_empty() {
                        // Skip empty bundles
                        continue;
                    }
                    let mut bundle_results = Vec::with_capacity(transactions.len());
                    let block_overrides = block_override.map(Box::new);

                    let mut transactions = transactions.into_iter().peekable();
                    while let Some(tx) = transactions.next() {
                        // apply state overrides only once, before the first transaction
                        let state_overrides = state_overrides.take();
                        let overrides = EvmOverrides::new(state_overrides, block_overrides.clone());

                        let (evm_env, tx_env) =
                            eth_api.prepare_call_env(evm_env.clone(), tx, &mut db, overrides)?;

                        let res = eth_api.transact(&mut db, evm_env.clone(), tx_env)?;
                        let gas_used = res.result.gas_used();
                        match Eth::Error::ensure_success(res.result) {
                            Ok(output) => {
                                bundle_results.push((
                                    gas_used,
                                    alloy_rpc_types::EthCallResponse {
                                        value: Some(output),
                                        error: None,
                                    },
                                ));
                            }
                            Err(err) => {
                                bundle_results.push((
                                    gas_used,
                                    alloy_rpc_types::EthCallResponse {
                                        value: None,
                                        error: Some(err.to_string()),
                                    },
                                ));
                            }
                        }
                        // If there is more transactions, commit the database
                        // If there is no transactions, but more bundles, commit to the database too
                        if transactions.peek().is_some() || bundles.peek().is_some() {
                            db.commit(res.state);
                        }
                    }
                    all_bundles.push(bundle_results);
                }
                info!("callMan3.ok {:?},{}", start_time.elapsed(), comments);
                Ok(all_bundles)
            })
            .await
    }

    /// The `debug_estimateGas2` method lets you run an `eth_estimateGas2` within the context of CM2...
    pub async fn debug_estimate_gas2(
        &self,
        request: RpcTxReq<Eth::NetworkTypes>,
        block_id: Option<BlockId>,
        state_override: Option<alloy_rpc_types::state::StateOverride>,
        block_overrides: Option<alloy_rpc_types::BlockOverrides>,
        cm2_idx: Option<u8>,
        comments: String,
    ) -> Result<U256, Eth::Error> {
        let cm2_idx = cm2_idx.unwrap_or(0);
        let mut block_id = block_id.unwrap_or_default();
        if let Some(0) = block_id.as_u64() {
            // fix target_block 0 to cached block number
            let cached_bn = cm2_temp_cache_query_bn(cm2_idx).unwrap_or(0);
            info!("estGas2: override bn={},i={}:{}", cached_bn, cm2_idx, comments);
            block_id = cached_bn.into();
        }
        let (evm_env, _) = self.eth_api().evm_env_at(block_id).await?;
        self.eth_api()
            .spawn_with_state_at_block(block_id, move |eth_api, mut db| {
                //
                //let _bn = evm_env.block_env.number().to::<u64>();
                db.cache = cm2_temp_cache_get(cm2_idx, 0);
                //
                Self::_estimate_gas_with2(
                    eth_api,
                    db,
                    evm_env,
                    request,
                    state_override,
                    block_overrides,
                )
            })
            .await
    }
    fn _estimate_gas_with2(
        eth_api: Eth,
        mut db: State<
            reth_revm::database::StateProviderDatabase<
                reth_rpc_eth_types::cache::db::StateProviderTraitObjWrapper,
            >,
        >,
        mut evm_env: EvmEnvFor<Eth::Evm>,
        mut request: RpcTxReq<Eth::NetworkTypes>,
        state_override: Option<alloy_rpc_types_eth::state::StateOverride>,
        block_overrides: Option<alloy_rpc_types_eth::BlockOverrides>,
    ) -> Result<U256, Eth::Error> {
        // Disabled because eth_estimateGas is sometimes used with eoa senders
        // See <https://github.com/paradigmxyz/reth/issues/1959>
        evm_env.cfg_env.disable_eip3607 = true;

        // The basefee should be ignored for eth_estimateGas and similar
        // See:
        // <https://github.com/ethereum/go-ethereum/blob/ee8e83fa5f6cb261dad2ed0a7bbcde4930c41e6c/internal/ethapi/api.go#L985>
        evm_env.cfg_env.disable_base_fee = true;

        // set nonce to None so that the correct nonce is chosen by the EVM
        request.as_mut().take_nonce();

        // Keep a copy of gas related request values
        let tx_request_gas_limit = request.as_ref().gas_limit();
        let tx_request_gas_price = request.as_ref().gas_price();
        // the gas limit of the corresponding block
        let max_gas_limit = evm_env.cfg_env.tx_gas_limit_cap.map_or_else(
            || evm_env.block_env.gas_limit(),
            |cap| cap.min(evm_env.block_env.gas_limit()),
        );

        // Determine the highest possible gas limit, considering both the request's specified limit
        // and the block's limit.
        let mut highest_gas_limit = tx_request_gas_limit
            .map(|mut tx_gas_limit| {
                if max_gas_limit < tx_gas_limit {
                    // requested gas limit is higher than the allowed gas limit, capping
                    tx_gas_limit = max_gas_limit;
                }
                tx_gas_limit
            })
            .unwrap_or(max_gas_limit);

        // Apply block overrides if specified.
        if let Some(overrides) = block_overrides {
            reth_evm::overrides::apply_block_overrides(
                overrides,
                &mut db,
                evm_env.block_env.inner_mut(),
            );
        }

        // Apply any state overrides if specified.
        if let Some(state_override) = state_override {
            reth_evm::overrides::apply_state_overrides(state_override, &mut db)
                .map_err(Eth::Error::from_eth_err)?;
        }

        let mut tx_env = eth_api.create_txn_env(&evm_env, request, &mut db)?;

        // Check if this is a basic transfer (no input data to account with no code)
        let is_basic_transfer = if tx_env.input().is_empty()
            && let revm_primitives::TxKind::Call(to) = tx_env.kind()
            && let Ok(code) = db.database.0 .0.account_code(&to)
        {
            code.map(|code| code.is_empty()).unwrap_or(true)
        } else {
            false
        };

        // Check funds of the sender (only useful to check if transaction gas price is more than 0).
        //
        // The caller allowance is check by doing `(account.balance - tx.value) / tx.gas_price`
        if tx_env.gas_price() > 0 {
            // cap the highest gas limit by max gas caller can afford with given gas price
            highest_gas_limit = highest_gas_limit.min(
                reth_evm::call::caller_gas_allowance(&mut db, &tx_env)
                    .map_err(Eth::Error::from_eth_err)?,
            );
        }

        // If the provided gas limit is less than computed cap, use that
        tx_env.set_gas_limit(tx_env.gas_limit().min(highest_gas_limit));

        // Create EVM instance once and reuse it throughout the entire estimation process
        let mut evm = eth_api.evm_config().evm_with_env(&mut db, evm_env);

        // For basic transfers, try using minimum gas before running full binary search
        if is_basic_transfer {
            // If the tx is a simple transfer (call to an account with no code) we can
            // shortcircuit. But simply returning
            // `MIN_TRANSACTION_GAS` is dangerous because there might be additional
            // field combos that bump the price up, so we try executing the function
            // with the minimum gas limit to make sure.
            let mut min_tx_env = tx_env.clone();
            min_tx_env.set_gas_limit(reth_chainspec::MIN_TRANSACTION_GAS);

            // Reuse the same EVM instance
            if let Ok(res) = evm.transact(min_tx_env).map_err(Eth::Error::from_evm_err)
                && res.result.is_success()
            {
                return Ok(U256::from(reth_chainspec::MIN_TRANSACTION_GAS));
            }
        }

        // info!(target: "rpc::debug::estGas2", ?tx_env, gas_limit = tx_env.gas_limit(), is_basic_transfer, "Starting gas estimation");
        info!(target: "rpc::debug::estGas2", ?tx_env, gas_limit = tx_env.gas_limit(), is_basic_transfer, "estGas2 starting");

        // Execute the transaction with the highest possible gas limit.
        let mut res = match evm.transact(tx_env.clone()).map_err(Eth::Error::from_evm_err) {
            // Handle the exceptional case where the transaction initialization uses too much
            // gas. If the gas price or gas limit was specified in the request,
            // retry the transaction with the block's gas limit to determine if
            // the failure was due to insufficient gas.
            Err(err)
                if reth_rpc_eth_api::AsEthApiError::is_gas_too_high(&err)
                    && (tx_request_gas_limit.is_some() || tx_request_gas_price.is_some()) =>
            {
                return Self::_map_out_of_gas_err(&mut evm, tx_env, max_gas_limit);
            }
            Err(err) if reth_rpc_eth_api::AsEthApiError::is_gas_too_low(&err) => {
                // This failed because the configured gas cost of the tx was lower than what
                // actually consumed by the tx This can happen if the
                // request provided fee values manually and the resulting gas cost exceeds the
                // sender's allowance, so we return the appropriate error here
                return Err(reth_rpc_eth_api::IntoEthApiError::into_eth_err(
                    reth_rpc_eth_types::RpcInvalidTransactionError::GasRequiredExceedsAllowance {
                        gas_limit: tx_env.gas_limit(),
                    },
                ));
            }
            // Propagate other results (successful or other errors).
            ethres => ethres?,
        };

        let gas_refund = match res.result {
            revm::context::result::ExecutionResult::Success { gas_refunded, .. } => gas_refunded,
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                // here we don't check for invalid opcode because already executed with highest gas
                // limit
                return Err(Eth::Error::from_evm_halt(reason, tx_env.gas_limit()));
            }
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                // if price or limit was included in the request then we can execute the request
                // again with the block's gas limit to check if revert is gas related or not
                return if tx_request_gas_limit.is_some() || tx_request_gas_price.is_some() {
                    Self::_map_out_of_gas_err(&mut evm, tx_env, max_gas_limit)
                } else {
                    // the transaction did revert
                    Err(reth_rpc_eth_api::IntoEthApiError::into_eth_err(
                        reth_rpc_eth_types::RpcInvalidTransactionError::Revert(
                            reth_rpc_eth_types::RevertError::new(output),
                        ),
                    ))
                };
            }
        };

        // At this point we know the call succeeded but want to find the _best_ (lowest) gas the
        // transaction succeeds with. We find this by doing a binary search over the possible range.

        // we know the tx succeeded with the configured gas limit, so we can use that as the
        // highest, in case we applied a gas cap due to caller allowance above
        highest_gas_limit = tx_env.gas_limit();

        // NOTE: this is the gas the transaction used, which is less than the
        // transaction requires to succeed.
        let mut gas_used = res.result.gas_used();
        // the lowest value is capped by the gas used by the unconstrained transaction
        let mut lowest_gas_limit = gas_used.saturating_sub(1);

        // As stated in Geth, there is a good chance that the transaction will pass if we set the
        // gas limit to the execution gas used plus the gas refund, so we check this first
        // <https://github.com/ethereum/go-ethereum/blob/a5a4fa7032bb248f5a7c40f4e8df2b131c4186a4/eth/gasestimator/gasestimator.go#L135
        //
        // Calculate the optimistic gas limit by adding gas used and gas refund,
        // then applying a 64/63 multiplier to account for gas forwarding rules.
        let optimistic_gas_limit = (gas_used
            + gas_refund
            + reth_rpc_server_types::constants::gas_oracle::CALL_STIPEND_GAS)
            * 64
            / 63;
        if optimistic_gas_limit < highest_gas_limit {
            // Set the transaction's gas limit to the calculated optimistic gas limit.
            let mut optimistic_tx_env = tx_env.clone();
            optimistic_tx_env.set_gas_limit(optimistic_gas_limit);

            // Re-execute the transaction with the new gas limit and update the result and
            // environment.
            res = evm.transact(optimistic_tx_env)?;

            // Update the gas used based on the new result.
            gas_used = res.result.gas_used();
            // Update the gas limit estimates (highest and lowest) based on the execution result.
            Self::_update_estimated_gas_range(
                res.result,
                optimistic_gas_limit,
                &mut highest_gas_limit,
                &mut lowest_gas_limit,
            )?;
        };

        // Pick a point that's close to the estimated gas
        let mut mid_gas_limit = std::cmp::min(
            gas_used * 3,
            ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64,
        );

        // if false {
        //     // 不走二分求最优直接返回;
        //     return Ok(U256::from(mid_gas_limit) | (U256::from(gas_used) << 128))
        // }

        info!(target: "rpc::debug::estGas2", ?highest_gas_limit, ?lowest_gas_limit, ?mid_gas_limit, ?gas_refund, "estGas2 starting binary search");

        // Binary search narrows the range to find the minimum gas limit needed for the transaction
        // to succeed.
        while lowest_gas_limit + 1 < highest_gas_limit {
            // An estimation error is allowed once the current gas limit range used in the binary
            // search is small enough (less than 1.5% of the highest gas limit)
            // <https://github.com/ethereum/go-ethereum/blob/a5a4fa7032bb248f5a7c40f4e8df2b131c4186a4/eth/gasestimator/gasestimator.go#L152
            if (highest_gas_limit - lowest_gas_limit) as f64 / (highest_gas_limit as f64) < 0.015 {
                break;
            };

            let mut mid_tx_env = tx_env.clone();
            mid_tx_env.set_gas_limit(mid_gas_limit);

            // Execute transaction and handle potential gas errors, adjustping limits accordingly.
            match evm.transact(mid_tx_env).map_err(Eth::Error::from_evm_err) {
                Err(err) if reth_rpc_eth_api::AsEthApiError::is_gas_too_high(&err) => {
                    // Decrease the highest gas limit if gas is too high
                    highest_gas_limit = mid_gas_limit;
                }
                Err(err) if reth_rpc_eth_api::AsEthApiError::is_gas_too_low(&err) => {
                    // Increase the lowest gas limit if gas is too low
                    lowest_gas_limit = mid_gas_limit;
                }
                // Handle other cases, including successful transactions.
                ethres => {
                    // Unpack the result and environment if the transaction was successful.
                    res = ethres?;
                    // Update the estimated gas range based on the transaction result.
                    Self::_update_estimated_gas_range(
                        res.result,
                        mid_gas_limit,
                        &mut highest_gas_limit,
                        &mut lowest_gas_limit,
                    )?;
                }
            }

            // New midpoint
            mid_gas_limit = ((highest_gas_limit as u128 + lowest_gas_limit as u128) / 2) as u64;
        }
        Ok(U256::from(highest_gas_limit) | (U256::from(gas_used) << 128))
    }
    /// Executes the requests again after an out of gas error to check if the error is gas related
    /// or not
    #[inline]
    fn _map_out_of_gas_err<DB>(
        evm: &mut reth_evm::EvmFor<Eth::Evm, DB>,
        mut tx_env: TxEnvFor<Eth::Evm>,
        higher_gas_limit: u64,
    ) -> Result<U256, Eth::Error>
    where
        DB: reth_evm::Database<
            Error = reth_revm::db::bal::EvmDatabaseError<reth_errors::ProviderError>,
        >,
        EthApiError: From<DB::Error>,
    {
        let req_gas_limit = tx_env.gas_limit();
        tx_env.set_gas_limit(higher_gas_limit);

        let retry_res = evm.transact(tx_env).map_err(Eth::Error::from_evm_err)?;

        match retry_res.result {
            revm::context::result::ExecutionResult::Success { .. } => {
                // Transaction succeeded by manually increasing the gas limit,
                // which means the caller lacks funds to pay for the tx
                Err(reth_rpc_eth_api::IntoEthApiError::into_eth_err(
                    reth_rpc_eth_types::RpcInvalidTransactionError::BasicOutOfGas(req_gas_limit),
                ))
            }
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                // reverted again after bumping the limit
                Err(reth_rpc_eth_api::IntoEthApiError::into_eth_err(
                    reth_rpc_eth_types::RpcInvalidTransactionError::Revert(
                        reth_rpc_eth_types::RevertError::new(output),
                    ),
                ))
            }
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                Err(Eth::Error::from_evm_halt(reason, req_gas_limit))
            }
        }
    }

    /// Updates the highest and lowest gas limits for binary search based on the execution result.
    ///
    /// This function refines the gas limit estimates used in a binary search to find the optimal
    /// gas limit for a transaction. It adjusts the highest or lowest gas limits depending on
    /// whether the execution succeeded, reverted, or halted due to specific reasons.
    #[inline]
    fn _update_estimated_gas_range<Halt>(
        result: revm::context::result::ExecutionResult<Halt>,
        tx_gas_limit: u64,
        highest_gas_limit: &mut u64,
        lowest_gas_limit: &mut u64,
    ) -> Result<(), EthApiError> {
        match result {
            revm::context::result::ExecutionResult::Success { .. } => {
                // Cap the highest gas limit with the succeeding gas limit.
                *highest_gas_limit = tx_gas_limit;
            }
            revm::context::result::ExecutionResult::Revert { .. }
            | revm::context::result::ExecutionResult::Halt { .. } => {
                // We know that transaction succeeded with a higher gas limit before, so any failure
                // means that we need to increase it.
                //
                // We are ignoring all halts here, and not just OOG errors because there are cases when
                // non-OOG halt might flag insufficient gas limit as well.
                //
                // Common usage of invalid opcode in OpenZeppelin:
                // <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/94697be8a3f0dfcd95dfb13ffbd39b5973f5c65d/contracts/metatx/ERC2771Forwarder.sol#L360-L367>
                *lowest_gas_limit = tx_gas_limit;
            }
        };

        Ok(())
    }


    /// Generates an execution witness for the given block hash. see
    /// [`Self::debug_execution_witness`] for more info.
    pub async fn debug_execution_witness_by_block_hash(
        &self,
        hash: B256,
    ) -> Result<ExecutionWitness, Eth::Error> {
        let this = self.clone();
        let block = this
            .eth_api()
            .recovered_block(hash.into())
            .await?
            .ok_or(EthApiError::HeaderNotFound(hash.into()))?;

        self.debug_execution_witness_for_block(block).await
    }

    /// The `debug_executionWitness` method allows for re-execution of a block with the purpose of
    /// generating an execution witness. The witness comprises of a map of all hashed trie nodes to
    /// their preimages that were required during the execution of the block, including during state
    /// root recomputation.
    pub async fn debug_execution_witness(
        &self,
        block_id: BlockNumberOrTag,
    ) -> Result<ExecutionWitness, Eth::Error> {
        let this = self.clone();
        let block = this
            .eth_api()
            .recovered_block(block_id.into())
            .await?
            .ok_or(EthApiError::HeaderNotFound(block_id.into()))?;

        self.debug_execution_witness_for_block(block).await
    }

    /// Generates an execution witness, using the given recovered block.
    pub async fn debug_execution_witness_for_block(
        &self,
        block: Arc<RecoveredBlock<ProviderBlock<Eth::Provider>>>,
    ) -> Result<ExecutionWitness, Eth::Error> {
        let block_number = block.header().number();

        let (mut exec_witness, lowest_block_number) = self
            .eth_api()
            .spawn_with_state_at_block(block.parent_hash(), move |eth_api, mut db| {
                let block_executor = eth_api.evm_config().executor(&mut db);

                let mut witness_record = ExecutionWitnessRecord::default();

                let _ = block_executor
                    .execute_with_state_closure(&block, |statedb: &State<_>| {
                        witness_record.record_executed_state(statedb);
                    })
                    .map_err(|err| EthApiError::Internal(err.into()))?;

                let ExecutionWitnessRecord { hashed_state, codes, keys, lowest_block_number } =
                    witness_record;

                let state = db
                    .database
                    .0
                    .witness(Default::default(), hashed_state)
                    .map_err(EthApiError::from)?;
                Ok((
                    ExecutionWitness { state, codes, keys, ..Default::default() },
                    lowest_block_number,
                ))
            })
            .await?;

        let smallest = match lowest_block_number {
            Some(smallest) => smallest,
            None => {
                // Return only the parent header, if there were no calls to the
                // BLOCKHASH opcode.
                block_number.saturating_sub(1)
            }
        };

        let range = smallest..block_number;
        exec_witness.headers = self
            .provider()
            .headers_range(range)
            .map_err(EthApiError::from)?
            .into_iter()
            .map(|header| {
                let mut serialized_header = Vec::new();
                header.encode(&mut serialized_header);
                serialized_header.into()
            })
            .collect();

        Ok(exec_witness)
    }

    /// Returns the code associated with a given hash at the specified block ID. If no code is
    /// found, it returns None. If no block ID is provided, it defaults to the latest block.
    pub async fn debug_code_by_hash(
        &self,
        hash: B256,
        block_id: Option<BlockId>,
    ) -> Result<Option<Bytes>, Eth::Error> {
        Ok(self
            .provider()
            .state_by_block_id(block_id.unwrap_or_default())
            .map_err(Eth::Error::from_eth_err)?
            .bytecode_by_hash(&hash)
            .map_err(Eth::Error::from_eth_err)?
            .map(|b| b.original_bytes()))
    }

    /// Returns the state root of the `HashedPostState` on top of the state for the given block with
    /// trie updates.
    async fn debug_state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
        block_id: Option<BlockId>,
    ) -> Result<(B256, TrieUpdates), Eth::Error> {
        self.inner
            .eth_api
            .spawn_blocking_io(move |this| {
                let state = this
                    .provider()
                    .state_by_block_id(block_id.unwrap_or_default())
                    .map_err(Eth::Error::from_eth_err)?;
                state.state_root_with_updates(hashed_state).map_err(Eth::Error::from_eth_err)
            })
            .await
    }
}

#[async_trait]
impl<Eth> DebugApiServer<RpcTxReq<Eth::NetworkTypes>> for DebugApi<Eth>
where
    Eth: EthTransactions + TraceExt,
{
    /// Handler for `debug_getRawHeader`
    async fn raw_header(&self, block_id: BlockId) -> RpcResult<Bytes> {
        let header = match block_id {
            BlockId::Hash(hash) => self.provider().header(hash.into()).to_rpc_result()?,
            BlockId::Number(number_or_tag) => {
                let number = self
                    .provider()
                    .convert_block_number(number_or_tag)
                    .to_rpc_result()?
                    .ok_or_else(|| {
                    internal_rpc_err("Pending block not supported".to_string())
                })?;
                self.provider().header_by_number(number).to_rpc_result()?
            }
        };

        let mut res = Vec::new();
        if let Some(header) = header {
            header.encode(&mut res);
        }

        Ok(res.into())
    }

    /// Handler for `debug_getRawBlock`
    async fn raw_block(&self, block_id: BlockId) -> RpcResult<Bytes> {
        let block = self
            .provider()
            .block_by_id(block_id)
            .to_rpc_result()?
            .ok_or(EthApiError::HeaderNotFound(block_id))?;
        let mut res = Vec::new();
        block.encode(&mut res);
        Ok(res.into())
    }

    /// Handler for `debug_getRawTransaction`
    ///
    /// If this is a pooled EIP-4844 transaction, the blob sidecar is included.
    ///
    /// Returns the bytes of the transaction for the given hash.
    async fn raw_transaction(&self, hash: B256) -> RpcResult<Option<Bytes>> {
        self.eth_api().raw_transaction_by_hash(hash).await.map_err(Into::into)
    }

    /// Handler for `debug_getRawTransactions`
    /// Returns the bytes of the transaction for the given hash.
    async fn raw_transactions(&self, block_id: BlockId) -> RpcResult<Vec<Bytes>> {
        let block: RecoveredBlock<BlockTy<Eth::Primitives>> = self
            .provider()
            .block_with_senders_by_id(block_id, TransactionVariant::NoHash)
            .to_rpc_result()?
            .unwrap_or_default();
        Ok(block.into_transactions_recovered().map(|tx| tx.encoded_2718().into()).collect())
    }

    /// Handler for `debug_getRawReceipts`
    async fn raw_receipts(&self, block_id: BlockId) -> RpcResult<Vec<Bytes>> {
        Ok(self
            .provider()
            .receipts_by_block_id(block_id)
            .to_rpc_result()?
            .unwrap_or_default()
            .into_iter()
            .map(|receipt| ReceiptWithBloom::from(receipt).encoded_2718().into())
            .collect())
    }

    /// Handler for `debug_getBadBlocks`
    async fn bad_blocks(&self) -> RpcResult<Vec<serde_json::Value>> {
        let blocks = self.inner.bad_block_store.all();
        let mut bad_blocks = Vec::with_capacity(blocks.len());

        #[derive(Serialize, Deserialize)]
        struct BadBlockSerde<T> {
            block: T,
            hash: B256,
            rlp: Bytes,
        }

        for block in blocks {
            let rlp = alloy_rlp::encode(block.sealed_block()).into();
            let hash = block.hash();

            let block = block
                .clone_into_rpc_block(
                    BlockTransactionsKind::Full,
                    |tx, tx_info| self.eth_api().converter().fill(tx, tx_info),
                    |header, size| self.eth_api().converter().convert_header(header, size),
                )
                .map_err(|err| Eth::Error::from(err).into())?;

            let bad_block = serde_json::to_value(BadBlockSerde { block, hash, rlp })
                .map_err(|err| EthApiError::other(internal_rpc_err(err.to_string())))?;

            bad_blocks.push(bad_block);
        }

        Ok(bad_blocks)
    }

    /// Handler for `debug_traceChain`
    async fn debug_trace_chain(
        &self,
        _start_exclusive: BlockNumberOrTag,
        _end_inclusive: BlockNumberOrTag,
    ) -> RpcResult<Vec<BlockTraceResult>> {
        Err(internal_rpc_err("unimplemented"))
    }

    /// Handler for `debug_traceBlock`
    async fn debug_trace_block(
        &self,
        rlp_block: Bytes,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_raw_block(self, rlp_block, opts.unwrap_or_default())
            .await
            .map_err(Into::into)
    }

    /// Handler for `debug_traceBlockByHash`
    async fn debug_trace_block_by_hash(
        &self,
        block: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_block(self, block.into(), opts.unwrap_or_default())
            .await
            .map_err(Into::into)
    }

    /// Handler for `debug_traceBlockByNumber`
    async fn debug_trace_block_by_number(
        &self,
        block: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_block(self, block.into(), opts.unwrap_or_default())
            .await
            .map_err(Into::into)
    }

    /// Handler for `debug_traceTransaction`
    async fn debug_trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<GethTrace> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_transaction(self, tx_hash, opts.unwrap_or_default())
            .await
            .map_err(Into::into)
    }

    /// Handler for `debug_traceCall`
    async fn debug_trace_call(
        &self,
        request: RpcTxReq<Eth::NetworkTypes>,
        block_id: Option<BlockId>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<GethTrace> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_call(self, request, block_id, opts.unwrap_or_default())
            .await
            .map_err(Into::into)
    }

    async fn debug_trace_call_many(
        &self,
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<Vec<Vec<GethTrace>>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_call_many(self, bundles, state_context, opts).await.map_err(Into::into)
    }

    async fn debug_trace_call_man2(
        &self,
        raw_txs: Vec<Bytes>,
        block_overrides: Option<alloy_rpc_types::BlockOverrides>,
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
        cm2_idx: Option<u8>,
        comments: Option<String>,
    ) -> RpcResult<Vec<Vec<GethTrace>>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_call_man2(
            self,
            raw_txs,
            block_overrides,
            bundles,
            state_context,
            opts,
            cm2_idx,
            comments.unwrap_or_default(),
        )
        .await
        .map_err(Into::into)
    }

    async fn debug_trace_call_man3(
        &self,
        raw_txs: Vec<Bytes>,
        block_overrides: Option<alloy_rpc_types::BlockOverrides>,
        bundles: Vec<Bundle<RpcTxReq<Eth::NetworkTypes>>>,
        state_context: Option<StateContext>,
        opts: Option<GethDebugTracingCallOptions>,
        cm2_idx: Option<u8>,
        comments: Option<String>,
    ) -> RpcResult<Vec<Vec<(u64, alloy_rpc_types::EthCallResponse)>>> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_trace_call_man3(
            self,
            raw_txs,
            block_overrides,
            bundles,
            state_context,
            opts,
            cm2_idx,
            comments.unwrap_or_default(),
        )
        .await
        .map_err(Into::into)
    }

    async fn debug_estimate_gas2(
        &self,
        request: RpcTxReq<Eth::NetworkTypes>,
        block_id: Option<BlockId>,
        state_override: Option<alloy_rpc_types::state::StateOverride>,
        block_overrides: Option<alloy_rpc_types::BlockOverrides>,
        cm2_idx: Option<u8>,
        comments: Option<String>,
    ) -> RpcResult<U256> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_estimate_gas2(
            self,
            request,
            block_id,
            state_override,
            block_overrides,
            cm2_idx,
            comments.unwrap_or_default(),
        )
        .await
        .map_err(Into::into)
    }

    /// Handler for `debug_executionWitness`
    async fn debug_execution_witness(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<ExecutionWitness> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_execution_witness(self, block).await.map_err(Into::into)
    }

    /// Handler for `debug_executionWitnessByBlockHash`
    async fn debug_execution_witness_by_block_hash(
        &self,
        hash: B256,
    ) -> RpcResult<ExecutionWitness> {
        let _permit = self.acquire_trace_permit().await;
        Self::debug_execution_witness_by_block_hash(self, hash).await.map_err(Into::into)
    }

    async fn debug_get_block_access_list(&self, _block_id: BlockId) -> RpcResult<BlockAccessList> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn debug_backtrace_at(&self, _location: &str) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_account_range(
        &self,
        _block_number: BlockNumberOrTag,
        _start: Bytes,
        _max_results: u64,
        _nocode: bool,
        _nostorage: bool,
        _incompletes: bool,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_block_profile(&self, _file: String, _seconds: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_chaindb_compact(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_chain_config(&self) -> RpcResult<ChainConfig> {
        Ok(self.provider().chain_spec().genesis().config.clone())
    }

    async fn debug_chaindb_property(&self, _property: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_code_by_hash(
        &self,
        hash: B256,
        block_id: Option<BlockId>,
    ) -> RpcResult<Option<Bytes>> {
        Self::debug_code_by_hash(self, hash, block_id).await.map_err(Into::into)
    }

    async fn debug_cpu_profile(&self, _file: String, _seconds: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_db_ancient(&self, _kind: String, _number: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_db_ancients(&self) -> RpcResult<()> {
        Ok(())
    }

    /// `debug_db_get` - database key lookup
    ///
    /// Currently supported:
    /// * Contract bytecode associated with a code hash. The key format is: `<0x63><code_hash>`
    ///     * Prefix byte: 0x63 (required)
    ///     * Code hash: 32 bytes
    ///   Must be provided as either:
    ///     * Hex string: "0x63..." (66 hex characters after 0x)
    ///     * Raw byte string: raw byte string (33 bytes)
    ///   See Geth impl: <https://github.com/ethereum/go-ethereum/blob/737ffd1bf0cbee378d0111a5b17ae4724fb2216c/core/rawdb/schema.go#L120>
    async fn debug_db_get(&self, key: String) -> RpcResult<Option<Bytes>> {
        let key_bytes = if key.starts_with("0x") {
            decode(&key).map_err(|_| EthApiError::InvalidParams("Invalid hex key".to_string()))?
        } else {
            key.into_bytes()
        };

        if key_bytes.len() != 33 {
            return Err(EthApiError::InvalidParams(format!(
                "Key must be 33 bytes, got {}",
                key_bytes.len()
            ))
            .into());
        }
        if key_bytes[0] != 0x63 {
            return Err(EthApiError::InvalidParams("Key prefix must be 0x63".to_string()).into());
        }

        let code_hash = B256::from_slice(&key_bytes[1..33]);

        // No block ID is provided, so it defaults to the latest block
        self.debug_code_by_hash(code_hash, None).await.map_err(Into::into)
    }

    async fn debug_dump_block(&self, _number: BlockId) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_free_os_memory(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_freeze_client(&self, _node: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_gc_stats(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_get_accessible_state(
        &self,
        _from: BlockNumberOrTag,
        _to: BlockNumberOrTag,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_get_modified_accounts_by_hash(
        &self,
        _start_hash: B256,
        _end_hash: B256,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_get_modified_accounts_by_number(
        &self,
        _start_number: u64,
        _end_number: u64,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_go_trace(&self, _file: String, _seconds: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_intermediate_roots(
        &self,
        _block_hash: B256,
        _opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_mem_stats(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_mutex_profile(&self, _file: String, _nsec: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_preimage(&self, _hash: B256) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_print_block(&self, _number: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_seed_hash(&self, _number: u64) -> RpcResult<B256> {
        Ok(Default::default())
    }

    async fn debug_set_block_profile_rate(&self, _rate: u64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_set_gc_percent(&self, _v: i32) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_set_head(&self, _number: U64) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_set_mutex_profile_fraction(&self, _rate: i32) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_set_trie_flush_interval(&self, _interval: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_stacks(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_standard_trace_bad_block_to_file(
        &self,
        _block: BlockNumberOrTag,
        _opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_standard_trace_block_to_file(
        &self,
        _block: BlockNumberOrTag,
        _opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_start_cpu_profile(&self, _file: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_start_go_trace(&self, _file: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
        block_id: Option<BlockId>,
    ) -> RpcResult<(B256, TrieUpdates)> {
        Self::debug_state_root_with_updates(self, hashed_state, block_id).await.map_err(Into::into)
    }

    async fn debug_stop_cpu_profile(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_stop_go_trace(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_storage_range_at(
        &self,
        _block_hash: B256,
        _tx_idx: usize,
        _contract_address: Address,
        _key_start: B256,
        _max_result: u64,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_trace_bad_block(
        &self,
        _block_hash: B256,
        _opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_verbosity(&self, _level: usize) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_vmodule(&self, _pattern: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_write_block_profile(&self, _file: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_write_mem_profile(&self, _file: String) -> RpcResult<()> {
        Ok(())
    }

    async fn debug_write_mutex_profile(&self, _file: String) -> RpcResult<()> {
        Ok(())
    }
}

impl<Eth: RpcNodeCore> std::fmt::Debug for DebugApi<Eth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugApi").finish_non_exhaustive()
    }
}

impl<Eth: RpcNodeCore> Clone for DebugApi<Eth> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

struct DebugApiInner<Eth: RpcNodeCore> {
    /// The implementation of `eth` API
    eth_api: Eth,
    // restrict the number of concurrent calls to blocking calls
    blocking_task_guard: BlockingTaskGuard,
    /// Cache for bad blocks.
    bad_block_store: BadBlockStore<BlockTy<Eth::Primitives>>,
}

/// A bounded, deduplicating store of recently observed bad blocks.
#[derive(Clone, Debug)]
struct BadBlockStore<B: BlockTrait> {
    inner: Arc<RwLock<VecDeque<Arc<RecoveredBlock<B>>>>>,
    limit: usize,
}

impl<B: BlockTrait> BadBlockStore<B> {
    /// Creates a new store with the given capacity.
    fn new(limit: usize) -> Self {
        Self { inner: Arc::new(RwLock::new(VecDeque::with_capacity(limit))), limit }
    }

    /// Inserts a recovered block, keeping only the most recent `limit` entries and deduplicating
    /// by block hash.
    fn insert(&self, block: RecoveredBlock<B>) {
        let hash = block.hash();
        let mut guard = self.inner.write();

        // skip if we already recorded this bad block , and keep original ordering
        if guard.iter().any(|b| b.hash() == hash) {
            return;
        }
        guard.push_back(Arc::new(block));

        while guard.len() > self.limit {
            guard.pop_front();
        }
    }

    /// Returns all cached bad blocks ordered from newest to oldest.
    fn all(&self) -> Vec<Arc<RecoveredBlock<B>>> {
        let guard = self.inner.read();
        guard.iter().rev().cloned().collect()
    }
}

impl<B: BlockTrait> Default for BadBlockStore<B> {
    fn default() -> Self {
        Self::new(64)
    }
}

struct Cm2TempCache {
    pub bn: u64,
    pub cache: reth_revm::db::CacheState,
}
static GLOBAL_CM2_TEMP_CACHE: std::sync::OnceLock<
    std::sync::Arc<std::sync::Mutex<[Cm2TempCache; 8]>>,
> = std::sync::OnceLock::new();

fn cm2_temp_cache_get(idx: u8, bn: u64) -> reth_revm::db::CacheState {
    let idx = (idx % 8) as usize;
    let inner = GLOBAL_CM2_TEMP_CACHE.get_or_init(|| {
        std::sync::Arc::new(std::sync::Mutex::new([
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
            Cm2TempCache { bn: 0, cache: Default::default() },
        ]))
    });
    let mut inner = inner.lock().unwrap();
    // NOTE: if bn is zero, do not update bn/cache
    if bn != 0 && inner[idx].bn != bn {
        inner[idx].bn = bn;
        inner[idx].cache = Default::default();
    }
    inner[idx].cache.clone()
}
fn cm2_temp_cache_extend(idx: u8, bn: u64, cache: reth_revm::db::CacheState) {
    let idx = (idx % 8) as usize;
    let mut inner = GLOBAL_CM2_TEMP_CACHE.get().unwrap().lock().unwrap();
    if inner[idx].bn != bn {
        inner[idx].bn = bn;
        inner[idx].cache = cache;
    } else {
        inner[idx].cache.accounts.extend(cache.accounts);
        inner[idx].cache.contracts.extend(cache.contracts);
        //inner[idx].cache.logs.extend(cache.logs);
        //inner[idx].cache.block_hashes.extend(cache.block_hashes);
        inner[idx].cache.has_state_clear = cache.has_state_clear;
    }
}
fn cm2_temp_cache_query_bn(idx: u8) -> Option<u64> {
    let idx = (idx % 8) as usize;
    let inner = GLOBAL_CM2_TEMP_CACHE.get()?.lock().unwrap();
    Some(inner[idx].bn)
}