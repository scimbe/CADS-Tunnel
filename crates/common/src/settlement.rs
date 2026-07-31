//! #147-L4 — dedicated settlement chain for LLM-token payments.
//!
//! A minimal **hash-linked, signature-verified, append-only ledger** — the "real chain" the maintainer
//! green-lit (#147 req 3), explicitly distinct from the *symbolic* `SettleReceipt`/`BillingCommitment`
//! family in [`crate::channel`]. This is the **L4.1 foundation**: block linkage, ed25519-signed
//! transfers, balances with no overdraft, and per-sender replay nonces — the integrity core a
//! settlement currency needs. It is deliberately **single-writer** (no consensus yet) and in-memory:
//!
//! NOT in this slice (explicit follows): consensus / Byzantine agreement across writers, P2P gossip of
//! blocks, and the marketplace integration — the auction (#147-L2) that decides *what* transfers to
//! settle, and the consumption-proof (#147-L3) that gates *when* a credit finalizes. This layer only
//! guarantees that, given a set of transfers, the resulting ledger is tamper-evident and conserves
//! value (no forgery, no double-spend, no overdraft).
//!
//! Accounts are ed25519 holder public keys — the same key family used everywhere else — so an agent's
//! settlement account is its identity, and a transfer is authorized only by the holder's own signature.

use crate::channel::UsageReceipt;
use crate::preimage::Preimage;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// A settlement account — an ed25519 holder public key.
pub type Account = [u8; 32];
/// The chain's currency unit (smallest denomination).
pub type Amount = u64;

/// Domain separating a [`Transfer`] preimage from every other signed object in the codebase.
const TRANSFER_DOMAIN: &[u8] = b"ct-settlement-transfer-v1";
/// Domain for a block hash — so a block hash can never be confused with any other digest.
const BLOCK_DOMAIN: &[u8] = b"ct-settlement-block-v1";

/// Why appending / validating failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A transfer's signature does not verify against its `from` account.
    BadSignature,
    /// The `from` account tried to spend more than its balance.
    Overdraft { from: Account, balance: Amount, amount: Amount },
    /// The transfer's nonce isn't the sender's next expected nonce (replay / gap).
    BadNonce { from: Account, expected: u64, got: u64 },
    /// Crediting `to` would overflow `u64` — rejected rather than silently wrapping/saturating a
    /// balance. Under the bounded-supply invariant this is unreachable; checking it keeps the value
    /// path **fail-closed** (money never silently changes magnitude).
    BalanceOverflow { to: Account, balance: Amount, amount: Amount },
    /// A stored block's hash or `prev_hash` linkage is wrong (tamper detected).
    BrokenChain { height: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BadSignature => write!(f, "transfer signature does not verify"),
            ChainError::Overdraft { balance, amount, .. } => {
                write!(f, "overdraft: balance {balance} < amount {amount}")
            }
            ChainError::BadNonce { expected, got, .. } => {
                write!(f, "bad nonce: expected {expected}, got {got}")
            }
            ChainError::BalanceOverflow { balance, amount, .. } => {
                write!(f, "balance overflow: {balance} + {amount} exceeds u64")
            }
            ChainError::BrokenChain { height } => write!(f, "broken chain at block {height}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// A signed token transfer. Authorized ONLY by `from`'s ed25519 signature over its canonical preimage,
/// so no one can move another account's funds. `nonce` is the sender's monotonic counter (0-based),
/// which makes a transfer single-use — a replayed transfer has a stale nonce and is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: Account,
    pub to: Account,
    pub amount: Amount,
    pub nonce: u64,
    pub signature: [u8; 64],
}

impl Transfer {
    /// Canonical fixed-wire preimage: `domain ‖ from ‖ to ‖ amount(LE) ‖ nonce(LE)`. All fields are
    /// fixed-size, so the encoding is injective without length prefixes.
    pub fn signing_bytes(from: &Account, to: &Account, amount: Amount, nonce: u64) -> Vec<u8> {
        // #184: DOMAIN ‖ from ‖ to ‖ amount(LE) ‖ nonce(LE) — byte-identical to the prior hand-rolled form.
        Preimage::new(TRANSFER_DOMAIN)
            .fixed(from)
            .fixed(to)
            .u64(amount)
            .u64(nonce)
            .finish()
    }

    /// Construct + sign a transfer from the sender's `SigningKey` (derives `from` from the key, so a
    /// caller cannot spend from an account it does not hold).
    pub fn sign_new(from_key: &SigningKey, to: Account, amount: Amount, nonce: u64) -> Transfer {
        let from = from_key.verifying_key().to_bytes();
        let signature = from_key
            .sign(&Self::signing_bytes(&from, &to, amount, nonce))
            .to_bytes();
        Transfer { from, to, amount, nonce, signature }
    }

    /// Whether `from`'s signature authentically authorizes this transfer.
    pub fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.from) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(&self.from, &self.to, self.amount, self.nonce),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Fixed wire length: `from(32) ‖ to(32) ‖ amount(8) ‖ nonce(8) ‖ signature(64)`.
    pub const WIRE_LEN: usize = 32 + 32 + 8 + 8 + 64;

    /// Canonical fixed-layout binary encoding (the persist / gossip wire form the L4.2/L4.3 slices
    /// consume — a chain that can't be serialized can't be replicated or agreed on).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode from [`encode`](Self::encode). `None` on a wrong-length input.
    pub fn decode(b: &[u8]) -> Option<Transfer> {
        if b.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Transfer {
            from: b[0..32].try_into().ok()?,
            to: b[32..64].try_into().ok()?,
            amount: u64::from_le_bytes(b[64..72].try_into().ok()?),
            nonce: u64::from_le_bytes(b[72..80].try_into().ok()?),
            signature: b[80..144].try_into().ok()?,
        })
    }
}

/// One block: its height, the hash of the previous block (linkage), the transfers it commits, and its
/// own content hash. Tampering any field changes `hash`, and the next block's `prev_hash` no longer
/// matches — so a single edit anywhere breaks [`Chain::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub transfers: Vec<Transfer>,
    pub hash: [u8; 32],
}

impl Block {
    /// Canonical binary encoding: `height(8) ‖ prev_hash(32) ‖ count(u32 LE) ‖ ⟨transfers⟩ ‖ hash(32)`
    /// — the wire form for persistence + L4.3 gossip.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + 32 + 4 + self.transfers.len() * Transfer::WIRE_LEN + 32);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&(self.transfers.len() as u32).to_le_bytes());
        for t in &self.transfers {
            out.extend_from_slice(&t.encode());
        }
        out.extend_from_slice(&self.hash);
        out
    }

    /// Decode from [`encode`](Self::encode). `None` on truncated / mis-sized input. **Structural only**
    /// — the content-hash correctness + `prev_hash` linkage are (re-)checked by [`Chain::is_valid`]
    /// once the block joins a chain, so a decoded block is never trusted on its own.
    pub fn decode(b: &[u8]) -> Option<Block> {
        const HEAD: usize = 8 + 32 + 4; // height + prev_hash + count
        if b.len() < HEAD + 32 {
            return None;
        }
        let height = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let prev_hash: [u8; 32] = b[8..40].try_into().ok()?;
        let count = u32::from_le_bytes(b[40..44].try_into().ok()?) as usize;
        let body = count.checked_mul(Transfer::WIRE_LEN)?;
        let expected = HEAD.checked_add(body)?.checked_add(32)?;
        if b.len() != expected {
            return None;
        }
        let mut transfers = Vec::with_capacity(count);
        for i in 0..count {
            let off = HEAD + i * Transfer::WIRE_LEN;
            transfers.push(Transfer::decode(&b[off..off + Transfer::WIRE_LEN])?);
        }
        let hash: [u8; 32] = b[expected - 32..expected].try_into().ok()?;
        Some(Block { height, prev_hash, transfers, hash })
    }
}

/// The domain-separated content hash of a block: `sha256(domain ‖ height ‖ prev_hash ‖ count ‖
/// ⟨each transfer's from‖to‖amount‖nonce‖signature⟩)`. Includes each signature, so tampering a
/// transfer's authorization also invalidates the block hash.
fn block_hash(height: u64, prev_hash: &[u8; 32], transfers: &[Transfer]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BLOCK_DOMAIN);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update((transfers.len() as u32).to_le_bytes());
    for t in transfers {
        h.update(t.from);
        h.update(t.to);
        h.update(t.amount.to_le_bytes());
        h.update(t.nonce.to_le_bytes());
        h.update(t.signature);
    }
    h.finalize().into()
}

/// An append-only, hash-linked settlement ledger (#147-L4.1). Starts from genesis balances (how the
/// currency is initially allocated — e.g. minted to capacity sellers as they earn) and grows one block
/// at a time. **Single-writer**: this owns the whole chain in memory; multi-writer consensus is a later
/// slice. Every append is fully validated (signatures, nonces, no overdraft) before it is committed, and
/// [`is_valid`](Self::is_valid) re-derives the entire state from genesis so a stored chain is
/// tamper-evident end to end.
#[derive(Debug, Clone)]
pub struct Chain {
    genesis: BTreeMap<Account, Amount>,
    blocks: Vec<Block>,
}

impl Chain {
    /// A new chain with the given genesis allocations. The genesis block is height 0, `prev_hash` all
    /// zero, no transfers.
    pub fn new(genesis: BTreeMap<Account, Amount>) -> Self {
        let genesis_block = Block {
            height: 0,
            prev_hash: [0u8; 32],
            transfers: Vec::new(),
            hash: block_hash(0, &[0u8; 32], &[]),
        };
        Self { genesis, blocks: vec![genesis_block] }
    }

    /// The hash of the current tip (the block a new block links to).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.blocks.last().expect("chain always has the genesis block").hash
    }

    /// The current height (the tip's height).
    pub fn height(&self) -> u64 {
        self.blocks.last().expect("genesis").height
    }

    /// The tip block — the one a node gossips to peers (#147-L4.3 send side). `encode` it and a peer
    /// feeds the bytes to [`accept_block`](Self::accept_block).
    pub fn tip_block(&self) -> &Block {
        self.blocks.last().expect("chain always has the genesis block")
    }

    /// Fold genesis + all committed transfers into `(balances, next_nonce per sender)`.
    fn state(&self) -> (BTreeMap<Account, Amount>, BTreeMap<Account, u64>) {
        let balances = self.genesis.clone();
        let nonces = BTreeMap::new();
        let mut acc = (balances, nonces);
        for block in &self.blocks {
            for t in &block.transfers {
                // Committed transfers were validated at append time; apply unconditionally.
                Self::apply(&mut acc.0, &mut acc.1, t);
            }
        }
        acc
    }

    fn apply(balances: &mut BTreeMap<Account, Amount>, nonces: &mut BTreeMap<Account, u64>, t: &Transfer) {
        *balances.entry(t.from).or_insert(0) = balances.get(&t.from).copied().unwrap_or(0).saturating_sub(t.amount);
        *balances.entry(t.to).or_insert(0) = balances.get(&t.to).copied().unwrap_or(0).saturating_add(t.amount);
        *nonces.entry(t.from).or_insert(0) += 1;
    }

    /// Validate a candidate transfer against a working `(balances, nonces)` state; on success mutate the
    /// state to reflect it. Rejects a bad signature, a stale/gapped nonce, or an overdraft.
    fn validate_and_apply(
        balances: &mut BTreeMap<Account, Amount>,
        nonces: &mut BTreeMap<Account, u64>,
        t: &Transfer,
    ) -> Result<(), ChainError> {
        if !t.verify() {
            return Err(ChainError::BadSignature);
        }
        let expected = nonces.get(&t.from).copied().unwrap_or(0);
        if t.nonce != expected {
            return Err(ChainError::BadNonce { from: t.from, expected, got: t.nonce });
        }
        let balance = balances.get(&t.from).copied().unwrap_or(0);
        if balance < t.amount {
            return Err(ChainError::Overdraft { from: t.from, balance, amount: t.amount });
        }
        // Fail-closed on the credit side too: reject a transfer that would overflow the recipient's
        // balance rather than let `apply`'s saturating_add silently cap it. Unreachable under bounded
        // supply, but a validated block must never contain a credit that changes magnitude silently.
        let to_balance = balances.get(&t.to).copied().unwrap_or(0);
        if to_balance.checked_add(t.amount).is_none() {
            return Err(ChainError::BalanceOverflow { to: t.to, balance: to_balance, amount: t.amount });
        }
        Self::apply(balances, nonces, t);
        Ok(())
    }

    /// Append a block of `transfers`, committing them only if ALL validate (signatures, nonces, no
    /// overdraft) against the current state applied in order. Rejects the whole block on the first bad
    /// transfer — the chain is never left in a partially-applied state.
    pub fn append(&mut self, transfers: Vec<Transfer>) -> Result<(), ChainError> {
        let (mut balances, mut nonces) = self.state();
        for t in &transfers {
            Self::validate_and_apply(&mut balances, &mut nonces, t)?;
        }
        let height = self.height() + 1;
        let prev_hash = self.tip_hash();
        let hash = block_hash(height, &prev_hash, &transfers);
        self.blocks.push(Block { height, prev_hash, transfers, hash });
        Ok(())
    }

    /// Accept a **complete block a peer produced** (#147-L4.2 receive side — the counterpart to
    /// [`append`](Self::append), which produces locally). Validates that it extends the current tip
    /// (right `height` + `prev_hash`), that its stored content `hash` is correct, and that every
    /// transfer is valid against *this node's* current state (signature, nonce, no overdraft) — then
    /// commits it, or rejects it leaving the chain unchanged. This is the primitive block gossip (L4.3)
    /// and consensus (L4.2) build on to replicate the ledger across writers; fork-choice / voting is a
    /// later slice (this only accepts a block that cleanly extends the local tip).
    pub fn accept_block(&mut self, block: Block) -> Result<(), ChainError> {
        // Gossip (L4.3) re-delivers blocks by design, so a peer will hand us blocks we already
        // hold. A genuine re-delivery of a block already committed at its height is an idempotent
        // no-op success — NOT an error — otherwise every redundant delivery looks like a fault and
        // a gossip loop that penalizes accept_block errors would punish a well-behaved peer. We
        // treat it as a duplicate only when it is content-consistent AND its hash matches the block
        // we already hold at that height; a *conflicting* block at a known height (same height,
        // different hash — a fork/equivocation) is still rejected, since accepting it would require
        // fork-choice (a later slice).
        if block.height <= self.height() {
            let known_hash = self.blocks[block.height as usize].hash;
            let content_ok =
                block.hash == block_hash(block.height, &block.prev_hash, &block.transfers);
            if content_ok && known_hash == block.hash {
                return Ok(());
            }
            return Err(ChainError::BrokenChain { height: block.height });
        }
        let expected_height = self.height() + 1;
        if block.height != expected_height
            || block.prev_hash != self.tip_hash()
            || block.hash != block_hash(block.height, &block.prev_hash, &block.transfers)
        {
            return Err(ChainError::BrokenChain { height: expected_height });
        }
        let (mut balances, mut nonces) = self.state();
        for t in &block.transfers {
            Self::validate_and_apply(&mut balances, &mut nonces, t)?;
        }
        self.blocks.push(block);
        Ok(())
    }

    /// The balance of `account` = its genesis allocation plus/minus every committed transfer.
    pub fn balance(&self, account: &Account) -> Amount {
        self.state().0.get(account).copied().unwrap_or(0)
    }

    /// Re-derive the whole chain from genesis and check it is intact: every block's stored `hash` is
    /// the true content hash, every `prev_hash` links to the previous block, and every transfer in
    /// sequence has a valid signature, the right nonce, and no overdraft. Any tamper anywhere → `Err`.
    pub fn is_valid(&self) -> Result<(), ChainError> {
        let mut balances = self.genesis.clone();
        let mut nonces: BTreeMap<Account, u64> = BTreeMap::new();
        let mut prev_hash = [0u8; 32];
        for (i, block) in self.blocks.iter().enumerate() {
            let expected_height = i as u64;
            if block.height != expected_height
                || block.prev_hash != prev_hash
                || block.hash != block_hash(block.height, &block.prev_hash, &block.transfers)
            {
                return Err(ChainError::BrokenChain { height: expected_height });
            }
            // The genesis block carries no transfers.
            for t in &block.transfers {
                Self::validate_and_apply(&mut balances, &mut nonces, t)?;
            }
            prev_hash = block.hash;
        }
        Ok(())
    }
}

/// Domain separating a [`Hold`] preimage from every other signed object in the codebase.
const HOLD_DOMAIN: &[u8] = b"ct-settlement-hold-v1";

/// A consumer's signed instruction to **lock** `amount` in escrow for one auction match (#147-L2 —
/// *escrow-at-match*, maintainer decision 2026-07-23). Authorized ONLY by `from`'s (the consumer's)
/// ed25519 signature, so no one can lock another account's funds. The locked amount is released to
/// `to` (the provider) when a co-signed [`UsageReceipt`] for the **same** `match_ref` proves
/// consumption (#147-L3), or refunded to `from` once `expires_at` passes with no proof — so a winning
/// bid's guaranteed floor is a *held* amount (≈ a cap), never a unilateral loss on an unfulfilled win.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    /// The consumer locking the funds (and the signer).
    pub from: Account,
    /// The provider who receives the funds on release.
    pub to: Account,
    pub amount: Amount,
    /// Binds the hold to a specific auction match — the same id the [`UsageReceipt`] carries.
    pub match_ref: [u8; 32],
    /// The consumer's monotonic hold counter (0-based) — makes a hold single-use, like a [`Transfer`].
    pub nonce: u64,
    /// Once `now >= expires_at`, an unreleased hold may be [`refund`](Escrow::refund)ed to `from`.
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl Hold {
    /// Canonical fixed-wire preimage: `domain ‖ from ‖ to ‖ amount(LE) ‖ match_ref ‖ nonce(LE) ‖
    /// expires_at(LE)`. All fields fixed-size, so the encoding is injective without length prefixes.
    pub fn signing_bytes(
        from: &Account,
        to: &Account,
        amount: Amount,
        match_ref: &[u8; 32],
        nonce: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ from ‖ to ‖ amount(LE) ‖ match_ref ‖ nonce(LE) ‖ expires_at(LE) — byte-identical.
        Preimage::new(HOLD_DOMAIN)
            .fixed(from)
            .fixed(to)
            .u64(amount)
            .fixed(match_ref)
            .u64(nonce)
            .u64(expires_at)
            .finish()
    }

    /// Construct + sign a hold from the consumer's `SigningKey` (derives `from` from the key, so a
    /// caller cannot lock funds from an account it does not hold).
    pub fn sign_new(
        from_key: &SigningKey,
        to: Account,
        amount: Amount,
        match_ref: [u8; 32],
        nonce: u64,
        expires_at: u64,
    ) -> Hold {
        let from = from_key.verifying_key().to_bytes();
        let signature = from_key
            .sign(&Self::signing_bytes(&from, &to, amount, &match_ref, nonce, expires_at))
            .to_bytes();
        Hold { from, to, amount, match_ref, nonce, expires_at, signature }
    }

    /// Whether `from`'s signature authentically authorizes this hold.
    pub fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.from) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.from,
                        &self.to,
                        self.amount,
                        &self.match_ref,
                        self.nonce,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Fixed wire length: `from(32) ‖ to(32) ‖ amount(8) ‖ match_ref(32) ‖ nonce(8) ‖ expires_at(8) ‖
    /// signature(64)`.
    pub const WIRE_LEN: usize = 32 + 32 + 8 + 32 + 8 + 8 + 64;

    /// Canonical fixed-layout binary encoding (#147-L2 on-chain escrow — maintainer decision
    /// 2026-07-24: escrow committed on-chain for maximum transaction security). This is the wire form a
    /// `Hold` needs to be persisted, replicated, and committed in a settlement block — exactly as
    /// [`Transfer::encode`] is for a transfer — so the lock becomes tamper-evident chain state rather
    /// than in-memory-only.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.match_ref);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode from [`encode`](Self::encode). `None` on a wrong-length input. Structural only — the
    /// signature is (re-)checked by [`verify`](Self::verify) / [`Escrow::lock`], so a decoded hold is
    /// never trusted on its own.
    pub fn decode(b: &[u8]) -> Option<Hold> {
        if b.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Hold {
            from: b[0..32].try_into().ok()?,
            to: b[32..64].try_into().ok()?,
            amount: u64::from_le_bytes(b[64..72].try_into().ok()?),
            match_ref: b[72..104].try_into().ok()?,
            nonce: u64::from_le_bytes(b[104..112].try_into().ok()?),
            expires_at: u64::from_le_bytes(b[112..120].try_into().ok()?),
            signature: b[120..184].try_into().ok()?,
        })
    }
}

/// Why an [`Escrow`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowError {
    /// The hold's signature does not verify against its `from` account.
    BadSignature,
    /// The consumer tried to lock more than its available balance.
    Overdraft { from: Account, balance: Amount, amount: Amount },
    /// The hold's nonce isn't the consumer's next expected nonce (replay / gap).
    BadNonce { from: Account, expected: u64, got: u64 },
    /// A hold already exists for this `match_ref` — a match escrows exactly once.
    DuplicateHold { match_ref: [u8; 32] },
    /// No held funds for this `match_ref` (never locked, or already released / refunded).
    UnknownHold { match_ref: [u8; 32] },
    /// The consumption proof isn't a valid co-signed receipt, or its `provider`/`consumer` don't
    /// match the held record — so it can't authorize releasing these funds.
    ReceiptMismatch,
    /// A refund was attempted before the hold's `expires_at` — the provider still has time to prove.
    NotYetExpired { expires_at: u64, now: u64 },
    /// Crediting the payee (provider on release, consumer on refund) would overflow `u64` — the op is
    /// rejected with the hold left intact rather than silently wrapping a balance. Unreachable under
    /// bounded supply; present so the value paths are fail-closed (money never silently wraps).
    BalanceOverflow { account: Account, balance: Amount, amount: Amount },
}

impl std::fmt::Display for EscrowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscrowError::BadSignature => write!(f, "hold signature does not verify"),
            EscrowError::Overdraft { balance, amount, .. } => {
                write!(f, "overdraft: balance {balance} < amount {amount}")
            }
            EscrowError::BadNonce { expected, got, .. } => {
                write!(f, "bad nonce: expected {expected}, got {got}")
            }
            EscrowError::DuplicateHold { .. } => write!(f, "a hold already exists for this match"),
            EscrowError::UnknownHold { .. } => write!(f, "no held funds for this match"),
            EscrowError::ReceiptMismatch => {
                write!(f, "receipt is not a valid co-signed proof for the held record")
            }
            EscrowError::NotYetExpired { expires_at, now } => {
                write!(f, "hold not yet refundable: now {now} < expires_at {expires_at}")
            }
            EscrowError::BalanceOverflow { balance, amount, .. } => {
                write!(f, "balance overflow: {balance} + {amount} exceeds u64")
            }
        }
    }
}

impl std::error::Error for EscrowError {}

/// One escrowed record: the funds locked for a match, awaiting release-on-proof or refund-on-timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldRecord {
    from: Account,
    to: Account,
    amount: Amount,
    expires_at: u64,
}

/// An **in-memory escrow ledger** (#147-L2, escrow-at-match). Same single-writer, in-memory scope as
/// the L4.1 [`Chain`] (folding holds into the hash-linked block is a follow slice). It tracks
/// available `balances`, per-consumer hold `nonces`, and the currently-`held` records keyed by
/// `match_ref`. The lifecycle: [`lock`](Self::lock) moves a consumer's funds out of available into
/// escrow at match time; [`release`](Self::release) pays them to the provider on a co-signed
/// [`UsageReceipt`]; [`refund`](Self::refund) returns them to the consumer after expiry if no proof
/// arrived. Value is conserved throughout: `Σ balances + Σ held` never changes across operations.
#[derive(Debug, Default)]
pub struct Escrow {
    balances: BTreeMap<Account, Amount>,
    nonces: BTreeMap<Account, u64>,
    held: BTreeMap<[u8; 32], HeldRecord>,
}

impl Escrow {
    /// A fresh escrow with genesis account balances (the consumers' spendable funds).
    pub fn new(genesis: BTreeMap<Account, Amount>) -> Self {
        Escrow { balances: genesis, nonces: BTreeMap::new(), held: BTreeMap::new() }
    }

    /// The available (spendable, not-escrowed) balance of `account`.
    pub fn balance(&self, account: &Account) -> Amount {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// The amount currently held in escrow for `match_ref` (0 if none).
    pub fn held_amount(&self, match_ref: &[u8; 32]) -> Amount {
        self.held.get(match_ref).map(|r| r.amount).unwrap_or(0)
    }

    /// **Lock** consumer funds for a match. Verifies the consumer's signature, that `nonce` is its
    /// next expected value, that no hold already exists for this `match_ref`, and that it has the
    /// balance — then moves `amount` out of available into escrow. On any error nothing changes.
    pub fn lock(&mut self, hold: &Hold) -> Result<(), EscrowError> {
        if !hold.verify() {
            return Err(EscrowError::BadSignature);
        }
        let expected = self.nonces.get(&hold.from).copied().unwrap_or(0);
        if hold.nonce != expected {
            return Err(EscrowError::BadNonce { from: hold.from, expected, got: hold.nonce });
        }
        if self.held.contains_key(&hold.match_ref) {
            return Err(EscrowError::DuplicateHold { match_ref: hold.match_ref });
        }
        let balance = self.balance(&hold.from);
        if balance < hold.amount {
            return Err(EscrowError::Overdraft { from: hold.from, balance, amount: hold.amount });
        }
        self.balances.insert(hold.from, balance - hold.amount);
        self.nonces.insert(hold.from, expected + 1);
        self.held.insert(
            hold.match_ref,
            HeldRecord { from: hold.from, to: hold.to, amount: hold.amount, expires_at: hold.expires_at },
        );
        Ok(())
    }

    /// **Release** a match's held funds to the provider on a valid co-signed consumption proof
    /// (#147-L3). The `receipt` must be a valid [`UsageReceipt`] whose `provider`/`consumer` match
    /// the held record's `to`/`from` — the receipt is what authorizes moving the money, so a forged
    /// or mismatched one can't drain the escrow. Idempotency: the hold is removed on release, so a
    /// replayed receipt hits [`EscrowError::UnknownHold`] rather than paying twice.
    pub fn release(&mut self, receipt: &UsageReceipt) -> Result<(), EscrowError> {
        let rec = self
            .held
            .get(&receipt.match_ref)
            .ok_or(EscrowError::UnknownHold { match_ref: receipt.match_ref })?;
        if !receipt.is_valid() || receipt.provider != rec.to || receipt.consumer != rec.from {
            return Err(EscrowError::ReceiptMismatch);
        }
        let (to, amount) = (rec.to, rec.amount);
        // Compute the credit before mutating, so an overflow leaves the hold intact (fail-closed).
        let credited = self
            .balance(&to)
            .checked_add(amount)
            .ok_or(EscrowError::BalanceOverflow { account: to, balance: self.balance(&to), amount })?;
        self.held.remove(&receipt.match_ref);
        self.balances.insert(to, credited);
        Ok(())
    }

    /// **Refund** a match's held funds to the consumer once `now >= expires_at` and no proof has
    /// released them. Before expiry this is [`EscrowError::NotYetExpired`] (the provider still has
    /// time to deliver + prove). The hold is removed on refund, so it can't be double-refunded or
    /// released afterwards.
    pub fn refund(&mut self, match_ref: &[u8; 32], now: u64) -> Result<(), EscrowError> {
        let rec = self
            .held
            .get(match_ref)
            .ok_or(EscrowError::UnknownHold { match_ref: *match_ref })?;
        if now < rec.expires_at {
            return Err(EscrowError::NotYetExpired { expires_at: rec.expires_at, now });
        }
        let (from, amount) = (rec.from, rec.amount);
        // Compute the credit before mutating, so an overflow leaves the hold intact (fail-closed).
        let credited = self
            .balance(&from)
            .checked_add(amount)
            .ok_or(EscrowError::BalanceOverflow { account: from, balance: self.balance(&from), amount })?;
        self.held.remove(match_ref);
        self.balances.insert(from, credited);
        Ok(())
    }

    /// Enumerate the `match_ref`s of every hold whose deadline has passed at `now` and that hasn't been
    /// released yet (#151 — the missing reconciliation primitive). A reconciliation loop calls this to
    /// **discover** which holds are refundable without having to track every `match_ref` it ever locked
    /// (fragile across restarts). Read-only; deterministic order (ascending `match_ref`).
    pub fn expired_holds(&self, now: u64) -> Vec<[u8; 32]> {
        self.held
            .iter()
            .filter(|(_, rec)| now >= rec.expires_at)
            .map(|(match_ref, _)| *match_ref)
            .collect()
    }

    /// **Refund every expired-but-unreleased hold** at `now`, returning the `match_ref`s actually
    /// refunded (#151 reconciliation sweep — the one call a lightweight periodic in-process loop makes
    /// so buyer funds don't sit locked forever when a provider never delivers). Combines
    /// [`expired_holds`](Self::expired_holds) with [`refund`](Self::refund) per match; value-conserving
    /// and idempotent — a second sweep at the same `now` refunds nothing new (the holds are gone) and
    /// still-current holds are untouched. No new service/DB/dependency: just a scheduled call into
    /// existing code (the `tokio::time::interval` driver is the live-wiring follow, wherever the escrow
    /// instance lives).
    pub fn refund_expired(&mut self, now: u64) -> Vec<[u8; 32]> {
        self.expired_holds(now)
            .into_iter()
            .filter(|match_ref| self.refund(match_ref, now).is_ok())
            .collect()
    }
}

/// Domain separating a [`Vote`] preimage from every other signed object in the codebase.
const VOTE_DOMAIN: &[u8] = b"ct-settlement-vote-v1";

/// A writer's **signed vote for a leader candidate in a term** (#147-L4.2, Raft-style election — the
/// maintainer-chosen "fast + fault-tolerant" flavor). The single-writer chain (L4.1) becomes
/// multi-writer by electing one leader per term who alone [`append`](Chain::append)s; this is the vote
/// the election tallies. Authorized ONLY by the voter's own ed25519 signature, so votes can't be
/// forged; an honest voter casts one vote per term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub term: u64,
    /// The writer proposed as leader (an [`Account`]).
    pub candidate: Account,
    /// The writer casting the vote (the signer).
    pub voter: Account,
    pub signature: [u8; 64],
}

impl Vote {
    /// Canonical fixed-wire preimage: `domain ‖ term(LE) ‖ candidate ‖ voter`. All fixed-size, so the
    /// encoding is injective without length prefixes.
    pub fn signing_bytes(term: u64, candidate: &Account, voter: &Account) -> Vec<u8> {
        // #184: DOMAIN ‖ term(LE) ‖ candidate ‖ voter — byte-identical to the prior hand-rolled form.
        Preimage::new(VOTE_DOMAIN)
            .u64(term)
            .fixed(candidate)
            .fixed(voter)
            .finish()
    }

    /// Construct + sign a vote from the voter's `SigningKey` (derives `voter` from the key, so a vote
    /// can't be attributed to a writer that didn't cast it).
    pub fn sign_new(voter_key: &SigningKey, term: u64, candidate: Account) -> Vote {
        let voter = voter_key.verifying_key().to_bytes();
        let signature = voter_key.sign(&Self::signing_bytes(term, &candidate, &voter)).to_bytes();
        Vote { term, candidate, voter, signature }
    }

    /// Whether the voter's signature authentically authorizes this vote.
    pub fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.voter) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(self.term, &self.candidate, &self.voter),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// **Tally votes for `term` and return the elected leader**, if a candidate has a strict majority of
/// `members` (#147-L4.2). A vote counts only when it (1) `verify`s, (2) is for `term`, (3) is cast by a
/// `members` writer, and (4) names a `members` writer as candidate. A voter that appears more than once
/// in the term is counted **once** — its first accepted vote in `votes` order — so an equivocating
/// writer can't inflate a candidate's tally beyond one. Returns the unique candidate with `> members/2`
/// votes, or `None` if none reaches a majority (a hung election — the caller keeps the prior leader /
/// retries a higher term, never a split-brain commit).
pub fn elect_leader(votes: &[Vote], members: &[Account], term: u64) -> Option<Account> {
    let member_set: BTreeSet<&Account> = members.iter().collect();
    // Group each member-voter's DISTINCT candidate choices among the valid votes for `term`. Using
    // `BTreeSet`s makes the tally a pure function of the vote *set*, independent of the `votes` slice's
    // iteration order (#157): two nodes that received the same votes over an unordered gossip channel in
    // a different arrival order now compute the identical result — no order-dependent split-brain.
    let mut voter_choices: BTreeMap<Account, BTreeSet<Account>> = BTreeMap::new();
    for v in votes {
        if v.term != term
            || !member_set.contains(&v.voter)
            || !member_set.contains(&v.candidate)
            || !v.verify()
        {
            continue;
        }
        voter_choices.entry(v.voter).or_default().insert(v.candidate);
    }
    // One vote per HONEST voter. A voter that chose **more than one** distinct candidate in the term is
    // equivocating — provably Byzantine — and is **excluded entirely** (never counted toward any
    // candidate), so it can't tip an election either way. A voter that merely repeated the same vote
    // (a gossip duplicate) chose exactly one candidate and counts once. The old "first accepted in slice
    // order" rule counted such an equivocator's arbitrary first vote, which is exactly the
    // order-dependence #157 reported.
    let mut tally: BTreeMap<Account, usize> = BTreeMap::new();
    for choices in voter_choices.values() {
        if choices.len() == 1 {
            let candidate = *choices.iter().next().expect("len == 1");
            *tally.entry(candidate).or_insert(0) += 1;
        }
    }
    let needed = members.len() / 2 + 1; // strict majority: > members/2
    tally.into_iter().find(|&(_, count)| count >= needed).map(|(candidate, _)| candidate)
}

/// Domain separating a [`LeaderAttestation`] preimage from every other signed object.
const LEADER_BLOCK_DOMAIN: &[u8] = b"ct-settlement-leader-block-v1";

/// A **leader's signature over a block it produced in a term** (#147-L4.2 leader-append). Once a term
/// elects a leader ([`elect_leader`]), only that leader may extend the chain; it attaches this
/// attestation to each block so a follower can verify — before [`accept_block`](Chain::accept_block)ing
/// — that the block came from the term's elected leader, not any writer. The leader signs
/// `domain ‖ term ‖ leader ‖ block_hash`, binding the attestation to the exact block (its content hash)
/// and term, so it can be neither forged nor replayed onto a different block or term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderAttestation {
    pub term: u64,
    /// The attesting leader (an [`Account`]) — the signature is checked against this.
    pub leader: Account,
    /// The content hash of the attested block (see [`Chain::tip_block`] / `Block::hash`).
    pub block_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl LeaderAttestation {
    /// Canonical fixed-wire preimage: `domain ‖ term(LE) ‖ leader ‖ block_hash`. All fixed-size, so the
    /// encoding is injective without length prefixes.
    pub fn signing_bytes(term: u64, leader: &Account, block_hash: &[u8; 32]) -> Vec<u8> {
        // #184: DOMAIN ‖ term(LE) ‖ leader ‖ block_hash — byte-identical to the prior hand-rolled form.
        Preimage::new(LEADER_BLOCK_DOMAIN)
            .u64(term)
            .fixed(leader)
            .fixed(block_hash)
            .finish()
    }

    /// Construct + sign an attestation from the leader's `SigningKey` (derives `leader` from the key,
    /// so an attestation can't be attributed to a writer that didn't produce the block).
    pub fn sign_new(leader_key: &SigningKey, term: u64, block_hash: [u8; 32]) -> LeaderAttestation {
        let leader = leader_key.verifying_key().to_bytes();
        let signature = leader_key.sign(&Self::signing_bytes(term, &leader, &block_hash)).to_bytes();
        LeaderAttestation { term, leader, block_hash, signature }
    }

    /// Whether the leader's signature authentically authorizes this attestation.
    pub fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.leader) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(self.term, &self.leader, &self.block_hash),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// **Authorize a block for leader-append** (#147-L4.2-iii): the follower-side check that composes the
/// election with block acceptance. Returns `true` iff the attestation (1) is for `term`, (2) names the
/// `elected_leader` for that term (from [`elect_leader`]), (3) is for **this** block (`block_hash`
/// matches), and (4) verifies. This is the reusable authorization heart a follower runs *before*
/// [`accept_block`](Chain::accept_block) so a non-leader — even a valid writer — cannot extend the
/// chain, enforcing Raft's single-leader-per-term safety. (Embedding the attestation in the block wire
/// form + calling this inside `accept_block` is the follow slice; this is the pure, tested predicate.)
pub fn authorize_leader_block(
    att: &LeaderAttestation,
    elected_leader: &Account,
    term: u64,
    block_hash: &[u8; 32],
) -> bool {
    att.term == term && &att.leader == elected_leader && &att.block_hash == block_hash && att.verify()
}

/// A single **settlement operation** a block commits (#147-L2 on-chain escrow (b) — maintainer
/// decision 2026-07-24: escrow on-chain as first-class tamper-evident ops). Unifies value transfers
/// with the escrow lifecycle so a block's `Vec<SettlementOp>` is the one tamper-evident record of
/// everything that moved or locked value:
/// - `Transfer` — a signed value transfer (authorized by `from`'s signature);
/// - `Hold` — a consumer's signed escrow lock;
/// - `Release` — release an escrowed hold to the provider, authorized by a co-signed [`UsageReceipt`];
/// - `Refund` — refund an expired, unreleased hold to its consumer (expiry-authorized at apply time,
///   so it carries only the `match_ref`, no signature).
///
/// Each op's payload is its own canonical wire form; [`encode`](Self::encode) prefixes a one-byte tag
/// so a decoder dispatches to the right payload. Structural only — signatures/expiry are re-checked
/// when the op is applied ([`Chain`]/[`Escrow`]), never trusted on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementOp {
    Transfer(Transfer),
    Hold(Hold),
    Release(UsageReceipt),
    Refund([u8; 32]),
}

impl SettlementOp {
    fn tag(&self) -> u8 {
        match self {
            SettlementOp::Transfer(_) => 0,
            SettlementOp::Hold(_) => 1,
            SettlementOp::Release(_) => 2,
            SettlementOp::Refund(_) => 3,
        }
    }

    /// Encode as `tag(1) ‖ <payload>`, where the payload is the op's own canonical wire form
    /// ([`Transfer::encode`]/[`Hold::encode`]/[`UsageReceipt::encode`], or the bare 32-byte `match_ref`
    /// for a refund).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.tag()];
        match self {
            SettlementOp::Transfer(t) => out.extend_from_slice(&t.encode()),
            SettlementOp::Hold(h) => out.extend_from_slice(&h.encode()),
            SettlementOp::Release(r) => out.extend_from_slice(&r.encode()),
            SettlementOp::Refund(match_ref) => out.extend_from_slice(match_ref),
        }
        out
    }

    /// Decode a single op from a buffer that is **exactly** one op (`tag ‖ payload`). `None` on an empty
    /// buffer, an unknown tag, or a payload that isn't exactly the tagged op's wire form (each payload
    /// decoder is exact-length / self-delimiting, so trailing bytes are rejected). Block framing of a
    /// `Vec<SettlementOp>` (length-prefixing each op) is the follow slice.
    pub fn decode(b: &[u8]) -> Option<SettlementOp> {
        let (tag, payload) = b.split_first()?;
        match tag {
            0 => Transfer::decode(payload).map(SettlementOp::Transfer),
            1 => Hold::decode(payload).map(SettlementOp::Hold),
            2 => UsageReceipt::decode(payload).map(SettlementOp::Release),
            3 => (payload.len() == 32).then(|| SettlementOp::Refund(payload.try_into().unwrap())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #252: `Preimage::new` now length-prefixes the domain (`u32-LE len || domain`).
    fn dom(d: &[u8]) -> Vec<u8> {
        let mut v = (d.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(d);
        v
    }

    #[test]
    fn signing_bytes_golden_vectors_are_byte_identical_after_the_preimage_refactor() {
        // #184 (frozen): pin the EXACT preimage bytes for each fixed-field settlement primitive so the
        // Preimage-builder refactor cannot drift a single byte — a drift would silently change every
        // signature over that object type and break all verification. `expected` is the canonical
        // `DOMAIN ‖ fields…` layout built by hand (identical to the prior hand-rolled encoders).
        let a1: Account = [0x11; 32];
        let a2: Account = [0x22; 32];
        let mref = [0x33u8; 32];
        let bhash = [0x44u8; 32];

        // Transfer: DOMAIN ‖ from ‖ to ‖ amount(LE) ‖ nonce(LE)
        let mut e = Vec::new();
        e.extend_from_slice(&dom(TRANSFER_DOMAIN));
        e.extend_from_slice(&a1);
        e.extend_from_slice(&a2);
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(Transfer::signing_bytes(&a1, &a2, 7, 9), e, "Transfer preimage drifted");

        // Hold: DOMAIN ‖ from ‖ to ‖ amount(LE) ‖ match_ref ‖ nonce(LE) ‖ expires_at(LE)
        let mut e = Vec::new();
        e.extend_from_slice(&dom(HOLD_DOMAIN));
        e.extend_from_slice(&a1);
        e.extend_from_slice(&a2);
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&mref);
        e.extend_from_slice(&9u64.to_le_bytes());
        e.extend_from_slice(&11u64.to_le_bytes());
        assert_eq!(Hold::signing_bytes(&a1, &a2, 7, &mref, 9, 11), e, "Hold preimage drifted");

        // Vote: DOMAIN ‖ term(LE) ‖ candidate ‖ voter
        let mut e = Vec::new();
        e.extend_from_slice(&dom(VOTE_DOMAIN));
        e.extend_from_slice(&5u64.to_le_bytes());
        e.extend_from_slice(&a1);
        e.extend_from_slice(&a2);
        assert_eq!(Vote::signing_bytes(5, &a1, &a2), e, "Vote preimage drifted");

        // LeaderAttestation: DOMAIN ‖ term(LE) ‖ leader ‖ block_hash
        let mut e = Vec::new();
        e.extend_from_slice(&dom(LEADER_BLOCK_DOMAIN));
        e.extend_from_slice(&5u64.to_le_bytes());
        e.extend_from_slice(&a1);
        e.extend_from_slice(&bhash);
        assert_eq!(LeaderAttestation::signing_bytes(5, &a1, &bhash), e, "LeaderAttestation preimage drifted");
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn acct(sk: &SigningKey) -> Account {
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn elect_leader_needs_a_verified_majority_and_resists_forgery_and_equivocation() {
        // #147-L4.2 (frozen): a Raft-style leader election elects the candidate with a STRICT majority
        // of members, counting only authentic votes for the term from members; forged/foreign votes are
        // ignored, an equivocating voter is counted once, and no majority → None (hung, never
        // split-brain). 3 members → 2 votes elect; 1 vote does not.
        let (w1, w2, w3) = (key(1), key(2), key(3));
        let (a, b, c) = (acct(&w1), acct(&w2), acct(&w3));
        let members = [a, b, c];
        let term = 7;

        // Majority: w1 and w2 both vote for candidate `a` in term 7 → a is elected.
        let elected = elect_leader(
            &[Vote::sign_new(&w1, term, a), Vote::sign_new(&w2, term, a)],
            &members,
            term,
        );
        assert_eq!(elected, Some(a), "two of three votes for `a` elect it");

        // No majority: one vote each for a and b → hung, None.
        assert_eq!(
            elect_leader(&[Vote::sign_new(&w1, term, a), Vote::sign_new(&w2, term, b)], &members, term),
            None,
            "a split vote elects no one (never split-brain)"
        );

        // Wrong term ignored: two votes but for term 6, asked for 7 → None.
        assert_eq!(
            elect_leader(&[Vote::sign_new(&w1, 6, a), Vote::sign_new(&w2, 6, a)], &members, 7),
            None,
            "votes for another term don't count"
        );

        // Forgery: a vote whose signature doesn't match its voter is ignored, so a forged second vote
        // can't manufacture a majority.
        let mut forged = Vote::sign_new(&w2, term, a);
        forged.voter = c; // claim w3 cast it, but it's w2's signature
        assert_eq!(
            elect_leader(&[Vote::sign_new(&w1, term, a), forged], &members, term),
            None,
            "a forged vote is ignored — one real vote is not a majority"
        );

        // Non-member voter ignored: an outsider's authentic vote doesn't count toward the majority.
        let outsider = key(9);
        assert_eq!(
            elect_leader(&[Vote::sign_new(&w1, term, a), Vote::sign_new(&outsider, term, a)], &members, term),
            None,
            "a non-member's vote doesn't count"
        );

        // #157: an equivocating voter (w2 votes for BOTH a and b) is EXCLUDED entirely (provably
        // Byzantine) — it counts toward NO candidate, so it can't tip an election. With only w1 honestly
        // voting `a`, that's 1 of 3 → no majority → None (the old "first accepted" rule wrongly counted
        // w2's arbitrary first vote toward `a` and elected it).
        assert_eq!(
            elect_leader(
                &[
                    Vote::sign_new(&w1, term, a),
                    Vote::sign_new(&w2, term, a),
                    Vote::sign_new(&w2, term, b),
                ],
                &members,
                term,
            ),
            None,
            "an equivocating voter is excluded, so `a` (1 honest vote) has no majority"
        );
        // Equivocation alone can't elect either.
        assert_eq!(
            elect_leader(&[Vote::sign_new(&w2, term, a), Vote::sign_new(&w2, term, b)], &members, term),
            None,
            "one equivocating voter cannot elect anyone"
        );

        // #157 core: the result is a pure function of the vote SET, independent of slice order. A gossip
        // duplicate (same voter, same candidate) still counts once; and permuting the votes — including
        // an equivocating pair — yields the identical result every time.
        let honest = [Vote::sign_new(&w1, term, a), Vote::sign_new(&w2, term, a), Vote::sign_new(&w2, term, a)];
        assert_eq!(elect_leader(&honest, &members, term), Some(a), "w1 + w2 (dup) for a → a elected");
        let mut reversed = honest.clone();
        reversed.reverse();
        assert_eq!(elect_leader(&reversed, &members, term), Some(a), "reversed order → same result (order-independent)");
        // An equivocating pair permuted both ways gives the SAME answer (None) — the reported bug was
        // that b-first vs a-first produced different results.
        let equiv_ab = [Vote::sign_new(&w1, term, a), Vote::sign_new(&w2, term, a), Vote::sign_new(&w2, term, b)];
        let mut equiv_ba = equiv_ab.clone();
        equiv_ba.reverse();
        assert_eq!(
            elect_leader(&equiv_ab, &members, term),
            elect_leader(&equiv_ba, &members, term),
            "same equivocating vote set, different order → identical result (#157 fixed)"
        );
    }

    #[test]
    fn authorize_leader_block_admits_only_the_terms_elected_leader() {
        // #147-L4.2-iii (frozen): a block is authorized for append iff a LeaderAttestation over its
        // hash verifies AND names the term's elected leader — so only the elected leader extends the
        // chain; a non-leader / stale-term / wrong-block / forged attestation is rejected.
        let (w1, w2, w3) = (key(1), key(2), key(3));
        let (a, b, c) = (acct(&w1), acct(&w2), acct(&w3));
        let members = [a, b, c];
        let term = 7;
        let elected =
            elect_leader(&[Vote::sign_new(&w1, term, a), Vote::sign_new(&w2, term, a)], &members, term)
                .expect("a is elected");
        assert_eq!(elected, a);
        let bh = [0x5Au8; 32]; // stand-in for a real Block content hash

        // The elected leader `a` attests the block → authorized.
        let att = LeaderAttestation::sign_new(&w1, term, bh);
        assert!(authorize_leader_block(&att, &elected, term, &bh), "the term's elected leader is authorized");

        // A non-leader `b` attesting the same block → rejected (authentic, but not the leader).
        let att_b = LeaderAttestation::sign_new(&w2, term, bh);
        assert!(!authorize_leader_block(&att_b, &elected, term, &bh), "a non-leader can't authorize a block");

        // Wrong term, wrong block, and a forged signature are all rejected.
        assert!(!authorize_leader_block(&att, &elected, term + 1, &bh), "an attestation for another term is rejected");
        assert!(!authorize_leader_block(&att, &elected, term, &[0u8; 32]), "an attestation for a different block is rejected");
        let mut forged = att.clone();
        forged.signature = [0u8; 64];
        assert!(!authorize_leader_block(&forged, &elected, term, &bh), "a forged/invalid signature is rejected");

        // Impersonation: claiming to be leader `a` while signing with a different key fails verify.
        let mut impersonate = LeaderAttestation::sign_new(&w2, term, bh);
        impersonate.leader = a;
        assert!(!authorize_leader_block(&impersonate, &elected, term, &bh), "claiming the leader's identity without its key fails");
    }

    #[test]
    fn hold_encode_round_trips_and_rejects_malformed() {
        // #147-L2 on-chain escrow (frozen): a Hold has a canonical fixed-wire form — the prerequisite
        // for committing escrow in a settlement block (maintainer decision 2026-07-24: escrow on-chain
        // for max transaction security). It round-trips losslessly, still verifies after decode (the
        // signed content is preserved), and rejects a wrong-length buffer.
        let consumer = key(1);
        let provider = key(2);
        let hold = Hold::sign_new(&consumer, acct(&provider), 4242, [0x3Cu8; 32], 7, 5_000);
        let bytes = hold.encode();
        assert_eq!(bytes.len(), Hold::WIRE_LEN, "fixed wire length");
        let back = Hold::decode(&bytes).expect("round-trips");
        assert_eq!(back, hold, "decode is the inverse of encode");
        assert!(back.verify(), "the decoded hold still verifies (signed content preserved)");
        assert!(Hold::decode(&bytes[..bytes.len() - 1]).is_none(), "a truncated buffer is rejected");
        let mut long = bytes.clone();
        long.push(0);
        assert!(Hold::decode(&long).is_none(), "an over-long buffer is rejected");
    }

    #[test]
    fn settlement_op_encode_round_trips_every_variant_and_rejects_bad_tags() {
        // #147-L2 on-chain escrow (b, frozen): each of the four block-committable ops round-trips
        // through the tagged SettlementOp wire form, the tag distinguishes variants, and a bad tag /
        // truncated / trailing-byte buffer is rejected.
        use crate::channel::{CapacityKind, UsageReceipt};
        let consumer = key(1);
        let provider = key(2);
        let (_c, p) = (acct(&consumer), acct(&provider));
        let m = [0x77u8; 32];

        let ops = vec![
            SettlementOp::Transfer(Transfer::sign_new(&consumer, p, 40, 0)),
            SettlementOp::Hold(Hold::sign_new(&consumer, p, 40, m, 0, 5_000)),
            SettlementOp::Release(UsageReceipt::co_sign(
                &provider, &consumer, CapacityKind::CloudApiQuota, "claude-opus-4-8".into(), 40, m, 1,
            )),
            SettlementOp::Refund(m),
        ];
        for op in &ops {
            let bytes = op.encode();
            assert_eq!(SettlementOp::decode(&bytes).as_ref(), Some(op), "op round-trips through the tagged wire form");
            assert!(SettlementOp::decode(&bytes[..bytes.len() - 1]).is_none(), "a truncated op is rejected");
            let mut long = bytes.clone();
            long.push(0);
            assert!(SettlementOp::decode(&long).is_none(), "trailing bytes are rejected");
        }

        // The tag distinguishes variants: a Hold's payload under the Transfer tag doesn't decode as a
        // Transfer (different fixed length), and vice-versa.
        let hold_bytes = ops[1].encode();
        let mut mistagged = hold_bytes.clone();
        mistagged[0] = 0; // claim Transfer over a Hold payload
        assert!(SettlementOp::decode(&mistagged).is_none(), "a Hold payload can't masquerade as a Transfer");

        // Unknown tag and empty buffer → None.
        assert!(SettlementOp::decode(&[9u8; 40]).is_none(), "an unknown tag is rejected");
        assert!(SettlementOp::decode(&[]).is_none(), "an empty buffer is rejected");

        // A refund is exactly tag ‖ 32-byte match_ref.
        assert_eq!(SettlementOp::Refund(m).encode().len(), 33, "refund is tag + 32-byte match_ref");
    }

    #[test]
    fn escrow_locks_at_match_releases_on_receipt_and_refunds_on_timeout() {
        // #147-L2 (frozen): escrow-at-match. A consumer locks funds for a match; a co-signed L3
        // UsageReceipt for that match releases them to the provider; if no proof arrives, the funds
        // refund to the consumer after expiry — never a unilateral loss. Value is conserved
        // throughout, forged/mismatched receipts can't drain escrow, and every op is single-shot.
        use crate::channel::{CapacityKind, UsageReceipt};
        let consumer = key(1);
        let provider = key(2);
        let (c, p) = (acct(&consumer), acct(&provider));
        let m1 = [0x11u8; 32]; // match A
        let m2 = [0x22u8; 32]; // match B
        let total = |e: &Escrow| e.balance(&c) + e.balance(&p) + e.held_amount(&m1) + e.held_amount(&m2);

        let mut esc = Escrow::new(BTreeMap::from([(c, 100)]));
        assert_eq!(total(&esc), 100, "genesis value");

        // LOCK match A: 40 of the consumer's funds move into escrow (out of available).
        let hold_a = Hold::sign_new(&consumer, p, 40, m1, 0, 1_000);
        esc.lock(&hold_a).expect("a well-signed, funded hold locks");
        assert_eq!(esc.balance(&c), 60, "locked funds leave available balance");
        assert_eq!(esc.held_amount(&m1), 40, "and sit in escrow for the match");
        assert_eq!(total(&esc), 100, "value conserved on lock");

        // RELEASE match A: a co-signed receipt for THIS match pays the provider.
        let receipt = UsageReceipt::co_sign(&provider, &consumer, CapacityKind::CloudApiQuota, "m".into(), 40, m1, 500);
        esc.release(&receipt).expect("a valid co-signed receipt releases to the provider");
        assert_eq!(esc.balance(&p), 40, "provider paid the held amount");
        assert_eq!(esc.held_amount(&m1), 0, "escrow for the match is cleared");
        assert_eq!(total(&esc), 100, "value conserved on release");
        // Replaying the same receipt can't pay twice — the hold is gone.
        assert_eq!(esc.release(&receipt), Err(EscrowError::UnknownHold { match_ref: m1 }), "no double-release");

        // LOCK match B, then let it time out and REFUND to the consumer.
        let hold_b = Hold::sign_new(&consumer, p, 25, m2, 1, 2_000);
        esc.lock(&hold_b).expect("second hold (next nonce) locks");
        assert_eq!(esc.balance(&c), 35, "60 - 25 held for match B");
        // Refund before expiry is refused — the provider still has time to prove.
        assert_eq!(
            esc.refund(&m2, 1_999),
            Err(EscrowError::NotYetExpired { expires_at: 2_000, now: 1_999 }),
            "can't refund before expiry"
        );
        esc.refund(&m2, 2_000).expect("at expiry, an unproven hold refunds to the consumer");
        assert_eq!(esc.balance(&c), 60, "consumer got the 25 back");
        assert_eq!(total(&esc), 100, "value conserved on refund");
        assert_eq!(esc.refund(&m2, 3_000), Err(EscrowError::UnknownHold { match_ref: m2 }), "no double-refund");

        // Guard rails on lock.
        let mut esc2 = Escrow::new(BTreeMap::from([(c, 10)]));
        let overdraft = Hold::sign_new(&consumer, p, 999, m1, 0, 1_000);
        assert!(matches!(esc2.lock(&overdraft), Err(EscrowError::Overdraft { .. })), "can't lock more than balance");
        let mut forged = Hold::sign_new(&consumer, p, 5, m1, 0, 1_000);
        forged.amount = 6; // tamper after signing
        assert_eq!(esc2.lock(&forged), Err(EscrowError::BadSignature), "a tampered hold is rejected");
        // Good lock, then a duplicate match_ref and a stale nonce are both refused.
        esc2.lock(&Hold::sign_new(&consumer, p, 5, m1, 0, 1_000)).expect("funded hold locks");
        let dup = Hold::sign_new(&consumer, p, 1, m1, 1, 1_000);
        assert_eq!(esc2.lock(&dup), Err(EscrowError::DuplicateHold { match_ref: m1 }), "one hold per match");
        let stale = Hold::sign_new(&consumer, p, 1, m2, 0, 1_000);
        assert!(matches!(esc2.lock(&stale), Err(EscrowError::BadNonce { .. })), "a replayed hold nonce is rejected");

        // A receipt for the WRONG match, or naming a different provider/consumer, can't release a hold.
        let mut esc3 = Escrow::new(BTreeMap::from([(c, 100)]));
        esc3.lock(&Hold::sign_new(&consumer, p, 30, m1, 0, 1_000)).unwrap();
        let wrong_match = UsageReceipt::co_sign(&provider, &consumer, CapacityKind::CloudApiQuota, "m".into(), 30, m2, 1);
        assert_eq!(esc3.release(&wrong_match), Err(EscrowError::UnknownHold { match_ref: m2 }), "receipt for another match doesn't release");
        let stranger = key(9);
        let wrong_provider = UsageReceipt::co_sign(&stranger, &consumer, CapacityKind::CloudApiQuota, "m".into(), 30, m1, 1);
        assert_eq!(esc3.release(&wrong_provider), Err(EscrowError::ReceiptMismatch), "receipt naming a different provider can't drain the hold");
        assert_eq!(esc3.held_amount(&m1), 30, "the mismatched attempts left the escrow untouched");
    }

    #[test]
    fn refund_expired_reconciles_only_past_deadline_holds_and_is_idempotent() {
        // #151 (frozen): the reconciliation sweep discovers and refunds every expired-but-unreleased
        // hold, leaves still-current holds locked, credits each consumer back (value-conserving), and
        // is idempotent — a second sweep at the same time refunds nothing new. This is what makes the
        // escrow-at-match buyer protection actual instead of theoretical.
        let consumer = key(1);
        let provider = key(2);
        let (c, p) = (acct(&consumer), acct(&provider));
        let (m1, m2, m3) = ([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]);
        let total = |e: &Escrow| e.balance(&c) + e.balance(&p) + e.held_amount(&m1) + e.held_amount(&m2) + e.held_amount(&m3);

        let mut esc = Escrow::new(BTreeMap::from([(c, 100)]));
        esc.lock(&Hold::sign_new(&consumer, p, 10, m1, 0, 1_000)).unwrap(); // expires 1_000
        esc.lock(&Hold::sign_new(&consumer, p, 20, m2, 1, 2_000)).unwrap(); // expires 2_000
        esc.lock(&Hold::sign_new(&consumer, p, 30, m3, 2, 1_000)).unwrap(); // expires 1_000
        assert_eq!(esc.balance(&c), 40, "60 locked across three holds");
        assert_eq!(total(&esc), 100, "genesis value");

        // Enumeration is read-only and finds exactly the past-deadline holds at now=1_500 (m1, m3).
        assert_eq!(esc.expired_holds(1_500), vec![m1, m3], "only the two expired holds are enumerated");
        assert_eq!(esc.held_amount(&m1), 10, "expired_holds does not mutate");

        // Sweep at 1_500: refunds m1 + m3 to the consumer; m2 (not yet expired) stays held.
        assert_eq!(esc.refund_expired(1_500), vec![m1, m3], "the sweep refunds exactly the expired holds");
        assert_eq!(esc.balance(&c), 80, "consumer made whole for m1(10)+m3(30)");
        assert_eq!(esc.held_amount(&m2), 20, "the still-current hold is untouched");
        assert_eq!(total(&esc), 100, "value conserved across the sweep");

        // Idempotent: a second sweep at the same time refunds nothing (the expired holds are gone, m2
        // isn't due yet).
        assert!(esc.refund_expired(1_500).is_empty(), "a repeat sweep refunds nothing new");
        assert_eq!(esc.balance(&c), 80, "no double refund");

        // Later, m2's deadline passes → the sweep refunds it too.
        assert_eq!(esc.refund_expired(2_000), vec![m2], "m2 refunds once its deadline passes");
        assert_eq!(esc.balance(&c), 100, "consumer fully made whole; nothing sat locked forever");
        assert!(esc.expired_holds(9_999).is_empty(), "no holds remain");
    }

    #[test]
    fn credits_that_would_overflow_a_balance_are_rejected_fail_closed() {
        // Central's money-path advisory (frozen): a credit that would overflow u64 is rejected with
        // an explicit error rather than silently saturating/wrapping a balance — on BOTH the L4.1
        // chain append path and the L2 escrow release/refund paths — and state is left unchanged.
        use crate::channel::{CapacityKind, UsageReceipt};
        let alice = key(1);
        let bob = key(2);
        let (a, b) = (acct(&alice), acct(&bob));

        // Chain: bob is near u64::MAX; a transfer that would overflow him is rejected at append and
        // the chain is left unchanged (no partial commit), while a fitting transfer still commits.
        let mut chain = Chain::new(BTreeMap::from([(a, 100), (b, u64::MAX - 10)]));
        assert!(
            matches!(
                chain.append(vec![Transfer::sign_new(&alice, b, 50, 0)]),
                Err(ChainError::BalanceOverflow { .. })
            ),
            "a transfer that would overflow the recipient is rejected"
        );
        assert_eq!(chain.height(), 0, "the overflowing block was not committed");
        assert_eq!(chain.balance(&b), u64::MAX - 10, "bob's balance is unchanged");
        chain.append(vec![Transfer::sign_new(&alice, b, 5, 0)]).expect("a fitting transfer still commits");
        assert_eq!(chain.balance(&b), u64::MAX - 5);

        // Escrow release: crediting a maxed-out provider is rejected with the hold left intact.
        // (The provider is pre-funded to u64::MAX in genesis — the receiving side of a real match.)
        let m = [0x33u8; 32];
        let mut esc = Escrow::new(BTreeMap::from([(a, 100), (b, u64::MAX)]));
        esc.lock(&Hold::sign_new(&alice, b, 40, m, 0, 1_000)).unwrap();
        let receipt = UsageReceipt::co_sign(&bob, &alice, CapacityKind::CloudApiQuota, "m".into(), 40, m, 1);
        assert_eq!(
            esc.release(&receipt),
            Err(EscrowError::BalanceOverflow { account: b, balance: u64::MAX, amount: 40 }),
            "releasing into a maxed provider is rejected, not silently wrapped"
        );
        assert_eq!(esc.held_amount(&m), 40, "the hold is left intact on overflow (fail-closed)");
        assert_eq!(esc.balance(&b), u64::MAX, "provider balance unchanged");

        // The refund credit path has the symmetric `checked_add` guard; an overflow there is
        // unreachable under value conservation (a consumer only gets back what it locked), so we just
        // confirm a normal refund still makes the consumer exactly whole.
        esc.refund(&m, 2_000).expect("after expiry the unreleased hold refunds");
        assert_eq!(esc.balance(&a), 100, "alice made whole (60 remaining + 40 refunded), no overflow");
        assert_eq!(esc.held_amount(&m), 0, "hold cleared by the refund");
    }

    #[test]
    fn a_chain_of_signed_transfers_conserves_value_and_stays_valid() {
        // #147-L4.1 (frozen): genesis funds an account; signed transfers move value; balances update;
        // the whole chain re-validates from genesis (hash links + signatures + nonces + no overdraft).
        let alice = key(1);
        let bob = key(2);
        let carol = key(3);
        let (a, b, c) = (acct(&alice), acct(&bob), acct(&carol));

        let mut chain = Chain::new(BTreeMap::from([(a, 100)]));
        assert!(chain.is_valid().is_ok(), "genesis chain is valid");
        assert_eq!(chain.balance(&a), 100);
        assert_eq!(chain.height(), 0);

        // Block 1: alice → bob 30, alice → carol 20 (alice's nonces 0 then 1).
        chain
            .append(vec![
                Transfer::sign_new(&alice, b, 30, 0),
                Transfer::sign_new(&alice, c, 20, 1),
            ])
            .expect("valid block appends");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.balance(&a), 50, "alice spent 50");
        assert_eq!(chain.balance(&b), 30);
        assert_eq!(chain.balance(&c), 20);

        // Block 2: bob → carol 30 (bob's first send, nonce 0). Value is conserved (30+50=80... total 100).
        chain.append(vec![Transfer::sign_new(&bob, c, 30, 0)]).expect("appends");
        assert_eq!(chain.balance(&b), 0);
        assert_eq!(chain.balance(&c), 50);
        assert_eq!(
            chain.balance(&a) + chain.balance(&b) + chain.balance(&c),
            100,
            "total value is conserved across the chain"
        );
        assert!(chain.is_valid().is_ok(), "the full chain re-validates");
    }

    #[test]
    fn overdraft_forgery_replay_are_all_rejected() {
        let alice = key(1);
        let bob = key(2);
        let mallory = key(9);
        let (a, b) = (acct(&alice), acct(&bob));

        let mut chain = Chain::new(BTreeMap::from([(a, 10)]));

        // Overdraft: alice has 10, tries to send 11.
        assert!(
            matches!(chain.append(vec![Transfer::sign_new(&alice, b, 11, 0)]), Err(ChainError::Overdraft { .. })),
            "spending more than the balance is rejected"
        );
        assert_eq!(chain.height(), 0, "the bad block was not committed");

        // Forgery: mallory signs a transfer FROM alice's account (from=a but signed by mallory's key).
        let mut forged = Transfer::sign_new(&mallory, b, 5, 0);
        forged.from = a; // claim it's from alice, but the signature is mallory's
        assert!(matches!(chain.append(vec![forged]), Err(ChainError::BadSignature)), "forged sender rejected");

        // Replay: a valid transfer, then the SAME transfer again (stale nonce 0).
        let t = Transfer::sign_new(&alice, b, 4, 0);
        chain.append(vec![t.clone()]).expect("first spend ok");
        assert!(
            matches!(chain.append(vec![t]), Err(ChainError::BadNonce { expected: 1, got: 0, .. })),
            "replaying a spent transfer (stale nonce) is rejected"
        );
        assert_eq!(chain.balance(&a), 6, "alice spent exactly 4, not 8");
    }

    #[test]
    fn tampering_a_committed_block_breaks_is_valid() {
        // #147-L4.1 (frozen): the chain is tamper-evident — editing a committed transfer's amount (even
        // if you don't touch the hash) is caught, because the stored hash no longer matches the content.
        let alice = key(1);
        let bob = key(2);
        let (a, b) = (acct(&alice), acct(&bob));

        let mut chain = Chain::new(BTreeMap::from([(a, 100)]));
        chain.append(vec![Transfer::sign_new(&alice, b, 10, 0)]).unwrap();
        assert!(chain.is_valid().is_ok());

        // Tamper: inflate the committed transfer amount (attacker rewriting history).
        let mut tampered = chain.clone();
        tampered.blocks[1].transfers[0].amount = 90;
        assert!(
            matches!(tampered.is_valid(), Err(ChainError::BrokenChain { height: 1 })),
            "a rewritten amount breaks the block hash"
        );

        // Tamper: break the prev_hash linkage (splice/reorder).
        let mut relinked = chain.clone();
        relinked.blocks[1].prev_hash = [0xAAu8; 32];
        // recompute the block's own hash so only the LINK is wrong, not the content hash
        relinked.blocks[1].hash =
            block_hash(relinked.blocks[1].height, &relinked.blocks[1].prev_hash, &relinked.blocks[1].transfers);
        assert!(
            matches!(relinked.is_valid(), Err(ChainError::BrokenChain { height: 1 })),
            "a broken prev_hash link is caught"
        );
    }

    #[test]
    fn transfer_and_block_encode_round_trip_and_reject_malformed() {
        // #147-L4.2-a (frozen): the persist/gossip wire form round-trips losslessly and rejects
        // truncated input — the prerequisite for replicating/agreeing on the chain (L4.2/L4.3).
        let alice = key(1);
        let bob = key(2);
        let b = acct(&bob);

        let t = Transfer::sign_new(&alice, b, 7, 3);
        assert_eq!(t.encode().len(), Transfer::WIRE_LEN);
        assert_eq!(Transfer::decode(&t.encode()).unwrap(), t, "transfer round-trips");
        assert!(Transfer::decode(&t.encode()[..Transfer::WIRE_LEN - 1]).is_none(), "truncated transfer → None");

        let mut chain = Chain::new(BTreeMap::from([(acct(&alice), 100)]));
        chain
            .append(vec![Transfer::sign_new(&alice, b, 10, 0), Transfer::sign_new(&alice, b, 5, 1)])
            .unwrap();
        let block = chain.blocks[1].clone();
        let bytes = block.encode();
        assert_eq!(Block::decode(&bytes).unwrap(), block, "a two-transfer block round-trips");
        assert!(Block::decode(&bytes[..bytes.len() - 1]).is_none(), "truncated block → None");

        // The genesis (empty) block also round-trips.
        let g = chain.blocks[0].clone();
        assert_eq!(Block::decode(&g.encode()).unwrap(), g, "genesis block round-trips");

        // A decoded block still content-hashes correctly (bytes are the same), so it will re-validate.
        let decoded = Block::decode(&bytes).unwrap();
        assert_eq!(decoded.hash, block_hash(decoded.height, &decoded.prev_hash, &decoded.transfers));
    }

    #[test]
    fn accept_block_replicates_a_valid_peer_block_and_rejects_bad_ones() {
        // #147-L4.2 (frozen): a node accepts a valid block a peer produced (extends tip, hash correct,
        // transfers valid) → the two chains converge; and it rejects wrong-height, tampered-hash, and
        // forged-transfer blocks. This is the ledger-sync primitive gossip + consensus build on.
        let alice = key(1);
        let bob = key(2);
        let mallory = key(9);
        let (a, b) = (acct(&alice), acct(&bob));
        let genesis = BTreeMap::from([(a, 100)]);

        // Producer mines a block; a fresh replica (same genesis) accepts it and converges.
        let mut producer = Chain::new(genesis.clone());
        let mut replica = Chain::new(genesis.clone());
        producer.append(vec![Transfer::sign_new(&alice, b, 40, 0)]).unwrap();
        let block = producer.blocks[1].clone();

        replica.accept_block(block.clone()).expect("a valid peer block is accepted");
        assert_eq!(replica.tip_hash(), producer.tip_hash(), "replica converged to the producer's tip");
        assert_eq!(replica.balance(&b), 40);
        assert!(replica.is_valid().is_ok(), "the replicated chain re-validates");

        // Gossip re-delivers blocks: re-accepting the SAME block the replica already holds is an
        // idempotent no-op (not a fault), so redundant delivery can't look like peer misbehavior.
        replica
            .accept_block(block.clone())
            .expect("re-accepting an already-held block is an idempotent no-op");
        assert_eq!(replica.height(), 1, "a duplicate delivery neither grows nor forks the chain");
        assert_eq!(replica.tip_hash(), producer.tip_hash(), "still converged after the duplicate");
        assert_eq!(replica.balance(&b), 40, "a duplicate delivery doesn't double-apply transfers");

        // A CONFLICTING block at an already-known height (same height, different content) is a real
        // fork and is still rejected — accepting it would require fork-choice (a later slice).
        let mut producer2 = Chain::new(genesis.clone());
        producer2.append(vec![Transfer::sign_new(&alice, b, 30, 0)]).unwrap();
        let conflicting = producer2.blocks[1].clone();
        assert_ne!(conflicting.hash, block.hash, "the fork block genuinely differs at height 1");
        assert!(
            matches!(replica.accept_block(conflicting), Err(ChainError::BrokenChain { .. })),
            "a conflicting block at an already-known height (a fork) is rejected, not silently taken"
        );
        assert_eq!(replica.balance(&b), 40, "the rejected fork left committed state untouched");

        // Tampered hash: a block claiming a correct link but a wrong content hash.
        let mut fresh = Chain::new(genesis.clone());
        let mut bad_hash = block.clone();
        bad_hash.hash = [0x11u8; 32];
        assert!(
            matches!(fresh.accept_block(bad_hash), Err(ChainError::BrokenChain { .. })),
            "a block with an incorrect content hash is rejected"
        );

        // Forged transfer: a well-linked, correctly-hashed block whose transfer isn't signed by `from`.
        let mut forged = Transfer::sign_new(&mallory, b, 5, 0);
        forged.from = a;
        let ph = fresh.tip_hash();
        let h = block_hash(1, &ph, std::slice::from_ref(&forged));
        let forged_block = Block { height: 1, prev_hash: ph, transfers: vec![forged], hash: h };
        assert!(
            matches!(fresh.accept_block(forged_block), Err(ChainError::BadSignature)),
            "a block carrying a forged transfer is rejected"
        );
        assert_eq!(fresh.height(), 0, "no bad block was ever committed to the replica");
    }
}
