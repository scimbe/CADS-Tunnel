//! Pseudonymous accounts + prepaid-credit ledger (M15.1, ADR-0012, SPEC §9).
//!
//! An account is addressed only by an opaque, random [`AccountId`] — the control
//! plane stores no PII, so accounts are pseudonymous. Each account carries a
//! prepaid credit balance: tunnels are paid for by debiting credits (M15.2), and
//! credits are topped up out of band by a payment stub (M15.3). In-memory,
//! and holds no trust material itself — unlike some other control-plane
//! services (credential-issuer key, EAB, DNS-provider token; see #266).
//!
//! Note on the threat model: pseudonymity + prepaid credit does not by itself
//! stop a *funded* adversary from opening many accounts (sybil). That economic
//! limitation is tracked in `BACKLOG.md` and flagged, not solved here.

use std::collections::HashMap;

use rand::RngCore;

/// Opaque pseudonymous account identifier (32 random bytes; hex on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(pub [u8; 32]);

/// Why a ledger operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// No account with this id.
    UnknownAccount,
    /// The account exists but lacks the credit to cover the debit; the balance
    /// is left unchanged.
    InsufficientCredit { balance: u64, requested: u64 },
    /// #440/#441: this exact idempotency key was already used by a DIFFERENT account's
    /// issuance — `token_issuances.idempotency_key` is the table's sole `PRIMARY KEY`
    /// (not yet scoped to `(account, idempotency_key)`; the caller's own per-account
    /// lookup already ruled out "my own retry", so a `UNIQUE` violation reaching this
    /// point means a genuine cross-account key collision, a real conflict to surface,
    /// not a raw DB error).
    IdempotencyKeyReused,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::UnknownAccount => write!(f, "unknown account"),
            LedgerError::InsufficientCredit { balance, requested } => {
                write!(f, "insufficient credit: balance {balance}, requested {requested}")
            }
            LedgerError::IdempotencyKeyReused => {
                write!(f, "idempotency key already used by a different account")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// In-memory pseudonymous-account credit ledger.
#[derive(Default)]
pub struct Ledger {
    balances: HashMap<AccountId, u64>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a fresh pseudonymous account with a zero balance; returns its id.
    pub fn open_account(&mut self) -> AccountId {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let id = AccountId(bytes);
        self.balances.insert(id.clone(), 0);
        id
    }

    /// Current balance, or [`LedgerError::UnknownAccount`].
    pub fn balance(&self, id: &AccountId) -> Result<u64, LedgerError> {
        self.balances
            .get(id)
            .copied()
            .ok_or(LedgerError::UnknownAccount)
    }

    /// Add prepaid credit (top-up); returns the new balance. Saturating so a
    /// hostile top-up amount can never wrap the balance.
    pub fn credit(&mut self, id: &AccountId, amount: u64) -> Result<u64, LedgerError> {
        let bal = self.balances.get_mut(id).ok_or(LedgerError::UnknownAccount)?;
        *bal = bal.saturating_add(amount);
        Ok(*bal)
    }

    /// Spend credit; returns the new balance. Fails with
    /// [`LedgerError::InsufficientCredit`] and leaves the balance unchanged when
    /// the account cannot cover `amount`.
    pub fn debit(&mut self, id: &AccountId, amount: u64) -> Result<u64, LedgerError> {
        let bal = self.balances.get_mut(id).ok_or(LedgerError::UnknownAccount)?;
        if *bal < amount {
            return Err(LedgerError::InsufficientCredit {
                balance: *bal,
                requested: amount,
            });
        }
        *bal -= amount;
        Ok(*bal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_account_is_pseudonymous_and_starts_at_zero() {
        let mut ledger = Ledger::new();
        let a = ledger.open_account();
        let b = ledger.open_account();
        assert_ne!(a, b, "each account gets a distinct opaque id");
        assert_eq!(ledger.balance(&a).unwrap(), 0, "new account has no credit");
    }

    #[test]
    fn credit_then_debit_tracks_the_balance() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        assert_eq!(ledger.credit(&acct, 100).unwrap(), 100);
        assert_eq!(ledger.credit(&acct, 50).unwrap(), 150, "top-ups accumulate");
        assert_eq!(ledger.debit(&acct, 30).unwrap(), 120);
        assert_eq!(ledger.balance(&acct).unwrap(), 120);
    }

    #[test]
    fn debit_beyond_balance_is_refused_without_mutation() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        ledger.credit(&acct, 10).unwrap();
        assert_eq!(
            ledger.debit(&acct, 25),
            Err(LedgerError::InsufficientCredit { balance: 10, requested: 25 })
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 10, "refused debit left the balance intact");
    }

    #[test]
    fn zero_balance_account_cannot_spend() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        assert!(matches!(
            ledger.debit(&acct, 1),
            Err(LedgerError::InsufficientCredit { balance: 0, requested: 1 })
        ));
    }

    #[test]
    fn unknown_account_operations_error() {
        let mut ledger = Ledger::new();
        let ghost = AccountId([9u8; 32]);
        assert_eq!(ledger.balance(&ghost), Err(LedgerError::UnknownAccount));
        assert_eq!(ledger.credit(&ghost, 5), Err(LedgerError::UnknownAccount));
        assert_eq!(ledger.debit(&ghost, 5), Err(LedgerError::UnknownAccount));
    }
}
