//! Credit-gated token issuance (M15.2, ADR-0012, SPEC §9).
//!
//! Ties the prepaid-credit [`Ledger`] to token issuance: a tunnel routing token
//! is minted only if the paying account has the credit to cover it, and the
//! account is debited as part of the same call. A zero- or low-balance account
//! is denied with no token minted and no change to its balance. This is the
//! economic gate on tunnel creation (SPEC §9); the underlying sybil-economics
//! limit stays an open risk (`BACKLOG.md`).

use rand::RngCore;

use ct_common::RoutingToken;

use crate::accounts::{AccountId, Ledger, LedgerError};

/// Default credit price of issuing one tunnel routing token.
pub const TOKEN_PRICE: u64 = 1;

/// Whether a client-supplied issuance `price` is acceptable: a routing token is
/// sold at the fixed [`TOKEN_PRICE`], so anything below it — notably `price:0` —
/// must be refused, otherwise a caller mints a free token (#87 SEC87a). The debit
/// itself still enforces sufficient balance; this is the *policy floor* on top of
/// it, so a funded account cannot buy a token for less than it costs.
pub fn issuance_price_ok(price: u64) -> bool {
    price >= TOKEN_PRICE
}

/// Issue a fresh routing token, charging `price` credits to `account`.
///
/// The debit and the mint are one operation: [`Ledger::debit`] runs first, so
/// on [`LedgerError::InsufficientCredit`] (or an unknown account) no token is
/// minted and the balance is left unchanged. On success the account is debited
/// and a random 32-byte routing token is returned.
pub fn issue_token_for_payment(
    ledger: &mut Ledger,
    account: &AccountId,
    price: u64,
) -> Result<RoutingToken, LedgerError> {
    ledger.debit(account, price)?;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(RoutingToken(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funded_account_gets_a_token_and_is_debited() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        ledger.credit(&acct, 5).unwrap();

        let token = issue_token_for_payment(&mut ledger, &acct, 2).unwrap();
        assert_ne!(token.0, [0u8; 32], "a real routing token is minted");
        assert_eq!(ledger.balance(&acct).unwrap(), 3, "the price was debited");
    }

    #[test]
    fn zero_balance_account_is_denied_without_minting_or_debiting() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();

        let result = issue_token_for_payment(&mut ledger, &acct, TOKEN_PRICE);
        assert!(
            matches!(result, Err(LedgerError::InsufficientCredit { balance: 0, requested: 1 })),
            "zero-balance issuance is refused"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 0, "balance untouched on denial");
    }

    #[test]
    fn issuance_runs_until_credit_is_exhausted() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        ledger.credit(&acct, 3).unwrap();

        // Three tokens at price 1, then denial at zero balance.
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.push(issue_token_for_payment(&mut ledger, &acct, 1).unwrap());
        }
        assert_eq!(ledger.balance(&acct).unwrap(), 0);
        assert!(issue_token_for_payment(&mut ledger, &acct, 1).is_err(), "no credit left");

        // Tokens are distinct.
        tokens.sort_by_key(|a| a.0);
        tokens.dedup_by(|a, b| a.0 == b.0);
        assert_eq!(tokens.len(), 3, "each issued token is unique");
    }

    #[test]
    fn unknown_account_cannot_buy_a_token() {
        let mut ledger = Ledger::new();
        let ghost = AccountId([7u8; 32]);
        assert_eq!(
            issue_token_for_payment(&mut ledger, &ghost, 1),
            Err(LedgerError::UnknownAccount)
        );
    }
}
