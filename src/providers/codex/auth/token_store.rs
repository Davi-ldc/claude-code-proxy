use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use super::jwt::{TokenIdentity, token_identity};
use crate::auth::{AuthStorage, AuthStoreLock, KeychainFileAuthStore, SystemKeychain};
use crate::paths;

pub const KEYCHAIN_SERVICE: &str = "claude-code-proxy.codex";
pub const KEYCHAIN_ACCOUNT: &str = "auth";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAuth {
    pub access: String,
    pub refresh: String,
    pub expires: u64,
    #[serde(
        default,
        rename = "accountId",
        alias = "account_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub account_id: Option<String>,
}

impl StoredAuth {
    pub fn identity(&self) -> TokenIdentity {
        token_identity(&self.access)
    }

    /// Pool key for the login behind these tokens. Token refreshes keep it,
    /// and signing in again as the same user replaces that entry.
    pub fn account_key(&self) -> String {
        self.identity()
            .account_user_id
            .or_else(|| self.account_id.clone())
            .unwrap_or_else(|| "default".to_string())
    }
}

/// A stored login and, while upstream reports its usage limit, when that
/// limit resets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexAccount {
    pub auth: StoredAuth,
    #[serde(
        default,
        rename = "limitedUntil",
        skip_serializing_if = "Option::is_none"
    )]
    pub limited_until: Option<u64>,
}

impl CodexAccount {
    pub fn key(&self) -> String {
        self.auth.account_key()
    }

    pub fn has_quota(&self, now: u64) -> bool {
        self.limited_until.is_none_or(|until| until <= now)
    }
}

/// Every stored Codex login and the one serving requests.
///
/// Selection is sticky: the active account serves until upstream reports its
/// usage limit. Prompt caches, `previous_response_id` continuations and pooled
/// sockets belong to one account, so rotating any sooner would discard them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "StoredPool")]
pub struct CodexAccountPool {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    pub accounts: Vec<CodexAccount>,
}

/// On-disk shapes. A file holding a single login loads as a pool of one.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredPool {
    Pool {
        #[serde(default)]
        active: Option<String>,
        accounts: Vec<CodexAccount>,
    },
    Single(StoredAuth),
}

impl From<StoredPool> for CodexAccountPool {
    fn from(stored: StoredPool) -> Self {
        match stored {
            StoredPool::Pool { active, accounts } => Self { active, accounts },
            StoredPool::Single(auth) => {
                let mut pool = Self::default();
                pool.upsert(auth);
                pool
            }
        }
    }
}

impl CodexAccountPool {
    pub fn index_of(&self, key: &str) -> Option<usize> {
        self.accounts
            .iter()
            .position(|account| account.key() == key)
    }

    pub fn active_index(&self) -> Option<usize> {
        self.index_of(self.active.as_deref()?)
    }

    /// Picks the account for the next request: the active one while it has
    /// quota, else the next one in order with quota, else the one whose limit
    /// resets first. Limits that have already reset are cleared.
    pub fn select(&mut self, now: u64) -> Option<&CodexAccount> {
        for account in &mut self.accounts {
            if account.limited_until.is_some_and(|until| until <= now) {
                account.limited_until = None;
            }
        }
        let len = self.accounts.len();
        if len == 0 {
            self.active = None;
            return None;
        }
        let start = self.active_index().unwrap_or(0);
        let index = (0..len)
            .map(|offset| (start + offset) % len)
            .find(|&index| self.accounts[index].limited_until.is_none())
            .or_else(|| (0..len).min_by_key(|&index| self.accounts[index].limited_until))
            .unwrap_or(start);
        self.active = Some(self.accounts[index].key());
        Some(&self.accounts[index])
    }

    /// Stores a login, replacing the tokens of an existing entry for the same
    /// user. The first login becomes active; later ones wait their turn.
    pub fn upsert(&mut self, auth: StoredAuth) -> usize {
        let index = match self.index_of(&auth.account_key()) {
            Some(index) => {
                self.accounts[index].auth = auth;
                index
            }
            None => {
                self.accounts.push(CodexAccount {
                    auth,
                    limited_until: None,
                });
                self.accounts.len() - 1
            }
        };
        if self.active_index().is_none() {
            self.active = Some(self.accounts[index].key());
        }
        index
    }

    /// Records a usage limit, keeping the later reset when one is known.
    pub fn mark_limited(&mut self, key: &str, until: u64) {
        if let Some(index) = self.index_of(key) {
            let limited_until = &mut self.accounts[index].limited_until;
            *limited_until = Some(limited_until.map_or(until, |current| current.max(until)));
        }
    }

    /// Makes an account active and forgets its recorded limit. An explicit
    /// choice overrides the bookkeeping; upstream re-reports a limit that
    /// still holds.
    pub fn activate(&mut self, index: usize) {
        self.accounts[index].limited_until = None;
        self.active = Some(self.accounts[index].key());
    }

    /// Removes an account. Removing the active one hands over to the account
    /// that took its place in order.
    pub fn remove(&mut self, index: usize) -> CodexAccount {
        let was_active = self.active_index() == Some(index);
        let removed = self.accounts.remove(index);
        if was_active {
            self.active = (!self.accounts.is_empty())
                .then(|| self.accounts[index % self.accounts.len()].key());
        }
        removed
    }

    /// Resolves a CLI selector: a 1-based position from `auth status`, an
    /// email, or a prefix of the account ID or account key.
    pub fn resolve(&self, selector: &str) -> anyhow::Result<usize> {
        let len = self.accounts.len();
        if let Ok(position) = selector.parse::<usize>() {
            return position
                .checked_sub(1)
                .filter(|&index| index < len)
                .ok_or_else(|| anyhow!("No account {position}; {len} stored"));
        }
        let matches: Vec<usize> = self
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, account)| {
                account
                    .auth
                    .identity()
                    .email
                    .is_some_and(|email| email.eq_ignore_ascii_case(selector))
                    || account
                        .auth
                        .account_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with(selector))
                    || account.key().starts_with(selector)
            })
            .map(|(index, _)| index)
            .collect();
        match matches.as_slice() {
            [index] => Ok(*index),
            [] => bail!("No stored account matches '{selector}'"),
            _ => bail!("'{selector}' matches several accounts; use its number from `auth status`"),
        }
    }
}

pub struct CodexTokenStore<S: AuthStorage<CodexAccountPool>> {
    store: S,
}

impl<S: AuthStorage<CodexAccountPool>> CodexTokenStore<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn load(&self) -> Result<CodexAccountPool, anyhow::Error> {
        Ok(self.store.load()?.unwrap_or_default())
    }

    pub fn save(&self, pool: CodexAccountPool) -> Result<(), anyhow::Error> {
        if pool.accounts.is_empty() {
            self.store.clear()
        } else {
            self.store.save(pool)
        }
    }

    pub fn lock(&self) -> Result<AuthStoreLock, anyhow::Error> {
        self.store.lock()
    }

    pub fn path(&self) -> String {
        self.store.path()
    }
}

pub type DefaultCodexAuthStore = KeychainFileAuthStore<CodexAccountPool, SystemKeychain>;

pub fn file_store() -> CodexTokenStore<DefaultCodexAuthStore> {
    let primary = paths::provider_auth_file("codex");
    let legacy = paths::provider_legacy_auth_file("codex");
    let store = KeychainFileAuthStore::new(
        primary.to_string_lossy().to_string(),
        legacy.to_string_lossy().to_string(),
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
        use_macos_keychain(),
        SystemKeychain,
    );
    CodexTokenStore::new(store)
}

fn use_macos_keychain() -> bool {
    cfg!(target_os = "macos") && std::env::var_os("CCP_CONFIG_DIR").is_none()
}

#[cfg(test)]
mod tests {
    use super::super::jwt::test_token;
    use super::*;
    use crate::auth::InMemoryAuthStore;
    use serde_json::json;

    fn login(account_id: &str) -> StoredAuth {
        StoredAuth {
            access: format!("access-{account_id}"),
            refresh: format!("refresh-{account_id}"),
            expires: 4102444800000,
            account_id: Some(account_id.into()),
        }
    }

    fn pool_of(account_ids: &[&str]) -> CodexAccountPool {
        let mut pool = CodexAccountPool::default();
        for account_id in account_ids {
            pool.upsert(login(account_id));
        }
        pool
    }

    fn active_account_id(pool: &mut CodexAccountPool, now: u64) -> Option<String> {
        pool.select(now)?.auth.account_id.clone()
    }

    #[test]
    fn stored_auth_reads_account_id_alias() {
        let auth: StoredAuth = serde_json::from_value(json!({
            "access": "a",
            "refresh": "r",
            "expires": 123,
            "accountId": "acct"
        }))
        .unwrap();
        assert_eq!(auth.account_id.as_deref(), Some("acct"));
    }

    #[test]
    fn stored_auth_writes_account_id_key() {
        let value = serde_json::to_value(login("acct_1")).unwrap();
        assert_eq!(value["accountId"], "acct_1");
        assert!(value.get("account_id").is_none());
    }

    #[test]
    fn account_key_prefers_workspace_user_over_shared_account_id() {
        let member = |user: &str| StoredAuth {
            access: test_token(json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "workspace",
                    "chatgpt_account_user_id": format!("{user}__workspace")
                }
            })),
            refresh: "r".into(),
            expires: 0,
            account_id: Some("workspace".into()),
        };
        let mut pool = CodexAccountPool::default();
        pool.upsert(member("user-1"));
        pool.upsert(member("user-2"));
        assert_eq!(pool.accounts.len(), 2);
        assert_eq!(pool.accounts[1].key(), "user-2__workspace");
    }

    #[test]
    fn single_login_file_loads_as_active_pool_of_one() {
        let pool: CodexAccountPool = serde_json::from_value(json!({
            "access": "a",
            "refresh": "r",
            "expires": 123,
            "accountId": "acct_1"
        }))
        .unwrap();
        assert_eq!(pool.active.as_deref(), Some("acct_1"));
        assert_eq!(pool.accounts.len(), 1);
        assert_eq!(pool.accounts[0].limited_until, None);
    }

    #[test]
    fn pool_roundtrips_through_store() {
        let store = CodexTokenStore::new(InMemoryAuthStore::new());
        let mut pool = pool_of(&["acct_1", "acct_2"]);
        pool.mark_limited("acct_1", 42);
        store.save(pool.clone()).unwrap();
        assert_eq!(store.load().unwrap(), pool);

        let value = serde_json::to_value(&pool).unwrap();
        assert_eq!(value["active"], "acct_1");
        assert_eq!(value["accounts"][0]["limitedUntil"], 42);
        assert!(value["accounts"][1].get("limitedUntil").is_none());
    }

    #[test]
    fn select_keeps_the_active_account_until_it_is_limited() {
        let mut pool = pool_of(&["acct_1", "acct_2", "acct_3"]);
        pool.activate(1);
        assert_eq!(active_account_id(&mut pool, 0).as_deref(), Some("acct_2"));

        pool.mark_limited("acct_2", 100);
        assert_eq!(active_account_id(&mut pool, 0).as_deref(), Some("acct_3"));
        assert_eq!(active_account_id(&mut pool, 0).as_deref(), Some("acct_3"));

        // A reset does not pull the pool back to the earlier account.
        assert_eq!(active_account_id(&mut pool, 100).as_deref(), Some("acct_3"));
        assert_eq!(pool.accounts[1].limited_until, None);
    }

    #[test]
    fn select_waits_on_the_earliest_reset_when_every_account_is_limited() {
        let mut pool = pool_of(&["acct_1", "acct_2"]);
        pool.mark_limited("acct_1", 300);
        pool.mark_limited("acct_2", 200);
        assert_eq!(active_account_id(&mut pool, 0).as_deref(), Some("acct_2"));
    }

    #[test]
    fn mark_limited_keeps_the_later_reset() {
        let mut pool = pool_of(&["acct_1"]);
        pool.mark_limited("acct_1", 300);
        pool.mark_limited("acct_1", 200);
        assert_eq!(pool.accounts[0].limited_until, Some(300));
    }

    #[test]
    fn upsert_replaces_tokens_for_the_same_login_without_changing_active() {
        let mut pool = pool_of(&["acct_1", "acct_2"]);
        let mut renewed = login("acct_2");
        renewed.refresh = "renewed".into();
        assert_eq!(pool.upsert(renewed), 1);
        assert_eq!(pool.accounts.len(), 2);
        assert_eq!(pool.accounts[1].auth.refresh, "renewed");
        assert_eq!(pool.active.as_deref(), Some("acct_1"));
    }

    #[test]
    fn removing_the_active_account_hands_over_to_its_successor() {
        let mut pool = pool_of(&["acct_1", "acct_2", "acct_3"]);
        pool.activate(2);
        assert_eq!(pool.remove(2).key(), "acct_3");
        assert_eq!(pool.active.as_deref(), Some("acct_1"));
        pool.remove(0);
        pool.remove(0);
        assert_eq!(pool.active, None);
    }

    #[test]
    fn resolve_accepts_position_email_and_id_prefix() {
        let mut pool = pool_of(&["acct_one", "acct_two"]);
        pool.upsert(StoredAuth {
            access: test_token(json!({
                "https://api.openai.com/profile": { "email": "Three@Example.com" }
            })),
            refresh: "r".into(),
            expires: 0,
            account_id: Some("other".into()),
        });

        assert_eq!(pool.resolve("2").unwrap(), 1);
        assert_eq!(pool.resolve("three@example.com").unwrap(), 2);
        assert_eq!(pool.resolve("acct_t").unwrap(), 1);
        assert!(pool.resolve("4").is_err());
        assert!(pool.resolve("0").is_err());
        assert!(pool.resolve("acct").is_err());
        assert!(pool.resolve("missing").is_err());
    }
}
