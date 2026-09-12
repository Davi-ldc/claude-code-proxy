use anyhow::{anyhow, bail};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

use super::constants::{CLIENT_ID, ISSUER, REFRESH_MARGIN_MS};
use super::jwt::{TokenResponse, extract_account_id, validate_token_response};
use super::token_store::{CodexAccount, CodexAccountPool, CodexTokenStore, StoredAuth};
use crate::auth::AuthStorage;

/// How long an account sits out when upstream reports its usage limit without
/// saying when it resets.
const UNREPORTED_USAGE_LIMIT_RESET_MS: u64 = 60 * 60 * 1000;

static CODEX_REFRESH_LOCK: LazyLock<Arc<AsyncMutex<()>>> =
    LazyLock::new(|| Arc::new(AsyncMutex::new(())));

/// Serializes pool updates within this process; the store lock covers other
/// processes.
static CODEX_POOL_LOCK: Mutex<()> = Mutex::new(());

pub struct CodexAuthManager<S: AuthStorage<CodexAccountPool>> {
    pub store: CodexTokenStore<S>,
    #[cfg(test)]
    test_pool: Arc<Mutex<Option<CodexAccountPool>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_client: reqwest::Client,
    token_endpoint: String,
}

impl<S: AuthStorage<CodexAccountPool>> CodexAuthManager<S> {
    pub fn new(store: CodexTokenStore<S>) -> Self {
        Self::new_with_token_endpoint(store, format!("{ISSUER}/oauth/token"))
    }

    fn new_with_token_endpoint(store: CodexTokenStore<S>, token_endpoint: String) -> Self {
        Self {
            store,
            #[cfg(test)]
            test_pool: Arc::new(Mutex::new(None)),
            refresh_lock: CODEX_REFRESH_LOCK.clone(),
            refresh_client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to create Codex OAuth refresh client"),
            token_endpoint,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Credential of the account that should serve the next request.
    pub async fn get_auth(&self) -> Result<StoredAuth, anyhow::Error> {
        let stored = self
            .update_pool(|pool| {
                Ok(pool
                    .select(Self::now_ms())
                    .map(|account| account.auth.clone()))
            })?
            .ok_or_else(|| anyhow!("Not authenticated. Run: claude-code-proxy codex auth login"))?;

        if stored.expires > Self::now_ms() + REFRESH_MARGIN_MS {
            return Ok(stored);
        }

        self.refresh(&stored.account_key(), false, None).await
    }

    pub async fn force_refresh(&self, rejected: &StoredAuth) -> Result<StoredAuth, anyhow::Error> {
        self.refresh(
            &rejected.account_key(),
            true,
            Some(rejected.access.as_str()),
        )
        .await
    }

    /// Records that `limited` reached its usage limit and moves the pool to
    /// the next account with quota, returning that account's credential.
    /// Returns `None` when every other account is limited too, so the caller
    /// surfaces the limit instead of retrying.
    pub async fn rotate_after_usage_limit(
        &self,
        limited: &StoredAuth,
        resets_at_ms: Option<u64>,
    ) -> Result<Option<StoredAuth>, anyhow::Error> {
        let limited_key = limited.account_key();
        let now = Self::now_ms();
        let next = self.update_pool(|pool| {
            pool.mark_limited(
                &limited_key,
                resets_at_ms.unwrap_or(now + UNREPORTED_USAGE_LIMIT_RESET_MS),
            );
            Ok(pool
                .select(now)
                .filter(|account| account.key() != limited_key && account.has_quota(now))
                .map(|account| account.auth.clone()))
        })?;
        let Some(next) = next else {
            return Ok(None);
        };
        if next.expires > now + REFRESH_MARGIN_MS {
            return Ok(Some(next));
        }
        self.refresh(&next.account_key(), false, None)
            .await
            .map(Some)
    }

    /// Every stored account, without changing which one is active.
    pub fn accounts(&self) -> Result<CodexAccountPool, anyhow::Error> {
        self.load_pool()
    }

    /// Makes another account active: the one `selector` names, or else the
    /// next account after the active one that has quota.
    pub fn switch(&self, selector: Option<&str>) -> Result<CodexAccount, anyhow::Error> {
        self.update_pool(|pool| {
            if pool.accounts.is_empty() {
                bail!("Not authenticated");
            }
            let index = match selector {
                Some(selector) => pool.resolve(selector)?,
                None => {
                    let len = pool.accounts.len();
                    let now = Self::now_ms();
                    let start = pool.active_index().unwrap_or(0);
                    (1..len)
                        .map(|offset| (start + offset) % len)
                        .find(|&index| pool.accounts[index].has_quota(now))
                        .ok_or_else(|| anyhow!("No other stored account has quota left"))?
                }
            };
            pool.activate(index);
            Ok(pool.accounts[index].clone())
        })
    }

    pub fn remove(&self, selector: &str) -> Result<CodexAccount, anyhow::Error> {
        self.update_pool(|pool| {
            let index = pool.resolve(selector)?;
            Ok(pool.remove(index))
        })
    }

    /// Deletes every stored account, including files this build cannot parse.
    pub fn clear(&self) -> Result<(), anyhow::Error> {
        let _process = CODEX_POOL_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        #[cfg(test)]
        if let Some(pool) = self
            .test_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            *pool = CodexAccountPool::default();
            return Ok(());
        }
        let _store = self.store.lock()?;
        self.store.save(CodexAccountPool::default())
    }

    pub fn storage_path(&self) -> String {
        self.store.path()
    }

    /// Adds a fresh login to the pool, or renews the tokens of the same login.
    pub fn persist_initial_tokens(
        &self,
        tokens: &TokenResponse,
    ) -> Result<StoredAuth, anyhow::Error> {
        validate_token_response(tokens)?;
        let account_id = extract_account_id(tokens);
        let expires = Self::now_ms() + (tokens.expires_in.unwrap_or(3600) * 1000);
        let auth = StoredAuth {
            access: tokens.access_token.clone(),
            refresh: tokens.refresh_token.clone(),
            expires,
            account_id,
        };
        self.update_pool(|pool| {
            pool.upsert(auth.clone());
            Ok(())
        })?;
        Ok(auth)
    }

    async fn refresh(
        &self,
        key: &str,
        force: bool,
        rejected_access: Option<&str>,
    ) -> Result<StoredAuth, anyhow::Error> {
        let _refresh_guard = self.refresh_lock.lock().await;

        // Reload from durable storage after acquiring the single-flight lock.
        // Another request may have rotated and persisted this account's token
        // while this caller was waiting, or the account may have been removed,
        // in which case the account now selected takes its place.
        let mut pool = self.load_pool()?;
        let current = match pool.index_of(key) {
            Some(index) => pool.accounts[index].auth.clone(),
            None => pool
                .select(Self::now_ms())
                .map(|account| account.auth.clone())
                .ok_or_else(|| anyhow!("Not authenticated"))?,
        };
        let replaced = current.account_key() != key;
        let force = force && !replaced;
        let rejected_access = rejected_access.filter(|_| !replaced);

        if (!force && current.expires > Self::now_ms() + REFRESH_MARGIN_MS)
            || rejected_access.is_some_and(|access| current.access != access)
        {
            return Ok(current);
        }

        self.refresh_now(&current).await
    }

    async fn refresh_now(&self, current: &StoredAuth) -> Result<StoredAuth, anyhow::Error> {
        if current.refresh.is_empty() {
            bail!("No refresh token stored; re-authenticate");
        }
        let key = current.account_key();

        let form = [
            ("client_id", CLIENT_ID.to_string()),
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", current.refresh.clone()),
        ];

        let resp = self
            .refresh_client
            .post(&self.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| anyhow!("refresh network error: {e}"))?;

        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            // A concurrent login or refresh may already have replaced the
            // rejected refresh token; only a still-current credential is
            // dropped, and only for this account.
            let latest = self.update_pool(|pool| {
                let Some(index) = pool.index_of(&key) else {
                    return Ok(None);
                };
                if pool.accounts[index].auth != *current {
                    return Ok(Some(pool.accounts[index].auth.clone()));
                }
                pool.remove(index);
                Ok(None)
            })?;
            if let Some(latest) = latest {
                return Ok(latest);
            }
            let err_msg = resp
                .text()
                .await
                .unwrap_or_else(|_| "Token refresh unauthorized".to_string());
            bail!("{err_msg}");
        }

        if !resp.status().is_success() {
            bail!("Token refresh failed: {status}");
        }

        let tokens: TokenResponse = resp
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse token response: {e}"))?;
        validate_token_response(&tokens)?;
        let account_id = extract_account_id(&tokens).or_else(|| current.account_id.clone());
        let expires = Self::now_ms() + (tokens.expires_in.unwrap_or(3600) * 1000);
        let next = StoredAuth {
            access: tokens.access_token,
            refresh: tokens.refresh_token,
            expires,
            account_id,
        };
        // An account removed while its refresh was in flight stays removed;
        // the fresh token still serves the request that asked for it.
        self.update_pool(|pool| {
            if let Some(index) = pool.index_of(&key) {
                pool.accounts[index].auth = next.clone();
            }
            Ok(())
        })?;
        Ok(next)
    }

    fn load_pool(&self) -> Result<CodexAccountPool, anyhow::Error> {
        #[cfg(test)]
        if let Some(pool) = self
            .test_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(pool);
        }
        self.store.load()
    }

    /// Runs `update` on the freshest pool under both locks and persists the
    /// result when it changed.
    fn update_pool<R>(
        &self,
        update: impl FnOnce(&mut CodexAccountPool) -> Result<R, anyhow::Error>,
    ) -> Result<R, anyhow::Error> {
        let _process = CODEX_POOL_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        #[cfg(test)]
        if let Some(pool) = self
            .test_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            return update(pool);
        }
        let _store = self.store.lock()?;
        let mut pool = self.store.load()?;
        let before = pool.clone();
        let result = update(&mut pool)?;
        if pool != before {
            self.store.save(pool)?;
        }
        Ok(result)
    }

    /// Replaces durable storage with a single login for tests.
    #[cfg(test)]
    pub fn set_test_auth(&self, auth: StoredAuth) {
        let mut pool = CodexAccountPool::default();
        pool.upsert(auth);
        self.set_test_pool(pool);
    }

    #[cfg(test)]
    pub fn set_test_pool(&self, pool: CodexAccountPool) {
        *self
            .test_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(pool);
    }

    #[cfg(test)]
    pub fn test_pool(&self) -> Option<CodexAccountPool> {
        self.test_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::InMemoryAuthStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn test_store() -> CodexTokenStore<InMemoryAuthStore<CodexAccountPool>> {
        CodexTokenStore::new(InMemoryAuthStore::new())
    }

    fn login(access: &str, refresh: &str, expires: u64, account_id: &str) -> StoredAuth {
        StoredAuth {
            access: access.into(),
            refresh: refresh.into(),
            expires,
            account_id: Some(account_id.into()),
        }
    }

    fn pool_of(logins: impl IntoIterator<Item = StoredAuth>) -> CodexAccountPool {
        let mut pool = CodexAccountPool::default();
        for auth in logins {
            pool.upsert(auth);
        }
        pool
    }

    fn manager_with(
        logins: impl IntoIterator<Item = StoredAuth>,
    ) -> CodexAuthManager<InMemoryAuthStore<CodexAccountPool>> {
        let store = test_store();
        store.save(pool_of(logins)).unwrap();
        CodexAuthManager::new(store)
    }

    fn unauthorized_token_server(
        listener: TcpListener,
        before_response: impl FnOnce() + Send + 'static,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            before_response();
            let body = b"rejected refresh token";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        })
    }

    #[tokio::test]
    async fn get_auth_returns_active_account() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
        ]);
        let result = manager.get_auth().await.unwrap();
        assert_eq!(result.access, "first");
        assert_eq!(result.account_id.as_deref(), Some("acct_1"));
    }

    #[tokio::test]
    async fn get_auth_fails_when_no_auth() {
        let manager = CodexAuthManager::new(test_store());
        assert!(
            manager
                .get_auth()
                .await
                .unwrap_err()
                .to_string()
                .contains("Not authenticated")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_expired_auth_refreshes_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let server_refreshes = refreshes.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0);
            assert!(String::from_utf8_lossy(&request[..read]).contains("refresh_token=stale"));
            server_refreshes.fetch_add(1, Ordering::SeqCst);

            let body = br#"{"access_token":"rotated","refresh_token":"rotated-refresh","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let store = test_store();
        store
            .save(pool_of([login("expired", "stale", 0, "acct_1")]))
            .unwrap();
        let manager = Arc::new(CodexAuthManager::new_with_token_endpoint(
            store,
            format!("http://{addr}/oauth/token"),
        ));
        let (first, second) = tokio::join!(manager.get_auth(), manager.get_auth());
        let results = [first.unwrap(), second.unwrap()];
        server.join().unwrap();

        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|auth| auth.access == "rotated"));
        assert!(results.iter().all(|auth| auth.refresh == "rotated-refresh"));
        let stored = manager.accounts().unwrap();
        assert_eq!(stored.accounts[0].auth.access, "rotated");
    }

    #[tokio::test]
    async fn stale_401_reuses_already_rotated_auth() {
        let store = test_store();
        store
            .save(pool_of([login(
                "rotated",
                "rotated-refresh",
                u64::MAX,
                "acct_1",
            )]))
            .unwrap();
        let manager = CodexAuthManager::new_with_token_endpoint(
            store,
            "http://127.0.0.1:1/should-not-be-called".into(),
        );

        let auth = manager
            .force_refresh(&login("rejected", "old", 0, "acct_1"))
            .await
            .unwrap();
        assert_eq!(auth.access, "rotated");
        assert_eq!(auth.refresh, "rotated-refresh");
    }

    #[tokio::test]
    async fn unauthorized_refresh_preserves_changed_refresh_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let backing = InMemoryAuthStore::new();
        let server_backing = backing.clone();
        let server = unauthorized_token_server(listener, move || {
            server_backing
                .save(pool_of([login(
                    "same-access",
                    "replacement-refresh",
                    u64::MAX,
                    "acct_1",
                )]))
                .unwrap();
        });

        let store = CodexTokenStore::new(backing);
        store
            .save(pool_of([login(
                "same-access",
                "rejected-refresh",
                0,
                "acct_1",
            )]))
            .unwrap();
        let manager =
            CodexAuthManager::new_with_token_endpoint(store, format!("http://{addr}/oauth/token"));

        let auth = manager.get_auth().await.unwrap();
        server.join().unwrap();
        assert_eq!(auth.access, "same-access");
        assert_eq!(auth.refresh, "replacement-refresh");
        assert_eq!(manager.accounts().unwrap().accounts[0].auth, auth);
    }

    #[tokio::test]
    async fn unauthorized_refresh_drops_only_the_rejected_account() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = unauthorized_token_server(listener, || {});
        let store = test_store();
        store
            .save(pool_of([
                login("expired", "revoked", 0, "acct_1"),
                login("valid", "r2", u64::MAX, "acct_2"),
            ]))
            .unwrap();
        let manager =
            CodexAuthManager::new_with_token_endpoint(store, format!("http://{addr}/oauth/token"));

        assert!(manager.get_auth().await.is_err());
        server.join().unwrap();

        let remaining = manager.accounts().unwrap();
        assert_eq!(remaining.accounts.len(), 1);
        assert_eq!(remaining.active.as_deref(), Some("acct_2"));
        assert_eq!(manager.get_auth().await.unwrap().access, "valid");
    }

    #[tokio::test]
    async fn durable_rotation_and_logout_are_observed_by_shared_manager() {
        let manager = manager_with([login("first", "first-refresh", u64::MAX, "acct_1")]);
        assert_eq!(manager.get_auth().await.unwrap().access, "first");

        manager
            .store
            .save(pool_of([login(
                "rotated",
                "rotated-refresh",
                u64::MAX,
                "acct_2",
            )]))
            .unwrap();
        let rotated = manager.get_auth().await.unwrap();
        assert_eq!(rotated.access, "rotated");
        assert_eq!(rotated.account_id.as_deref(), Some("acct_2"));

        manager.clear().unwrap();
        assert!(manager.get_auth().await.is_err());
    }

    #[tokio::test]
    async fn usage_limit_rotates_to_the_next_account_and_stays_there() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
            login("third", "r3", u64::MAX, "acct_3"),
        ]);
        let first = manager.get_auth().await.unwrap();
        let resets_at = CodexAuthManager::<InMemoryAuthStore<CodexAccountPool>>::now_ms() + 60_000;

        let next = manager
            .rotate_after_usage_limit(&first, Some(resets_at))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.access, "second");
        assert_eq!(manager.get_auth().await.unwrap().access, "second");

        let pool = manager.accounts().unwrap();
        assert_eq!(pool.active.as_deref(), Some("acct_2"));
        assert_eq!(pool.accounts[0].limited_until, Some(resets_at));
    }

    #[tokio::test]
    async fn usage_limit_on_every_account_returns_none() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
        ]);
        let first = manager.get_auth().await.unwrap();
        let second = manager
            .rotate_after_usage_limit(&first, None)
            .await
            .unwrap()
            .unwrap();
        assert!(
            manager
                .rotate_after_usage_limit(&second, None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn usage_limit_rotation_by_a_stale_request_keeps_the_newer_choice() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
        ]);
        let first = manager.get_auth().await.unwrap();
        manager
            .rotate_after_usage_limit(&first, None)
            .await
            .unwrap();

        // A second in-flight request on the first account hits the same limit.
        let next = manager
            .rotate_after_usage_limit(&first, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.access, "second");
    }

    #[tokio::test]
    async fn unreported_usage_limit_reset_uses_the_fallback_window() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
        ]);
        let before = CodexAuthManager::<InMemoryAuthStore<CodexAccountPool>>::now_ms();
        let first = manager.get_auth().await.unwrap();
        manager
            .rotate_after_usage_limit(&first, None)
            .await
            .unwrap();
        let limited_until = manager.accounts().unwrap().accounts[0]
            .limited_until
            .unwrap();
        assert!(limited_until >= before + UNREPORTED_USAGE_LIMIT_RESET_MS);
    }

    #[test]
    fn switch_moves_to_the_next_account_with_quota_or_the_named_one() {
        let manager = manager_with([
            login("first", "r1", u64::MAX, "acct_1"),
            login("second", "r2", u64::MAX, "acct_2"),
            login("third", "r3", u64::MAX, "acct_3"),
        ]);
        manager
            .update_pool(|pool| {
                pool.mark_limited("acct_2", u64::MAX);
                Ok(())
            })
            .unwrap();

        assert_eq!(manager.switch(None).unwrap().key(), "acct_3");
        assert_eq!(manager.switch(None).unwrap().key(), "acct_1");

        let named = manager.switch(Some("2")).unwrap();
        assert_eq!(named.key(), "acct_2");
        assert_eq!(named.limited_until, None);
        assert_eq!(
            manager.accounts().unwrap().active.as_deref(),
            Some("acct_2")
        );
    }

    #[test]
    fn switch_without_another_account_fails() {
        let manager = manager_with([login("first", "r1", u64::MAX, "acct_1")]);
        assert!(manager.switch(None).is_err());
        assert!(
            CodexAuthManager::new(test_store())
                .switch(None)
                .unwrap_err()
                .to_string()
                .contains("Not authenticated")
        );
    }

    #[test]
    fn persist_initial_tokens_adds_accounts_without_changing_active() {
        let manager = manager_with([login("first", "r1", u64::MAX, "acct_1")]);
        let token = |account: &str| TokenResponse {
            id_token: None,
            access_token: super::super::jwt::test_token(serde_json::json!({
                "chatgpt_account_id": account
            })),
            refresh_token: "r".into(),
            expires_in: Some(3600),
        };
        manager.persist_initial_tokens(&token("acct_2")).unwrap();
        manager.persist_initial_tokens(&token("acct_2")).unwrap();

        let pool = manager.accounts().unwrap();
        assert_eq!(pool.accounts.len(), 2);
        assert_eq!(pool.active.as_deref(), Some("acct_1"));
    }
}
