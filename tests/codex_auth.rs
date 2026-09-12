use assert_cmd::Command;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A `codex auth` command isolated from the real user config. HOME is
/// overridden too so the legacy config fallback resolves inside the temp dir.
fn codex_auth(temp: &TempDir, args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("claude-code-proxy").unwrap();
    cmd.args(["codex", "auth"]).args(args);
    cmd.env("CCP_CONFIG_DIR", temp.path());
    cmd.env("HOME", temp.path());
    cmd
}

fn write_auth(temp: &TempDir, contents: &str) -> std::io::Result<()> {
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(auth_dir.join("auth.json"), contents)
}

fn stdout(cmd: &mut Command) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(
        cmd.assert().success().get_output().stdout.clone(),
    )?)
}

/// Account 2 is limited until 2100.
const TWO_ACCOUNTS: &str = r#"{
  "active": "acct_1",
  "accounts": [
    {"auth": {"access": "a1", "refresh": "r1", "expires": 4102444800000, "accountId": "acct_1"}},
    {"auth": {"access": "a2", "refresh": "r2", "expires": 4102444800000, "accountId": "acct_2"},
     "limitedUntil": 4102444800000}
  ]
}"#;

const THREE_ACCOUNTS: &str = r#"{
  "active": "acct_1",
  "accounts": [
    {"auth": {"access": "a1", "refresh": "r1", "expires": 4102444800000, "accountId": "acct_1"}},
    {"auth": {"access": "a2", "refresh": "r2", "expires": 4102444800000, "accountId": "acct_2"},
     "limitedUntil": 4102444800000},
    {"auth": {"access": "a3", "refresh": "r3", "expires": 4102444800000, "accountId": "acct_3"}}
  ]
}"#;

#[test]
fn codex_auth_status_reads_single_login_file() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(
        &temp,
        r#"{"access":"a","refresh":"r","expires":4102444800000,"accountId":"acct_1"}"#,
    )?;
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "* 1  acct_1");
    assert!(
        lines[1].starts_with("     Expires: 2100-01-01T00:00:00.000Z (in "),
        "{out}"
    );
    assert!(lines[1].ends_with("s)"), "{out}");
    assert!(lines[2].starts_with("Storage: "), "{out}");
    Ok(())
}

#[test]
fn codex_auth_status_reads_legacy_account_id_key() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(
        &temp,
        r#"{"access":"a","refresh":"r","expires":4102444800000,"account_id":"acct_2"}"#,
    )?;
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    assert_eq!(out.lines().next(), Some("* 1  acct_2"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_status_no_auth() -> TestResult {
    let temp = TempDir::new()?;
    let output = codex_auth(&temp, &["status"]).output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stdout)?, "Not authenticated\n");
    Ok(())
}

#[test]
fn codex_auth_status_no_account_id_shows_none() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(
        &temp,
        r#"{"access":"a","refresh":"r","expires":4102444800000}"#,
    )?;
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    assert_eq!(out.lines().next(), Some("* 1  (none)"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_status_expired_auth_shows_negative_seconds() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(
        &temp,
        r#"{"access":"a","refresh":"r","expires":946684800000,"accountId":"acct_1"}"#,
    )?;
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    let lines: Vec<_> = out.lines().collect();
    assert!(
        lines[1].starts_with("     Expires: 2000-01-01T00:00:00.000Z (in -"),
        "{out}"
    );
    Ok(())
}

#[test]
fn codex_auth_status_lists_every_account_with_active_marker_and_limits() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, TWO_ACCOUNTS)?;
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 6, "{out}");
    assert_eq!(lines[0], "* 1  acct_1");
    assert_eq!(lines[2], "  2  acct_2");
    assert!(
        lines[4].starts_with("     Usage limit resets: 2100-01-01T00:00:00.000Z (in "),
        "{out}"
    );
    assert!(lines[5].starts_with("Storage: "), "{out}");
    Ok(())
}

#[test]
fn codex_auth_switch_skips_limited_accounts() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, THREE_ACCOUNTS)?;
    assert_eq!(
        stdout(&mut codex_auth(&temp, &["switch"]))?,
        "Active: 3  acct_3\n"
    );
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    assert!(out.contains("\n* 3  acct_3\n"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_switch_to_named_account_clears_its_limit() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, TWO_ACCOUNTS)?;
    assert_eq!(
        stdout(&mut codex_auth(&temp, &["switch", "acct_2"]))?,
        "Active: 2  acct_2\n"
    );
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    assert!(out.starts_with("  1  acct_1\n"), "{out}");
    assert!(out.contains("\n* 2  acct_2\n"), "{out}");
    assert!(!out.contains("Usage limit"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_switch_without_another_account_with_quota_fails() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, TWO_ACCOUNTS)?;
    let output = codex_auth(&temp, &["switch"]).output()?;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "No other stored account has quota left\n"
    );
    Ok(())
}

#[test]
fn codex_auth_logout_with_account_removes_only_that_account() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, TWO_ACCOUNTS)?;
    assert_eq!(
        stdout(&mut codex_auth(&temp, &["logout", "1"]))?,
        "Removed: acct_1\n"
    );
    let out = stdout(&mut codex_auth(&temp, &["status"]))?;
    assert!(out.starts_with("* 1  acct_2\n"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_logout_without_account_removes_every_account() -> TestResult {
    let temp = TempDir::new()?;
    write_auth(&temp, TWO_ACCOUNTS)?;
    assert_eq!(stdout(&mut codex_auth(&temp, &["logout"]))?, "Logged out\n");
    let output = codex_auth(&temp, &["status"]).output()?;
    assert_eq!(output.status.code(), Some(1));
    Ok(())
}
