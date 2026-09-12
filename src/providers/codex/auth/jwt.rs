use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    organizations: Option<Vec<OrgClaim>>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    #[serde(rename = "https://api.openai.com/auth")]
    openai_auth: Option<OpenAiAuthClaim>,
    #[serde(default)]
    #[serde(rename = "https://api.openai.com/profile")]
    openai_profile: Option<OpenAiProfileClaim>,
    #[serde(default)]
    #[serde(rename = "https://api.openai.com/auth.chatgpt_account_id")]
    openai_chatgpt_account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrgClaim {
    id: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiAuthClaim {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_user_id: Option<String>,
    #[serde(default)]
    chatgpt_user_id: Option<String>,
    #[serde(default)]
    chatgpt_plan_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiProfileClaim {
    #[serde(default)]
    email: Option<String>,
}

/// Who a ChatGPT token belongs to, as far as its claims say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenIdentity {
    /// One login: a user inside a ChatGPT workspace. Members of a workspace
    /// share its account ID but each has their own usage limits.
    pub account_user_id: Option<String>,
    pub email: Option<String>,
    pub plan_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: Option<u64>,
}

fn parse_jwt_claims(token: &str) -> Option<IdTokenClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_b64 = parts[1].replace('-', "+").replace('_', "/");
    let padded = match payload_b64.len() % 4 {
        2 => format!("{payload_b64}=="),
        3 => format!("{payload_b64}="),
        _ => payload_b64,
    };
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn extract_account_id_from_claims(claims: &IdTokenClaims) -> Option<String> {
    claims
        .chatgpt_account_id
        .clone()
        .or_else(|| claims.openai_auth.as_ref()?.chatgpt_account_id.clone())
        .or_else(|| claims.openai_chatgpt_account_id.clone())
        .or_else(|| claims.organizations.as_ref()?.first()?.id.clone().into())
}

pub fn validate_token_response(tokens: &TokenResponse) -> anyhow::Result<()> {
    if tokens.access_token.trim().is_empty() {
        anyhow::bail!("token response missing access token");
    }
    if tokens.refresh_token.trim().is_empty() {
        anyhow::bail!("token response missing refresh token");
    }
    if matches!(tokens.expires_in, Some(0)) {
        anyhow::bail!("token response has invalid expiration");
    }
    Ok(())
}

pub fn extract_account_id(tokens: &TokenResponse) -> Option<String> {
    if let Some(ref id_token) = tokens.id_token
        && let Some(claims) = parse_jwt_claims(id_token)
        && let Some(account_id) = extract_account_id_from_claims(&claims)
    {
        return Some(account_id);
    }
    let claims = parse_jwt_claims(&tokens.access_token)?;
    extract_account_id_from_claims(&claims)
}

pub fn token_identity(token: &str) -> TokenIdentity {
    let Some(claims) = parse_jwt_claims(token) else {
        return TokenIdentity::default();
    };
    let auth = claims.openai_auth.as_ref();
    let account_user_id = auth
        .and_then(|auth| auth.chatgpt_account_user_id.clone())
        .or_else(|| {
            let user_id = auth?.chatgpt_user_id.clone()?;
            Some(match extract_account_id_from_claims(&claims) {
                Some(account_id) => format!("{user_id}__{account_id}"),
                None => user_id,
            })
        });
    TokenIdentity {
        account_user_id,
        email: claims
            .openai_profile
            .as_ref()
            .and_then(|profile| profile.email.clone())
            .or_else(|| claims.email.clone()),
        plan_type: auth.and_then(|auth| auth.chatgpt_plan_type.clone()),
    }
}

#[cfg(test)]
pub(crate) fn test_token(claims: serde_json::Value) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("eyJhbGciOiJub25lIn0.{payload}.sig")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_identity_reads_nested_openai_claims() {
        let token = test_token(serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct_1",
                "chatgpt_account_user_id": "user-1__acct_1",
                "chatgpt_plan_type": "pro"
            },
            "https://api.openai.com/profile": { "email": "one@example.com" }
        }));
        assert_eq!(
            token_identity(&token),
            TokenIdentity {
                account_user_id: Some("user-1__acct_1".into()),
                email: Some("one@example.com".into()),
                plan_type: Some("pro".into()),
            }
        );
    }

    #[test]
    fn token_identity_joins_user_and_account_when_combined_claim_is_missing() {
        let token = test_token(serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct_1",
                "chatgpt_user_id": "user-1"
            }
        }));
        assert_eq!(
            token_identity(&token).account_user_id.as_deref(),
            Some("user-1__acct_1")
        );
    }

    #[test]
    fn token_identity_is_empty_for_opaque_tokens() {
        assert_eq!(token_identity("opaque"), TokenIdentity::default());
    }

    #[test]
    fn extract_account_id_from_access_token() {
        let token = TokenResponse {
            id_token: None,
            access_token: "eyJhbGciOiJIUzI1NiJ9.eyJjaGF0Z3B0X2FjY291bnRfaWQiOiJhY2N0XzEyMyJ9.sig"
                .into(),
            refresh_token: "r".into(),
            expires_in: Some(3600),
        };
        assert_eq!(extract_account_id(&token), Some("acct_123".into()));
    }

    #[test]
    fn extract_account_id_from_id_token_takes_precedence() {
        let token = TokenResponse {
            id_token: Some(
                "eyJhbGciOiJIUzI1NiJ9.eyJjaGF0Z3B0X2FjY291bnRfaWQiOiJpZF9hY2N0In0.sig".into(),
            ),
            access_token: "eyJhbGciOiJIUzI1NiJ9.eyJjaGF0Z3B0X2FjY291bnRfaWQiOiJhY2NfYWNjIn0.sig"
                .into(),
            refresh_token: "r".into(),
            expires_in: Some(3600),
        };
        assert_eq!(extract_account_id(&token), Some("id_acct".into()));
    }

    #[test]
    fn extract_account_id_returns_none_for_invalid_token() {
        let token = TokenResponse {
            id_token: None,
            access_token: "invalid".into(),
            refresh_token: "r".into(),
            expires_in: None,
        };
        assert_eq!(extract_account_id(&token), None);
    }

    #[test]
    fn validate_token_response_rejects_empty_access_token() {
        let token = TokenResponse {
            access_token: "".into(),
            refresh_token: "r".into(),
            expires_in: Some(3600),
            id_token: None,
        };
        assert!(validate_token_response(&token).is_err());
        assert!(
            validate_token_response(&token)
                .unwrap_err()
                .to_string()
                .contains("missing access token")
        );
    }

    #[test]
    fn validate_token_response_rejects_empty_refresh_token() {
        let token = TokenResponse {
            access_token: "a".into(),
            refresh_token: "".into(),
            expires_in: Some(3600),
            id_token: None,
        };
        assert!(validate_token_response(&token).is_err());
        assert!(
            validate_token_response(&token)
                .unwrap_err()
                .to_string()
                .contains("missing refresh token")
        );
    }

    #[test]
    fn validate_token_response_rejects_zero_expires_in() {
        let token = TokenResponse {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_in: Some(0),
            id_token: None,
        };
        assert!(validate_token_response(&token).is_err());
        assert!(
            validate_token_response(&token)
                .unwrap_err()
                .to_string()
                .contains("invalid expiration")
        );
    }

    #[test]
    fn validate_token_response_accepts_valid() {
        let token = TokenResponse {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_in: Some(3600),
            id_token: None,
        };
        assert!(validate_token_response(&token).is_ok());
    }

    #[test]
    fn validate_token_response_accepts_no_expires_in() {
        let token = TokenResponse {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_in: None,
            id_token: None,
        };
        assert!(validate_token_response(&token).is_ok());
    }
}
