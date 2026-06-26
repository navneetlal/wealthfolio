//! Optional OIDC SSO for the web/server build.
//!
//! OIDC is *authentication only*: a successful Authorization-Code + PKCE flow
//! converges on the exact same `wf_session` JWT cookie that password login mints
//! (see [`crate::auth::AuthManager::issue_session_cookie`]). Everything past the
//! cookie (`require_jwt`, sliding refresh, the frontend `AuthGate`) is unchanged.
//!
//! The per-login transaction state (PKCE verifier, nonce, CSRF token) is kept in
//! a short-lived **encrypted** cookie rather than server memory, so the flow is
//! stateless and survives restarts.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{
        header::{COOKIE, SET_COOKIE},
        HeaderMap, HeaderValue,
    },
    response::{IntoResponse, Redirect, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce as OidcNonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::main_lib::AppState;

const TX_COOKIE_NAME: &str = "wf_oidc_tx";
const TX_COOKIE_PATH: &str = "/api/v1/auth/oidc";
const TX_COOKIE_TTL_SECS: u64 = 300;

/// Parsed `WF_OIDC_*` configuration. Present iff issuer + client id are set.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub allowed_emails: Vec<String>,
    pub allowed_subs: Vec<String>,
}

impl OidcConfig {
    /// Reads `WF_OIDC_*` from the environment. Returns `None` when OIDC is not
    /// configured. Panics on a partial configuration so misconfig fails loudly.
    pub fn from_env() -> Option<Self> {
        let issuer_url = env_nonempty("WF_OIDC_ISSUER_URL");
        let client_id = env_nonempty("WF_OIDC_CLIENT_ID");

        match (issuer_url, client_id) {
            (None, None) => None,
            (Some(issuer_url), Some(client_id)) => {
                let redirect_url = env_nonempty("WF_OIDC_REDIRECT_URL").unwrap_or_else(|| {
                    panic!(
                        "WF_OIDC_REDIRECT_URL must be set when OIDC is enabled, \
                         e.g. https://your.host/api/v1/auth/oidc/callback"
                    )
                });
                let scopes = env_nonempty("WF_OIDC_SCOPES")
                    .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| vec!["openid".into(), "email".into(), "profile".into()]);
                let allowed_emails = csv_list("WF_OIDC_ALLOWED_EMAILS");
                let allowed_subs = csv_list("WF_OIDC_ALLOWED_SUBS");

                if allowed_emails.is_empty() && allowed_subs.is_empty() {
                    tracing::warn!(
                        "OIDC is enabled WITHOUT an allowlist: any user your IdP authenticates \
                         will be granted full access to this instance. Set WF_OIDC_ALLOWED_EMAILS \
                         or WF_OIDC_ALLOWED_SUBS to restrict access."
                    );
                }

                Some(Self {
                    issuer_url,
                    client_id,
                    client_secret: env_nonempty("WF_OIDC_CLIENT_SECRET"),
                    redirect_url,
                    scopes,
                    allowed_emails,
                    allowed_subs,
                })
            }
            _ => panic!(
                "OIDC is partially configured: set BOTH WF_OIDC_ISSUER_URL and \
                 WF_OIDC_CLIENT_ID, or neither."
            ),
        }
    }
}

/// Holds the discovered provider metadata and the parameters needed to rebuild a
/// `CoreClient` per request (rebuilding is cheap and avoids storing the client's
/// verbose typestate generics in a struct field).
pub struct OidcManager {
    provider_metadata: CoreProviderMetadata,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect_url: RedirectUrl,
    scopes: Vec<String>,
    /// Lowercased for case-insensitive comparison.
    allowed_emails: Vec<String>,
    allowed_subs: Vec<String>,
    http_client: reqwest::Client,
    encryption_key: [u8; 32],
}

impl OidcManager {
    /// Performs OIDC discovery against the issuer. Called once at startup.
    pub async fn discover(config: &OidcConfig, encryption_key: [u8; 32]) -> anyhow::Result<Self> {
        // Disallow redirects: discovery and token endpoints must be hit directly.
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let issuer = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|e| anyhow::anyhow!("Invalid WF_OIDC_ISSUER_URL: {e}"))?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery failed: {e}"))?;
        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| anyhow::anyhow!("Invalid WF_OIDC_REDIRECT_URL: {e}"))?;

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(config.client_id.clone()),
            client_secret: config.client_secret.clone().map(ClientSecret::new),
            redirect_url,
            scopes: config.scopes.clone(),
            allowed_emails: config
                .allowed_emails
                .iter()
                .map(|e| e.to_ascii_lowercase())
                .collect(),
            allowed_subs: config.allowed_subs.clone(),
            http_client,
            encryption_key,
        })
    }

    fn client(
        &self,
    ) -> openidconnect::core::CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    > {
        CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone())
    }

    /// Whether the authenticated subject/email is permitted. With no allowlist
    /// configured, any IdP-authenticated user is allowed (warned at startup).
    fn is_allowed(&self, claims: &CoreIdTokenClaims) -> bool {
        if self.allowed_emails.is_empty() && self.allowed_subs.is_empty() {
            return true;
        }
        if !self.allowed_subs.is_empty() {
            let sub = claims.subject().as_str();
            if self.allowed_subs.iter().any(|s| s == sub) {
                return true;
            }
        }
        if !self.allowed_emails.is_empty() {
            if let Some(email) = claims.email() {
                let email = email.as_str().to_ascii_lowercase();
                if self.allowed_emails.iter().any(|e| e == &email) {
                    return true;
                }
            }
        }
        false
    }
}

/// Per-login transaction state stored (encrypted) in the `wf_oidc_tx` cookie.
#[derive(Serialize, Deserialize)]
struct OidcTx {
    pkce_verifier: String,
    nonce: String,
    csrf: String,
}

/// `GET /api/v1/auth/oidc/login` — start the flow: build the authorize URL and
/// stash PKCE/nonce/CSRF in an encrypted cookie, then redirect to the IdP.
pub async fn oidc_login(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return error_redirect("oidc_not_configured");
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let client = oidc.client();
    let mut authorize = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        OidcNonce::new_random,
    );
    // `openid` is added by the AuthorizationCode flow; add the rest.
    for scope in &oidc.scopes {
        if scope != "openid" {
            authorize = authorize.add_scope(Scope::new(scope.clone()));
        }
    }
    let (auth_url, csrf, nonce) = authorize.set_pkce_challenge(pkce_challenge).url();

    let tx = OidcTx {
        pkce_verifier: pkce_verifier.secret().clone(),
        nonce: nonce.secret().clone(),
        csrf: csrf.secret().clone(),
    };
    let Ok(encrypted) = encrypt_tx(&oidc.encryption_key, &tx) else {
        return error_redirect("oidc_internal");
    };
    let cookie = build_tx_cookie(
        &encrypted,
        TX_COOKIE_TTL_SECS,
        cookie_secure(&state, &headers),
    );

    let mut response = Redirect::to(auth_url.as_str()).into_response();
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, val);
    }
    response
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /api/v1/auth/oidc/callback` — finish the flow: verify state, exchange the
/// code, validate the ID token, enforce the allowlist, then mint `wf_session`.
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return error_redirect("oidc_not_configured");
    };

    if let Some(err) = query.error {
        tracing::warn!("OIDC provider returned an error: {err}");
        return error_redirect("oidc_provider_error");
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return error_redirect("oidc_missing_params");
    };

    // Recover and decrypt the transaction cookie.
    let Some(tx_cookie) = read_cookie(&headers, TX_COOKIE_NAME) else {
        return error_redirect("oidc_expired");
    };
    let Ok(tx) = decrypt_tx(&oidc.encryption_key, &tx_cookie) else {
        return error_redirect("oidc_expired");
    };

    // CSRF: the returned `state` must match what we issued.
    if tx.csrf != returned_state {
        return error_redirect("oidc_state_mismatch");
    }

    let client = oidc.client();
    let exchange = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("OIDC token endpoint unavailable: {e}");
            return error_redirect("oidc_exchange_failed");
        }
    };
    let token_response = match exchange
        .set_pkce_verifier(PkceCodeVerifier::new(tx.pkce_verifier))
        .request_async(&oidc.http_client)
        .await
    {
        Ok(tr) => tr,
        Err(e) => {
            tracing::warn!("OIDC token exchange failed: {e}");
            return error_redirect("oidc_exchange_failed");
        }
    };

    let Some(id_token) = token_response.id_token() else {
        return error_redirect("oidc_no_id_token");
    };
    let verifier = client.id_token_verifier();
    let nonce = OidcNonce::new(tx.nonce);
    let claims = match id_token.claims(&verifier, &nonce) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!("OIDC ID token verification failed: {e}");
            return error_redirect("oidc_invalid_token");
        }
    };

    if !oidc.is_allowed(claims) {
        tracing::warn!("OIDC login denied: subject not in allowlist");
        return error_redirect("oidc_forbidden");
    }

    // Mint the shared session cookie. `auth` is always present when OIDC is on.
    let Some(auth) = state.auth.clone() else {
        return error_redirect("oidc_internal");
    };
    let Ok((session_cookie, _ttl)) = auth.issue_session_cookie(&headers) else {
        return error_redirect("oidc_internal");
    };

    let mut response = Redirect::to("/").into_response();
    let out = response.headers_mut();
    if let Ok(val) = HeaderValue::from_str(&session_cookie) {
        out.append(SET_COOKIE, val);
    }
    if let Ok(val) = HeaderValue::from_str(&clear_tx_cookie()) {
        out.append(SET_COOKIE, val);
    }
    response
}

fn encrypt_tx(key: &[u8; 32], tx: &OidcTx) -> anyhow::Result<String> {
    let serialized = serde_json::to_vec(tx)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), serialized.as_ref())
        .map_err(|_| anyhow::anyhow!("failed to encrypt oidc tx"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(BASE64URL.encode(out))
}

fn decrypt_tx(key: &[u8; 32], value: &str) -> anyhow::Result<OidcTx> {
    let raw = BASE64URL.decode(value)?;
    if raw.len() < 12 {
        anyhow::bail!("oidc tx cookie too short");
    }
    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("failed to decrypt oidc tx"))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn build_tx_cookie(value: &str, max_age: u64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{TX_COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path={TX_COOKIE_PATH}; Max-Age={max_age}{secure_attr}"
    )
}

fn clear_tx_cookie() -> String {
    format!("{TX_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path={TX_COOKIE_PATH}; Max-Age=0")
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        if let Some((k, v)) = pair.trim().split_once('=') {
            if k.trim() == name {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn cookie_secure(state: &AppState, headers: &HeaderMap) -> bool {
    state
        .auth
        .as_ref()
        .is_some_and(|auth| auth.should_secure_cookie(headers))
}

fn error_redirect(code: &str) -> Response {
    Redirect::to(&format!("/?oidc_error={code}")).into_response()
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn csv_list(key: &str) -> Vec<String> {
    env_nonempty(key)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_cookie_roundtrips() {
        let key = [7u8; 32];
        let tx = OidcTx {
            pkce_verifier: "verifier-123".into(),
            nonce: "nonce-456".into(),
            csrf: "csrf-789".into(),
        };
        let encrypted = encrypt_tx(&key, &tx).unwrap();
        let decoded = decrypt_tx(&key, &encrypted).unwrap();
        assert_eq!(decoded.pkce_verifier, "verifier-123");
        assert_eq!(decoded.nonce, "nonce-456");
        assert_eq!(decoded.csrf, "csrf-789");
    }

    #[test]
    fn tx_cookie_rejects_tampering() {
        let key = [7u8; 32];
        let tx = OidcTx {
            pkce_verifier: "v".into(),
            nonce: "n".into(),
            csrf: "c".into(),
        };
        let mut encrypted = encrypt_tx(&key, &tx).unwrap();
        // Flip a character to corrupt the ciphertext/tag.
        encrypted.push('A');
        assert!(decrypt_tx(&key, &encrypted).is_err());
    }

    #[test]
    fn tx_cookie_rejects_wrong_key() {
        let tx = OidcTx {
            pkce_verifier: "v".into(),
            nonce: "n".into(),
            csrf: "c".into(),
        };
        let encrypted = encrypt_tx(&[1u8; 32], &tx).unwrap();
        assert!(decrypt_tx(&[2u8; 32], &encrypted).is_err());
    }
}
