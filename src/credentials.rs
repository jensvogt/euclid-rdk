//! The on-disk session cache, `$HOME/.euclid/credentials`.
//!
//! Field names and shape are euclid-cli's `Credentials::Save()`, since euclid-cli, euclid-jdk and
//! this crate all read and write the same file: a login from any of them is picked up by the
//! others. `namespace` is written as an empty string rather than null when unset, so the CLI's
//! string reader can take it. `baseUrl` is the one field only the SDKs write - the CLI has no
//! equivalent check.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::Result;

/// One cached login, exactly as it sits in the credentials file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CachedCredentials {
    pub token: Option<String>,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub is_admin: bool,
    pub base_url: Option<String>,
    #[serde(serialize_with = "empty_if_none")]
    pub namespace: Option<String>,
}

fn empty_if_none<S: serde::Serializer>(value: &Option<String>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(value.as_deref().unwrap_or(""))
}

/// `$HOME/.euclid/credentials`, resolved per call rather than once, so a process that changes its
/// home directory is not left talking to a stale path.
pub fn default_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".euclid").join("credentials"))
}

/// Reads the cache at `path`. `None` if it is missing, unreadable or not valid JSON - a broken
/// cache means "log in again", never an error.
pub fn load(path: &Path) -> Option<CachedCredentials> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes the cache at `path`, creating its directory, readable by the owner only.
pub fn store(path: &Path, credentials: &CachedCredentials) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(credentials)?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // A file that already existed keeps its old mode through open(); tighten it before the token
    // goes in. Best-effort: not every filesystem has POSIX permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Patches the cached namespace in place, if what is cached is for `base_url`. Silently a no-op
/// otherwise - nothing cached for this server means nothing to keep in sync.
pub fn update_namespace(path: &Path, base_url: &str, namespace: Option<&str>) {
    let Some(mut cached) = load(path) else { return };
    if cached.base_url.as_deref() != Some(base_url) {
        return;
    }
    cached.namespace = namespace.filter(|n| !n.is_empty()).map(str::to_owned);
    let _ = store(path, &cached);
}

/// Whether a JWT is well-formed enough to read and its `exp` claim is still in the future.
///
/// The signature is not checked - that is the server's job; this only decides whether a cached
/// token is worth presenting rather than logging in again.
pub fn is_token_valid(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Some(exp) = claims
        .get("exp")
        .and_then(|e| e.as_i64().or_else(|| e.as_f64().map(|f| f as i64)))
    else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);
    now < exp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"jens","exp":{exp}}}"#));
        format!("{header}.{payload}.signature")
    }

    fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[test]
    fn token_validity_follows_exp() {
        assert!(is_token_valid(&jwt(now() + 3600)));
        assert!(!is_token_valid(&jwt(now() - 1)));
        assert!(!is_token_valid("not-a-jwt"));
        assert!(!is_token_valid("a.!!!.c"));
    }

    #[test]
    fn padded_payload_is_accepted() {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload = base64::engine::general_purpose::URL_SAFE.encode(format!(r#"{{"exp":{}}}"#, now() + 60));
        assert!(is_token_valid(&format!("{header}.{payload}.sig")));
    }

    #[test]
    fn store_and_load_round_trip_in_cli_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("credentials");
        let creds = CachedCredentials {
            token: Some("t".into()),
            user_id: Some("jens".into()),
            account_id: Some("863459426936".into()),
            region: Some("eu-central-1".into()),
            access_key_id: None,
            secret_access_key: None,
            is_admin: true,
            base_url: Some("https://euclid".into()),
            namespace: None,
        };
        store(&path, &creds).unwrap();

        let raw: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["namespace"], "");
        assert_eq!(raw["isAdmin"], true);
        assert_eq!(raw["userId"], "jens");
        assert!(raw["accessKeyId"].is_null());

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.namespace.as_deref(), Some(""));
        assert_eq!(loaded.token, creds.token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn update_namespace_only_touches_matching_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        store(
            &path,
            &CachedCredentials {
                base_url: Some("https://a".into()),
                ..Default::default()
            },
        )
        .unwrap();

        update_namespace(&path, "https://b", Some("prod"));
        assert_eq!(load(&path).unwrap().namespace.as_deref(), Some(""));

        update_namespace(&path, "https://a", Some("prod"));
        assert_eq!(load(&path).unwrap().namespace.as_deref(), Some("prod"));
    }
}
