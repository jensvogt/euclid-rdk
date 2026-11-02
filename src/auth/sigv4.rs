//! AWS Signature Version 4, as euclid speaks it.
//!
//! Byte-for-byte the scheme of euclid-jdk's `SigV4` and euclid-cli: the signed header list is
//! fixed rather than chosen per request - the server rejects a signature covering anything else -
//! and the payload hash is of the body exactly as sent.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SCOPE_TERMINATOR: &str = "aws4_request";

/// The headers every signature covers, in canonical order.
pub const SIGNED_HEADER_NAMES: [&str; 8] = [
    "host",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-euclid-account-id",
    "x-euclid-action",
    "x-euclid-region",
    "x-euclid-target",
    "x-euclid-user-id",
];

/// The headers a signature produces, to be sent with the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeaders {
    pub amz_date: String,
    pub content_sha256: String,
    pub authorization: String,
}

/// Signs a request.
///
/// `headers` holds the request's headers as (name, value) pairs; names are matched
/// case-insensitively and values trimmed, and a signed header that is absent is signed as empty.
/// `target` is the request path, optionally with a query string. `amz_date` is
/// `yyyyMMdd'T'HHmmss'Z'` in UTC.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> SignatureHeaders {
    let date_stamp = &amz_date[..8.min(amz_date.len())];
    let content_sha256 = hex(&Sha256::digest(body));

    let lookup = |name: &str| -> String {
        match name {
            "x-amz-date" => amz_date.to_owned(),
            "x-amz-content-sha256" => content_sha256.clone(),
            _ => headers
                .iter()
                .rev()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default(),
        }
    };

    let (canonical_uri, canonical_query) = match target.split_once('?') {
        Some((path, query)) => (path, canonicalize_query_string(query)),
        None => (target, String::new()),
    };

    let mut canonical_headers = String::new();
    for name in SIGNED_HEADER_NAMES {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&lookup(name));
        canonical_headers.push('\n');
    }
    let signed_headers = SIGNED_HEADER_NAMES.join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{content_sha256}"
    );
    let credential_scope = format!("{date_stamp}/{region}/{service}/{SCOPE_TERMINATOR}");
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = derive_signing_key(secret_access_key, date_stamp, region, service);
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    SignatureHeaders {
        amz_date: amz_date.to_owned(),
        content_sha256,
        authorization: format!(
            "{ALGORITHM} Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
}

/// The current time as SigV4's `yyyyMMdd'T'HHmmss'Z'`.
pub fn amz_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    amz_date(secs)
}

/// Formats seconds since the epoch as SigV4's `yyyyMMdd'T'HHmmss'Z'` (UTC).
pub fn amz_date(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn derive_signing_key(secret_access_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, SCOPE_TERMINATOR.as_bytes())
}

/// Sorts query parameters and re-encodes them with SigV4's URI encoding.
pub fn canonicalize_query_string(raw_query: &str) -> String {
    let mut params: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                uri_encode(&percent_decode(name), true),
                uri_encode(&percent_decode(value), true),
            )
        })
        .collect();
    params.sort();
    params
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~')
}

fn uri_encode(value: &[u8], encode_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for &c in value {
        if is_unreserved(c) || (c == b'/' && !encode_slash) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_matches_aws_reference_vector() {
        // From the AWS SigV4 documentation.
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn amz_date_formats_utc() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_762_084_800), "20251102T120000Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
    }

    #[test]
    fn query_is_sorted_and_reencoded() {
        assert_eq!(canonicalize_query_string("b=2&a=x%2Fy&a=1&&c"), "a=1&a=x%2Fy&b=2&c=");
        assert_eq!(canonicalize_query_string("k=a b"), "k=a%20b");
    }

    #[test]
    fn signature_is_deterministic_and_covers_body() {
        let headers = [
            ("Host", "euclid:5566"),
            ("x-euclid-target", "eqs"),
            ("x-euclid-action", "list-queues"),
        ];
        let a = sign(
            "POST",
            "/",
            &headers,
            b"{}",
            "AK",
            "SK",
            "eu-central-1",
            "eqs",
            "20261102T120000Z",
        );
        let b = sign(
            "POST",
            "/",
            &headers,
            b"{}",
            "AK",
            "SK",
            "eu-central-1",
            "eqs",
            "20261102T120000Z",
        );
        let c = sign(
            "POST",
            "/",
            &headers,
            b"{ }",
            "AK",
            "SK",
            "eu-central-1",
            "eqs",
            "20261102T120000Z",
        );
        assert_eq!(a, b);
        assert_ne!(a.authorization, c.authorization);
        assert_eq!(
            a.content_sha256,
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert!(a.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AK/20261102/eu-central-1/eqs/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-euclid-account-id;x-euclid-action;x-euclid-region;x-euclid-target;x-euclid-user-id, Signature="
        ));
    }
}
