// Copyright 2016 oauth-client-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OAuth 1.0 client library for Rust.
//!
//! [Repository](https://github.com/charlag/oauth-client-rs)
//!
//! # Examples
//!
//! Send request for request token.
//!
//! ```
//! const REQUEST_TOKEN: &'static str = "http://oauthbin.com/v1/request-token";
//! let consumer = oauth_client::Token::new("key", "secret");
//! let bytes = oauth_client::get(REQUEST_TOKEN, &consumer, None, None).unwrap();
//! ```
#![warn(bad_style)]
#![warn(missing_docs)]
#![warn(unused)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![allow(unused_doc_comments)]

extern crate base64;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate percent_encoding;
extern crate rand;
extern crate reqwest;
extern crate ring;
extern crate time;

use rand::{distributions::Alphanumeric, Rng};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use ring::{digest, hmac};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Read;
use std::iter;
use time::OffsetDateTime;

/// Result type.
pub type Result<T> = std::result::Result<T, failure::Error>;

/// An error happening due to a HTTP status error.
#[derive(Debug, Fail, Clone, Copy)]
#[fail(display = "HTTP status error code {}", _0)]
pub struct HttpStatusError(pub u16);

lazy_static! {
    static ref CLIENT: Client = Client::new();
}

/// Token structure for the OAuth
#[derive(Clone, Debug)]
pub struct Token<'a> {
    /// 'key' field of the token
    pub key: Cow<'a, str>,
    /// 'secret' part of the token
    pub secret: Cow<'a, str>,
}

impl<'a> Token<'a> {
    /// Create new token from `key` and `secret`
    ///
    /// # Examples
    ///
    /// ```
    /// let consumer = oauth_client::Token::new("key", "secret");
    /// ```
    pub fn new<K, S>(key: K, secret: S) -> Token<'a>
    where
        K: Into<Cow<'a, str>>,
        S: Into<Cow<'a, str>>,
    {
        Token {
            key: key.into(),
            secret: secret.into(),
        }
    }
}

/// Alias for `HashMap<Cow<'a, str>, Cow<'a, str>>`
pub type ParamList<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;

fn insert_param<'a, K, V>(param: &mut ParamList<'a>, key: K, value: V) -> Option<Cow<'a, str>>
where
    K: Into<Cow<'a, str>>,
    V: Into<Cow<'a, str>>,
{
    param.insert(key.into(), value.into())
}

fn join_query<'a>(param: &ParamList<'a>) -> String {
    let mut pairs = param
        .iter()
        .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join("&")
}

// Encode all but the unreserved characters defined in
// RFC 3986, section 2.3. "Unreserved Characters"
// https://tools.ietf.org/html/rfc3986#page-12
//
// This is required by
// OAuth Core 1.0, section 5.1. "Parameter Encoding"
// https://oauth.net/core/1.0/#encoding_parameters
const STRICT_ENCODE_SET: percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent encode string
fn encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), &STRICT_ENCODE_SET).collect()
}

/// Create signature. See https://dev.twitter.com/oauth/overview/creating-signatures
fn signature(
    method: &str,
    uri: &str,
    query: &str,
    consumer_secret: &str,
    token_secret: Option<&str>,
) -> String {
    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(query));
    let key = format!(
        "{}&{}",
        encode(consumer_secret),
        encode(token_secret.unwrap_or(""))
    );
    debug!("Signature base string: {}", base);
    debug!("Authorization header: Authorization: {}", base);
    let signing_key = hmac::SigningKey::new(&digest::SHA1, key.as_bytes());
    let signature = hmac::sign(&signing_key, base.as_bytes());
    base64::encode(signature.as_ref())
}

/// Constuct plain-text header
fn header(param: &ParamList) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("OAuth {}", pairs.join(", "))
}

/// Construct plain-text body from 'ParamList'
fn body(param: &ParamList) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| !k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}={}", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("{}", pairs.join("&"))
}

/// Create header and body
fn get_header(
    method: &str,
    uri: &str,
    consumer: &Token,
    token: Option<&Token>,
    other_param: Option<&ParamList>,
) -> (String, String) {
    let mut param = HashMap::new();
    let timestamp = format!("{}", OffsetDateTime::now_utc().unix_timestamp());
    let mut rng = rand::thread_rng();
    let nonce = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(32)
        .collect::<String>();

    let _ = insert_param(&mut param, "oauth_consumer_key", consumer.key.to_string());
    let _ = insert_param(&mut param, "oauth_nonce", nonce);
    let _ = insert_param(&mut param, "oauth_signature_method", "HMAC-SHA1");
    let _ = insert_param(&mut param, "oauth_timestamp", timestamp);
    let _ = insert_param(&mut param, "oauth_version", "1.0");
    if let Some(tk) = token {
        let _ = insert_param(&mut param, "oauth_token", tk.key.as_ref());
    }

    if let Some(ps) = other_param {
        for (k, v) in ps.iter() {
            let _ = insert_param(&mut param, k.as_ref(), v.as_ref());
        }
    }

    let sign = signature(
        method,
        uri,
        join_query(&param).as_ref(),
        consumer.secret.as_ref(),
        token.map(|t| t.secret.as_ref()),
    );
    let _ = insert_param(&mut param, "oauth_signature", sign);

    (header(&param), body(&param))
}

/// Create an authorization header.
/// See https://dev.twitter.com/oauth/overview/authorizing-requests
///
/// # Examples
///
/// ```
/// # extern crate oauth_client;
/// # fn main() {
/// const REQUEST_TOKEN: &'static str = "http://oauthbin.com/v1/request-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let header = oauth_client::authorization_header("GET", REQUEST_TOKEN, &consumer, None, None);
/// # }
/// ```
pub fn authorization_header(
    method: &str,
    uri: &str,
    consumer: &Token,
    token: Option<&Token>,
    other_param: Option<&ParamList>,
) -> (String, String) {
    get_header(method, uri, consumer, token, other_param)
}

/// Send authorized GET request to the specified URL.
/// `consumer` is a consumer token.
///
/// # Examples
///
/// ```
/// let REQUEST_TOKEN: &'static str = "http://oauthbin.com/v1/request-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let bytes = oauth_client::get(REQUEST_TOKEN, &consumer, None, None).unwrap();
/// let resp = String::from_utf8(bytes).unwrap();
/// ```
pub fn get(
    uri: &str,
    consumer: &Token,
    token: Option<&Token>,
    other_param: Option<&ParamList>,
) -> Result<Vec<u8>> {
    let (header, body) = get_header("GET", uri, consumer, token, other_param);
    let req_uri = if body.len() > 0 {
        format!("{}?{}", uri, body)
    } else {
        format!("{}", uri)
    };

    let rsp = send(CLIENT.get(&req_uri).header(AUTHORIZATION, header))?;
    Ok(rsp)
}

/// Send authorized POST request to the specified URL.
/// `consumer` is a consumer token.
///
/// # Examples
///
/// ```
/// # let request = oauth_client::Token::new("key", "secret");
/// let ACCESS_TOKEN: &'static str = "http://oauthbin.com/v1/access-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let bytes = oauth_client::post(ACCESS_TOKEN, &consumer, Some(&request), None).unwrap();
/// let resp = String::from_utf8(bytes).unwrap();
/// ```
pub fn post(
    uri: &str,
    consumer: &Token,
    token: Option<&Token>,
    other_param: Option<&ParamList>,
) -> Result<Vec<u8>> {
    let (header, body) = get_header("POST", uri, consumer, token, other_param);

    let rsp = send(
        CLIENT
            .post(uri)
            .body(body)
            .header(AUTHORIZATION, header)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded"),
    )?;
    Ok(rsp)
}

/// Send request to the server
fn send(builder: RequestBuilder) -> Result<Vec<u8>> {
    let mut response = builder.send()?;
    if response.status() != StatusCode::OK {
        bail!(HttpStatusError(response.status().into()));
    }
    let mut buf = vec![];
    let _ = response.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::encode;
    use std::collections::HashMap;

    #[test]
    fn query() {
        let mut map = HashMap::new();
        let _ = map.insert("aaa".into(), "AAA".into());
        let _ = map.insert("bbbb".into(), "BBBB".into());
        let query = super::join_query(&map);
        assert_eq!("aaa=AAA&bbbb=BBBB", query);
    }

    #[test]
    fn test_encode() {
        let method = "GET";
        let uri = "http://oauthbin.com/v1/request-token";
        let encoded_uri = "http%3A%2F%2Foauthbin.com%2Fv1%2Frequest-token";
        let query = [
            "oauth_consumer_key=key&",
            "oauth_nonce=s6HGl3GhmsDsmpgeLo6lGtKs7rQEzzsA&",
            "oauth_signature_method=HMAC-SHA1&",
            "oauth_timestamp=1471445561&",
            "oauth_version=1.0",
        ]
        .iter()
        .cloned()
        .collect::<String>();
        let encoded_query = [
            "oauth_consumer_key%3Dkey%26",
            "oauth_nonce%3Ds6HGl3GhmsDsmpgeLo6lGtKs7rQEzzsA%26",
            "oauth_signature_method%3DHMAC-SHA1%26",
            "oauth_timestamp%3D1471445561%26",
            "oauth_version%3D1.0",
        ]
        .iter()
        .cloned()
        .collect::<String>();

        assert_eq!(encode(method), "GET");
        assert_eq!(encode(uri), encoded_uri);
        assert_eq!(encode(&query), encoded_query);
    }
}
