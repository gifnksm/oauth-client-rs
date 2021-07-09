// Copyright 2016 oauth-client-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OAuth 1.0 client library for Rust.
//!
//! [Repository](https://github.com/gifnksm/oauth-client-rs)
//!
//! # Examples
//!
//! Send request for request token.
//!
//! ```
//! # use oauth_client::DefaultRequestBuilder;
//! const REQUEST_TOKEN: &str = "http://oauthbin.com/v1/request-token";
//! let consumer = oauth_client::Token::new("key", "secret");
//! let bytes = oauth_client::get::<DefaultRequestBuilder>(REQUEST_TOKEN, &consumer, None, None).unwrap();
//! ```
#![warn(bad_style)]
#![warn(missing_docs)]
#![warn(unused)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![allow(unused_doc_comments)]

use http::{HeaderValue, StatusCode, header::{AUTHORIZATION, CONTENT_TYPE, HeaderName}};
use lazy_static::lazy_static;
use log::debug;
use rand::{distributions::Alphanumeric, Rng};
#[cfg(feature="client-reqwest")]
use reqwest::IntoUrl;
#[cfg(all(feature="client-reqwest", feature="reqwest-blocking"))]
use reqwest::{
    blocking::{Client, RequestBuilder},
};
use url::Url;
use std::str::FromStr;
use ring::hmac;
use std::{borrow::Cow, collections::HashMap, convert::TryFrom, io::{self, Read}, iter};
use thiserror::Error;
use time::OffsetDateTime;

/// Result type.
pub type Result<T,E=Error> = std::result::Result<T, E>;

#[cfg(feature="client-reqwest")]
/// Re-exporting `reqwest` crate.
pub use reqwest;
use std::fmt::Debug;

/// Error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An error happening due to a HTTP status error.
    #[error("HTTP status error code: {0}")]
    HttpStatus(StatusCode),
    /// An error happening due to a IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// An error happening due to a reqwest error.
    #[cfg(feature="client-reqwest")]
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[cfg(not(feature="client-reqwest"))]
    #[error("other error: {0}")]
    CustomHTTPError(#[from] Box<dyn std::error::Error>)
}

#[cfg(all(feature="client-reqwest", feature="reqwest-blocking"))]
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

fn join_query(param: &ParamList<'_>) -> String {
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
    let signing_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let signature = hmac::sign(&signing_key, base.as_bytes());
    base64::encode(signature.as_ref())
}

/// Construct plain-text header
fn header(param: &ParamList<'_>) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("OAuth {}", pairs.join(", "))
}

/// Construct plain-text body from 'ParamList'
fn body(param: &ParamList<'_>) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| !k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}={}", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join("&")
}

/// Create header and body
fn get_header(
    method: &str,
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
) -> (String, String) {
    let mut param = HashMap::new();
    let timestamp = format!("{}", OffsetDateTime::now_utc().unix_timestamp());
    let mut rng = rand::thread_rng();
    let nonce = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
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
/// const REQUEST_TOKEN: &str = "http://oauthbin.com/v1/request-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let header = oauth_client::authorization_header(
///   "GET", REQUEST_TOKEN, &consumer, None, None
/// );
/// # }
/// ```
pub fn authorization_header(
    method: &str,
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
) -> (String, String) {
    get_header(method, uri, consumer, token, other_param)
}

/// Send authorized GET request to the specified URL.
/// `consumer` is a consumer token.
///
/// # Examples
///
/// ```
/// # use oauth_client::DefaultRequestBuilder;
/// let REQUEST_TOKEN: &str = "http://oauthbin.com/v1/request-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let resp = oauth_client::get::<DefaultRequestBuilder>(REQUEST_TOKEN, &consumer, None, None).unwrap();
/// ```
pub fn get<RB: RequestBuildah>(
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
) -> Result<RB::ReturnValue, RB::Error> {
    let (header, body) = get_header(
        "GET", uri, consumer, token, other_param
    );
    let req_uri = if !body.is_empty() {
        format!("{}?{}", uri, body)
    } else {
        uri.to_string()
    };

    let rsp = RB::new(http::Method::GET, &req_uri)
            .header(AUTHORIZATION, header)
            .send()?;
    Ok(rsp)
}

/// Send authorized POST request to the specified URL.
/// `consumer` is a consumer token.
///
/// # Examples
///
/// ```
/// # use oauth_client::DefaultRequestBuilder;
/// let request = oauth_client::Token::new("key", "secret");
/// let ACCESS_TOKEN: &'static str = "http://oauthbin.com/v1/access-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let resp = oauth_client::post::<DefaultRequestBuilder>(ACCESS_TOKEN, &consumer, Some(&request), None).unwrap();
/// ```
pub fn post<RB: RequestBuildah>(
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
) -> Result<RB::ReturnValue, RB::Error> {
    let (header, body) = get_header(
        "POST", uri, consumer, token, other_param
    );

    Ok(
        RB::new(http::Method::POST, uri)
            .body(body)
            .header(AUTHORIZATION, header)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .send()?
    )
}

/// Default one to use if you're not using a custom HTTP Client
/// and are ok with bundling reqwest
#[cfg(all(feature="client-reqwest", feature="reqwest-blocking"))]
pub struct DefaultRequestBuilder {
    inner: RequestBuilder,
}

#[cfg(all(feature="client-reqwest", feature="reqwest-blocking"))]
impl RequestBuildah for DefaultRequestBuilder {
    type Error = Error;
    type ReturnValue = String;
    /// If the url is wrong then it will fail only during send
    fn new(method: http::Method, url: &'_ str) -> Self {
        let rb = CLIENT.request(method, Url::from_str(url).unwrap());
        Self {
            inner: rb
        }
    }

    fn body(mut self, b: String) -> Self {
        self.inner = self.inner.body(b);

        self
    }

    fn header<K, V>(mut self, key: K, val: V) -> Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>
        {
        self.inner = self.inner.header(key, val);

        self
    }

    fn send(mut self) -> std::result::Result<Self::ReturnValue, Error> {
        let mut response = self.inner.send()?;
        if response.status() != StatusCode::OK {
            return Err(Error::HttpStatus(response.status()));
        }
        let mut buf = String::with_capacity(200);
        let _ = response.read_to_string(&mut buf)?;
        Ok(buf)
    }
}

pub trait RequestBuildah {
    type Error: Debug;
    type ReturnValue;

    fn new(method: http::Method, url: &'_ str) -> Self;
    // fn uri(&mut self, u: impl TryInto<url::Url>) -> &mut Self;
    // fn method(&mut self, m: http::method::Method) -> &mut Self;
    fn body(self, b: String) -> Self;
    // fn header(&mut self, key: impl TryInto<HeaderName>, val: impl TryInto<HeaderValue>) -> &mut Self;
    fn header<K,V>(self, key: K, val: V) -> Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>
    ;
    fn send(self) -> std::result::Result<Self::ReturnValue, Self::Error>;
}

#[macro_export]
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + $crate::count!($($xs)*));
}
use log::warn;

#[derive(Debug, Error)]
pub enum ParseQueryError {
    #[error("Not enough key value pairs provided. Was: {0}")]
    NotEnoughPairs(usize),
    #[error("One of the key value pairs was invalid.")]
    InvalidKeyValuePair
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn macro_rulez_dont_sort_already_sorted() {
        let input = "b=BBB&a=AAA";
        let [(a_key, a),(b_key, b)] = parse_query_string!(input, false, "a", "b").unwrap();
        assert_eq!(a_key, "b");
        assert_eq!(b_key, "a");
        assert_eq!(b, "AAA");
        assert_eq!(a, "BBB");
    }

    #[test]
    fn macro_rulez_sort_out_of_order() {
        let input = "b=BBB&a=AAA";
        let [(a_key, a),(b_key, b)] = parse_query_string!(input, true, "a", "b").unwrap();
        assert_eq!(a_key, "a");
        assert_eq!(b_key, "b");
        assert_eq!(a, "AAA");
        assert_eq!(b, "BBB");
    }
    #[test]
    fn macro_rulez_sort_already_sorted() {
        let input = "a=AAA&b=BBB";
        let [(a_key, a),(b_key, b)] = parse_query_string!(input, true, "a", "b").unwrap();
        assert_eq!(a_key, "a");
        assert_eq!(b_key, "b");
        assert_eq!(a, "AAA");
        assert_eq!(b, "BBB");
    }

    #[test]
    fn macro_rulez_invalid_keys() {
        let input = "a=AAA&b=BBB";
        match parse_query_string!(input, true, "a", "x") {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::NotEnoughPairs(_) => {},
                _ => panic!("Wrong error")
            }
        }
    }

    #[test]
    fn macro_rulez_empty_string() {
        let input = "";
        assert_eq!("".split('&').collect::<Vec<_>>(), [""]);
        assert_eq!("&".split('&').collect::<Vec<_>>(), ["", ""]);
        assert_eq!(0, "".split_terminator('&').collect::<Vec<_>>().len());
        match parse_query_string!(input, true, "a", "b") {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::NotEnoughPairs(_) => {},
                _ => panic!("Wrong error")
            }
        }
    }

    #[test]
    fn macro_rulez_invalid_format() {
        let input = "x&";
        match parse_query_string!(input, true, "x") {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::InvalidKeyValuePair => {},
                _ => panic!("Wrong error")
            }
        }
    }

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

/// Assumptions:
/// 1. Keys are distinct
///
/// Arguments:
/// 1. &str Key to search
/// 2. bool Whether to (unstable-y) sort the return value (for reproducibility)
/// 3+. Variadic! `&str` The names of the keys. (If put more than existing, or invalid then error might happen
///    because we are looking for all provided keys.)
#[macro_export]
macro_rules! parse_query_string {
    ($query:expr, $sort:expr, $( $key:expr ),+) => {
        {
            const count_keys: usize = $crate::count!($($key)*);

            let used_for_question_mark = || -> Result<_, $crate::ParseQueryError> {
                let mut rv: [Option<(&str, &str)>; count_keys] = [None; count_keys];
                let mut num_inserted = 0;
                for kv in $query.split_terminator('&') {
                    let mut iter = kv.split_terminator('=');
                    let key = iter.next().ok_or($crate::ParseQueryError::InvalidKeyValuePair)?;
                    let val = iter.next().ok_or($crate::ParseQueryError::InvalidKeyValuePair)?;

                    match key {
                        $($key)|+ => {
                            rv[num_inserted] = Some((key, val));
                            num_inserted += 1;
                        },
                        key => {
                            warn!("Unexpected key {:?}. (value {:?})", key, val);
                        }
                    }
                }

                if num_inserted < count_keys {
                    return Err(
                        $crate::ParseQueryError::NotEnoughPairs(num_inserted)
                    );
                }

                // SAFETY:
                //  1. We overwrote all Nones, with actual values.
                //  2. References are non-null so their size is the same as options.
                let mut rv: [(&str, &str); count_keys] = unsafe {
                    std::mem::transmute::<[Option<(&str, &str)>; count_keys], [(&str, &str); count_keys]>(rv)
                };

                if $sort {
                    // NOTE: Assumption: keys are distinct
                    rv.sort_unstable_by_key(|&(k,v)| k);
                }

                Ok(rv)
            };
            used_for_question_mark()
        }
    }
}
