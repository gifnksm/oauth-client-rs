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
//! let bytes = oauth_client::get::<DefaultRequestBuilder>(REQUEST_TOKEN, &consumer, None, None, &()).unwrap();
//! ```
#![warn(bad_style)]
#![warn(missing_docs)]
#![warn(unused)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![allow(unused_doc_comments)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use http::{
    header::{HeaderName, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, StatusCode,
};
use log::debug;
use rand::{distributions::Alphanumeric, Rng};
use ring::hmac;
use std::{borrow::Cow, collections::HashMap, convert::TryFrom, io, iter, mem::MaybeUninit};
use thiserror::Error;
use time::OffsetDateTime;
#[cfg(all(feature = "reqwest-blocking"))]
use ::{
    lazy_static::lazy_static,
    reqwest::blocking::Client,
    std::{io::Read, str::FromStr},
    url::Url,
};

/// Re-exporting `reqwest` crate.
#[cfg(feature = "client-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest")))]
pub use reqwest;
use std::fmt::Debug;

/// Error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error<B>
where
    B: RequestBuilder,
{
    /// An error happening due to a HTTP status error.
    #[error("HTTP status error code: {0}")]
    HttpStatus(StatusCode),

    /// An error happening due to a IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// An error happening due to a HTTP request error.
    #[error("HTTP request error: {0}")]
    HttpRequest(B::HttpRequestError),
}

#[cfg(feature = "client-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest")))]
impl<B> From<reqwest::Error> for Error<B>
where
    B: RequestBuilder<HttpRequestError = reqwest::Error>,
{
    fn from(e: reqwest::Error) -> Self {
        Self::HttpRequest(e)
    }
}

#[cfg(feature = "reqwest-blocking")]
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
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
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

use self::percent_encode_string as encode;
/// Percent-encode the string in the manner defined in RFC 3986
pub fn percent_encode_string(s: &str) -> Cow<str> {
    percent_encoding::percent_encode(s.as_bytes(), &STRICT_ENCODE_SET).collect()
}

/// Create signature. See <https://dev.twitter.com/oauth/overview/creating-signatures>
pub fn signature(
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

/// Things that can go wrong while verifying a request's signature
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// No authorization header
    #[error("Authorization header not found")]
    NoAuthorizationHeader,

    /// Invalid header
    #[error("Non ASCII values in header: {0}")]
    NonAsciiHeader(#[source] http::header::ToStrError),

    /// Invalid params
    #[error("Invalid key value pair in query params")]
    InvalidKeyValuePair,
}

/// Generic request type. Allows you to pass any [`reqwest::Request`]-like object.
/// You're gonna need to wrap whatever client's `Request` type you're using in your own
/// type, as the orphan rules won't allow you to `impl` this trait.
pub trait GenericRequest {
    /// Headers
    fn headers(&self) -> &http::header::HeaderMap<HeaderValue>;

    /// Url
    fn url(&self) -> &str;

    /// Method.
    fn method(&self) -> &str;
}

#[cfg(feature = "client-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest")))]
impl GenericRequest for reqwest::Request {
    fn headers(&self) -> &http::header::HeaderMap<HeaderValue> {
        self.headers()
    }

    fn url(&self) -> &str {
        if let Some(host) = self.headers().get("host") {
            // Host field actually contains the url used to connect, while the url provided
            // by the request can be inaccurate
            host.to_str().unwrap_or_else(|_e| self.url().as_str())
        } else {
            self.url().as_str()
        }
    }

    fn method(&self) -> &str {
        self.method().as_str()
    }
}

/// Verifies that the provided request's signature is valid.
/// The `url_middleware` argument allows you to modify the url before it's used to calculate the
/// signature. This could be useful for tests, where there can be multiple `localhost` urls.
///
/// # Examples
///
/// ```
/// # use std::borrow::Cow;
/// # use oauth_client::{Error, RequestBuilder, Token};
/// # use oauth_client::reqwest::header::{HeaderName, HeaderValue};
/// # use std::convert::TryFrom;
/// #[derive(Debug)]
/// struct DummyRequestBuilder(reqwest::RequestBuilder);
///
/// impl RequestBuilder for DummyRequestBuilder {
///     type HttpRequestError = reqwest::Error;
///     type ReturnValue = reqwest::Request;
///     type ClientBuilder = reqwest::Client;
///
///     fn new(method: http::Method, url: &'_ str, client: &Self::ClientBuilder) -> Self {
///         Self(client.request(method, url))
///     }
///     fn body(mut self, b: String) -> Self {
///         self.0 = self.0.body(b); self
///     }
///     fn header<K, V>(mut self, key: K, val: V) -> Self
///         where
///             HeaderName: TryFrom<K>,
///             HeaderValue: TryFrom<V>,
///             <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
///             <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
///     {
///         self.0 = self.0.header(key, val); self
///     }
///     fn send(self) -> Result<Self::ReturnValue, Error<Self>> {
///         Ok(self.0.build()?)
///     }
/// }
/// let client = reqwest::Client::new();
/// let token = Token::new("key", "secret");
/// let request = oauth_client::get::<DummyRequestBuilder>(
///     "http://localhost/",
///     &token,
///     None,
///     None,
///     &client,
/// ).unwrap();
/// assert!(
///     oauth_client::check_signature_request(request, &token.secret, None, |u| Cow::from(u)).unwrap(),
///     "Invalid signature"
/// );
/// ```
pub fn check_signature_request<R: GenericRequest>(
    request: R,
    consumer_secret: &str,
    token_secret: Option<&str>,
    mut url_middleware: impl FnMut(&str) -> Cow<str>,
) -> Result<bool, VerifyError> {
    let authorization_header = request
        .headers()
        .get("Authorization")
        .ok_or(VerifyError::NoAuthorizationHeader)?;

    let (provided_signature, mut auth_params_without_signature): (Vec<&str>, Vec<&str>) =
        authorization_header
            .to_str()
            .map_err(VerifyError::NonAsciiHeader)?
            .split(',')
            .map(str::trim)
            .partition(|x| x.starts_with("oauth_signature="));

    assert_eq!(
        provided_signature.len(),
        1,
        "provided_signature: {:?}",
        provided_signature
    );
    let provided_signature = provided_signature.first().unwrap();
    let all_other_max = auth_params_without_signature.len() - 1;
    let mut all_together_max = all_other_max;
    let mut query_params = None;
    let mut url = request.url();
    if let Some(qm_i) = request.url().rfind('?') {
        // Strip query params from url
        url = &url[..qm_i];
        let qp = request.url()[qm_i + 1..].split('&').collect::<Vec<&str>>();
        all_together_max += qp.len();
        query_params = Some(qp);
    }
    fn split_key_value_pair(qp: &str) -> Result<(&str, &str), VerifyError> {
        qp.split_once('=')
            .ok_or(VerifyError::InvalidKeyValuePair)
            .map(|(k, v)| (k, v))
    }
    // First one starts with "OAuth oauth_callback=..."
    auth_params_without_signature[0] = &auth_params_without_signature[0]["OAuth ".len()..];
    let query: Result<Vec<(&str, &str)>, VerifyError> = auth_params_without_signature
        .into_iter()
        .map(|qp|
            split_key_value_pair(qp).map(|(k,v)| (k, &v[1..v.len()-1]))
        )
        // Append the query from URL params at the end
        .chain(
            if let Some(query_params) = query_params.take() {
                query_params.into_iter()
            } else {
                Vec::new().into_iter()
            }.map(split_key_value_pair)
        )
        .collect();
    let mut query = query?;
    query.sort_by(|(a, _), (b, _)| a.cmp(b));

    let query: String = query
        .iter()
        .enumerate()
        .flat_map(|(i, (k, v))| [k, "=", v, if i == all_together_max { &"" } else { &"&" }])
        .collect();

    // Fix the url provided by reqwest::Request, e.g. being `localhost` instead of `127.0.0.1`
    let url = url_middleware(url);

    return Ok(check_signature(
        &provided_signature["oauth_signature=\"".len()..provided_signature.len() - 1],
        request.method(),
        &url,
        &query,
        consumer_secret,
        token_secret,
    ));
}

/// Checks if the signature created by the given request data is the same
/// as the provided signature.
///
/// See [`check_signature_request`] for a function that automatically
/// does this with any [`GenericRequest`]
pub fn check_signature(
    signature_to_check: &str,
    method: &str,
    uri: &str,
    query: &str,
    consumer_secret: &str,
    token_secret: Option<&str>,
) -> bool {
    let signature = signature(method, uri, query, consumer_secret, token_secret);
    let new_encoded_signature = encode(&signature);

    new_encoded_signature == signature_to_check
}

/// Construct plain-text header.
///
/// See https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
fn header(param: &ParamList<'_>) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("OAuth {}", pairs.join(", "))
}

/// Construct plain-text body from 'ParamList'
fn body(param: &ParamList<'_>) -> String {
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| !k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}={}", k, encode(v)))
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
/// See <https://dev.twitter.com/oauth/overview/authorizing-requests>
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
/// let resp = oauth_client::get::<DefaultRequestBuilder>(REQUEST_TOKEN, &consumer, None, None, &()).unwrap();
/// ```
pub fn get<RB: RequestBuilder>(
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
    client: &RB::ClientBuilder,
) -> Result<RB::ReturnValue, Error<RB>> {
    let (header, body) = get_header("GET", uri, consumer, token, other_param);
    let req_uri = if !body.is_empty() {
        format!("{}?{}", uri, body)
    } else {
        uri.to_string()
    };

    let rsp = RB::new(http::Method::GET, &req_uri, client)
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
/// let ACCESS_TOKEN: &'static str = "https://oauthbin.com/v1/access-token";
/// let consumer = oauth_client::Token::new("key", "secret");
/// let resp = oauth_client::post::<DefaultRequestBuilder>(ACCESS_TOKEN, &consumer, Some(&request), None, &()).unwrap();
/// ```
pub fn post<RB: RequestBuilder>(
    uri: &str,
    consumer: &Token<'_>,
    token: Option<&Token<'_>>,
    other_param: Option<&ParamList<'_>>,
    client: &RB::ClientBuilder,
) -> Result<RB::ReturnValue, Error<RB>> {
    let (header, body) = get_header("POST", uri, consumer, token, other_param);

    RB::new(http::Method::POST, uri, client)
        .body(body)
        .header(AUTHORIZATION, header)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .send()
}

/// Default one to use if you're not using a custom HTTP Client
/// and are ok with bundling reqwest
#[cfg(feature = "reqwest-blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest-blocking")))]
#[derive(Debug)]
pub struct DefaultRequestBuilder {
    inner: reqwest::blocking::RequestBuilder,
}

#[cfg(feature = "reqwest-blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest-blocking")))]
impl RequestBuilder for DefaultRequestBuilder {
    type HttpRequestError = reqwest::Error;
    type ReturnValue = String;
    type ClientBuilder = ();
    /// If the url is wrong then it will fail only during send
    fn new(method: http::Method, url: &'_ str, _: &Self::ClientBuilder) -> Self {
        let rb = CLIENT.request(method, Url::from_str(url).unwrap());
        Self { inner: rb }
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
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header(key, val);

        self
    }

    fn send(self) -> Result<Self::ReturnValue, Error<Self>> {
        let mut response = self.inner.send()?;
        if response.status() != StatusCode::OK {
            return Err(Error::HttpStatus(response.status()));
        }
        let mut buf = String::with_capacity(200);
        let _ = response.read_to_string(&mut buf)?;
        Ok(buf)
    }
}

/// A generic request builder. Allows you to use any HTTP client.
/// See [`DefaultRequestBuilder`] for one that uses [`reqwest::Client`].
pub trait RequestBuilder: Debug {
    /// The error produced while sending a HTTP request
    type HttpRequestError: std::error::Error;

    /// Generic return value allows you to return a future, allowing the possibility
    /// of using this library in `async` environments.
    type ReturnValue;

    /// This is useful for reusing existing connection pools.
    type ClientBuilder;

    /// Construct the request builder
    fn new(method: http::Method, url: &'_ str, client: &Self::ClientBuilder) -> Self;

    /// Set the body
    fn body(self, b: String) -> Self;

    /// Set a header
    fn header<K, V>(self, key: K, val: V) -> Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>;

    /// A `build`-like function that also sends the request
    fn send(self) -> Result<Self::ReturnValue, Error<Self>>
    where
        Self: Sized;
}

/// Errors possible while using [`parse_query_string`].
#[derive(Debug, Error)]
pub enum ParseQueryError {
    /// You provided more keys than there actually were to parse.
    /// Empty string.
    #[error("Not enough key value pairs provided. Was: {0}")]
    NotEnoughPairs(usize),

    /// Lacks an `=`, or nothing after the `=` sign in some key value pair.
    #[error("One of the key value pairs was invalid.")]
    InvalidKeyValuePair,
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;
    use std::collections::HashMap;

    #[test]
    fn parse_dont_sort_doesnt_sort() {
        let input = "b=BBB&a=AAA";
        let [(a_key, a), (b_key, b)] = parse_query_string(input, false, &["a", "b"]).unwrap();
        assert_eq!(a_key, "b");
        assert_eq!(b_key, "a");
        assert_eq!(b, "AAA");
        assert_eq!(a, "BBB");
    }

    #[test]
    fn parse_sort_out_of_order() {
        let input = "b=BBB&a=AAA";
        let [(a_key, a), (b_key, b)] = parse_query_string(input, true, &["a", "b"]).unwrap();
        assert_eq!(a_key, "a");
        assert_eq!(b_key, "b");
        assert_eq!(a, "AAA");
        assert_eq!(b, "BBB");
    }

    #[test]
    fn parse_sort_already_sorted() {
        let input = "a=AAA&b=BBB";
        let [(a_key, a), (b_key, b)] = parse_query_string(input, true, &["a", "b"]).unwrap();
        assert_eq!(a_key, "a");
        assert_eq!(b_key, "b");
        assert_eq!(a, "AAA");
        assert_eq!(b, "BBB");
    }

    #[test]
    fn parse_invalid_keys() {
        let input = "a=AAA&b=BBB";
        match parse_query_string(input, true, &["a", "x"]) {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::NotEnoughPairs(_) => {}
                _ => panic!("Wrong error"),
            },
        }
    }

    #[test]
    fn parse_empty_string() {
        let input = "";
        assert_eq!("".split('&').collect::<Vec<_>>(), [""]);
        assert_eq!("&".split('&').collect::<Vec<_>>(), ["", ""]);
        assert_eq!(0, "".split_terminator('&').collect::<Vec<_>>().len());
        match parse_query_string(input, true, &["a", "b"]) {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::NotEnoughPairs(_) => {}
                _ => panic!("Wrong error"),
            },
        }
    }

    #[test]
    fn parse_invalid_format() {
        let input = "x&";
        match parse_query_string(input, true, &["x"]) {
            Ok(_) => panic!("Should error"),
            Err(e) => match e {
                ParseQueryError::InvalidKeyValuePair => {}
                _ => panic!("Wrong error"),
            },
        }
    }

    #[test]
    fn check_signature_request_test() {
        simple_logger::SimpleLogger::new()
            .with_level(LevelFilter::Trace)
            .init()
            .unwrap();
        #[derive(Debug)]
        struct DummyRequestBuilder(reqwest::RequestBuilder);

        impl RequestBuilder for DummyRequestBuilder {
            type HttpRequestError = reqwest::Error;
            type ReturnValue = reqwest::Request;
            type ClientBuilder = reqwest::Client;

            fn new(method: http::Method, url: &'_ str, client: &Self::ClientBuilder) -> Self {
                Self(client.request(method, url))
            }
            fn body(mut self, b: String) -> Self {
                self.0 = self.0.body(b);

                self
            }
            fn header<K, V>(mut self, key: K, val: V) -> Self
            where
                HeaderName: TryFrom<K>,
                HeaderValue: TryFrom<V>,
                <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
                <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
            {
                self.0 = self.0.header(key, val);

                self
            }
            fn send(self) -> Result<Self::ReturnValue, Error<Self>> {
                let rv = self.0.build()?;
                Ok(rv)
            }
        }
        let client = reqwest::Client::new();
        let token = Token::new("key", "secret");
        let param_list = {
            let mut hm: ParamList<'_> = HashMap::with_capacity(2);
            assert!(hm
                .insert(
                    "oauth_any_string".into(),
                    "gets_put_into_auth_header".into()
                )
                .is_none());
            assert!(hm
                .insert(
                    "doesnt_start_with_oauth".into(),
                    "doesnt_get_put_into_auth_header".into()
                )
                .is_none());
            assert!(hm
                .insert("oauth_callback".into(), "http://xd.xy?xy=xz&xd=xx".into())
                .is_none());

            hm
        };
        let request = get::<DummyRequestBuilder>(
            // FIXME: Trailing slash important, otherwise it fails, dunno how to fix
            "http://localhost/",
            &token,
            None,
            Some(&param_list),
            &client,
        )
        .unwrap();
        assert_eq!(
            check_signature_request(request, &token.secret, None, |u| Cow::from(u)).unwrap(),
            true
        );
    }

    #[test]
    fn query() {
        let mut map = HashMap::new();
        let _ = map.insert("aaa".into(), "AAA".into());
        let _ = map.insert("bbbb".into(), "BBBB".into());
        let query = join_query(&map);
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

use log::warn;

/// Utility function to parse the `Authorization` header from an HTTP request.
///
/// Assumptions:
/// 1. Keys are distinct
///
/// Arguments:
/// 1. Key to search
/// 2. Whether to sort the return value (for reproducibility).
///
///    Set to true if in doubt. If the server changes its order of arguments you'll be fine.
///
/// 3. The names of the keys. (If put more than existing, or invalid then error might happen
///    because we are looking for all provided keys.)
pub fn parse_query_string<'q, const N: usize>(
    query_string: &'q str,
    sort: bool,
    keys: &[&str; N],
) -> Result<[(&'q str, &'q str); N], ParseQueryError> {
    // Create an uninitialized array of `MaybeUninit`. The `assume_init` is
    // safe because the type we are claiming to have initialized here is a
    // bunch of `MaybeUninit`s, which do not require initialization.
    let mut rv: [MaybeUninit<(&str, &str)>; N] = unsafe { MaybeUninit::uninit().assume_init() };

    let mut num_inserted = 0;
    for kv in query_string.split_terminator('&') {
        let mut iter = kv.split_terminator('=');
        let key = iter.next().ok_or(ParseQueryError::InvalidKeyValuePair)?;
        let val = iter.next().ok_or(ParseQueryError::InvalidKeyValuePair)?;

        if keys.contains(&key) {
            // Dropping a `MaybeUninit` does nothing. Thus using element
            // assignment instead of `ptr::write` does not cause the old
            // uninitialized value to be dropped.
            rv[num_inserted] = MaybeUninit::new((key, val));
            num_inserted += 1;
        } else {
            warn!("Unexpected key {:?}. (value {:?})", key, val);
        }
    }

    if num_inserted < N {
        return Err(ParseQueryError::NotEnoughPairs(num_inserted));
    }

    // Everything is initialized. Transmute the array to the
    // initialized type.
    let mut rv: [(&str, &str); N] = unsafe { std::mem::transmute_copy(&rv) };

    if sort {
        // NOTE: Assumption: keys are distinct
        rv.sort_unstable_by_key(|&(k, _v)| k);
    }

    Ok(rv)
}
