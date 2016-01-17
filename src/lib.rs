// Copyright 2016 oauth-client-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OAuth 1.0 client library for Rust.
//!
//! Dependent on libcurl.
//!
//! [Repository](https://github.com/charlag/oauth-client-rs)
//!
//!# Examples
//!
//! Send request for request token.
//!
//! ```
//!let consumer = Token::new("key", "secret")
//!let bytes = oauth::get(api::REQUEST_TOKEN, consumer, None, None).unwrap();
//! ```
#![warn(bad_style)]
#![warn(missing_docs)]
#![warn(unused)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

extern crate crypto;
extern crate curl;
#[macro_use]
extern crate log;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate url;

use std::borrow::Cow;
use std::collections::HashMap;
use std::{error, fmt};
use rand::Rng;
use rustc_serialize::base64::{self, ToBase64};
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use curl::http::{self, Response};
use curl::http::handle::Method;
use url::percent_encoding;

/// The `Error` type
#[derive(Debug)]
pub enum Error {
    /// Curl error
    Curl(curl::ErrCode),
    /// Http status
    HttpStatus(Response),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Curl(ref err) => write!(f, "Curl error: {}", err),
            Error::HttpStatus(ref resp) => write!(f, "HTTP status error: {}", resp),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Curl(ref err) => err.description(),
            Error::HttpStatus(_) => "HTTP status error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Curl(ref err) => Some(err),
            Error::HttpStatus(_) => None,
        }
    }
}

impl From<curl::ErrCode> for Error {
    fn from(err: curl::ErrCode) -> Error {
        Error::Curl(err)
    }
}

/// Token structure for the OAuth
#[derive(Clone, Debug)]
pub struct Token<'a> {
    pub key: Cow<'a, str>,
    pub secret: Cow<'a, str>,
}

impl<'a> Token<'a> {
    /// Create new token from `key` and `secret`
    ///
    ///# Examples
    ///
    /// ```
    ///let consumer = Token::new("key", "secret");
    /// ```
    pub fn new<K, S>(key: K, secret: S) -> Token<'a>
        where K: Into<Cow<'a, str>>,
              S: Into<Cow<'a, str>>
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
    where K: Into<Cow<'a, str>>,
          V: Into<Cow<'a, str>>
{
    param.insert(key.into(), value.into())
}

fn join_query<'a>(param: &ParamList<'a>) -> String {
    let mut pairs = param.iter()
                         .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
                         .collect::<Vec<_>>();
    pairs.sort();
    pairs.join("&")
}

/// Percent encode string
fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::FORM_URLENCODED_ENCODE_SET)
}

/// Wrapper function around 'crypto::Hmac'
fn hmac_sha1(key: &[u8], data: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(data);
    hmac.result()
}

/// Create signature. See https://dev.twitter.com/oauth/overview/creating-signatures
fn signature(method: &str,
             uri: &str,
             query: &str,
             consumer_secret: &str,
             token_secret: Option<&str>)
             -> String {
    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(query));
    let key = format!("{}&{}",
                      encode(consumer_secret),
                      encode(token_secret.unwrap_or("")));
    let conf = base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: None,
    };
    debug!("Signature base string: {}", base);
    debug!("Authorization header: Authorization: {}", base);
    hmac_sha1(key.as_bytes(), base.as_bytes()).code().to_base64(conf)
}

/// Constuct plain-text header
fn header(param: &ParamList) -> String {
    let mut pairs = param.iter()
                         .filter(|&(k, _)| k.starts_with("oauth_"))
                         .map(|(k, v)| format!("{}=\"{}\"", k, encode(&v)))
                         .collect::<Vec<_>>();
    pairs.sort();
    format!("OAuth {}", pairs.join(", "))
}

/// Construct plain-text body from 'PaaramList'
fn body(param: &ParamList) -> String {
    let mut pairs = param.iter()
                         .filter(|&(k, _)| !k.starts_with("oauth_"))
                         .map(|(k, v)| format!("{}={}", k, encode(&v)))
                         .collect::<Vec<_>>();
    pairs.sort();
    format!("{}", pairs.join("&"))
}

/// Create header and body
fn get_header(method: Method,
              uri: &str,
              consumer: &Token,
              token: Option<&Token>,
              other_param: Option<&ParamList>)
              -> (String, String) {
    let mut param = HashMap::new();
    let timestamp = format!("{}", time::now_utc().to_timespec().sec);
    let nonce = rand::thread_rng().gen_ascii_chars().take(32).collect::<String>();

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

    let method_str = match method {
        Method::Options => "OPTIONS",
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
        Method::Trace => "TRACE",
        Method::Connect => "CONNECT",
    };

    let sign = signature(method_str,
                         uri,
                         join_query(&param).as_ref(),
                         consumer.secret.as_ref(),
                         token.map(|t| t.secret.as_ref()));
    let _ = insert_param(&mut param, "oauth_signature", sign);

    (header(&param), body(&param))
}

/// Create an authorization header.
/// See https://dev.twitter.com/oauth/overview/authorizing-requests
///
///# Examples
///
///```
///let header = oauth::authorization_header(Method::Get, api::REQUEST_TOKEN, consumer, None, None);
///```
pub fn authorization_header(method: Method,
                            uri: &str,
                            consumer: &Token,
                            token: Option<&Token>,
                            other_param: Option<&ParamList>)
                            -> String {
    get_header(method, uri, consumer, token, other_param).0
}

/// Send authorized GET request to the specified URL.
/// `consumer` is a consumer token.
///
///# Examples
///
///```
///let REQUEST_TOKEN: &'static str = "http://oauthbin.com/v1/request-token"
///let bytes = oauth::get(REQUEST_TOKEN, consumer, None, None).unwrap();
///let resp = String::from_utf8(bytes).unwrap();
///```
pub fn get(uri: &str,
           consumer: &Token,
           token: Option<&Token>,
           other_param: Option<&ParamList>)
           -> Result<Vec<u8>, Error> {
    let (header, body) = get_header(Method::Get, uri, consumer, token, other_param);
    let req_uri = if body.len() > 0 {
        format!("{}?{}", uri, body)
    } else {
        format!("{}", uri)
    };
    let resp = try!(http::handle()
                        .get(req_uri)
                        .header("Authorization", header.as_ref())
                        .exec());
    debug!("{}", resp);
    if resp.get_code() != 200 {
        return Err(Error::HttpStatus(resp));
    }
    Ok(resp.move_body())
}

/// Send authorized POST request to the specified URL.
/// `consumer` is a consumer token.
///
///# Examples
///
///```
///let ACCESS_TOKEN: &'static str = "http://oauthbin.com/v1/access-token"
///let bytes = oauth::post(ACCESS_TOKEN, consumer, Some(request), None).unwrap();
///let resp = String::from_utf8(bytes).unwrap();
///```
pub fn post(uri: &str,
            consumer: &Token,
            token: Option<&Token>,
            other_param: Option<&ParamList>)
            -> Result<Vec<u8>, Error> {
    let (header, body) = get_header(Method::Post, uri, consumer, token, other_param);
    let resp = try!(http::handle()
                        .post(uri, &body)
                        .header("Authorization", header.as_ref())
                        .content_type("application/x-www-form-urlencoded")
                        .exec());
    debug!("{}", resp);
    if resp.get_code() != 200 {
        return Err(Error::HttpStatus(resp));
    }
    Ok(resp.move_body())
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn query() {
        let mut map = HashMap::new();
        let _ = map.insert("aaa".into(), "AAA".into());
        let _ = map.insert("bbbb".into(), "BBBB".into());
        let query = super::join_query(&map);
        assert_eq!("aaa=AAA&bbbb=BBBB", query);
    }
}
