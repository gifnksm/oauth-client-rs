#![warn(bad_style, missing_docs,
        unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]

extern crate crypto;
extern crate curl;
#[macro_use] extern crate log;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate url;

use std::borrow::Cow;
use std::collections::HashMap;
use std::str;
use rand::Rng;
use rustc_serialize::base64::{self, ToBase64};
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use curl::http;
use curl::http::handle::Method;
use url::percent_encoding;

#[derive(Clone, Debug)]
pub struct Token<'a> { pub key: Cow<'a, str>, pub secret: Cow<'a, str> }

impl<'a> Token<'a> {
    pub fn new<K, S>(key: K, secret: S) -> Token<'a>
        where K : Into<Cow<'a, str>>, S: Into<Cow<'a, str>>
    {
        Token { key: key.into(), secret: secret.into() }
    }
}

pub type ParamList<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;

fn insert_param<'a, K, V>(param: &mut ParamList<'a>, key: K, value: V)
                          -> Option<Cow<'a, str>>
    where K : Into<Cow<'a, str>>, V: Into<Cow<'a, str>>
{
    param.insert(key.into(), value.into())
}

fn join_query<'a>(param: &ParamList<'a>) -> String {
    let mut pairs = param
        .iter()
        .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.connect("&")
}

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::FORM_URLENCODED_ENCODE_SET)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(data);
    hmac.result()
}

fn signature(method: &str, uri: &str, query: &str, consumer_secret: &str, token_secret: Option<&str>) -> String {
    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(query));
    let key  = format!("{}&{}", encode(consumer_secret), encode(token_secret.unwrap_or("")));
    let conf = base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: None
    };
    debug!("Signature base string: {}", base);
    debug!("Authorization header: Authorization: {}", base);
    hmac_sha1(key.as_bytes(), base.as_bytes()).code().to_base64(conf)
}

fn header(param: &ParamList) -> String{
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("OAuth {}", pairs.connect(", "))
}

fn body(param: &ParamList) -> String{
    let mut pairs = param
        .iter()
        .filter(|&(k, _)| !k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}={}", k, encode(&v)))
        .collect::<Vec<_>>();
    pairs.sort();
    format!("{}", pairs.connect("&"))
}

fn get_header(method: Method, uri: &str, consumer: &Token, token: Option<&Token>, other_param: Option<&ParamList>) -> (String, String) {
    let mut param = HashMap::new();
    let timestamp = format!("{}", time::now_utc().to_timespec().sec);
    let nonce = rand::thread_rng().gen_ascii_chars().take(32).collect::<String>();

    let _ = insert_param(&mut param, "oauth_consumer_key",     consumer.key.to_string());
    let _ = insert_param(&mut param, "oauth_nonce",            nonce);
    let _ = insert_param(&mut param, "oauth_signature_method", "HMAC-SHA1");
    let _ = insert_param(&mut param, "oauth_timestamp",        timestamp);
    let _ = insert_param(&mut param, "oauth_version",          "1.0");
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
        Method::Connect => "CONNECT"
    };

    let sign = signature(method_str, uri,
                         join_query(&param).as_ref(),
                         consumer.secret.as_ref(),
                         token.map(|t| t.secret.as_ref()));
    let _ = insert_param(&mut param, "oauth_signature", sign);

    (header(&param), body(&param))
}

pub fn authorization_header(method: Method, uri: &str, consumer: &Token, token: Option<&Token>, other_param: Option<&ParamList>) -> String {
    get_header(method, uri, consumer, token, other_param).0
}

pub fn get(uri: &str, consumer: &Token, token: Option<&Token>, other_param: Option<&ParamList>) -> String {
    let (header, body) = get_header(Method::Get, uri, consumer, token, other_param);
    let resp = http::handle()
        .get(if body.len() > 0 { format!("{}?{}", uri, body) } else { format!("{}", uri) })
        .header("Authorization", header.as_ref())
        .exec().unwrap();
    debug!("{}", resp);
    assert_eq!(200, resp.get_code());
    str::from_utf8(resp.get_body()).unwrap().to_string()
}

pub fn post(uri: &str, consumer: &Token, token: Option<&Token>, other_param: Option<&ParamList>) -> String {
    let (header, body) = get_header(Method::Post, uri, consumer, token, other_param);
    let resp = http::handle()
        .post(uri, &body)
        .header("Authorization", header.as_ref())
        .content_type("application/x-www-form-urlencoded")
        .exec().unwrap();
    debug!("{}", resp);
    assert_eq!(200, resp.get_code());
    str::from_utf8(resp.get_body()).unwrap().to_string()
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
