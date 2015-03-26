#![warn(bad_style,
        unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, unused_typecasts)]

#![feature(convert, into_cow)]

extern crate curl;
extern crate oauth_client as oauth;
extern crate rand;

use std::borrow::{Cow, IntoCow};
use std::collections::HashMap;
use std::str;
use curl::http;
use curl::http::handle::Method;
use oauth::Token;
use rand::Rng;

mod api {
    pub const REQUEST_TOKEN: &'static str = "http://term.ie/oauth/example/request_token.php";
    pub const ACCESS_TOKEN: &'static str = "http://term.ie/oauth/example/access_token.php";
    pub const ECHO: &'static str = "http://term.ie/oauth/example/echo_api.php";
}

fn split_query<'a>(query: &'a str) -> HashMap<Cow<'a, str>, Cow<'a, str>> {
    let mut param = HashMap::new();
    for q in query.split('&') {
        let mut s = q.splitn(2, '=');
        let k = s.next().unwrap();
        let v = s.next().unwrap();
        let _ = param.insert(k.into_cow(), v.into_cow());
    }
    param
}

fn get_request_token(consumer: &Token) -> Token<'static> {
    let header = oauth::authorization_header(Method::Get, api::REQUEST_TOKEN, consumer, None, None);
    let resp = http::handle()
        .get(api::REQUEST_TOKEN)
        .header("Authorization", header.as_ref())
        .exec()
        .unwrap();
    let resp = str::from_utf8(resp.get_body())
        .unwrap()
        .to_string();
    println!("get_request_token response: {:?}", resp);
    let param = split_query(resp.as_ref());
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn get_access_token(consumer: &Token, request: &Token) -> Token<'static> {
    let header = oauth::authorization_header(Method::Get, api::ACCESS_TOKEN, consumer, Some(request), None);
    let resp = http::handle()
        .get(api::ACCESS_TOKEN)
        .header("Authorization", header.as_ref())
        .exec()
        .unwrap();
    let resp = str::from_utf8(resp.get_body())
        .unwrap()
        .to_string();
    println!("get_access_token response: {:?}", resp);
    let param = split_query(resp.as_ref());
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn echo(consumer: &Token, access: &Token) {
    let header = oauth::authorization_header(Method::Post, api::ECHO, consumer, Some(access), None);

    let mut rng = rand::thread_rng();
    let req_body = rng.gen_ascii_chars().take(100).collect::<String>();
    let resp = http::handle()
        .post(api::ECHO, &req_body)
        .header("Authorization", header.as_ref())
        .exec()
        .unwrap();
    let resp = str::from_utf8(resp.get_body()).unwrap();
    println!("echo response: {:?}", resp);
    let resp_body: &str = resp.as_ref();
    assert_eq!("", resp_body);
}

fn main() {
    let consumer = Token::new("key", "secret");
    println!("consumer: {:?}", consumer);

    let request = get_request_token(&consumer);
    println!("request: {:?}", request);

    let access = get_access_token(&consumer, &request);
    println!("access: {:?}", access);

    echo(&consumer, &access);

    println!("OK");
}

