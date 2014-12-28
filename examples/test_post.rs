#![warn(bad_style,
        unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, unused_typecasts)]

#![feature(phase)]

extern crate "oauth-client" as oauth;

use std::collections::HashMap;
use std::str::CowString;
use std::rand::{Rng, OsRng};
use oauth::Token;

mod api {
    pub const REQUEST_TOKEN: &'static str = "http://term.ie/oauth/example/request_token.php";
    pub const ACCESS_TOKEN: &'static str = "http://term.ie/oauth/example/access_token.php";
    pub const ECHO: &'static str = "http://term.ie/oauth/example/echo_api.php";
}

fn split_query<'a>(query: &'a str) -> HashMap<CowString<'a>, CowString<'a>> {
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
    let resp = oauth::post(api::REQUEST_TOKEN, consumer, None, None);
    println!("get_request_token response: {}", resp);
    let param = split_query(resp.as_slice());
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn get_access_token(consumer: &Token, request: &Token) -> Token<'static> {
    let resp = oauth::post(api::ACCESS_TOKEN, consumer, Some(request), None);
    println!("get_access_token response: {}", resp);
    let param = split_query(resp.as_slice());
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn echo(consumer: &Token, access: &Token) {
    let mut rng = OsRng::new().unwrap();
    let mut req_param = HashMap::new();
    let _ = req_param.insert("testFOO".into_cow(), "testFOO".into_cow());
    let _ = req_param.insert(rng.gen_ascii_chars().take(32).collect::<String>().into_cow(),
                             rng.gen_ascii_chars().take(32).collect::<String>().into_cow());
    let _ = req_param.insert(rng.gen_ascii_chars().take(32).collect::<String>().into_cow(),
                             rng.gen_ascii_chars().take(32).collect::<String>().into_cow());
    let resp = oauth::post(api::ECHO, consumer, Some(access), Some(&req_param));
    println!("echo response: {}", resp);
    let resp_param = split_query(resp.as_slice());
    assert_eq!(req_param, resp_param);
}

fn main() {
    let consumer = Token::new("key", "secret");
    println!("consumer: {}", consumer);

    let request = get_request_token(&consumer);
    println!("request: {}", request);

    let access = get_access_token(&consumer, &request);
    println!("access: {}", access);

    echo(&consumer, &access);

    println!("OK");
}

