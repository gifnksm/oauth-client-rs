#![warn(bad_style,
        unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]

extern crate oauth_client as oauth;
extern crate rand;

use std::borrow::Cow;
use std::collections::HashMap;
use oauth::Token;
use rand::Rng;

mod api {
    pub const REQUEST_TOKEN: &'static str = "http://oauthbin.com/v1/request-token";
    pub const ACCESS_TOKEN: &'static str = "http://oauthbin.com/v1/access-token";
    pub const ECHO: &'static str = "http://oauthbin.com/v1/echo";
}

fn split_query<'a>(query: &'a str) -> HashMap<Cow<'a, str>, Cow<'a, str>> {
    let mut param = HashMap::new();
    for q in query.split('&') {
        let mut s = q.splitn(2, '=');
        let k = s.next().unwrap();
        let v = s.next().unwrap();
        let _ = param.insert(k.into(), v.into());
    }
    param
}

fn get_request_token(consumer: &Token) -> Token<'static> {
    let resp = oauth::get(api::REQUEST_TOKEN, consumer, None, None);
    println!("get_request_token response: {:?}", resp);
    let param = split_query(&resp);
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn get_access_token(consumer: &Token, request: &Token) -> Token<'static> {
    let resp = oauth::get(api::ACCESS_TOKEN, consumer, Some(request), None);
    println!("get_access_token response: {:?}", resp);
    let param = split_query(&resp);
    Token::new(param.get("oauth_token").unwrap().to_string(),
               param.get("oauth_token_secret").unwrap().to_string())
}

fn echo(consumer: &Token, access: &Token) {
    let mut rng = rand::thread_rng();
    let mut req_param = HashMap::new();
    let _ = req_param.insert("testFOO".into(), "testFOO".into());
    let _ = req_param.insert(rng.gen_ascii_chars().take(32).collect::<String>().into(),
                             rng.gen_ascii_chars().take(32).collect::<String>().into());
    let _ = req_param.insert(rng.gen_ascii_chars().take(32).collect::<String>().into(),
                             rng.gen_ascii_chars().take(32).collect::<String>().into());
    let resp = oauth::get(api::ECHO, consumer, Some(access), Some(&req_param));
    println!("echo response: {:?}", resp);
    // let resp_param = split_query(&resp);
    // assert_eq!(req_param, resp_param);
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
