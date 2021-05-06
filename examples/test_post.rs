// Copyright 2016 oauth-client-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(
    bad_style,
    unused,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

extern crate oauth_client as oauth;
extern crate rand;

use crate::oauth::Token;
use rand::{distributions::Alphanumeric, Rng};
use std::borrow::Cow;
use std::collections::HashMap;
use std::iter;

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
    let bytes = oauth::post(api::REQUEST_TOKEN, consumer, None, None).unwrap();
    let resp = String::from_utf8(bytes).unwrap();
    println!("get_request_token response: {:?}", resp);
    let param = split_query(&resp[..]);
    Token::new(
        param.get("oauth_token").unwrap().to_string(),
        param.get("oauth_token_secret").unwrap().to_string(),
    )
}

fn get_access_token(consumer: &Token, request: &Token) -> Token<'static> {
    let bytes = oauth::post(api::ACCESS_TOKEN, consumer, Some(request), None).unwrap();
    let resp = String::from_utf8(bytes).unwrap();
    println!("get_access_token response: {:?}", resp);
    let param = split_query(&resp[..]);
    Token::new(
        param.get("oauth_token").unwrap().to_string(),
        param.get("oauth_token_secret").unwrap().to_string(),
    )
}

fn echo(consumer: &Token, access: &Token) {
    let mut rng = rand::thread_rng();
    let mut req_param = HashMap::new();
    let _ = req_param.insert("testFOO".into(), "testFOO".into());
    for _ in 0..2 {
        let _ = req_param.insert(
            iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect(),
            iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect(),
        );
    }
    let bytes = oauth::post(api::ECHO, consumer, Some(access), Some(&req_param)).unwrap();
    let resp = String::from_utf8(bytes).unwrap();
    println!("echo response: {:?}", resp);
    let resp_param = split_query(&resp[..]);
    assert_eq!(req_param, resp_param);
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
