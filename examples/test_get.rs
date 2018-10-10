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

extern crate futures;
extern crate oauth_client as oauth;
extern crate rand;
extern crate tokio_core;

use futures::Future;
use oauth::Token;
use rand::{distributions::Alphanumeric, Rng};
use std::borrow::Cow;
use std::collections::HashMap;
use std::iter;
use tokio_core::reactor::Core;

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

fn get_request_token(consumer: &Token) -> impl Future<Item = Token<'static>, Error = ()> {
    oauth::get(api::REQUEST_TOKEN, consumer, None, None)
        .map_err(|_| ())
        .map(|bytes| {
            let resp = String::from_utf8(bytes).unwrap();
            println!("get_request_token response: {:?}", resp);
            let param = split_query(&resp);

            Token::new(
                param.get("oauth_token").unwrap().to_string(),
                param.get("oauth_token_secret").unwrap().to_string(),
            )
        })
}

fn get_access_token(
    consumer: &Token,
    request: &Token,
) -> impl Future<Item = Token<'static>, Error = ()> {
    oauth::get(api::ACCESS_TOKEN, consumer, Some(request), None)
        .map_err(|_| ())
        .map(|bytes| {
            let resp = String::from_utf8(bytes).unwrap();
            println!("get_access_token response: {:?}", resp);
            let param = split_query(&resp);

            Token::new(
                param.get("oauth_token").unwrap().to_string(),
                param.get("oauth_token_secret").unwrap().to_string(),
            )
        })
}

fn echo(consumer: &Token, access: &Token) -> impl Future<Item = (), Error = ()> {
    let mut rng = rand::thread_rng();
    let mut req_param = HashMap::new();
    let _ = req_param.insert("testFOO".into(), "testFOO".into());
    for _ in 0..2 {
        let _ = req_param.insert(
            iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .take(32)
                .collect(),
            iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .take(32)
                .collect(),
        );
    }
    oauth::get(api::ECHO, consumer, Some(access), Some(&req_param))
        .map_err(|_| ())
        .map(move |bytes| {
            let req_param = req_param.clone();
            let resp = String::from_utf8(bytes).unwrap();
            println!("echo response: {:?}", resp);
            let resp_param = split_query(&resp);
            assert_eq!(req_param, resp_param);
        })
}

fn main() {
    let mut core = Core::new().unwrap();

    let consumer = Token::new("key", "secret");
    println!("consumer: {:?}", consumer);

    let request = core.run(get_request_token(&consumer)).unwrap();
    println!("request: {:?}", request);

    let access = core.run(get_access_token(&consumer, &request)).unwrap();
    println!("access: {:?}", access);

    core.run(echo(&consumer, &access)).unwrap();

    println!("OK");
}
