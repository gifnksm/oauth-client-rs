use oauth_client::{RequestBuildah, Token};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client, Method, RequestBuilder,
};
use std::convert::TryFrom;
use std::error::Error;

mod api {
    pub const REQUEST_TOKEN: &str = "http://oauthbin.com/v1/request-token";
}

pub struct AsyncRequestBuilder {
    inner: RequestBuilder,
}

impl RequestBuildah for AsyncRequestBuilder {
    type Error = reqwest::Error;
    type ReturnValue = tokio::task::JoinHandle<Result<String, Self::Error>>;
    type ClientBuilder = Client;

    fn new(method: Method, url: &'_ str, client: &Self::ClientBuilder) -> Self {
        Self {
            inner: client.clone().request(method, url),
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
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header(key, val);

        self
    }

    fn send(self) -> Result<Self::ReturnValue, Self::Error> {
        Ok(tokio::spawn(async {
            Ok(self.inner.send().await?.error_for_status()?.text().await?)
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let consumer = Token::new("key", "secret");
    let client = reqwest::Client::new();
    let resp = oauth_client::get::<AsyncRequestBuilder>(
        api::REQUEST_TOKEN,
        &consumer,
        None,
        None,
        &client,
    )?
    .await??;

    println!("Response: {:#?}", resp);

    Ok(())
}
