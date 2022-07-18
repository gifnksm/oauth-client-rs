# oauth-client-rs

[![maintenance status: passively-maintained](https://img.shields.io/badge/maintenance-passively--maintained-yellowgreen.svg)](https://doc.rust-lang.org/cargo/reference/manifest.html#the-badges-section)
[![license](https://img.shields.io/crates/l/oauth-client.svg)](#license)
[![crates.io](https://img.shields.io/crates/v/oauth-client.svg)](https://crates.io/crates/oauth-client)
[![docs.rs](https://img.shields.io/docsrs/oauth-client/latest)](https://docs.rs/oauth-client/latest/)
[![rust 1.57.0+ badge](https://img.shields.io/badge/rust-1.57.0+-93450a.svg)](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)
[![Rust CI](https://github.com/gifnksm/oauth-client-rs/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/gifnksm/oauth-client-rs/actions/workflows/rust-ci.yml)
[![codecov](https://codecov.io/gh/gifnksm/oauth-client-rs/branch/master/graph/badge.svg?token=bFNgEBUdSx)](https://codecov.io/gh/gifnksm/oauth-client-rs)

OAuth client for Rust

[Documentation](https://docs.rs/oauth-client/)

## How to use?

Add this to your `Cargo.toml`:

```toml
[dependencies]
oauth-client = "0.6"
```

See [examples](./examples).

## Minimum supported Rust version (MSRV)

The minimum supported Rust version is **Rust 1.57.0**.
At least the last 3 versions of stable Rust are supported at any given time.

While a crate is pre-release status (0.x.x) it may have its MSRV bumped in a patch release.
Once a crate has reached 1.x, any MSRV bump will be accompanied with a new minor version.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
