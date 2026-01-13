# Rustls - Reality Protocol Edition

[![Build Status](https://github.com/rustls/rustls/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/rustls/actions/workflows/build.yml?query=branch%3Amain)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **⚠️ ATTENTION:** This is a **modified fork** of Rustls, specifically patched to support the **Reality Protocol** (Xray-core).  
> **⚠️ 注意:** 这是 Rustls 的**魔改版本**，专为 **Reality 协议** (Xray-core) 添加了底层支持。

It exposes internal handshake states and injects authentication logic into the TLS 1.3 server hello stage, enabling "Man-in-the-Middle" style key exchange required by Reality.

**Do NOT use this crate for general-purpose TLS applications.** Please use the official [rustls](https://github.com/rustls/rustls) crate instead.

---

## ✨ Key Modifications / 主要修改

1.  **Handshake Injection**: Exposes hooks in `ServerHello` generation to inject Reality authentication data into the `server_random` field.
2.  **State Exposure**: Exposes internal `ActiveCertifiedKey` and handshake transcript states to allow external manipulation.
3.  **Low-Level Access**: Added `dangerous_configuration` features to bypass certain safety checks required for proxy protocol implementation.
4.  **Renamed Package**: The crate is renamed to `rustls-reality` to avoid conflicts with the official `rustls` crate in dependency trees.

## 📦 Usage / 使用方法

In your `Cargo.toml`:

```toml
[dependencies]
rustls = { git = "https://github.com/undead-undead/rustls-reality.git", package = "rustls-reality", features = ["dangerous_configuration"] }
```

## 🔗 Related Projects

- **[Xray-Lite](https://github.com/undead-undead/xray-lite)**: The lightweight proxy server that utilizes this library.
- **[Xray-core](https://github.com/XTLS/Xray-core)**: The original implementation of the Reality protocol.

---

## Original Rustls Documentation

*Below is the original README from the official Rustls project.*

# Rustls: a modern TLS library in Rust

Rustls is a TLS library that aims to provide a good level of cryptographic security, requires no configuration to achieve that security, and provides no unsafe features or obsolete cryptography by default.

## Current functionality (with default crate features)

* TLS1.2 and TLS1.3.
* ECDSA, Ed25519 or RSA server authentication by clients.
* ECDSA, Ed25519 or RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* ChaCha20-Poly1305 bulk encryption ([RFC7905](https://tools.ietf.org/html/rfc7905)).
* ALPN support.
* SNI support.
* Tunable fragment size to make TLS messages match size of underlying transport.
* Optional use of vectored IO to minimise system calls.
* TLS1.2 session resumption.
* TLS1.2 resumption via tickets ([RFC5077](https://tools.ietf.org/html/rfc5077)).
* TLS1.3 resumption via tickets or session storage.
* TLS1.3 0-RTT data for clients.
* TLS1.3 0-RTT data for servers.
* Client authentication by clients.
* Client authentication by servers.
* Extended master secret support ([RFC7627](https://tools.ietf.org/html/rfc7627)).
* Exporters ([RFC5705](https://tools.ietf.org/html/rfc5705)).
* OCSP stapling by servers.

## License

Rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC respectively. You may use this software under the terms of any of these licenses, at your option.
