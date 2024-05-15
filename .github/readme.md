<h1 align="center">Bitcoin RPC Proxy<br />
<div align="center">
<a href="https://github.com/dobtc/btc-rpc-proxy"><img src="https://raw.githubusercontent.com/dobtc/btc-rpc-proxy/master/.github/logo.png" title="Logo" style="max-width:100%;" width="128" /></a>
</div>
<div align="center">
  
[![Build]][build_url]
[![Version]][tag_url]
[![Size]][tag_url]
[![Pulls]][hub_url]

</div></h1>

Finer-grained permission management for bitcoind.

## How to use

Via Docker Compose:

```yaml
services:
  rpc-proxy:
    container_name: rpc-proxy
    image: dobtc/btc-rpc-proxy
    ports:
      - 8331:8331
    volumes:
      - /path/to/config/btc_rpc_proxy.toml:/etc/btc_rpc_proxy.toml
```

## About

This is a proxy made specifically for `bitcoind` to allow finer-grained control of permissions. It enables you to specify several users and for each user the list of RPC calls they are allowed to make. When run against a prunded node, the proxy will perform on-demand block fetching and verification, enabling features of a non-pruned node while still using a pruned node.

### Fine-grained permission management

This is useful because `bitcoind` allows every application with password to make possibly harmful calls like stopping the daemon or spending from wallet (if enabled). If you have several applications, you can provide the less trusted ones a different password and permissions than the others using this project.

There's another interesting advantage: since this is written in Rust, it might serve as a filter for **some** malformed requests which might be exploits. But I don't recommend relying on it!

### On-demand block fetching

By connecting to your pruned Bitcoin node through Bitcoin Proxy, your node will now behave as though it is not pruned. If a user or application requires a block that is not retained by your pruned node, Bitcoin Proxy will dynamically fetch the block over the P2P network, then verify its hash against your node to ensure validity.

This means that you can run multiple services against your _pruned_ Bitcoin node — such as Lightning and BTCPay — without them fighting for control over the pruning. Both are happy because both believe they are dealing with an _unpruned_ node.

A tradeoff to the proxy is speed and bandwidth. Every time the proxy needs to fetch a block not retained by your pruned node, it must reach out over the P2P network, consuming both Internet bandwidth and time.

## Usage

For security and performance reasons this application is written in Rust. Thus, you need a recent Rust compiler to compile it.

You need to configure the proxy using config files. You can specify their paths using `--conf /path/to/file.toml` or `--conf-dir /path/to/config/dir`. **Make sure to set their permissions to `600` before you write the passwords to them!** If `--conf-dir` is used, all files in that directory will be loaded and merged. You can use `--conf` multiple times. This is useful to organize your configuration (e.g. put sensitive information into a separate file).

An example configuration file is provided in this repository, hopefuly it's understandable. After configuring, you only need to run the compiled binary (e.g. using `cargo run --release -- --conf btc_rpc_proxy.toml`)

A man page can be generated using [`cfg_me`](https://crates.io/crates/cfg_me) and `--help` option is provided.

### Systemd integration

Using socket activation enables you to delay the start of `btc-rpc-proxy` until it's actually needed or start it in parallel with its clients leading to faster boot times.

Systemd socket activation is configured using `bind_systemd_socket_name` option.
Setting it to a valid socket name will cause `btc-rpc-proxy` to use systemd socket activation using the socket with the specified socket name.

This feature is only available for Linux and only if the `systemd` feature is enabled. (Enabled by default.)
Disabling it can decrease compile time and binary size but please keep it enabled if you intend to distribute the binary so that the users can benefit from it.
Especially in case of packaged software.

## Limitations

* It uses `serde_json`, which allocates during deserialization (`Value`). Expect a bit lower performance than without proxy.
* Logging can't be configured yet.
* No support for changing UID.
* No support for Unix sockets.
* Redirect instead of blocking might be a useful feaure, which is now lacking.

## Stars
[![Stars](https://starchart.cc/dobtc/btc-rpc-proxy.svg?variant=adaptive)](https://starchart.cc/dobtc/btc-rpc-proxy)

[build_url]: https://github.com/dobtc/btc-rpc-proxy/
[hub_url]: https://hub.docker.com/r/dobtc/btc-rpc-proxy/
[tag_url]: https://hub.docker.com/r/dobtc/btc-rpc-proxy/tags

[Build]: https://github.com/dobtc/btc-rpc-proxy/actions/workflows/build.yml/badge.svg
[Size]: https://img.shields.io/docker/image-size/dobtc/btc-rpc-proxy/latest?color=066da5&label=size
[Pulls]: https://img.shields.io/docker/pulls/dobtc/btc-rpc-proxy.svg?style=flat&label=pulls&logo=docker
[Version]: https://img.shields.io/docker/v/dobtc/btc-rpc-proxy/latest?arch=amd64&sort=semver&color=066da5
