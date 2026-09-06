use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use btc_rpc_proxy::users::Password;
use btc_rpc_proxy::{AuthSource, BlockCache, Peers, RpcClient, State, TorState};
use slog::Drain;
use systemd_socket::SocketAddr;
use tokio::sync::{OnceCell, RwLock};

mod config {
    include!(concat!(env!("OUT_DIR"), "/configure_me_config.rs"));
}
use self::config::{Config, ResultExt};

pub fn create_state() -> Result<(State, SocketAddr), Error> {
    use slog::Level;

    let (config, _) =
        Config::including_optional_config_files(std::iter::empty::<&str>()).unwrap_or_exit();

    let log_level = match config.verbose {
        0 => Level::Critical,
        1 => Level::Error,
        2 => Level::Warning,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    };

    let decorator = slog_term::TermDecorator::new().stderr().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .build()
        .filter_level(log_level)
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!());

    let auth = AuthSource::from_config(
        config.bitcoind_user,
        config.bitcoind_password,
        config.cookie_file,
    )?;
    let bitcoin_uri = format!(
        "http://{}:{}/",
        config.bitcoind_address, config.bitcoind_port
    )
    .parse()
    .map_err(|error: http::uri::InvalidUri| {
        let msg = "failed to parse bitcoin URI";
        let new_error = anyhow::anyhow!("{}: {}", msg, error);
        slog::error!(logger, "{}", msg; "error" => #error);
        new_error
    })?;
    let rpc_client = RpcClient::new(auth, bitcoin_uri, &logger);

    let tor_only = config.tor_only;
    let tor = config.tor_proxy.map(|proxy| TorState {
        proxy,
        only: tor_only,
    });

    // not const/static because from() is not const
    let default_bind_address = std::net::IpAddr::from([127, 0, 0, 1]);
    // for consistency
    let default_bind_port = 8331;

    let bind_addr = match (
        config.bind_address,
        config.bind_port,
        config.bind_systemd_socket_name,
    ) {
        (Some(addr), Some(port), None) => (addr, port).into(),
        (None, Some(port), None) => (default_bind_address, port).into(),
        (Some(addr), None, None) => (addr, default_bind_port).into(),
        (None, None, None) => (default_bind_address, default_bind_port).into(),
        (None, None, Some(socket_name)) => {
            SocketAddr::from_systemd_name(socket_name).map_err(|error| {
                let msg = "failed to parse systemd socket name";
                let new_error = anyhow::anyhow!("{}: {}", msg, error);
                slog::error!(logger, "{}", msg; "error" => #error);
                new_error
            })?
        }
        _ => {
            let msg = "bind_systemd_socket_name can NOT be specified when bind_address or bind_port is specified";
            slog::error!(logger, "{}", msg);
            anyhow::bail!("{}", msg)
        }
    };

    let mut users = config.user;
    if let Some(conf) = config.passthrough_rpcauth {
        for line in std::fs::read_to_string(conf)?.lines() {
            if let Some((uname, (salt, hash))) = line
                .trim()
                .strip_prefix("rpcauth=")
                .and_then(|tok| tok.trim().split_once(":"))
                .and_then(|(uname, pass)| Some((uname, pass.split_once("$")?)))
            {
                users.insert(
                    uname.into(),
                    btc_rpc_proxy::users::input::User {
                        allowed_calls: None,
                        password: Password::Hash(salt.to_owned(), hex::decode(hash)?),
                        fetch_blocks: None,
                        override_wallet: None,
                    },
                );
            }
        }
    }
    if let Some(conf) = config.passthrough_rpccookie {
        // Only the user half is taken now. It is the map key, and bitcoind
        // always writes the same one (`__cookie__`). The password half is read
        // from the file at comparison time instead of being copied in here,
        // because bitcoind replaces the whole cookie every time it starts: a
        // copy taken now is wrong from the node's next restart onwards, and
        // wrong in the way that answers every caller 401 forever.
        for line in std::fs::read_to_string(&conf)?.lines() {
            if let Some((uname, _)) = line.trim().split_once(":") {
                users.insert(
                    uname.into(),
                    btc_rpc_proxy::users::input::User {
                        allowed_calls: None,
                        password: Password::CookieFile {
                            path: conf.clone(),
                            cached: std::sync::RwLock::new(None),
                        },
                        fetch_blocks: None,
                        override_wallet: None,
                    },
                );
            }
        }
    }

    Ok((
        State {
            rpc_client,
            tor,
            i2p_proxy: config.i2p_proxy,
            users: btc_rpc_proxy::users::input::map_default(users, config.default_fetch_blocks),
            logger,
            peer_timeout: Duration::from_secs(config.peer_timeout),
            peers: RwLock::new(Arc::new(Peers::new())),
            max_peer_age: Duration::from_secs(config.max_peer_age),
            max_peer_concurrency: config.max_peer_concurrency,
            network: OnceCell::new(),
            // Saturating, because a nonsense value here would otherwise wrap:
            // in release that silently yields a tiny cache, and in debug it
            // panics at startup. Saturating gives "as much as this machine
            // could address", which is the honest reading of an absurd number.
            block_cache: BlockCache::new(config.block_cache_size_mib.saturating_mul(1024 * 1024)),
        },
        bind_addr,
    ))
}
