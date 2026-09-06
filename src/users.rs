use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Error;
use hyper::{header::HeaderValue, StatusCode};
use serde_json::Value;

use crate::client::{
    GenericRpcMethod, GenericRpcParams, RpcError, RpcMethod, RpcRequest, RpcResponse,
    METHOD_NOT_ALLOWED_ERROR_CODE, METHOD_NOT_ALLOWED_ERROR_MESSAGE, MISC_ERROR_CODE,
    PRUNE_ERROR_MESSAGE,
};
use crate::fetch_blocks::{fetch_block, fetch_block_raw};
use crate::rpc_methods::{
    DecodeRawTransaction, GetBlock, GetBlockHeader, GetBlockHeaderParams, GetBlockResult,
    GetRawTransaction,
};
use crate::state::State;

pub use password::Password;

pub mod input {
    use std::collections::{HashMap, HashSet};

    #[derive(Debug, serde::Deserialize)]
    pub struct User {
        pub password: super::Password,
        pub allowed_calls: Option<HashSet<String>>,
        #[serde(default)]
        pub fetch_blocks: Option<bool>,
        #[serde(default)]
        pub override_wallet: Option<String>,
    }

    impl User {
        fn map_default(self, default_fetch_blocks: bool) -> super::User {
            let wallet = self.override_wallet.map(|mut wallet| {
                wallet.insert_str(0, "/wallet/");
                wallet
            });
            super::User {
                password: self.password,
                allowed_calls: self.allowed_calls,
                fetch_blocks: self.fetch_blocks.unwrap_or(default_fetch_blocks),
                override_wallet: wallet,
            }
        }
    }

    pub fn map_default(users: HashMap<String, User>, default_fetch_blocks: bool) -> super::Users {
        super::Users(
            users
                .into_iter()
                .map(|(name, user)| (name, user.map_default(default_fetch_blocks)))
                .collect(),
        )
    }
}

mod password {
    use std::convert::TryFrom;
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::path::PathBuf;
    use std::sync::RwLock;
    use std::time::SystemTime;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // No `PartialEq` derive: `CookieFile` holds a lock, and comparing one
    // password to another is not something anything here does. The comparison
    // that matters is `PartialEq<&str>`, below.
    #[derive(serde::Deserialize)]
    #[serde(try_from = "String")]
    pub enum Password {
        Cleartext(String),
        Hash(String, Vec<u8>),
        /// The password half of a bitcoind cookie file, re-read whenever the
        /// file changes underneath us.
        ///
        /// bitcoind writes a fresh cookie every time it starts. Reading one at
        /// startup and holding it forever means that the moment the node
        /// restarts, the proxy is checking callers against a password that no
        /// longer exists and answering all of them 401. Nothing recovers from
        /// that on its own: a client can restart as often as it likes, because
        /// the stale half is here. That is a permanent outage for any dependent
        /// (electrs indexes nothing, and crash-loops) until somebody thinks to
        /// restart the proxy itself.
        CookieFile {
            path: PathBuf,
            cached: RwLock<Option<(SystemTime, String)>>,
        },
    }

    impl Password {
        /// The current password half of the cookie at `path`, reading the file
        /// only when its mtime has moved.
        ///
        /// A cookie is `user:password`, and only the password half is compared;
        /// the user half is the map key and does not change. Any failure to
        /// read is `None`, which fails the comparison and answers 401, exactly
        /// as a wrong password does. That is the right answer while the node is
        /// down and the file is missing.
        fn cookie_password(
            path: &PathBuf,
            cached: &RwLock<Option<(SystemTime, String)>>,
        ) -> Option<String> {
            let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
            if let (Some(mtime), Ok(guard)) = (mtime, cached.read()) {
                if let Some((seen, password)) = guard.as_ref() {
                    if *seen == mtime {
                        return Some(password.clone());
                    }
                }
            }
            let contents = std::fs::read_to_string(path).ok()?;
            let password = contents
                .trim_end_matches('\n')
                .split_once(':')?
                .1
                .to_owned();
            // Re-stat after reading rather than trusting the value from before
            // it: if the file changed in between, this caches the mtime of
            // contents we did not read and would then serve them until the next
            // change. Failing to stat just means no caching this time round.
            if let (Ok(mtime), Ok(mut guard)) = (
                std::fs::metadata(path).and_then(|m| m.modified()),
                cached.write(),
            ) {
                *guard = Some((mtime, password.clone()));
            }
            Some(password)
        }

        fn validate_str(string: &str) -> Result<(), InvalidPasswordError> {
            for (pos, byte) in string.bytes().enumerate() {
                if byte <= 0x1F || byte >= 0x7F {
                    return Err(InvalidPasswordError(InvalidPasswordErrorInner::BadChar {
                        pos,
                        byte,
                    }));
                }
            }
            Ok(())
        }
    }

    impl fmt::Debug for Password {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("Password(secret)")
        }
    }

    impl TryFrom<String> for Password {
        type Error = InvalidPasswordError;

        fn try_from(string: String) -> Result<Self, Self::Error> {
            Password::validate_str(&string)?;
            Ok(Password::Cleartext(string))
        }
    }

    impl TryFrom<&'_ str> for Password {
        type Error = InvalidPasswordError;

        fn try_from(string: &str) -> Result<Self, Self::Error> {
            Password::validate_str(string)?;
            Ok(Password::Cleartext(string.to_owned()))
        }
    }

    impl configure_me::parse_arg::ParseArg for Password {
        type Error = InvalidPasswordError;

        fn parse_arg(arg: &OsStr) -> Result<Self, Self::Error> {
            let string = arg
                .to_str()
                .ok_or(InvalidPasswordError(InvalidPasswordErrorInner::NonAscii))?;
            Password::validate_str(string)?;
            Ok(Password::Cleartext(string.to_owned()))
        }

        fn parse_owned_arg(arg: OsString) -> Result<Self, Self::Error> {
            let string = arg
                .into_string()
                .map_err(|_| InvalidPasswordError(InvalidPasswordErrorInner::NonAscii))?;
            Password::validate_str(&string)?;
            Ok(Password::Cleartext(string.to_owned()))
        }

        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("an ASCII string with no control characters")
        }
    }

    impl PartialEq<&'_ str> for Password {
        fn eq(&self, other: &&str) -> bool {
            // timing safe equality
            #[inline(never)]
            fn xor_contents(a: &[u8], b: &[u8]) -> usize {
                a.iter()
                    .enumerate()
                    .map(|(i, byte)| *byte ^ b[i % b.len()])
                    .fold(a.len() ^ b.len(), |acc, item| acc | usize::from(item))
            }

            match self {
                Self::Cleartext(pw) => {
                    if pw.is_empty() {
                        return other.is_empty();
                    }

                    let bits = xor_contents(pw.as_bytes(), other.as_bytes());
                    unsafe { std::ptr::read_volatile(&bits) == 0 }
                }
                Self::Hash(salt, hash) => (|| {
                    let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes())?;
                    mac.update(other.as_bytes());
                    if mac.finalize().into_bytes().as_slice() != &hash[..] {
                        Err(anyhow::anyhow!("password does not match"))
                    } else {
                        Ok(())
                    }
                })()
                .is_ok(),
                Self::CookieFile { path, cached } => {
                    match Password::cookie_password(path, cached) {
                        // Compared the same way as `Cleartext`, because that is
                        // what it is once read.
                        Some(pw) if !pw.is_empty() => {
                            let bits = xor_contents(pw.as_bytes(), other.as_bytes());
                            unsafe { std::ptr::read_volatile(&bits) == 0 }
                        }
                        Some(pw) => pw.is_empty() && other.is_empty(),
                        None => false,
                    }
                }
            }
        }
    }

    #[test]
    fn test_hash() {
        let salt = "eef909bebf93e7cd1d714af9c3daf1f1".to_owned();
        let hash = hex::decode("ff9123dfba51640705a0cd977faa98033f537f5930942b566b44639f8c63057b")
            .unwrap();
        assert_eq!(Password::Hash(salt, hash), "bar");
    }

    /// The cookie has to be followed, not copied.
    ///
    /// bitcoind writes a new one every time it starts, so a copy taken when the
    /// proxy started is wrong from the node's next restart onwards, and wrong in
    /// the direction that rejects every caller. Restarting the client does not
    /// help, because the stale half is on this side.
    #[test]
    fn a_cookie_password_follows_the_file() {
        use std::io::Write;
        use std::time::Duration;

        let path = std::env::temp_dir().join(format!(
            "btc-rpc-proxy-cookie-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // mtime is set explicitly rather than left to the clock, so the test
        // cannot flake when two writes land inside one filesystem timestamp
        // tick.
        let write = |contents: &str, when: SystemTime| {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(contents.as_bytes()).unwrap();
            f.sync_all().unwrap();
            f.set_modified(when).unwrap();
        };

        let t0 = SystemTime::now();
        write("__cookie__:first\n", t0);
        let pw = Password::CookieFile {
            path: path.clone(),
            cached: RwLock::new(None),
        };
        assert!(pw == "first", "reads the password half of the cookie");
        assert!(!(pw == "second"), "a wrong password does not match");
        assert!(
            !(pw == "__cookie__:first"),
            "the user half is not the password"
        );

        write("__cookie__:second\n", t0 + Duration::from_secs(5));
        assert!(pw == "second", "follows the file when the node replaces it");
        assert!(!(pw == "first"), "the cookie it replaced stops working");

        // While the node is down the cookie is gone, and nothing should match.
        std::fs::remove_file(&path).unwrap();
        assert!(!(pw == "second"), "a missing cookie matches no password");
    }

    #[derive(Debug, thiserror::Error)]
    enum InvalidPasswordErrorInner {
        #[error("invalid byte 0x{byte:02X} at position {pos}")]
        BadChar { pos: usize, byte: u8 },
        // non-utf-8 implies non-ascii
        #[error("not an ascii string")]
        NonAscii,
    }

    #[derive(Debug, thiserror::Error)]
    #[error(transparent)]
    pub struct InvalidPasswordError(InvalidPasswordErrorInner);
}

#[derive(Debug, serde::Deserialize)]
pub struct Users(pub HashMap<String, User>);
impl Users {
    pub fn get(&self, auth: &HeaderValue) -> Option<(String, &User)> {
        let header_str = auth.to_str().ok()?;
        let auth = header_str.strip_prefix("Basic ")?;
        let auth_decoded = base64::decode(auth).ok()?;
        let auth_decoded_str = std::str::from_utf8(&auth_decoded).ok()?;
        let (name, pass) = auth_decoded_str.split_once(":")?;
        self.0
            .get(name)
            .filter(|u| u.password == pass)
            .map(|u| (name.to_owned(), u))
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct User {
    pub password: Password,
    pub allowed_calls: Option<HashSet<String>>,
    #[serde(default)]
    pub fetch_blocks: bool,
    pub override_wallet: Option<String>,
}
impl User {
    pub async fn intercept<'a>(
        &self,
        state: Arc<State>,
        req: &'a RpcRequest<GenericRpcMethod>,
    ) -> Result<Option<RpcResponse<GenericRpcMethod>>, RpcError> {
        if self
            .allowed_calls
            .as_ref()
            .map_or(true, |ac| ac.contains(&*req.method))
        {
            match &req.params {
                GenericRpcParams::Array(params)
                    if self.fetch_blocks && &*req.method == GetBlock.as_str() =>
                // only non-verbose for now
                {
                    match params.get(1).unwrap_or(&1_u64.into()) {
                        Value::Number(ref n) if n.as_u64() == Some(0) => {
                            match fetch_block_raw(
                                state.clone(),
                                serde_json::from_value(params[0].clone()).map_err(Error::from)?,
                            )
                            .await
                            {
                                Ok(Some(block)) => Ok(Some(RpcResponse {
                                    id: req.id.clone(),
                                    result: Some(Value::String(hex::encode(&block))),
                                    error: None,
                                })),
                                Ok(None) => Ok(Some(RpcResponse {
                                    id: req.id.clone(),
                                    result: None,
                                    error: Some(RpcError {
                                        code: MISC_ERROR_CODE,
                                        message: PRUNE_ERROR_MESSAGE.to_owned(),
                                        status: None,
                                    }),
                                })),
                                Err(e) => Ok(Some(e.into())),
                            }
                        }
                        Value::Number(ref n) if n.as_u64() == Some(1) => {
                            let hash =
                                serde_json::from_value(params[0].clone()).map_err(Error::from)?;
                            let fetch_header_req = RpcRequest {
                                id: None,
                                method: GetBlockHeader,
                                params: GetBlockHeaderParams(hash, Some(true)),
                            };
                            match futures::try_join!(
                                async {
                                    state
                                        .rpc_client
                                        .call(&fetch_header_req)
                                        .await?
                                        .into_result()
                                },
                                async { fetch_block(state.clone(), hash).await }
                            ) {
                                Ok((header, Some(block))) => Ok(Some(RpcResponse {
                                    id: req.id.clone(),
                                    result: {
                                        let size = block.size();
                                        let strippedsize = block.strippedsize();
                                        Some(serde_json::to_value(GetBlockResult {
                                            header: header.into_right().ok_or_else(|| {
                                                anyhow::anyhow!(
                                                    "unexpected response for getblockheader"
                                                )
                                            })?,
                                            size,
                                            strippedsize: if strippedsize != size {
                                                Some(strippedsize)
                                            } else {
                                                None
                                            },
                                            weight: block.weight(),
                                            tx: block
                                                .txdata
                                                .into_iter()
                                                .map(|tx| tx.txid())
                                                .collect(),
                                        })?)
                                    },
                                    error: None,
                                })),
                                Ok((_, None)) => Ok(Some(RpcResponse {
                                    id: req.id.clone(),
                                    result: None,
                                    error: Some(RpcError {
                                        code: MISC_ERROR_CODE,
                                        message: PRUNE_ERROR_MESSAGE.to_owned(),
                                        status: None,
                                    }),
                                })),
                                Err(e) => Ok(Some(e.into())),
                            }
                        }
                        _ => Ok(None), // TODO
                    }
                }
                GenericRpcParams::Array(params)
                    if self.fetch_blocks && &*req.method == GetRawTransaction.as_str() =>
                {
                    self.intercept_raw_transaction(state, req, params).await
                }
                _ => Ok(None),
            }
        } else {
            Err(RpcError {
                code: METHOD_NOT_ALLOWED_ERROR_CODE,
                message: METHOD_NOT_ALLOWED_ERROR_MESSAGE.to_owned(),
                status: Some(StatusCode::FORBIDDEN),
            })
        }
    }

    /// `getrawtransaction "txid" ( verbose "blockhash" )` for a block bitcoind
    /// has pruned.
    ///
    /// **Only with a blockhash.** Core needs `txindex` to find a transaction
    /// without one, and the proxy has no txid index to substitute; a request
    /// that omits it is passed through so Core can answer or refuse on its own
    /// terms. With a blockhash Core needs only the block, which is exactly what
    /// this proxy can fetch from peers.
    ///
    /// This is what an Electrum server needs to serve a verbose transaction
    /// lookup on a pruned node: electrs finds the blockhash in its own index and
    /// passes it here.
    async fn intercept_raw_transaction<'a>(
        &self,
        state: Arc<State>,
        req: &'a RpcRequest<GenericRpcMethod>,
        params: &'a [Value],
    ) -> Result<Option<RpcResponse<GenericRpcMethod>>, RpcError> {
        let (txid, verbose, blockhash) = match interceptable(params) {
            Some(t) => t,
            None => return Ok(None),
        };

        let block = match fetch_block(state.clone(), blockhash).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                return Ok(Some(RpcResponse {
                    id: req.id.clone(),
                    result: None,
                    error: Some(RpcError {
                        code: MISC_ERROR_CODE,
                        message: PRUNE_ERROR_MESSAGE.to_owned(),
                        status: None,
                    }),
                }))
            }
            Err(e) => return Ok(Some(e.into())),
        };

        let tx = match block.txdata.iter().find(|tx| tx.txid() == txid) {
            Some(tx) => tx,
            // Core's own wording for this case, so a caller cannot tell the
            // difference between a proxied answer and a direct one.
            None => {
                return Ok(Some(RpcResponse {
                    id: req.id.clone(),
                    result: None,
                    error: Some(RpcError {
                        code: MISC_ERROR_CODE,
                        message: "No such transaction found in the provided block.".to_owned(),
                        status: None,
                    }),
                }))
            }
        };
        let hex = bitcoin::consensus::encode::serialize_hex(tx);

        if !verbose {
            return Ok(Some(RpcResponse {
                id: req.id.clone(),
                result: Some(Value::String(hex)),
                error: None,
            }));
        }

        // The nine fields decoderawtransaction returns are byte-identical to
        // verbose getrawtransaction's, script classification and addresses
        // included, so Core renders them rather than this reproducing them. The
        // six that remain come from the header, which Core keeps when pruned.
        let decode_req = RpcRequest {
            id: None,
            method: DecodeRawTransaction,
            params: (hex.clone(),),
        };
        let header_req = RpcRequest {
            id: None,
            method: GetBlockHeader,
            params: GetBlockHeaderParams(blockhash, Some(true)),
        };
        match futures::try_join!(
            async { state.rpc_client.call(&decode_req).await?.into_result() },
            async { state.rpc_client.call(&header_req).await?.into_result() },
        ) {
            Ok((mut decoded, header)) => {
                let header = match header.into_right() {
                    Some(h) => h,
                    None => {
                        return Ok(Some(
                            RpcError::from(Error::msg("unexpected response for getblockheader"))
                                .into(),
                        ))
                    }
                };
                // For a block off the main chain Core answers
                // `in_active_chain: false` with `confirmations: 0`, and omits
                // `time` and `blocktime` entirely.
                let in_active_chain = header.confirmations >= 0;
                if let Some(obj) = decoded.as_object_mut() {
                    obj.insert("in_active_chain".to_owned(), Value::Bool(in_active_chain));
                    obj.insert("hex".to_owned(), Value::String(hex));
                    obj.insert("blockhash".to_owned(), serde_json::json!(blockhash));
                    obj.insert(
                        "confirmations".to_owned(),
                        serde_json::json!(if in_active_chain {
                            header.confirmations
                        } else {
                            0
                        }),
                    );
                    if in_active_chain {
                        obj.insert("time".to_owned(), serde_json::json!(header.time));
                        obj.insert("blocktime".to_owned(), serde_json::json!(header.time));
                    }
                }
                Ok(Some(RpcResponse {
                    id: req.id.clone(),
                    result: Some(decoded),
                    error: None,
                }))
            }
            Err(e) => Ok(Some(e.into())),
        }
    }
}

/// Whether a `getrawtransaction` call is one this proxy can answer, and its
/// arguments if so.
///
/// `None` means pass it through to Core untouched, which is the right answer
/// for everything the proxy cannot improve on:
///
/// - **no blockhash**: Core needs `txindex` to find the transaction, and the
///   proxy has no txid index to substitute for one
/// - **verbosity 2**: wants prevout data, which needs the undo files a pruned
///   node has also discarded
/// - **anything malformed**: Core writes better argument errors than this would
fn interceptable(params: &[Value]) -> Option<(bitcoin::Txid, bool, bitcoin::BlockHash)> {
    let blockhash = serde_json::from_value(params.get(2)?.clone()).ok()?;
    let verbose = match params.get(1) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        // Core accepts 0 and 1 for the boolean, and 2 for a form this cannot serve.
        Some(Value::Number(n)) if n.as_u64() == Some(0) => false,
        Some(Value::Number(n)) if n.as_u64() == Some(1) => true,
        _ => return None,
    };
    let txid = serde_json::from_value(params.first()?.clone()).ok()?;
    Some((txid, verbose, blockhash))
}

#[cfg(test)]
mod raw_transaction_tests {
    use super::interceptable;
    use serde_json::json;

    const TXID: &str = "780124042ee6e11fc3eeceec7d3b27379d71c4901e18d516ed1491eba025ba85";
    const HASH: &str = "60facf42231c33113d9bd67062d2ec290604458937db0fa0d0c13f2c074e9344";

    /// The form electrs sends, which is the whole reason this exists.
    #[test]
    fn verbose_with_a_blockhash_is_intercepted() {
        let (txid, verbose, blockhash) =
            interceptable(&[json!(TXID), json!(true), json!(HASH)]).expect("should intercept");
        assert_eq!(txid.to_string(), TXID);
        assert_eq!(blockhash.to_string(), HASH);
        assert!(verbose);
    }

    #[test]
    fn non_verbose_with_a_blockhash_is_intercepted() {
        let (_, verbose, _) =
            interceptable(&[json!(TXID), json!(false), json!(HASH)]).expect("should intercept");
        assert!(!verbose);
    }

    /// Core takes 0 and 1 as well as false and true.
    #[test]
    fn numeric_verbosity_zero_and_one_are_intercepted() {
        assert!(
            !interceptable(&[json!(TXID), json!(0), json!(HASH)])
                .unwrap()
                .1
        );
        assert!(
            interceptable(&[json!(TXID), json!(1), json!(HASH)])
                .unwrap()
                .1
        );
    }

    /// Without a blockhash there is nothing to fetch: Core needs txindex and the
    /// proxy has no index of its own. Passing through lets Core say so.
    #[test]
    fn no_blockhash_passes_through() {
        assert!(interceptable(&[json!(TXID), json!(true)]).is_none());
        assert!(interceptable(&[json!(TXID)]).is_none());
    }

    /// Verbosity 2 asks for prevouts, which need undo data a pruned node has
    /// also discarded. Answering it without them would be answering wrongly.
    #[test]
    fn verbosity_two_passes_through() {
        assert!(interceptable(&[json!(TXID), json!(2), json!(HASH)]).is_none());
    }

    #[test]
    fn malformed_arguments_pass_through() {
        assert!(interceptable(&[json!(TXID), json!("yes"), json!(HASH)]).is_none());
        assert!(interceptable(&[json!(TXID), json!(true), json!("not a hash")]).is_none());
        assert!(interceptable(&[json!("not a txid"), json!(true), json!(HASH)]).is_none());
        assert!(interceptable(&[]).is_none());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::convert::TryInto;

    fn check(input: Option<bool>, default: bool, expected: bool) {
        let mut users = HashMap::new();
        users.insert(
            "satoshi".to_owned(),
            super::input::User {
                password: "secret".try_into().expect("failed to create password"),
                allowed_calls: Some(HashSet::new()),
                fetch_blocks: input,
                override_wallet: None,
            },
        );

        let result = super::input::map_default(users, default);
        assert_eq!(result.0["satoshi"].fetch_blocks, expected);
    }

    #[test]
    fn default_fetch_blocks_none_false() {
        check(None, false, false);
    }

    #[test]
    fn default_fetch_blocks_none_true() {
        check(None, true, true);
    }

    #[test]
    fn default_fetch_blocks_some_false_false() {
        check(Some(false), false, false);
    }

    #[test]
    fn default_fetch_blocks_some_false_true() {
        check(Some(false), true, false);
    }

    #[test]
    fn default_fetch_blocks_some_true_false() {
        check(Some(true), false, true);
    }

    #[test]
    fn default_fetch_blocks_some_true_true() {
        check(Some(true), true, true);
    }
}
