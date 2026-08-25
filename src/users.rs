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
use crate::rpc_methods::{GetBlock, GetBlockHeader, GetBlockHeaderParams, GetBlockResult};
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

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[derive(PartialEq, serde::Deserialize)]
    #[serde(try_from = "String")]
    pub enum Password {
        Cleartext(String),
        Hash(String, Vec<u8>),
    }

    impl Password {
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
