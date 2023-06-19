use std::path::PathBuf;

use color_eyre::eyre::Error;
use hyper::{
    body::to_bytes,
    client::{Client, HttpConnector},
    header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH},
    Body, Method, Request, Response, StatusCode, Uri,
};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use serde_json::{Map, Value};

pub const MISC_ERROR_CODE: i64 = -1;
pub const METHOD_NOT_ALLOWED_ERROR_CODE: i64 = -32604;
pub const PARSE_ERROR_CODE: i64 = -32700;
pub const METHOD_NOT_ALLOWED_ERROR_MESSAGE: &'static str = "Method not allowed";
pub const PRUNE_ERROR_MESSAGE: &'static str = "Block not available (pruned data)";

type HttpClient = Client<HttpConnector>;

#[derive(Debug)]
pub enum SingleOrBatchRpcRequest {
    Single(RpcRequest<GenericRpcMethod>),
    Batch(Vec<RpcRequest<GenericRpcMethod>>),
}
impl Serialize for SingleOrBatchRpcRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            SingleOrBatchRpcRequest::Single(s) => s.serialize(serializer),
            SingleOrBatchRpcRequest::Batch(b) => b.serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for SingleOrBatchRpcRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SingleOrBatchRpcRequest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a single rpc request, or a batch of rpc requests"
                )
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut res = Vec::with_capacity(seq.size_hint().unwrap_or(16));
                while let Some(elem) = seq.next_element()? {
                    res.push(elem);
                }
                Ok(SingleOrBatchRpcRequest::Batch(res))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut id = None;
                let mut method = None;
                let mut params = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "id" => {
                            id = map.next_value()?;
                        }
                        "method" => {
                            method = map.next_value()?;
                        }
                        "params" => {
                            params = map.next_value()?;
                        }
                        _ => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }
                Ok(SingleOrBatchRpcRequest::Single(RpcRequest {
                    id,
                    method: method.ok_or_else(|| serde::de::Error::missing_field("method"))?,
                    params: params.ok_or_else(|| serde::de::Error::missing_field("params"))?,
                }))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

pub trait RpcMethod {
    type Params: Serialize + for<'de> Deserialize<'de>;
    type Response: Serialize + for<'de> Deserialize<'de>;
    fn as_str<'a>(&'a self) -> &'a str;
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GenericRpcMethod(pub String);

#[derive(Debug)]
pub enum GenericRpcParams {
    Array(Vec<Value>),
    Object(Map<String, Value>),
}
impl Serialize for GenericRpcParams {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            GenericRpcParams::Array(s) => s.serialize(serializer),
            GenericRpcParams::Object(b) => b.serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for GenericRpcParams {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = GenericRpcParams;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array or object")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut res = Vec::with_capacity(seq.size_hint().unwrap_or(16));
                while let Some(elem) = seq.next_element()? {
                    res.push(elem);
                }
                Ok(GenericRpcParams::Array(res))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut res = Map::with_capacity(map.size_hint().unwrap_or(16));
                while let Some((k, v)) = map.next_entry()? {
                    res.insert(k, v);
                }
                Ok(GenericRpcParams::Object(res))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl RpcMethod for GenericRpcMethod {
    type Params = GenericRpcParams;
    type Response = Value;
    fn as_str<'a>(&'a self) -> &'a str {
        self.0.as_str()
    }
}

impl std::ops::Deref for GenericRpcMethod {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RpcRequest<T: RpcMethod> {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: T,
    pub params: T::Params,
}

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[error("bitcoin RPC failed with code {code}, message: {message}")]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip)]
    pub status: Option<StatusCode>,
}
impl From<Error> for RpcError {
    fn from(e: Error) -> Self {
        RpcError {
            code: MISC_ERROR_CODE,
            message: format!("{}", e),
            status: None,
        }
    }
}
impl From<serde_json::Error> for RpcError {
    fn from(e: serde_json::Error) -> Self {
        RpcError {
            code: PARSE_ERROR_CODE,
            message: format!("{}", e),
            status: None,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RpcResponse<T: RpcMethod> {
    pub id: Option<Value>,
    pub error: Option<RpcError>,
    pub result: Option<T::Response>,
}
impl From<RpcError> for RpcResponse<GenericRpcMethod> {
    fn from(e: RpcError) -> Self {
        RpcResponse {
            id: None,
            error: Some(e),
            result: None,
        }
    }
}
impl<T: RpcMethod> RpcResponse<T> {
    pub fn into_result(self) -> Result<T::Response, RpcError> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(self.result).transpose().unwrap_or_else(|| {
                serde_json::from_value(Value::Null)
                    .map_err(Error::from)
                    .map_err(RpcError::from)
            }),
        }
    }
    pub fn into_response(mut self) -> Result<Response<Body>, Error> {
        let body = serde_json::to_vec(&self)?;
        Ok(Response::builder()
            .status(match self.error.as_mut().and_then(|e| e.status.take()) {
                Some(s) => s,
                None if self.error.is_some() => StatusCode::INTERNAL_SERVER_ERROR,
                None => StatusCode::OK,
            })
            .header(CONTENT_LENGTH, body.len())
            .body(body.into())?)
    }
}

#[derive(Debug)]
pub struct RpcClient {
    uri: Uri,
    client: HttpClient,
}
impl RpcClient {
    pub fn new(uri: Uri) -> Self {
        RpcClient {
            uri,
            client: HttpClient::new(),
        }
    }
    pub async fn send(&self, mut req: Request<Body>) -> Result<Response<Body>, ClientError> {
        let mut new_uri = self.uri.clone().into_parts();
        new_uri.path_and_query = req.uri().path_and_query().cloned();
        *req.uri_mut() = Uri::from_parts(new_uri).map_err(http::Error::from)?;
        Ok(self.client.request(req).await?)
    }
    pub async fn call<T: RpcMethod + Serialize>(
        &self,
        auth: &HeaderValue,
        req: &RpcRequest<T>,
    ) -> Result<RpcResponse<T>, ClientError> {
        let response = self
            .send(
                Request::builder()
                    .method(Method::POST)
                    .header(AUTHORIZATION, auth)
                    .body(serde_json::to_string(req)?.into())?,
            )
            .await?;
        let status = response.status();
        let body = to_bytes(response.into_body()).await?;
        let mut rpc_response: RpcResponse<T> =
            serde_json::from_slice(&body).map_err(|serde_error| {
                match std::str::from_utf8(&body) {
                    Ok(body) => ClientError::ParseResponseUtf8 {
                        method: req.method.as_str().to_owned(),
                        status,
                        body: body.to_owned(),
                        serde_error,
                    },
                    Err(error) => ClientError::ResponseNotUtf8 {
                        method: req.method.as_str().to_owned(),
                        status,
                        utf8_error: error,
                    },
                }
            })?;
        if let Some(ref mut error) = rpc_response.error {
            error.status = Some(status);
        }
        Ok(rpc_response)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("serialization failed")]
    Serde(#[from] serde_json::Error),
    #[error("failed to load authentication data")]
    LoadAuth(#[from] AuthLoadError),
    #[error("hyper failed to process HTTP request")]
    Hyper(#[from] hyper::Error),
    #[error("invalid HTTP request")]
    Http(#[from] http::Error),
    #[error(
        "HTTP response (status: {status}) to method {method} can't be parsed as json, body: {body}"
    )]
    ParseResponseUtf8 {
        method: String,
        status: http::status::StatusCode,
        body: String,
        #[source]
        serde_error: serde_json::Error,
    },
    #[error("HTTP response (status: {status}) to method {method} is not UTF-8")]
    ResponseNotUtf8 {
        method: String,
        status: http::status::StatusCode,
        utf8_error: std::str::Utf8Error,
    },
}

impl From<ClientError> for RpcError {
    fn from(error: ClientError) -> Self {
        RpcError {
            code: MISC_ERROR_CODE,
            message: error.to_string(),
            status: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthLoadError {
    #[error("failed to get metadata of file {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("failed to get modification time of file {path}")]
    Modified {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("failed to read file {path}")]
    Read {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("invalid header value")]
    HeaderValue(#[from] http::header::InvalidHeaderValue),
}
