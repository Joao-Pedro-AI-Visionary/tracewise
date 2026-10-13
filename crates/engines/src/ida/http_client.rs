//! A `reqwest`-backed streamable-HTTP client for rmcp's transport worker.
//!
//! rmcp 0.11 ships the same adapter behind its `transport-streamable-http-client-reqwest`
//! feature, but that feature also switches on rustls for every `reqwest` user in the
//! workspace. IDA only needs plain-HTTP endpoints on the local host (REA admits nothing
//! else), so the adapter is written out here against the public `StreamableHttpClient`
//! trait. Headers and the redirect policy live on the wrapped `reqwest::Client`.

use std::borrow::Cow;
use std::sync::Arc;

use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::http_header::{
    EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
};
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use sse_stream::{Sse, SseStream};

#[derive(Clone)]
pub struct HttpClient(pub reqwest::Client);

fn accept() -> String {
    [EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE].join(", ")
}

impl StreamableHttpClient for HttpClient {
    type Error = reqwest::Error;

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let mut request = self
            .0
            .get(uri.as_ref())
            .header(ACCEPT, accept())
            .header(HEADER_SESSION_ID, session_id.as_ref());
        if let Some(last_event_id) = last_event_id {
            request = request.header(HEADER_LAST_EVENT_ID, last_event_id);
        }
        if let Some(token) = auth_header {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(StreamableHttpError::Client)?;
        if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        let response = response
            .error_for_status()
            .map_err(StreamableHttpError::Client)?;
        match response.headers().get(CONTENT_TYPE) {
            Some(kind)
                if kind
                    .as_bytes()
                    .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes())
                    || kind.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {}
            Some(kind) => {
                return Err(StreamableHttpError::UnexpectedContentType(Some(
                    String::from_utf8_lossy(kind.as_bytes()).to_string(),
                )))
            }
            None => return Err(StreamableHttpError::UnexpectedContentType(None)),
        }
        Ok(SseStream::from_bytes_stream(response.bytes_stream()).boxed())
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let mut request = self
            .0
            .delete(uri.as_ref())
            .header(HEADER_SESSION_ID, session_id.as_ref());
        if let Some(token) = auth_header {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(StreamableHttpError::Client)?;
        // A server without session deletion is fine.
        if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Ok(());
        }
        response
            .error_for_status()
            .map_err(StreamableHttpError::Client)?;
        Ok(())
    }

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let mut request = self.0.post(uri.as_ref()).header(ACCEPT, accept());
        if let Some(token) = auth_header {
            request = request.bearer_auth(token);
        }
        if let Some(session_id) = session_id {
            request = request.header(HEADER_SESSION_ID, session_id.as_ref());
        }
        let response = request
            .json(&message)
            .send()
            .await
            .map_err(StreamableHttpError::Client)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::from(
                "the IDA MCP endpoint requires authorization (401)",
            )));
        }
        let response = response
            .error_for_status()
            .map_err(StreamableHttpError::Client)?;
        if matches!(
            status,
            reqwest::StatusCode::ACCEPTED | reqwest::StatusCode::NO_CONTENT
        ) {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        let session = response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let kind = response.headers().get(CONTENT_TYPE).cloned();
        match kind {
            Some(kind)
                if kind
                    .as_bytes()
                    .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) =>
            {
                let stream = SseStream::from_bytes_stream(response.bytes_stream()).boxed();
                Ok(StreamableHttpPostResponse::Sse(stream, session))
            }
            Some(kind) if kind.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
                let reply: ServerJsonRpcMessage =
                    response.json().await.map_err(StreamableHttpError::Client)?;
                Ok(StreamableHttpPostResponse::Json(reply, session))
            }
            other => Err(StreamableHttpError::UnexpectedContentType(
                other.map(|kind| String::from_utf8_lossy(kind.as_bytes()).to_string()),
            )),
        }
    }
}
