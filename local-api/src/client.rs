//! A no-iroh mcpmesh-local/1 client: connect the UDS, read the server's `Hello`
//! first frame, assert the api name, then issue typed request/response frames. Distinct
//! from the CLI crate (`cli/`)'s ControlClient (which uses mcpmesh_net::framing) — this one links no
//! iroh, so kb and the host shell can use it. kb calls this to self-register
//! its `[services.kb]` socket backend with the running mcpmesh daemon.
use std::path::Path;

use serde_json::Value;

use crate::codec::{FrameReader, Inbound, MAX_FRAME_BYTES, write_frame};
use crate::protocol::{
    AuditSummaryResult, BackendSpec, BlobFetchParams, BlobFetchResult, BlobGrantParams,
    BlobPublishParams, BlobPublishResult, BlobScopeList, Hello, InviteParams, InviteResult,
    OpenSessionParams, OrgJoinParams, OrgJoinResult, PairParams, PairResult, PeerRemoveParams,
    PeerRenameParams, RegisterServiceParams, Request, RosterInstallParams, RosterInstallResult,
    SetRosterUrlParams, StatusResult, StreamFrame,
};
use crate::transport::{LocalReadHalf, LocalWriteHalf, connect_local, split_local};

/// A connected mcpmesh-local/1 client: the framed UDS stream + the server's `Hello`.
// DEVIATION (declared): `#[derive(Debug)]` added — the plan's `wrong_api_hello_is_rejected`
// test formats `Result<ControlClient, _>` with `{:?}`. [source: plan T2 client.rs test]
#[derive(Debug)]
pub struct ControlClient {
    hello: Hello,
    reader: FrameReader<LocalReadHalf>,
    writer: LocalWriteHalf,
}

/// The error surface of the client — thin, so callers can `anyhow`-wrap it.
///
/// The `Display`/`Error`/`From` impls below are hand-rolled rather than derived: the
/// `client` feature deliberately pulls ONLY tokio (no `thiserror`), and the hand-rolled
/// impls are behavior-identical (same messages, same `?`-conversion from `io::Error`)
/// with zero extra dependencies.
#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Closed(&'static str),
    Malformed(&'static str),
    WrongApi { got: String, want: &'static str },
    Api(Value),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(err) => write!(f, "io: {err}"),
            ClientError::Closed(what) => write!(f, "connection closed before {what}"),
            ClientError::Malformed(what) => write!(f, "malformed {what} frame"),
            ClientError::WrongApi { got, want } => {
                write!(f, "unexpected api: got {got:?}, want {want:?}")
            }
            ClientError::Api(err) => write!(f, "control API error: {err}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::Io(err)
    }
}

impl ControlClient {
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Issue a typed request; return the JSON-RPC `result` (or `ClientError::Api` on a
    /// JSON-RPC `error`).
    pub async fn request(&mut self, request: Request) -> Result<Value, ClientError> {
        let frame = serde_json::to_value(&request).expect("Request serializes");
        self.request_value(&frame).await
    }

    /// Issue a RAW request frame — the escape hatch for methods outside the typed
    /// [`Request`] surface (the daemon-internal `shutdown`, third-party
    /// `{"method":..,"params":{}}` shapes the dispatcher tolerates). Returns the JSON-RPC
    /// `result` value (or `ClientError::Api` on a JSON-RPC `error`).
    pub async fn request_value(&mut self, request: &Value) -> Result<Value, ClientError> {
        write_frame(&mut self.writer, request).await?;
        match self.reader.next().await? {
            Some(Inbound::Frame(resp)) => {
                if let Some(err) = resp.get("error") {
                    return Err(ClientError::Api(err.clone()));
                }
                Ok(resp.get("result").cloned().unwrap_or(Value::Null))
            }
            Some(Inbound::Violation(_)) => Err(ClientError::Malformed("response")),
            None => Err(ClientError::Closed("response")),
        }
    }

    /// Send a request WITHOUT reading a response — for `OpenSession`, after which the
    /// socket stops being JSON-RPC and becomes a raw MCP byte pipe (protocol.rs). Returns
    /// the framed halves so the caller can pump the session — the SAME `FrameReader` that
    /// read the Hello, so bytes the daemon pipelined behind it are never lost. A caller
    /// that must re-box the read half calls `FrameReader::into_inner`, which returns the
    /// BUFFERED reader (its read-ahead travels with it — see the pipelining test below).
    pub async fn open_session(
        mut self,
        peer: String,
        service: String,
    ) -> Result<(FrameReader<LocalReadHalf>, LocalWriteHalf), ClientError> {
        let frame = serde_json::to_value(Request::OpenSession(OpenSessionParams { peer, service }))
            .expect("Request serializes");
        write_frame(&mut self.writer, &frame).await?;
        Ok((self.reader, self.writer))
    }

    /// Send a parameterless stream-upgrade request WITHOUT reading a response — like
    /// [`open_session`](Self::open_session), but generic on the `method`: after this call the
    /// socket stops being request/response and becomes a one-way push stream of frames the caller
    /// READS (the `subscribe` telemetry surface). Returns the framed halves — the SAME
    /// `FrameReader` that read the Hello, so any frame the daemon pipelined behind it is never
    /// lost. The write half is handed back so the caller can hold the connection open (a watcher
    /// only reads, but dropping the writer would half-close the socket).
    pub async fn open_stream(
        mut self,
        method: &str,
    ) -> Result<(FrameReader<LocalReadHalf>, LocalWriteHalf), ClientError> {
        let frame = serde_json::json!({ "method": method });
        write_frame(&mut self.writer, &frame).await?;
        Ok((self.reader, self.writer))
    }

    /// Issue `request` and deserialize the JSON-RPC `result` into `T` — the shared core of every
    /// typed helper below. `what` names the result in the [`ClientError::Malformed`] surface. The
    /// wrong-type hazard the raw [`request`](Self::request) leaves to the caller is closed here:
    /// each helper pairs its Request variant with its result type once, in this crate.
    async fn request_typed<T: serde::de::DeserializeOwned>(
        &mut self,
        request: Request,
        what: &'static str,
    ) -> Result<T, ClientError> {
        let v = self.request(request).await?;
        serde_json::from_value(v).map_err(|_| ClientError::Malformed(what))
    }

    /// Issue `request` and discard the ack body (the daemon answers `{}` for verbs with no result
    /// vocabulary). A JSON-RPC error still surfaces as [`ClientError::Api`].
    async fn request_ack(&mut self, request: Request) -> Result<(), ClientError> {
        self.request(request).await.map(|_| ())
    }

    /// The daemon's `status` picture: services served, known peers, roster/presence state,
    /// self identity, recent pairings, and advisory reachability.
    pub async fn status(&mut self) -> Result<StatusResult, ClientError> {
        self.request_typed(Request::Status, "status result").await
    }

    /// Register/update a `[services.*]` entry idempotently (the daemon persists it and hot-reloads
    /// serving). The daemon acks; the ack body is discarded.
    pub async fn register_service(
        &mut self,
        name: &str,
        backend: BackendSpec,
        allow: Vec<String>,
    ) -> Result<(), ClientError> {
        self.request_ack(Request::RegisterService(RegisterServiceParams {
            name: name.to_string(),
            backend,
            allow,
        }))
        .await
    }

    /// Mint a one-time pairing invite granting `services`; return the copyable
    /// `mcpmesh-invite:` line + its expiry.
    pub async fn invite(&mut self, services: Vec<String>) -> Result<InviteResult, ClientError> {
        self.invite_with(services, None).await
    }

    /// [`invite`](Self::invite) with an opaque `app_label` (#31) carried through to the redeemer's
    /// `pair` result. mcpmesh never interprets the label; the embedder does (e.g. its own URN).
    pub async fn invite_with(
        &mut self,
        services: Vec<String>,
        app_label: Option<String>,
    ) -> Result<InviteResult, ClientError> {
        self.request_typed(
            Request::Invite(InviteParams {
                services,
                app_label,
            }),
            "invite result",
        )
        .await
    }

    /// Redeem a pairing invite; return the inviter's suggested nickname, the display-only SAS
    /// code, and the granted services.
    pub async fn pair(&mut self, invite_line: &str) -> Result<PairResult, ClientError> {
        self.request_typed(
            Request::Pair(PairParams {
                invite_line: invite_line.to_string(),
            }),
            "pair result",
        )
        .await
    }

    /// Unpair a peer by nickname: drops its identity row AND its every-`allow` membership
    /// (idempotent; live sessions are not severed). The daemon acks; the ack body is discarded.
    pub async fn peer_remove(&mut self, nickname: &str) -> Result<(), ClientError> {
        self.request_ack(Request::PeerRemove(PeerRemoveParams {
            nickname: nickname.to_string(),
        }))
        .await
    }

    /// Rename a contact's nickname to `to` — every device sharing `user_id` when given, else the
    /// single provisional `nickname` entry — carrying its grants along. The daemon refuses (a
    /// [`ClientError::Api`]) when `to` is empty or already names a different identity. The daemon
    /// acks; the ack body is discarded.
    pub async fn peer_rename(
        &mut self,
        user_id: Option<String>,
        nickname: Option<String>,
        to: &str,
    ) -> Result<(), ClientError> {
        self.request_ack(Request::PeerRename(PeerRenameParams {
            user_id,
            nickname,
            to: to.to_string(),
        }))
        .await
    }

    /// Install a signed roster from the LOCAL file at `path` (`org_root_pk` pins the org root on
    /// FIRST install); return the installed org id + serial + severed-session count.
    pub async fn roster_install(
        &mut self,
        path: &str,
        org_root_pk: Option<String>,
    ) -> Result<RosterInstallResult, ClientError> {
        self.request_typed(
            Request::RosterInstall(RosterInstallParams {
                path: path.to_string(),
                org_root_pk,
            }),
            "roster_install result",
        )
        .await
    }

    /// Pin the org root on a JOINER (no roster yet). `user_key` is a LOCAL path — the key never
    /// crosses the API. Returns the pinned org id.
    pub async fn org_join(
        &mut self,
        org_id: &str,
        org_root_pk: &str,
        user_id: &str,
        user_key: &str,
    ) -> Result<OrgJoinResult, ClientError> {
        self.request_typed(
            Request::OrgJoin(OrgJoinParams {
                org_id: org_id.to_string(),
                org_root_pk: org_root_pk.to_string(),
                user_id: user_id.to_string(),
                user_key: user_key.to_string(),
            }),
            "org_join result",
        )
        .await
    }

    /// Pin the HTTPS roster URL (`[roster].url`) in the daemon's config. The daemon acks; the
    /// ack body is discarded.
    pub async fn set_roster_url(&mut self, url: &str) -> Result<(), ClientError> {
        self.request_ack(Request::SetRosterUrl(SetRosterUrlParams {
            url: url.to_string(),
        }))
        .await
    }

    /// Summarize the daemon's LOCAL audit log into per-peer / per-service session counts
    /// (local-only — nothing is transmitted).
    pub async fn audit_summary(&mut self) -> Result<AuditSummaryResult, ClientError> {
        self.request_typed(Request::AuditSummary, "audit_summary result")
            .await
    }

    /// Publish a local file into `scope`; return the minted `mcpmesh/blob/1` ticket + hash.
    pub async fn blob_publish(
        &mut self,
        scope: &str,
        path: &str,
    ) -> Result<BlobPublishResult, ClientError> {
        self.request_typed(
            Request::BlobPublish(BlobPublishParams {
                scope: scope.to_string(),
                path: path.to_string(),
            }),
            "blob_publish result",
        )
        .await
    }

    /// List the daemon's blob scopes (name → hashes + grants).
    pub async fn blob_list(&mut self) -> Result<BlobScopeList, ClientError> {
        self.request_typed(Request::BlobList, "blob_list result")
            .await
    }

    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (BLAKE3-verified), export to
    /// `dest_path`; return the verified hash + byte length.
    pub async fn blob_fetch(
        &mut self,
        ticket: &str,
        dest_path: &str,
    ) -> Result<BlobFetchResult, ClientError> {
        self.request_typed(
            Request::BlobFetch(BlobFetchParams {
                ticket: ticket.to_string(),
                dest_path: dest_path.to_string(),
            }),
            "blob_fetch result",
        )
        .await
    }

    /// Grant a scope to a principal — any flat-namespace entry: a group name, a user_id,
    /// or a nickname (the shared `principal_set` expansion).
    /// The daemon acks; the ack body is discarded (a JSON-RPC error surfaces as
    /// `ClientError::Api`). Granting a scope to your own user_id reaches ALL of that
    /// person's devices.
    pub async fn blob_grant(&mut self, scope: &str, principal: &str) -> Result<(), ClientError> {
        self.request_ack(Request::BlobGrant(BlobGrantParams {
            scope: scope.to_string(),
            principal: principal.to_string(),
        }))
        .await
    }

    /// The TYPED `subscribe` upgrade: send [`Request::Subscribe`] (after which the connection
    /// stops being request/response — see [`open_stream`](Self::open_stream)) and return a
    /// [`StreamSubscription`] yielding [`StreamFrame`]s. For raw frames (e.g. to tolerate frame
    /// types newer than this crate), use `open_stream("subscribe")` instead.
    pub async fn subscribe(self) -> Result<StreamSubscription, ClientError> {
        let (reader, writer) = self.open_stream("subscribe").await?;
        Ok(StreamSubscription {
            reader,
            _writer: writer,
        })
    }
}

/// A live [`Request::Subscribe`] stream yielding typed [`StreamFrame`]s (snapshot, then
/// events/lagged notices) until the daemon side closes. Holds the connection's write half for its
/// lifetime — a subscriber only reads, but dropping the writer would half-close the socket. Drop
/// the subscription to disconnect (there is no request channel back).
#[derive(Debug)]
pub struct StreamSubscription {
    reader: FrameReader<LocalReadHalf>,
    _writer: LocalWriteHalf,
}

impl StreamSubscription {
    /// The next frame, or `None` when the daemon closed the stream. A frame this crate's
    /// [`StreamFrame`] does not model (a NEWER daemon's frame type) surfaces as
    /// [`ClientError::Malformed`] — a forward-compatible consumer reads raw frames via
    /// [`ControlClient::open_stream`] instead.
    pub async fn next(&mut self) -> Result<Option<StreamFrame>, ClientError> {
        match self.reader.next().await? {
            Some(Inbound::Frame(v)) => serde_json::from_value(v)
                .map(Some)
                .map_err(|_| ClientError::Malformed("stream frame")),
            Some(Inbound::Violation(_)) => Err(ClientError::Malformed("stream frame")),
            None => Ok(None),
        }
    }
}

/// Connect + complete the hello handshake, asserting the api name is `mcpmesh-local/1`.
pub async fn connect_control(path: &Path) -> Result<ControlClient, ClientError> {
    let stream = connect_local(path).await?;
    let (read_half, writer) = split_local(stream);
    let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
    let hello: Hello = match reader.next().await? {
        Some(Inbound::Frame(v)) => {
            serde_json::from_value(v).map_err(|_| ClientError::Malformed("hello"))?
        }
        Some(Inbound::Violation(_)) => return Err(ClientError::Malformed("hello")),
        None => return Err(ClientError::Closed("hello")),
    };
    if hello.api != crate::protocol::API_NAME {
        return Err(ClientError::WrongApi {
            got: hello.api,
            want: crate::protocol::API_NAME,
        });
    }
    Ok(ControlClient {
        hello,
        reader,
        writer,
    })
}

/// [`connect_control`] at the platform default endpoint ([`crate::paths::default_endpoint`]):
/// the quickstart front door — a consumer dials the running daemon without reimplementing
/// the platform endpoint rule. Resolution failure surfaces as [`ClientError::Io`]
/// (`NotFound`), same as a daemon that is not running.
pub async fn connect_control_default() -> Result<ControlClient, ClientError> {
    connect_control(&crate::paths::default_endpoint()?).await
}

// Seam-ported (Task 6): every stub daemon binds via the platform seam
// (`transport::bind_local` + `LocalListener::accept`) rather than a raw `UnixListener`,
// so these exercise the platform-identical `ControlClient` on BOTH unix (UDS) and windows
// (named pipe). Gated on `feature = "service"` (bind needs it) rather than `unix`: under
// `cargo test --workspace` feature unification turns `service` on for this crate (cli
// depends on local-api with features=["service"]), so the module compiles and RUNS on the
// windows CI leg. `test_endpoint` yields a platform-appropriate unique endpoint.
#[cfg(all(test, feature = "service"))]
mod tests {
    use super::*;
    use crate::protocol::{API_NAME, API_VERSION, BackendKind, ServiceInfo, StatusResult};
    use crate::transport::{LocalListener, bind_local, split_local};
    use tokio::io::AsyncWriteExt;

    /// A unique local endpoint for a stub daemon, platform-appropriate: a tempdir socket
    /// path on unix, a per-process-unique `\\.\pipe\…` name on windows. Returns the
    /// endpoint plus a guard that MUST outlive the listener (the `TempDir` on unix; unit
    /// on windows, whose pipe namespace needs no filesystem cleanup).
    #[cfg(unix)]
    fn test_endpoint(tag: &str) -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{tag}.sock"));
        (path, dir)
    }
    #[cfg(windows)]
    fn test_endpoint(tag: &str) -> (std::path::PathBuf, ()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::path::PathBuf::from(format!(
            r"\\.\pipe\mcpmesh-client-test-{}-{tag}-{n}",
            std::process::id()
        ));
        (path, ())
    }

    /// A stub mcpmesh daemon: send Hello, then answer one `status` with a StatusResult.
    async fn stub_daemon(mut listener: LocalListener) {
        let stream = listener.accept().await.unwrap();
        let (read_half, mut writer) = split_local(stream);
        write_frame(
            &mut writer,
            &serde_json::to_value(Hello {
                api: API_NAME.into(),
                api_version: API_VERSION.into(),
                api_minor: 0,
                stack_version: "0.1.0".into(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
        let req = match reader.next().await.unwrap().unwrap() {
            Inbound::Frame(v) => v,
            Inbound::Violation(_) => panic!("violation"),
        };
        assert_eq!(req["method"], "status");
        let result = StatusResult {
            stack_version: "0.1.0".into(),
            services: vec![ServiceInfo {
                name: "kb".into(),
                allow: vec![],
                backend: BackendKind::Socket,
            }],
            peers: vec![],
            roster: None,
            presence: vec![],
            self_user_id: None,
            recent_pairings: vec![],
            reachability: vec![],
        };
        write_frame(
            &mut writer,
            &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
        )
        .await
        .unwrap();
        writer.flush().await.unwrap();
    }

    #[tokio::test]
    async fn connect_reads_hello_asserts_api_and_requests() {
        let (sock, _guard) = test_endpoint("status");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(stub_daemon(listener));

        let mut client = connect_control(&sock).await.unwrap();
        assert_eq!(client.hello().api, API_NAME);
        let result = client.request(Request::Status).await.unwrap();
        assert_eq!(result["services"][0]["name"], "kb");
        assert_eq!(result["services"][0]["backend"], "socket");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_api_hello_is_rejected() {
        let (sock, _guard) = test_endpoint("wrongapi");
        let listener = bind_local(&sock).unwrap();
        tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (_r, mut w) = split_local(stream);
            write_frame(
                &mut w,
                &serde_json::json!({"api":"other/1","api_version":"1.0","stack_version":"0"}),
            )
            .await
            .unwrap();
            w.flush().await.unwrap();
        });
        match connect_control(&sock).await {
            Err(ClientError::WrongApi { got, want }) => {
                assert_eq!(got, "other/1");
                assert_eq!(want, API_NAME);
            }
            other => panic!("expected WrongApi, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blob_fetch_and_publish_deserialize_typed_results() {
        use crate::protocol::{BlobFetchResult, BlobPublishResult};
        let (sock, _guard) = test_endpoint("blob");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (read_half, mut writer) = split_local(stream);
            write_frame(
                &mut writer,
                &serde_json::to_value(Hello {
                    api: API_NAME.into(),
                    api_version: API_VERSION.into(),
                    api_minor: 0,
                    stack_version: "0.1.0".into(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
            // First request: blob_publish -> a ticket + hash.
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "blob_publish");
            assert_eq!(req["params"]["scope"], "eng");
            write_frame(
                &mut writer,
                &serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ticket":"blobT","hash":"ab"}}),
            )
            .await
            .unwrap();
            // Second request: blob_fetch -> a verified hash + length.
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "blob_fetch");
            assert_eq!(req["params"]["ticket"], "blobT");
            assert_eq!(req["params"]["dest_path"], "/tmp/out.bin");
            write_frame(
                &mut writer,
                &serde_json::json!({"jsonrpc":"2.0","id":2,"result":{"hash":"cd","bytes_len":7}}),
            )
            .await
            .unwrap();
            let _ = (
                BlobFetchResult {
                    hash: "cd".into(),
                    bytes_len: 7,
                },
                BlobPublishResult {
                    ticket: "blobT".into(),
                    hash: "ab".into(),
                },
            );
        });

        let mut client = connect_control(&sock).await.unwrap();
        let pub_res = client.blob_publish("eng", "/tmp/a.bin").await.unwrap();
        assert_eq!(pub_res.ticket, "blobT");
        assert_eq!(pub_res.hash, "ab");
        let fetch_res = client.blob_fetch("blobT", "/tmp/out.bin").await.unwrap();
        assert_eq!(fetch_res.hash, "cd");
        assert_eq!(fetch_res.bytes_len, 7);
        server.await.unwrap();
    }

    /// Regression (lossless rebox): a frame the server PIPELINES in the same write as
    /// the Hello must survive `open_session` + kb's production re-box shape
    /// (`FrameReader::new(Box::new(reader.into_inner()), …)`, bridge/session.rs). Against
    /// the old `into_inner -> R` — which unwrapped the internal `BufReader` and DROPPED
    /// its read-ahead — the pipelined frame vanished and this test failed (EOF instead of
    /// the frame). `into_inner -> BufReader<R>` carries the read-ahead across the rebox.
    #[tokio::test]
    async fn frame_pipelined_behind_hello_survives_open_session_rebox() {
        use tokio::io::AsyncRead;

        let (sock, _guard) = test_endpoint("pipelined");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (read_half, mut writer) = split_local(stream);
            // ONE write carrying the Hello AND a session frame → both land in the
            // client's first BufReader fill (the read-ahead under test).
            let mut bytes = serde_json::to_vec(
                &serde_json::to_value(Hello {
                    api: API_NAME.into(),
                    api_version: API_VERSION.into(),
                    api_minor: 0,
                    stack_version: "0.1.0".into(),
                })
                .unwrap(),
            )
            .unwrap();
            bytes.push(b'\n');
            bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{}}\n");
            writer.write_all(&bytes).await.unwrap();
            writer.flush().await.unwrap();
            // Absorb the client's open_session frame so its write never sees EPIPE.
            let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "open_session");
        });

        let client = connect_control(&sock).await.unwrap();
        let (reader, _writer) = client
            .open_session("peer".into(), "kb".into())
            .await
            .unwrap();
        // kb's production shape: erase the half type behind a boxed pipe, then re-frame.
        let boxed: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader.into_inner());
        let mut reframed = FrameReader::new(boxed, MAX_FRAME_BYTES);
        match reframed.next().await.unwrap() {
            Some(Inbound::Frame(v)) => assert_eq!(v["id"], 42),
            other => panic!("pipelined frame was lost across the rebox: {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn blob_grant_issues_request_and_acks() {
        let (sock, _guard) = test_endpoint("grant");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (read_half, mut writer) = split_local(stream);
            write_frame(
                &mut writer,
                &serde_json::to_value(Hello {
                    api: API_NAME.into(),
                    api_version: API_VERSION.into(),
                    api_minor: 0,
                    stack_version: "0.1.0".into(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "blob_grant");
            assert_eq!(req["params"]["scope"], "kb-sync");
            assert_eq!(req["params"]["principal"], "alice");
            write_frame(
                &mut writer,
                &serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}),
            )
            .await
            .unwrap();
        });
        let mut client = connect_control(&sock).await.unwrap();
        client.blob_grant("kb-sync", "alice").await.unwrap();
        server.await.unwrap();
    }

    /// The typed `status()` helper pairs `Request::Status` with `StatusResult` — the caller gets
    /// the struct, not a `Value` to hand-deserialize (and a malformed result surfaces as
    /// `ClientError::Malformed`, never a silently-wrong type).
    #[tokio::test]
    async fn typed_status_helper_deserializes_the_result() {
        let (sock, _guard) = test_endpoint("typedstatus");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(stub_daemon(listener));

        let mut client = connect_control(&sock).await.unwrap();
        let status = client.status().await.unwrap();
        assert_eq!(status.stack_version, "0.1.0");
        assert_eq!(status.services[0].name, "kb");
        assert_eq!(status.services[0].backend, BackendKind::Socket);
        assert!(status.peers.is_empty());
        server.await.unwrap();
    }

    /// The ack-shaped typed helpers issue the right wire method and discard the `{}` ack; a
    /// JSON-RPC error frame surfaces as `ClientError::Api`.
    #[tokio::test]
    async fn typed_ack_helpers_issue_requests_and_surface_api_errors() {
        let (sock, _guard) = test_endpoint("typedack");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (read_half, mut writer) = split_local(stream);
            write_frame(
                &mut writer,
                &serde_json::to_value(Hello {
                    api: API_NAME.into(),
                    api_version: API_VERSION.into(),
                    api_minor: 0,
                    stack_version: "0.1.0".into(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
            // peer_remove → ack.
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "peer_remove");
            assert_eq!(req["params"]["nickname"], "bob");
            write_frame(
                &mut writer,
                &serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}),
            )
            .await
            .unwrap();
            // peer_rename → an error frame (collision refusal).
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "peer_rename");
            assert_eq!(req["params"]["to"], "Bobby");
            write_frame(
                &mut writer,
                &serde_json::json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"taken"}}),
            )
            .await
            .unwrap();
        });

        let mut client = connect_control(&sock).await.unwrap();
        client.peer_remove("bob").await.unwrap();
        match client.peer_rename(None, Some("bob".into()), "Bobby").await {
            Err(ClientError::Api(e)) => assert_eq!(e["message"], "taken"),
            other => panic!("expected Api error, got {other:?}"),
        }
        server.await.unwrap();
    }

    /// The typed `subscribe()` upgrade yields `StreamFrame`s — snapshot, event, lagged — then
    /// `None` when the daemon side closes.
    #[tokio::test]
    async fn typed_subscribe_yields_frames_then_end() {
        use crate::protocol::{ActiveSession, AuditRecord, PeerReachability};

        let (sock, _guard) = test_endpoint("subscribe");
        let listener = bind_local(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut listener = listener;
            let stream = listener.accept().await.unwrap();
            let (read_half, mut writer) = split_local(stream);
            write_frame(
                &mut writer,
                &serde_json::to_value(Hello {
                    api: API_NAME.into(),
                    api_version: API_VERSION.into(),
                    api_minor: 0,
                    stack_version: "0.1.0".into(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            let mut reader = FrameReader::new(read_half, MAX_FRAME_BYTES);
            let req = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => v,
                Inbound::Violation(_) => panic!("violation"),
            };
            assert_eq!(req["method"], "subscribe");
            for frame in [
                StreamFrame::Snapshot {
                    active_sessions: vec![ActiveSession {
                        peer: "bob".into(),
                        service: "notes".into(),
                        opened_at: 7,
                    }],
                    reachability: vec![PeerReachability {
                        name: "bob".into(),
                        reachable: true,
                        rtt_ms: Some(42),
                        age_secs: Some(3),
                    }],
                },
                StreamFrame::Event {
                    record: Box::new(AuditRecord::session_open(
                        "2026-07-03T14:02:11.480Z".into(),
                        Some("bob".into()),
                        "notes".into(),
                    )),
                },
                StreamFrame::Lagged { dropped: 12 },
            ] {
                write_frame(&mut writer, &serde_json::to_value(&frame).unwrap())
                    .await
                    .unwrap();
            }
            writer.flush().await.unwrap();
            // Drop the connection: the client must see the stream END (Ok(None)), not an error.
        });

        let client = connect_control(&sock).await.unwrap();
        let mut sub = client.subscribe().await.unwrap();
        match sub.next().await.unwrap().unwrap() {
            StreamFrame::Snapshot {
                active_sessions,
                reachability,
            } => {
                assert_eq!(active_sessions[0].peer, "bob");
                assert_eq!(reachability[0].rtt_ms, Some(42));
            }
            other => panic!("expected the snapshot first, got {other:?}"),
        }
        match sub.next().await.unwrap().unwrap() {
            StreamFrame::Event { record } => {
                assert_eq!(record.peer.as_deref(), Some("bob"));
                assert_eq!(record.service.as_deref(), Some("notes"));
            }
            other => panic!("expected the event, got {other:?}"),
        }
        assert_eq!(
            sub.next().await.unwrap(),
            Some(StreamFrame::Lagged { dropped: 12 })
        );
        assert_eq!(sub.next().await.unwrap(), None, "clean end of stream");
        server.await.unwrap();
    }
}
