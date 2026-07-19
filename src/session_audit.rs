use chrono::{SecondsFormat, Utc};
use hbb_common::{
    log,
    tokio::{self},
    anyhow::{anyhow, Context},
    ResultType,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 1;
const WRITER_QUEUE_SIZE: usize = 256;
pub const RECONNECT_GRACE: Duration = Duration::from_secs(30);
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Controller,
    Controlled,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Controlled => "controlled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    SessionStarted,
    SessionEnded,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    LocalUserClosed,
    PeerClosed,
    NetworkLost,
    IdleTimeout,
    ServiceStopped,
    ApplicationShutdown,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndInitiator {
    Local,
    Peer,
    Network,
    System,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct Endpoint {
    pub ip: String,
    pub hostname: String,
    pub username: String,
    pub identity_status: &'static str,
}

impl Endpoint {
    pub fn new(ip: String, hostname: String, username: String) -> Self {
        let identity_status = if hostname.is_empty() || username.is_empty() {
            "unavailable"
        } else {
            "complete"
        };
        Self {
            ip,
            hostname,
            username,
            identity_status,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    schema_version: u32,
    event_id: String,
    event_type: EventType,
    session_id: String,
    role: Role,
    session_type: &'static str,
    connection_mode: &'static str,
    local: Endpoint,
    peer: Endpoint,
    started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_reason: Option<EndReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_initiator: Option<EndInitiator>,
    reconnect_count: u32,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    #[serde(flatten)]
    event: &'a AuditEvent,
    prev_hash: &'a str,
    record_hash: &'a str,
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Clone)]
pub struct AuditSession {
    inner: Arc<Mutex<AuditSessionInner>>,
}

struct AuditSessionInner {
    session_id: Uuid,
    role: Role,
    local: Endpoint,
    peer: Endpoint,
    started_at: String,
    started_instant: Instant,
    reconnect_count: u32,
    disconnect_generation: u64,
    state: SessionState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SessionState {
    Pending,
    Active,
    Grace,
    Ended,
}

impl AuditSession {
    pub fn new(session_id: Uuid, role: Role, local: Endpoint, peer: Endpoint) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditSessionInner {
                session_id,
                role,
                local,
                peer,
                started_at: utc_now(),
                started_instant: Instant::now(),
                reconnect_count: 0,
                disconnect_generation: 0,
                state: SessionState::Pending,
            })),
        }
    }

    pub fn session_id(&self) -> Uuid {
        self.inner.lock().unwrap().session_id
    }

    pub fn is_ended(&self) -> bool {
        self.inner.lock().unwrap().state == SessionState::Ended
    }

    pub async fn start(&self) -> ResultType<()> {
        let event = {
            let inner = self.inner.lock().unwrap();
            if inner.state != SessionState::Pending {
                return Ok(());
            }
            inner.event(EventType::SessionStarted, None, None, None, None)
        };
        persist(event).await?;
        let mut inner = self.inner.lock().unwrap();
        if inner.state == SessionState::Pending {
            inner.state = SessionState::Active;
        }
        Ok(())
    }

    pub fn reconnected(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.state == SessionState::Grace {
            inner.disconnect_generation = inner.disconnect_generation.wrapping_add(1);
            inner.reconnect_count = inner.reconnect_count.saturating_add(1);
            inner.state = SessionState::Active;
        }
    }

    pub async fn finish(&self, reason: EndReason, initiator: EndInitiator) -> ResultType<()> {
        let event = {
            let mut inner = self.inner.lock().unwrap();
            if inner.state == SessionState::Ended || inner.state == SessionState::Pending {
                return Ok(());
            }
            inner.disconnect_generation = inner.disconnect_generation.wrapping_add(1);
            inner.state = SessionState::Ended;
            inner.event(
                EventType::SessionEnded,
                Some(utc_now()),
                Some(reason),
                Some(initiator),
                None,
            )
        };
        if let Err(err) = persist_with_retry(event).await {
            self.inner.lock().unwrap().state = SessionState::Active;
            return Err(err);
        }
        Ok(())
    }

    pub fn begin_reconnect_grace(&self, reason: EndReason, initiator: EndInitiator) {
        let (generation, ended_at, duration_ms) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.state != SessionState::Active {
                return;
            }
            inner.disconnect_generation = inner.disconnect_generation.wrapping_add(1);
            inner.state = SessionState::Grace;
            (
                inner.disconnect_generation,
                utc_now(),
                inner.started_instant.elapsed().as_millis() as u64,
            )
        };
        let session = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RECONNECT_GRACE).await;
            let event = {
                let mut inner = session.inner.lock().unwrap();
                if inner.state != SessionState::Grace || inner.disconnect_generation != generation {
                    return;
                }
                inner.state = SessionState::Ended;
                inner.event(
                    EventType::SessionEnded,
                    Some(ended_at),
                    Some(reason),
                    Some(initiator),
                    Some(duration_ms),
                )
            };
            if let Err(err) = persist_with_retry(event).await {
                log::error!("Failed to persist session audit end event: {}", err);
                session.inner.lock().unwrap().state = SessionState::Active;
            }
        });
    }

    #[cfg(test)]
    fn event_for_test(&self, event_type: EventType) -> AuditEvent {
        self.inner
            .lock()
            .unwrap()
            .event(event_type, None, None, None, None)
    }
}

impl AuditSessionInner {
    fn event(
        &self,
        event_type: EventType,
        ended_at: Option<String>,
        reason: Option<EndReason>,
        initiator: Option<EndInitiator>,
        duration_ms: Option<u64>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7().to_string(),
            event_type,
            session_id: self.session_id.to_string(),
            role: self.role,
            session_type: "remote_desktop",
            connection_mode: "direct",
            local: self.local.clone(),
            peer: self.peer.clone(),
            started_at: self.started_at.clone(),
            ended_at,
            duration_ms: if matches!(event_type, EventType::SessionEnded) {
                duration_ms.or_else(|| Some(self.started_instant.elapsed().as_millis() as u64))
            } else {
                None
            },
            end_reason: reason,
            end_initiator: initiator,
            reconnect_count: self.reconnect_count,
        }
    }
}

async fn persist(event: AuditEvent) -> ResultType<()> {
    tokio::task::spawn_blocking(move || writer()?.write(event))
        .await
        .map_err(|err| anyhow!("audit writer task failed: {err}"))?
}

async fn persist_with_retry(event: AuditEvent) -> ResultType<()> {
    let mut last_error = None;
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        match persist(event.clone()).await {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("audit write failed")))
}

struct WriteRequest {
    event: AuditEvent,
    ack: mpsc::Sender<Result<(), String>>,
}

struct AuditWriterHandle {
    sender: SyncSender<WriteRequest>,
}

impl AuditWriterHandle {
    fn start(directory: PathBuf) -> ResultType<Self> {
        let (sender, receiver) = mpsc::sync_channel(WRITER_QUEUE_SIZE);
        thread::Builder::new()
            .name("session-audit-writer".to_owned())
            .spawn(move || writer_loop(directory, receiver))
            .context("start session audit writer")?;
        Ok(Self { sender })
    }

    fn write(&self, event: AuditEvent) -> ResultType<()> {
        let (ack, result) = mpsc::channel();
        self.sender
            .send(WriteRequest { event, ack })
            .map_err(|_| anyhow!("session audit writer stopped"))?;
        result
            .recv()
            .map_err(|_| anyhow!("session audit writer dropped acknowledgement"))?
            .map_err(|err| anyhow!(err))
    }
}

static WRITER: OnceLock<AuditWriterHandle> = OnceLock::new();
static SERVER_SESSIONS: OnceLock<Mutex<HashMap<Uuid, AuditSession>>> = OnceLock::new();

fn writer() -> ResultType<&'static AuditWriterHandle> {
    if let Some(writer) = WRITER.get() {
        return Ok(writer);
    }
    let candidate = AuditWriterHandle::start(default_audit_directory())?;
    let _ = WRITER.set(candidate);
    WRITER
        .get()
        .ok_or_else(|| anyhow!("session audit writer initialization failed"))
}

pub fn server_session(session_id: Uuid, local: Endpoint, peer: Endpoint) -> AuditSession {
    let sessions = SERVER_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut sessions = sessions.lock().unwrap();
    sessions.retain(|_, session| !session.is_ended());
    sessions
        .entry(session_id)
        .or_insert_with(|| AuditSession::new(session_id, Role::Controlled, local, peer))
        .clone()
}

pub fn close_reason(reason: &str) -> (EndReason, EndInitiator, bool) {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("auto disconnect") {
        return (EndReason::IdleTimeout, EndInitiator::System, false);
    }
    if reason.contains("stop service") {
        return (EndReason::ServiceStopped, EndInitiator::System, false);
    }
    if reason == "end" || reason.contains("application") {
        return (EndReason::ApplicationShutdown, EndInitiator::System, false);
    }
    if reason.contains("peer close") || reason.contains("closed manually by the peer") {
        return (EndReason::PeerClosed, EndInitiator::Peer, false);
    }
    if reason.contains("connection manager") || reason.contains("web console") {
        return (EndReason::LocalUserClosed, EndInitiator::Local, false);
    }
    (EndReason::NetworkLost, EndInitiator::Network, true)
}

fn default_audit_directory() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RUSTDESK_AUDIT_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        return base.join("RustDesk").join("audit");
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/rustdesk/audit")
    }
}

fn writer_loop(directory: PathBuf, receiver: Receiver<WriteRequest>) {
    let mut files = HashMap::<Role, AuditFile>::new();
    while let Ok(request) = receiver.recv() {
        let result = files
            .entry(request.event.role)
            .or_insert_with(|| AuditFile::new(directory.clone(), request.event.role))
            .append(&request.event)
            .map_err(|err| err.to_string());
        let _ = request.ack.send(result);
    }
}

struct AuditFile {
    directory: PathBuf,
    role: Role,
    date: String,
    previous_hash: String,
    file: Option<BufWriter<File>>,
}

impl AuditFile {
    fn new(directory: PathBuf, role: Role) -> Self {
        Self {
            directory,
            role,
            date: String::new(),
            previous_hash: ZERO_HASH.to_owned(),
            file: None,
        }
    }

    fn append(&mut self, event: &AuditEvent) -> ResultType<()> {
        self.ensure_open()?;
        let payload = serde_json::to_vec(event).context("serialize session audit event")?;
        let mut hasher = Sha256::new();
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(&payload);
        let record_hash = hex::encode(hasher.finalize());
        let record = AuditRecord {
            event,
            prev_hash: &self.previous_hash,
            record_hash: &record_hash,
        };
        let mut line = serde_json::to_vec(&record).context("serialize session audit record")?;
        line.push(b'\n');
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow!("session audit file is not open"))?;
        file.write_all(&line)
            .context("append session audit record")?;
        file.flush().context("flush session audit record")?;
        file.get_ref()
            .sync_data()
            .context("sync session audit record")?;
        self.previous_hash = record_hash;
        Ok(())
    }

    fn ensure_open(&mut self) -> ResultType<()> {
        let date = Utc::now().format("%Y%m%d").to_string();
        if self.file.is_some() && self.date == date {
            return Ok(());
        }
        fs::create_dir_all(&self.directory).with_context(|| {
            format!(
                "create session audit directory {}",
                self.directory.display()
            )
        })?;
        let path = self.directory.join(format!(
            "sessions-{}-{}-{}.jsonl",
            date,
            self.role.as_str(),
            std::process::id()
        ));
        self.previous_hash = last_record_hash(&path)?.unwrap_or_else(|| ZERO_HASH.to_owned());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open session audit file {}", path.display()))?;
        self.file = Some(BufWriter::new(file));
        self.date = date;
        Ok(())
    }
}

fn last_record_hash(path: &Path) -> ResultType<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let file =
        File::open(path).with_context(|| format!("read session audit file {}", path.display()))?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line.context("read session audit record")?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).context("parse previous session audit record")?;
        last = value
            .get("record_hash")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(ip: &str, host: &str, user: &str) -> Endpoint {
        Endpoint::new(ip.to_owned(), host.to_owned(), user.to_owned())
    }

    #[test]
    fn event_contains_required_fields() {
        let session = AuditSession::new(
            Uuid::nil(),
            Role::Controller,
            endpoint("10.0.0.1", "controller", "alice"),
            endpoint("10.0.0.2", "controlled", "bob"),
        );
        let value = serde_json::to_value(session.event_for_test(EventType::SessionStarted))
            .expect("event must serialize");
        assert_eq!(value["session_id"], Uuid::nil().to_string());
        assert_eq!(value["role"], "controller");
        assert_eq!(value["local"]["username"], "alice");
        assert_eq!(value["peer"]["hostname"], "controlled");
        assert!(value.get("ended_at").is_none());
    }

    #[test]
    fn writer_chains_records() {
        let directory = std::env::temp_dir().join(format!("rustdesk-audit-{}", Uuid::new_v4()));
        let writer = AuditWriterHandle::start(directory.clone()).expect("writer must start");
        let session = AuditSession::new(
            Uuid::new_v4(),
            Role::Controller,
            endpoint("10.0.0.1", "controller", "alice"),
            endpoint("10.0.0.2", "controlled", "bob"),
        );
        writer
            .write(session.event_for_test(EventType::SessionStarted))
            .expect("first record must be written");
        writer
            .write(session.event_for_test(EventType::SessionEnded))
            .expect("second record must be written");
        drop(writer);

        let path = fs::read_dir(&directory)
            .expect("audit directory must exist")
            .next()
            .expect("audit file must exist")
            .expect("audit entry must be readable")
            .path();
        let lines: Vec<serde_json::Value> = BufReader::new(File::open(path).unwrap())
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["prev_hash"], lines[0]["record_hash"]);
        fs::remove_dir_all(directory).expect("temporary audit directory must be removed");
    }
}
