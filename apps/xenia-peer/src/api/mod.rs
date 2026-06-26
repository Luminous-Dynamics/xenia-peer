use axum::{routing::{get, post}, Router};
use std::sync::Arc;
use tokio::sync::Mutex;
use xenia_ledger::Chain;

pub struct ApiState {
    pub ledger: Arc<Mutex<Chain>>,
    pub challenges: Arc<Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    pub secret: Arc<Vec<u8>>,
    pub public_key: Arc<String>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/challenge", get(handle_challenge))
        .route("/verify", post(handle_verify))
        .route("/ledger", get(handle_ledger))
        .route("/identity", get(handle_identity))
        .with_state(state)
}

// ... handlers moved here ...
