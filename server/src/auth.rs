use axum::extract::{Form, Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::sync::{Arc, RwLock};

// --- Data model ---

#[derive(Serialize, Deserialize, Default)]
pub struct Db {
    users: HashMap<String, String>,  // login -> password_hash
    tokens: HashMap<String, String>, // token -> login
    #[serde(skip)]
    sessions: HashMap<String, String>, // session_id -> login (in-memory only)
    #[serde(skip)]
    path: String,
}

impl Db {
    pub fn load(path: &str) -> Self {
        let mut db = match fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Db::default(),
        };
        db.path = path.to_string();
        db
    }

    fn save(&self) {
        let data = serde_json::to_string_pretty(self).unwrap();
        fs::write(&self.path, data).expect("Failed to save database");
    }

    fn create_user(&mut self, login: &str, password: &str) {
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("bcrypt hash failed");
        self.users.insert(login.to_string(), hash);
        self.save();
    }

    pub fn validate_token(&self, key: &str) -> bool {
        self.tokens.contains_key(key)
    }
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    let mut s = String::with_capacity(len * 2);
    for b in &bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn get_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("session=").map(|v| v.to_string()))
}

fn set_session_cookie(value: &str) -> ([(axum::http::header::HeaderName, String); 1],) {
    ([(SET_COOKIE, format!("session={}; Path=/; HttpOnly", value))],)
}

fn clear_session_cookie() -> ([(axum::http::header::HeaderName, String); 1],) {
    ([(SET_COOKIE, "session=; Path=/; HttpOnly; Max-Age=0".to_string())],)
}

// --- Router ---

pub fn router() -> Router<Arc<RwLock<Db>>> {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/tokens", post(create_token))
        .route("/tokens/{token}/delete", post(delete_token))
}

// --- Handlers ---

#[derive(Deserialize)]
struct LoginForm {
    login: String,
    password: String,
}

async fn login_page(headers: HeaderMap, state: State<Arc<RwLock<Db>>>) -> Response {
    if let Some(session_id) = get_session_cookie(&headers) {
        let db = state.read().unwrap();
        if db.sessions.contains_key(&session_id) {
            return Redirect::to("/").into_response();
        }
    }
    Html(LOGIN_HTML).into_response()
}

async fn login_submit(state: State<Arc<RwLock<Db>>>, Form(form): Form<LoginForm>) -> Response {
    let mut db = state.write().unwrap();

    // First login ever — create the account
    if db.users.is_empty() {
        db.create_user(&form.login, &form.password);
    }

    if let Some(hash) = db.users.get(&form.login) {
        if bcrypt::verify(&form.password, hash).unwrap_or(false) {
            let session_id = random_hex(32);
            db.sessions.insert(session_id.clone(), form.login);
            let (cookie,) = set_session_cookie(&session_id);
            return (cookie, Redirect::to("/")).into_response();
        }
    }
    Html(LOGIN_HTML.replace("</form>", "<small><ins>Invalid credentials</ins></small></form>"))
        .into_response()
}

async fn logout(headers: HeaderMap, state: State<Arc<RwLock<Db>>>) -> Response {
    if let Some(session_id) = get_session_cookie(&headers) {
        let mut db = state.write().unwrap();
        db.sessions.remove(&session_id);
    }
    let (cookie,) = clear_session_cookie();
    (cookie, Redirect::to("/login")).into_response()
}

async fn dashboard(headers: HeaderMap, state: State<Arc<RwLock<Db>>>) -> Response {
    let session_id = match get_session_cookie(&headers) {
        Some(s) => s,
        None => return Redirect::to("/login").into_response(),
    };

    let db = state.read().unwrap();
    let login = match db.sessions.get(&session_id) {
        Some(l) => l.clone(),
        None => return Redirect::to("/login").into_response(),
    };

    let mut rows = String::new();
    for (token, owner) in &db.tokens {
        if owner == &login {
            rows.push_str(&format!(
                "<tr><td><code>{}</code></td><td>\
                 <form method=\"post\" action=\"/tokens/{}/delete\">\
                 <button type=\"submit\" class=\"secondary outline\">Delete</button></form></td></tr>",
                html_escape(token),
                html_escape(token),
            ));
        }
    }

    let html = DASHBOARD_HTML
        .replace("{user}", &html_escape(&login))
        .replace("{rows}", &rows);
    Html(html).into_response()
}

async fn create_token(headers: HeaderMap, state: State<Arc<RwLock<Db>>>) -> Response {
    let session_id = match get_session_cookie(&headers) {
        Some(s) => s,
        None => return Redirect::to("/login").into_response(),
    };

    let mut db = state.write().unwrap();
    if let Some(login) = db.sessions.get(&session_id).cloned() {
        let token = random_hex(16);
        db.tokens.insert(token, login);
        db.save();
    }
    Redirect::to("/").into_response()
}

async fn delete_token(
    headers: HeaderMap,
    state: State<Arc<RwLock<Db>>>,
    Path(token): Path<String>,
) -> Response {
    let session_id = match get_session_cookie(&headers) {
        Some(s) => s,
        None => return Redirect::to("/login").into_response(),
    };

    let mut db = state.write().unwrap();
    if let Some(login) = db.sessions.get(&session_id) {
        if db.tokens.get(&token).map(|o| o == login).unwrap_or(false) {
            db.tokens.remove(&token);
            db.save();
        }
    }
    Redirect::to("/").into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const LOGIN_HTML: &str = include_str!("web/login.html");
const DASHBOARD_HTML: &str = include_str!("web/dashboard.html");
