//! Minimal Bitcoin Core JSON-RPC client (HTTP basic auth, no TLS) for regtest.

use serde_json::{json, Value};

/// Connection to a local `bitcoind`.
pub struct Rpc {
    url: String,
    auth: String,
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = (u32::from(ch[0]) << 16) | (u32::from(*ch.get(1).unwrap_or(&0)) << 8) | u32::from(*ch.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

impl Rpc {
    /// Connect to `127.0.0.1:port` with credentials.
    pub fn new(port: u16, user: &str, pass: &str) -> Self {
        Self { url: format!("http://127.0.0.1:{port}"), auth: format!("Basic {}", b64(format!("{user}:{pass}").as_bytes())) }
    }

    /// Call a method on the node (or on `wallet` if given).
    pub fn call(&self, wallet: Option<&str>, method: &str, params: Value) -> Result<Value, String> {
        let url = match wallet {
            Some(w) => format!("{}/wallet/{w}", self.url),
            None => self.url.clone(),
        };
        let body = json!({"jsonrpc": "1.0", "id": "pqcd", "method": method, "params": params});
        let resp = ureq::post(&url).set("Authorization", &self.auth).send_json(body);
        let v: Value = match resp {
            Ok(r) => r.into_json().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(_, r)) => r.into_json().map_err(|e| e.to_string())?,
            Err(e) => return Err(e.to_string()),
        };
        if !v["error"].is_null() {
            return Err(v["error"].to_string());
        }
        Ok(v["result"].clone())
    }
}
