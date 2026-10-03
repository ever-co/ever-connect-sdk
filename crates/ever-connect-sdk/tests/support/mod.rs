//! A recording HTTP/1.1 server on a local port for the client tests (one request per connection;
//! the answers say `connection: close`).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay_ms: u64,
}

impl Reply {
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        let content_type = if status >= 400 {
            "application/problem+json"
        } else {
            "application/json"
        };
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.to_string().into_bytes(),
            delay_ms: 0,
        }
    }
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay_ms: 0,
        }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
    pub const fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
}

pub struct Server {
    pub url: String,
    pub calls: Arc<Mutex<Vec<Recorded>>>,
}

impl Server {
    pub fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls: Arc<Mutex<Vec<Recorded>>> = Arc::default();
        let recorded = Arc::clone(&calls);
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    let mut headers = HashMap::new();
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                        }
                    }
                    let length: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let request = Recorded {
                        method,
                        path,
                        headers,
                        body,
                    };
                    recorded.lock().unwrap().push(request.clone());
                    let reply = handler(&request);
                    if reply.delay_ms > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(reply.delay_ms));
                    }
                    let mut head = format!(
                        "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (k, v) in &reply.headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&reply.body);
                });
            }
        });
        Self { url, calls }
    }

    pub fn calls(&self) -> Vec<Recorded> {
        self.calls.lock().unwrap().clone()
    }
}
