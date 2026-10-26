//! Authenticated Streamable HTTP MCP service and optional local stdio bridge.
#[path = "mcp/http.rs"]
mod http;
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

const MAX_MESSAGE: u64 = 256 * 1024;
pub struct Command {
    pub request: Value,
    pub reply: mpsc::SyncSender<Value>,
    pub expires: std::time::Instant,
}
pub struct Server {
    pub port: u16,
    pub token: String,
    pub host: Ipv4Addr,
    pub commands: mpsc::Receiver<Command>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn start(port: u16, token: String, lan: bool, host: Ipv4Addr) -> Result<Self, String> {
        if token.len() < 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(
                "MCP requires an access token of at least 32 hexadecimal characters".into(),
            );
        }
        if !valid_host(host) || (lan && host.is_loopback()) {
            return Err("Enter the Windows LAN IPv4 address before enabling remote access".into());
        }
        let bind = if lan {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        };
        let host = if lan { host } else { Ipv4Addr::LOCALHOST };
        let listener = TcpListener::bind((bind, port)).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let (tx, commands) = mpsc::sync_channel(8);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let secret = token.clone();
        let authorities = vec![
            format!("{host}:{port}"),
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
        ];
        let workers = Arc::new(AtomicUsize::new(0));
        std::thread::Builder::new()
            .name("clumsymagi-mcp".into())
            .spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if workers.fetch_add(1, Ordering::SeqCst) >= 16 {
                                workers.fetch_sub(1, Ordering::SeqCst);
                                continue;
                            }
                            let active = workers.clone();
                            let tx = tx.clone();
                            let secret = secret.clone();
                            let authorities = authorities.clone();
                            let stop = stopped.clone();
                            let task = std::thread::Builder::new()
                                .name("clumsymagi-mcp-http".into())
                                .spawn(move || {
                                    struct Worker(Arc<AtomicUsize>);
                                    impl Drop for Worker {
                                        fn drop(&mut self) {
                                            self.0.fetch_sub(1, Ordering::SeqCst);
                                        }
                                    }
                                    let _worker = Worker(active);
                                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                                    struct TimedRead<'a> {
                                        stream: &'a mut TcpStream,
                                        deadline: std::time::Instant,
                                    }
                                    impl Read for TimedRead<'_> {
                                        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                                            if std::time::Instant::now() >= self.deadline {
                                                return Err(io::Error::new(
                                                    io::ErrorKind::TimedOut,
                                                    "HTTP request deadline exceeded",
                                                ));
                                            }
                                            self.stream.read(bytes)
                                        }
                                    }
                                    let request =
                                        http::read_request(&mut BufReader::new(TimedRead {
                                            stream: &mut stream,
                                            deadline: std::time::Instant::now()
                                                + Duration::from_secs(5),
                                        }));
                                    let response = match request {
                                        Ok(request) => http::handle(
                                            request,
                                            &secret,
                                            &authorities,
                                            |message| {
                                                if stop.load(Ordering::SeqCst) {
                                                    return Err(http::Response::error(
                                                        503,
                                                        "MCP disabled",
                                                    ));
                                                }
                                                let (reply, rx) = mpsc::sync_channel(1);
                                                tx.try_send(Command {
                                                    request: message,
                                                    reply,
                                                    expires: std::time::Instant::now()
                                                        + Duration::from_secs(8),
                                                })
                                                .map_err(|_| {
                                                    http::Response::error(
                                                        503,
                                                        "MCP busy or disabled",
                                                    )
                                                })?;
                                                rx.recv_timeout(Duration::from_secs(10)).map_err(
                                                    |_| {
                                                        http::Response::error(
                                                            504,
                                                            "GUI request timed out",
                                                        )
                                                    },
                                                )
                                            },
                                        ),
                                        Err(error) => error,
                                    };
                                    let _ = response.write(&mut stream);
                                });
                            if task.is_err() {
                                workers.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(25))
                        }
                        Err(_) => break,
                    }
                }
                stopped.store(true, Ordering::SeqCst);
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            port,
            token,
            host,
            commands,
            stop,
        })
    }

    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}:{}/mcp", self.host, self.port)
    }

    pub fn client_config(&self) -> Result<String, String> {
        remote_config(&self.endpoint(), &self.token)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub fn capture_filter(filter: &str, port: u16) -> String {
    format!("({filter}) and not (tcp and (tcp.SrcPort == {port} or tcp.DstPort == {port}))")
}

fn valid_host(host: Ipv4Addr) -> bool {
    !host.is_unspecified() && !host.is_multicast() && !host.is_broadcast() && host.octets()[0] != 0
}

pub fn detect_lan_host() -> Option<Ipv4Addr> {
    // UDP connect chooses the default interface without sending a packet.
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if valid_host(ip) && !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn remote_config(endpoint: &str, token: &str) -> Result<String, String> {
    serde_json::to_string_pretty(&json!({"mcpServers":{"clumsymagi":{
        "url":endpoint,"headers":{"Authorization":format!("Bearer {token}")}
    }}}))
    .map_err(|e| e.to_string())
}

#[cfg(windows)]
pub fn new_token() -> Result<String, String> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> i32;
    }
    let mut bytes = [0u8; 32];
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), bytes.as_mut_ptr(), 32, 2) };
    if status < 0 {
        return Err("Cannot generate MCP access token".into());
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Value> {
    let mut line = String::new();
    reader.take(MAX_MESSAGE + 1).read_line(&mut line)?;
    if line.len() as u64 > MAX_MESSAGE || !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid or oversized MCP message",
        ));
    }
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Runs before console hiding, single-instance enforcement or GUI/driver initialization.
pub fn bridge(args: &[String]) -> Result<(), String> {
    let port = args
        .windows(2)
        .find(|w| w[0] == "--mcp-port")
        .and_then(|w| w[1].parse::<u16>().ok())
        .filter(|p| *p != 0)
        .ok_or("Missing --mcp-port")?;
    let token =
        std::env::var("CLUMSYMAGI_MCP_TOKEN").map_err(|_| "Missing CLUMSYMAGI_MCP_TOKEN")?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        if input.fill_buf().map_err(|e| e.to_string())?.is_empty() {
            return Ok(());
        }
        let request = match read_message(&mut input) {
            Ok(v) => v,
            Err(e) => {
                writeln!(output, "{}", rpc_error(Value::Null, -32700, &e.to_string()))
                    .map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
                continue;
            }
        };
        let mut stream = TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_secs(2),
        )
        .map_err(|_| "MCP is disabled or ClumsyMagi is not running")?;
        stream
            .set_read_timeout(Some(Duration::from_secs(12)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        let body = request.to_string();
        write!(stream,"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).map_err(|e|e.to_string())?;
        if let Some(response) = http::read_response(&mut BufReader::new(stream))? {
            writeln!(output, "{response}").map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
        }
    }
}

pub fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

pub fn tools() -> Value {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    let module = json!({"type":"string","enum":["lag","drop","throttle","duplicate","ood","tamper","reset","bandwidth"]});
    let definitions = vec![
        ("get_status", "Read filtering state, live configuration, deadline and driver availability.", empty.clone()),
        ("get_stats", "Read packet counters for the current or last run.", empty.clone()),
        ("get_logs", "Read the latest 100 event log entries for the current or last run.", empty.clone()),
        ("list_processes", "List processes (names, IDs and socket counts), paginated.", json!({"type":"object","properties":{"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":100}},"additionalProperties":false})),
        ("get_process_sockets", "Read up to 100 sockets for a process, paginated.", json!({"type":"object","properties":{"pid":{"type":"integer","minimum":1,"maximum":4294967295u64},"offset":{"type":"integer","minimum":0}},"required":["pid"],"additionalProperties":false})),
        ("validate_filter", "Compile a WinDivert expression without starting capture.", json!({"type":"object","properties":{"filter":{"type":"string","minLength":1,"maxLength":8192}},"required":["filter"],"additionalProperties":false})),
        ("set_filter", "Set a validated capture filter while stopped; detaches process targeting.", json!({"type":"object","properties":{"filter":{"type":"string","minLength":1,"maxLength":8192}},"required":["filter"],"additionalProperties":false})),
        ("set_target", "Select a running process with active sockets while stopped. Port-based targeting may include shared ports.", json!({"type":"object","properties":{"pid":{"type":"integer","minimum":1}},"required":["pid"],"additionalProperties":false})),
        ("configure_module", "Update a module's live parameters. Omitted fields remain unchanged.", json!({"type":"object","properties":{
            "module":module,"enabled":{"type":"boolean"},"inbound":{"type":"boolean"},"outbound":{"type":"boolean"},
            "chance_percent":{"type":"number","minimum":0,"maximum":100},"delay_ms":{"type":"integer","minimum":0,"maximum":15000},
            "throttle_frame_ms":{"type":"integer","minimum":0,"maximum":1000},"drop_throttled":{"type":"boolean"},
            "dup_count":{"type":"integer","minimum":2,"maximum":50},"redo_checksum":{"type":"boolean"},
            "bandwidth_limit_kbps":{"type":"integer","minimum":0,"maximum":99999}
        },"required":["module"],"additionalProperties":false})),
        ("start", "Start filtering with an automatic stop deadline (1-3600 seconds).", json!({"type":"object","properties":{"duration_secs":{"type":"integer","minimum":1,"maximum":3600}},"required":["duration_secs"],"additionalProperties":false})),
        ("stop", "Stop filtering and retain final counters and logs.", empty.clone()),
        ("reset_next", "Request a TCP RST on the next eligible packet; reset module must be enabled.", empty),
    ];
    json!({"tools":definitions.into_iter().map(|(name, description, schema)| json!({"name":name,"description":description,"inputSchema":schema})).collect::<Vec<_>>()})
}

/// Validate against our deliberately small schema vocabulary, before mutating state.
pub fn validate_arguments(name: &str, args: &Value) -> Result<(), String> {
    let catalog = tools();
    let tool = catalog["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .ok_or("Unknown tool")?;
    let schema = &tool["inputSchema"];
    let object = args.as_object().ok_or("Arguments must be an object")?;
    if let Some(required) = schema["required"].as_array() {
        for key in required {
            if !object.contains_key(key.as_str().unwrap()) {
                return Err(format!("Missing {key}"));
            }
        }
    }
    for (key, value) in object {
        let s = &schema["properties"][key];
        let valid = match s["type"].as_str() {
            Some("boolean") => value.is_boolean(),
            Some("string") => value.as_str().is_some_and(|v| {
                s["minLength"].as_u64().is_none_or(|n| v.len() as u64 >= n)
                    && s["maxLength"].as_u64().is_none_or(|n| v.len() as u64 <= n)
            }),
            Some("integer") => value.as_i64().is_some(),
            Some("number") => value.as_f64().is_some(),
            _ => false,
        };
        if !valid {
            return Err(format!("Invalid parameter: {key}"));
        }
        if let Some(choices) = s["enum"].as_array() {
            if !choices.contains(value) {
                return Err(format!("Invalid {key}"));
            }
        }
        if let Some(n) = value.as_f64() {
            if s["minimum"].as_f64().is_some_and(|min| n < min)
                || s["maximum"].as_f64().is_some_and(|max| n > max)
            {
                return Err(format!("{key} is out of range"));
            }
        }
    }
    Ok(())
}

pub fn dispatch(
    request: Value,
    mut call: impl FnMut(&str, &Value) -> Result<Value, String>,
) -> Value {
    use serde_json::{json, Value};
    let id = request.get("id").cloned();
    if request["jsonrpc"] != "2.0" || !request["method"].is_string() {
        return crate::mcp::rpc_error(id.unwrap_or(Value::Null), -32600, "Invalid request");
    }
    let Some(id) = id else {
        return Value::Null;
    };
    let result = match request["method"].as_str().unwrap() {
        "initialize" => {
            let requested = request["params"]["protocolVersion"].as_str().unwrap_or("");
            let version = match requested {
                "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25" => requested,
                _ => "2025-11-25",
            };
            json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"clumsymagi","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => crate::mcp::tools(),
        "tools/call" => {
            let name = request["params"]["name"].as_str().unwrap_or("");
            let args = request["params"]
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));
            let outcome =
                crate::mcp::validate_arguments(name, &args).and_then(|_| call(name, &args));
            match outcome {
                Ok(value) => {
                    json!({"content":[{"type":"text","text":value.to_string()}],"isError":false})
                }
                Err(error) => json!({"content":[{"type":"text","text":error}],"isError":true}),
            }
        }
        _ => return crate::mcp::rpc_error(id, -32601, "Method not found"),
    };
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_parameters_before_execution() {
        for args in [
            json!({"module":"lag","delay_ms":15001}),
            json!({"module":"lag","enabled":1}),
            json!({"module":"unknown"}),
            json!({"module":"lag","extra":true}),
        ] {
            assert!(validate_arguments("configure_module", &args).is_err());
        }
        assert!(validate_arguments(
            "configure_module",
            &json!({"module":"drop","chance_percent":12.5})
        )
        .is_ok());
        assert!(validate_arguments("start", &json!({})).is_err());
        assert!(validate_arguments("start", &json!({"duration_secs":0})).is_err());
    }
    #[test]
    fn framing_requires_bounded_newline_delimited_json() {
        assert!(read_message(&mut &b"{\"id\":1}\n"[..]).is_ok());
        assert!(read_message(&mut &b"{}"[..]).is_err());
        assert!(read_message(&mut &b"invalid\n"[..]).is_err());
        let large = vec![b' '; MAX_MESSAGE as usize + 2];
        assert!(read_message(&mut large.as_slice()).is_err());
    }
    #[test]
    fn control_port_is_excluded_from_impairment_filter() {
        assert_eq!(
            capture_filter("udp or tcp", 39761),
            "(udp or tcp) and not (tcp and (tcp.SrcPort == 39761 or tcp.DstPort == 39761))"
        );
    }
    #[test]
    fn remote_config_is_usable_without_a_windows_executable() {
        let config: Value = serde_json::from_str(
            &remote_config("http://192.168.1.10:39761/mcp", "test-secret").unwrap(),
        )
        .unwrap();
        let server = &config["mcpServers"]["clumsymagi"];
        assert_eq!(server["url"], "http://192.168.1.10:39761/mcp");
        assert_eq!(server["headers"]["Authorization"], "Bearer test-secret");
        assert!(server.get("command").is_none());
        assert!(!valid_host(Ipv4Addr::UNSPECIFIED));
        assert!(!valid_host(Ipv4Addr::BROADCAST));
    }
    #[test]
    fn protocol_handshake_discovery_and_tool_errors() {
        let no_call =
            |_: &str, _: &Value| -> Result<Value, String> { panic!("Unexpected tool execution") };
        let initialized = dispatch(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
            no_call,
        );
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        let catalog = dispatch(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            no_call,
        );
        assert_eq!(catalog["result"]["tools"].as_array().unwrap().len(), 12);
        assert!(dispatch(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            no_call
        )
        .is_null());
        let invalid = dispatch(
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start","arguments":{"duration_secs":0}}}),
            no_call,
        );
        assert_eq!(invalid["result"]["isError"], true);
        let result = dispatch(
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"stop"}}),
            |name, _| {
                assert_eq!(name, "stop");
                Ok(json!({"stopped":true}))
            },
        );
        assert_eq!(result["id"], 4);
        assert_eq!(result["result"]["isError"], false);
        let unknown = dispatch(json!({"jsonrpc":"2.0","id":5,"method":"unknown"}), no_call);
        assert_eq!(unknown["error"]["code"], -32601);
    }
}
