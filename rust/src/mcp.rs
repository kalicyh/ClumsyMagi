//! Stdio MCP bridge to the GUI's authenticated, loopback-only command queue.
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
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
    pub commands: mpsc::Receiver<Command>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn start(port: u16, token: String) -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let (tx, commands) = mpsc::sync_channel(8);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let secret = token.clone();
        std::thread::Builder::new()
            .name("clumsymagi-mcp".into())
            .spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                            let envelope = read_message(&mut BufReader::new(&mut stream));
                            if stopped.load(Ordering::SeqCst) {
                                break;
                            }
                            let response = match envelope {
                                Ok(v) if v["token"].as_str() == Some(secret.as_str()) => {
                                    let (reply, rx) = mpsc::sync_channel(1);
                                    if tx
                                        .try_send(Command {
                                            request: v["request"].clone(),
                                            reply,
                                            expires: std::time::Instant::now()
                                                + Duration::from_secs(8),
                                        })
                                        .is_err()
                                    {
                                        json!({"bridgeError":"MCP is busy or disabled"})
                                    } else {
                                        rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(
                                            |_| json!({"bridgeError":"GUI request timed out"}),
                                        )
                                    }
                                }
                                _ => json!({"bridgeError":"Invalid MCP credentials or message"}),
                            };
                            let _ = writeln!(stream, "{response}");
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
            commands,
            stop,
        })
    }

    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }

    pub fn client_config(&self) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&json!({"mcpServers":{"clumsymagi":{
            "command":exe, "args":["--mcp", "--mcp-port", self.port.to_string()],
            "env":{"CLUMSYMAGI_MCP_TOKEN":self.token}
        }}}))
        .map_err(|e| e.to_string())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
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
        writeln!(stream, "{}", json!({"token":token,"request":request}))
            .map_err(|e| e.to_string())?;
        let response = read_message(&mut BufReader::new(stream)).map_err(|e| e.to_string())?;
        if let Some(error) = response["bridgeError"].as_str() {
            return Err(error.into());
        }
        if !response.is_null() {
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
    fn authenticated_requests_reach_gui_and_invalid_tokens_do_not() {
        let server = Server::start(0, "test-secret".into()).unwrap();
        let port = server.port;
        let send = |token: &str| {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            writeln!(
                stream,
                "{}",
                json!({"token":token,"request":{"jsonrpc":"2.0","id":7,"method":"ping"}})
            )
            .unwrap();
            read_message(&mut BufReader::new(stream)).unwrap()
        };
        assert!(send("wrong")["bridgeError"].is_string());
        assert!(server.commands.try_recv().is_err());
        std::thread::scope(|scope| {
            let client = scope.spawn(|| send("test-secret"));
            let command = server
                .commands
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            assert_eq!(command.request["id"], 7);
            command
                .reply
                .send(json!({"jsonrpc":"2.0","id":7,"result":{}}))
                .unwrap();
            assert_eq!(client.join().unwrap()["id"], 7);
        });
        let config: Value = serde_json::from_str(&server.client_config().unwrap()).unwrap();
        assert_eq!(
            config["mcpServers"]["clumsymagi"]["env"]["CLUMSYMAGI_MCP_TOKEN"],
            "test-secret"
        );
        let stopped = server.stop.clone();
        drop(server);
        assert!(stopped.load(Ordering::SeqCst));
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
