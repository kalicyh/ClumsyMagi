//! Bounded HTTP/1.1 transport. Each connection carries one request and is closed.
//! Stateless Streamable HTTP: JSON responses, 202 notifications, no SSE/session IDs.
use super::{rpc_error, MAX_MESSAGE};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

const MAX_HEADERS: usize = 16 * 1024;
#[derive(Debug)]
pub(super) struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
#[derive(Debug)]
pub(super) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
    pub fn error(status: u16, text: &str) -> Self {
        Self::new(status, json!({"error":text}).to_string())
    }
    pub fn write(&self, output: &mut impl Write) -> io::Result<()> {
        let extra = match self.status {
            401 => "WWW-Authenticate: Bearer realm=\"ClumsyMagi\"\r\n",
            405 => "Allow: POST\r\n",
            _ => "",
        };
        write!(output, "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n{}\r\n", self.status, reason(self.status), self.body.len(), extra)?;
        output.write_all(&self.body)
    }
}
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Gateway Timeout",
    }
}
impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}
fn line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, Response> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| Response::error(400, "Incomplete HTTP request"))?;
    if bytes.len() > limit {
        return Err(Response::error(431, "HTTP headers too large"));
    }
    if !bytes.ends_with(b"\r\n") {
        return Err(Response::error(400, "Expected CRLF"));
    }
    Ok(bytes)
}

pub(super) fn read_request(reader: &mut impl BufRead) -> Result<Request, Response> {
    let mut bytes = Vec::new();
    loop {
        let next = line(reader, MAX_HEADERS - bytes.len())?;
        let done = next == b"\r\n";
        bytes.extend(next);
        if done {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(parsed.parse(&bytes), Ok(httparse::Status::Complete(_))) {
        return Err(Response::error(400, "Invalid HTTP headers"));
    }
    let mut request = Request {
        method: parsed.method.unwrap_or("").into(),
        path: parsed.path.unwrap_or("").into(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        // Avoid ambiguous framing and authentication through duplicate headers.
        if request.header(&name).is_some() {
            return Err(Response::error(400, "Duplicate HTTP header"));
        }
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Response::error(400, "Invalid header encoding"))?;
        request.headers.push((name, value.trim().into()));
    }
    if request.header("expect").is_some() {
        return Err(Response::error(417, "Expect is not supported"));
    }
    let length = request.header("content-length");
    let transfer = request.header("transfer-encoding");
    if transfer.is_some() && length.is_some() {
        return Err(Response::error(400, "Ambiguous body framing"));
    }
    if let Some(transfer) = transfer {
        if !transfer.eq_ignore_ascii_case("chunked") {
            return Err(Response::error(400, "Unsupported transfer encoding"));
        }
        loop {
            let chunk_line = line(reader, 128)?;
            let chunk = std::str::from_utf8(&chunk_line)
                .map_err(|_| Response::error(400, "Invalid chunk size"))?;
            let size = usize::from_str_radix(chunk.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| Response::error(400, "Invalid chunk size"))?;
            if size == 0 {
                let mut trailer_bytes = 0;
                loop {
                    let trailer = line(reader, MAX_HEADERS - trailer_bytes)?;
                    trailer_bytes += trailer.len();
                    if trailer == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            if size as u64 > MAX_MESSAGE - request.body.len() as u64 {
                return Err(Response::error(413, "MCP message too large"));
            }
            let offset = request.body.len();
            request.body.resize(offset + size, 0);
            reader
                .read_exact(&mut request.body[offset..])
                .map_err(|_| Response::error(400, "Incomplete body"))?;
            if line(reader, 2)? != b"\r\n" {
                return Err(Response::error(400, "Invalid chunk terminator"));
            }
        }
    } else if let Some(length) = length {
        let size = length
            .parse::<usize>()
            .map_err(|_| Response::error(400, "Invalid Content-Length"))?;
        if size as u64 > MAX_MESSAGE {
            return Err(Response::error(413, "MCP message too large"));
        }
        request.body.resize(size, 0);
        reader
            .read_exact(&mut request.body)
            .map_err(|_| Response::error(400, "Incomplete body"))?;
    } else if request.method == "POST" {
        return Err(Response::error(
            411,
            "Content-Length or chunked body required",
        ));
    }
    Ok(request)
}

fn token_matches(actual: &str, expected: &str) -> bool {
    actual.len() == expected.len()
        && actual
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
pub(super) fn handle(
    request: Request,
    token: &str,
    authorities: &[String],
    submit: impl FnOnce(Value) -> Result<Value, Response>,
) -> Response {
    if request.path != "/mcp" {
        return Response::error(404, "Use /mcp");
    }
    // Native MCP clients do not send Origin. Reject browser-originated access.
    if request.header("origin").is_some() {
        return Response::error(403, "Browser origins are not allowed");
    }
    if !request.header("host").is_some_and(|host| {
        authorities
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }) {
        return Response::error(403, "Host is not an advertised MCP address");
    }
    let supplied = request
        .header("authorization")
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, value)| value);
    if !supplied.is_some_and(|value| token_matches(value, token)) {
        return Response::error(401, "Bearer token required");
    }
    if request.method != "POST" {
        return Response::error(
            405,
            "Only POST is supported; server has no SSE stream or sessions",
        );
    }
    if request
        .header("mcp-protocol-version")
        .is_some_and(|version| {
            !matches!(
                version,
                "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25"
            )
        })
    {
        return Response::error(400, "Unsupported MCP protocol version");
    }
    if !request.header("content-type").is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    }) {
        return Response::error(415, "Use application/json");
    }
    if !request.header("accept").is_some_and(|v| {
        v.split(',').any(|part| {
            matches!(
                part.trim().split(';').next().unwrap_or(""),
                "application/json" | "*/*"
            )
        })
    }) {
        return Response::error(406, "Accept application/json responses");
    }
    let message: Value = match serde_json::from_slice(&request.body) {
        Ok(value) => value,
        Err(_) => {
            return Response::new(
                400,
                rpc_error(Value::Null, -32700, "Invalid JSON").to_string(),
            )
        }
    };
    if message["jsonrpc"] != "2.0" || !message.is_object() {
        return Response::new(
            400,
            rpc_error(Value::Null, -32600, "Invalid request").to_string(),
        );
    }
    // Responses to server requests (none issued currently) require no response body.
    if message.get("method").is_none()
        && (message.get("result").is_some() || message.get("error").is_some())
    {
        return Response::new(202, Vec::new());
    }
    match submit(message) {
        Ok(value) if value.is_null() => Response::new(202, Vec::new()),
        Ok(value) => Response::new(200, value.to_string()),
        Err(error) => error,
    }
}

/// Read a JSON HTTP response for the optional local stdio bridge.
pub(super) fn read_response(reader: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut bytes = Vec::new();
    loop {
        let next = line(reader, MAX_HEADERS - bytes.len()).map_err(|_| "Invalid HTTP response")?;
        let done = next == b"\r\n";
        bytes.extend(next);
        if done {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(&bytes), Ok(httparse::Status::Complete(_))) {
        return Err("Invalid HTTP response".into());
    }
    let status = response.code.unwrap_or(500);
    if status == 202 {
        return Ok(None);
    }
    if status != 200 {
        return Err(format!(
            "MCP HTTP error {status}; check service, IP and token"
        ));
    }
    let size = response
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or("Missing response size")?;
    if size > 4 * 1024 * 1024 {
        return Err("MCP response too large".into());
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(method: &str, extra: &str, body: &str) -> Request {
        let wire = format!("{method} /mcp HTTP/1.1\r\nHost: 192.168.1.10:39761\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{extra}Content-Length: {}\r\n\r\n{body}", body.len());
        read_request(&mut wire.as_bytes()).unwrap()
    }
    fn run(request: Request) -> Response {
        handle(request, "secret", &["192.168.1.10:39761".into()], |value| {
            Ok(super::super::dispatch(value, |_, _| {
                Ok(json!({"stopped":true}))
            }))
        })
    }
    #[test]
    fn native_remote_client_can_initialize_list_call_and_notify() {
        for (message, status) in [
            (
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
                200,
            ),
            (json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}), 200),
            (
                json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stop"}}),
                200,
            ),
            (
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                202,
            ),
        ] {
            let response = run(request(
                "POST",
                "Authorization: Bearer secret\r\n",
                &message.to_string(),
            ));
            assert_eq!(response.status, status);
            if status == 200 {
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body).unwrap()["id"],
                    message["id"]
                );
            } else {
                assert!(response.body.is_empty());
            }
        }
    }
    #[test]
    fn unauthorized_and_browser_requests_never_reach_tools() {
        for (headers, status) in [
            ("", 401),
            ("Authorization: Bearer wrong\r\n", 401),
            (
                "Authorization: Bearer secret\r\nOrigin: https://evil.example\r\n",
                403,
            ),
        ] {
            let response = handle(
                request("POST", headers, "{}"),
                "secret",
                &["192.168.1.10:39761".into()],
                |_| panic!("Unauthorized dispatch"),
            );
            assert_eq!(response.status, status);
        }
        assert_eq!(
            handle(
                request("POST", "Authorization: Bearer secret\r\n", "{}"),
                "secret",
                &["127.0.0.1:39761".into()],
                |_| panic!("Bad Host dispatch")
            )
            .status,
            403
        );
        assert_eq!(
            run(request("GET", "Authorization: Bearer secret\r\n", "")).status,
            405
        );
        assert_eq!(
            run(request(
                "POST",
                "Authorization: Bearer secret\r\nMCP-Protocol-Version: invalid\r\n",
                "{}"
            ))
            .status,
            400
        );
    }
    #[test]
    fn malformed_and_oversized_framing_is_rejected() {
        for wire in [
            "POST /mcp HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nContent-Length: 999999\r\n\r\n",
        ] {
            assert!(read_request(&mut wire.as_bytes()).is_err());
        }
        let wire = b"POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(read_request(&mut &wire[..]).unwrap().body, b"{}");
    }
}
