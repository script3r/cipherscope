use serde::Deserialize;
use vercel_runtime::{Body, Error, Request, Response, StatusCode, run};

use cipherscope::patterns::Language;
use cipherscope::scan_snippet;

const MAX_BODY_BYTES: usize = 64 * 1024;
const SOURCE_LABEL: &str = "snippet";
const ALLOWED_ORIGINS: [&str; 4] = [
    "https://cipherscope.com",
    "https://www.cipherscope.com",
    "http://localhost:8081",
    "http://100.104.34.90:8081",
];

#[derive(Deserialize)]
struct ScanRequest {
    code: String,
    language: String,
}

fn parse_language(raw: &str) -> Option<Language> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "c" => Some(Language::C),
        "cpp" | "c++" => Some(Language::Cpp),
        "java" => Some(Language::Java),
        "python" | "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "swift" => Some(Language::Swift),
        "php" => Some(Language::Php),
        "objc" | "objective-c" => Some(Language::Objc),
        "rust" | "rs" => Some(Language::Rust),
        _ => None,
    }
}

fn body_bytes(body: &Body) -> Vec<u8> {
    match body {
        Body::Binary(data) => data.clone(),
        Body::Text(text) => text.as_bytes().to_vec(),
        Body::Empty => Vec::new(),
    }
}

fn with_cors(mut builder: http::response::Builder, origin: &str) -> http::response::Builder {
    builder = builder
        .header("access-control-allow-origin", origin)
        .header("access-control-allow-methods", "POST, OPTIONS")
        .header("access-control-allow-headers", "content-type")
        .header("access-control-max-age", "600")
        .header("vary", "Origin");
    builder
}

fn json_response_with_origin(
    status: StatusCode,
    value: serde_json::Value,
    origin: &str,
) -> Response<Body> {
    with_cors(Response::builder().status(status), origin)
        .header("content-type", "application/json")
        .body(Body::Text(value.to_string()))
        .unwrap_or_else(|_| Response::new(Body::Text("{\"error\":\"response\"}".to_string())))
}

fn error_response(status: StatusCode, message: &str, origin: &str) -> Response<Body> {
    json_response_with_origin(status, serde_json::json!({ "error": message }), origin)
}

fn allowed_origin(req: &Request) -> Option<&'static str> {
    let origin = req.headers().get("origin")?.to_str().ok()?;
    ALLOWED_ORIGINS
        .iter()
        .copied()
        .find(|allowed| *allowed == origin)
}

async fn handler(req: Request) -> Result<Response<Body>, Error> {
    let Some(origin) = allowed_origin(&req) else {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::Empty)
            .unwrap_or_else(|_| Response::new(Body::Empty)));
    };

    if req.method() == "OPTIONS" {
        return Ok(
            with_cors(Response::builder().status(StatusCode::NO_CONTENT), origin)
                .header("allow", "POST, OPTIONS")
                .body(Body::Empty)
                .unwrap_or_else(|_| Response::new(Body::Empty)),
        );
    }

    if req.method() != "POST" {
        return Ok(with_cors(
            Response::builder().status(StatusCode::METHOD_NOT_ALLOWED),
            origin,
        )
        .header("allow", "POST, OPTIONS")
        .body(Body::Empty)
        .unwrap_or_else(|_| Response::new(Body::Empty)));
    }

    let raw_body = body_bytes(req.body());
    if raw_body.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "missing body",
            origin,
        ));
    }
    if raw_body.len() > MAX_BODY_BYTES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload too large",
            origin,
        ));
    }

    let payload: ScanRequest = match serde_json::from_slice(&raw_body) {
        Ok(payload) => payload,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "invalid json",
                origin,
            ));
        }
    };
    let code_bytes = payload.code.len();
    if code_bytes == 0 {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "empty code",
            origin,
        ));
    }
    if code_bytes > MAX_BODY_BYTES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "code too large",
            origin,
        ));
    }

    let lang = match parse_language(&payload.language) {
        Some(lang) => lang,
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "unsupported language",
                origin,
            ));
        }
    };

    let items = match scan_snippet(&payload.code, lang, SOURCE_LABEL) {
        Ok(items) => items,
        Err(_) => {
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan failed",
                origin,
            ));
        }
    };

    Ok(json_response_with_origin(
        StatusCode::OK,
        serde_json::json!({ "items": items }),
        origin,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}
