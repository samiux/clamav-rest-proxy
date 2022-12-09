use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use axum_macros::debug_handler;


use serde::Serialize;
use std::{
    convert::Infallible,
    net::{SocketAddr, ToSocketAddrs},
};
use tracing::{
    log::warn,
    log::{error}, instrument,
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[allow(dead_code)]
const EICAR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Debug, Clone)]
struct ServerConfig {
    clamav_upstream: SocketAddr,
}

#[derive(Serialize)]
struct ScanInfo {
    is_infected: bool,
    infected_files: Vec<String>,
    detected_mime_type: Option<String>,
}

// Handler that accepts a multipart form upload and streams each field to a file.
#[debug_handler]
async fn accept_data(
    Extension(server_config): Extension<ServerConfig>,
    mut multipart: Multipart,
) -> Result<Json<ScanInfo>, (StatusCode, String)> {
    // Check that there is a field
    let Ok(field) = multipart.next_field().await else {
            warn!("Got a request without a form field");
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};
    let Some(field) = field else {
            warn!("Got a request without a form field");
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};

    tracing::info!("Scanning {:?}", field.name());
    let Ok(bytes) = field.bytes().await else {
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};
    let body = bytes.to_vec();

    let data = match clamav_tcp::scan(server_config.clamav_upstream, &mut &body[..], Some(8192)) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Received a ClamAVClientError: {}", e.to_string());
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed connecting to clamav".into(),
            ));
        }
    };

    if data.is_infected {
        warn!("DETECTION: Found {}", data.detected_infections.join(","));
    }

    let detection = infer::get(&body);
    let detection_string = detection.map(|detection| detection.to_string());

    Ok(Json(ScanInfo {
        is_infected: data.is_infected,
        infected_files: data.detected_infections,
        detected_mime_type: detection_string,
    }))
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or("3000".into())
        .parse()
        .unwrap();

    // Parse server config
    let server_cfg = ServerConfig {
        clamav_upstream: std::env::var("CLAMAV_UPSTREAM")
            .unwrap_or("localhost:3310".into())
            .to_socket_addrs()
            .expect("Couldn't parse CLAMAV_UPSTREAM into a socket address")
            .collect::<Vec<SocketAddr>>()[0],
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clamav_rest_proxy=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    // build our application with a single route
    tracing::info!("Using ClamAV at {}", server_cfg.clamav_upstream);
    let app = Router::new().route(
        "/scan",
        post(accept_data)
            .layer::<Extension<ServerConfig>, Body, Infallible>(Extension(server_cfg))
            .layer(DefaultBodyLimit::max(104_857_600)),
    );

    // run it with hyper on localhost:3000
    let sock_addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!("listening on {}", sock_addr);
    axum::Server::bind(&sock_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
