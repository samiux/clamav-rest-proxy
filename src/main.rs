use std::{
    io::{self, BufWriter},
    net::SocketAddr,
};

use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use axum_macros::debug_handler;
use clamav_tcp::ScanResult;
use futures::{Stream, StreamExt, TryStreamExt};
use serde::Serialize;
use tokio_util::io::StreamReader;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const EICAR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Serialize)]
struct Stuff {
    is_infected: bool,
    infected_files: Vec<String>,
}

// Handler that accepts a multipart form upload and streams each field to a file.
#[debug_handler]
async fn accept_data(mut multipart: Multipart) -> Result<Json<Stuff>, (StatusCode, String)> {
    // Check that there is a field
    let Ok(field) = multipart.next_field().await else {
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};
    let Some(field) = field else {
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};

    tracing::info!("Scanning {:?}", field.name());
    let Ok(bytes) = field.bytes().await else {
			return Err((StatusCode::BAD_REQUEST, "Missing multipart file".into()))
		};
    let stuff = bytes.to_vec();

		let data = match clamav_tcp::scan("localhost:3310", &mut &stuff[..], Some(8192)) {
			Ok(resp) => { 
				println!("{:?}", resp);
				resp
			},
			Err(e) => {
				println!("hmm, {}", e);
				return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed connecting to clamav".into()))
			}
		};

    Ok(Json(Stuff {
        is_infected: data.is_infected,
        infected_files: data.detected_infections,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clamav_rest_proxy=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    // build our application with a single route
    let app = Router::new().route(
        "/scan",
        post(accept_data).layer(DefaultBodyLimit::max(2_000_000_000)),
    );

    // run it with hyper on localhost:3000
    let sock_addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", sock_addr);
    axum::Server::bind(&sock_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
