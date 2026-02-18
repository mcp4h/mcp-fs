mod fs;
mod protocol;
mod server;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
	let config = server::load_config()?;
	server::init_tracing(&config);
	server::init_preview_cache(&config);
	let result = server::run(config).await;
	opentelemetry::global::shutdown_tracer_provider();
	result
}
