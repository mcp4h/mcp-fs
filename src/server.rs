use crate::fs;
use crate::protocol::{Request, Response};
use anyhow::{anyhow, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace as sdktrace;
use opentelemetry_semantic_conventions::resource as semconv;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use syntect::html::{line_tokens_to_classed_spans, ClassStyle};
use syntect::parsing::{ParseState, ScopeStack, SyntaxSet};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info_span, warn, Span};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug)]
struct ProtocolError {
	code: i64,
	message: String,
}

impl ProtocolError {
	fn new(code: i64, message: impl Into<String>) -> Self {
		Self {
			code,
			message: message.into()
		}
	}
}

impl std::fmt::Display for ProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for ProtocolError {}

#[derive(Debug)]
struct RequestedScopeError {
	scopes: Vec<String>,
}

impl std::fmt::Display for RequestedScopeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "path outside root")
	}
}

impl std::error::Error for RequestedScopeError {}

#[derive(Clone)]
struct PreviewEntry {
	uri: String,
	html: String,
	diff: String,
	path: String,
}

struct PreviewCache {
	capacity: Option<usize>,
	map: HashMap<String, PreviewEntry>,
	order: VecDeque<String>,
}

impl PreviewCache {
	fn new(capacity: Option<usize>) -> Self {
		Self {
			capacity,
			map: HashMap::new(),
			order: VecDeque::new()
		}
	}
	fn set_capacity(&mut self, capacity: Option<usize>) {
		self.capacity = capacity;
		self.trim();
	}
	fn insert(&mut self, entry: PreviewEntry) {
		let key = entry.uri.clone();
		if self.map.contains_key(&key) {
			self.touch(&key);
			self.map.insert(key, entry);
			return;
		}
		self.map.insert(key.clone(), entry);
		self.order.push_back(key);
		self.trim();
	}
	fn get(&mut self, uri: &str) -> Option<PreviewEntry> {
		if self.map.contains_key(uri) {
			self.touch(uri);
		}
		self.map
			.get(uri)
			.cloned()
	}
	fn list(&self) -> Vec<PreviewEntry> {
		self.order
			.iter()
			.filter_map(|key| self.map.get(key))
			.cloned()
			.collect()
	}
	fn touch(&mut self, uri: &str) {
		if let Some(pos) = self.order
			.iter()
			.position(|item| item == uri) {
			self.order.remove(pos);
		}
		self.order.push_back(uri.to_string());
	}
	fn trim(&mut self) {
		let Some(capacity) = self.capacity else {
			return;
		};
		while self.order.len() > capacity {
			if let Some(key) = self.order.pop_front() {
				self.map.remove(&key);
			}
		}
	}
}

static PREVIEW_CACHE: Lazy<Mutex<PreviewCache>> = Lazy::new(|| Mutex::new(PreviewCache::new(Some(100))));

static SYNTAX_SET: Lazy<SyntaxSet> = Lazy::new(SyntaxSet::load_defaults_newlines);

#[derive(Clone, Debug)]
pub struct RootConfig {
	pub path: PathBuf,
	pub path_canon: PathBuf,
	pub display: String,
	pub default: bool,
	pub immutable: Vec<String>,
	pub deny: Vec<String>,
	pub allow: Vec<String>,
}

#[derive(Clone, Debug)]
struct CallRoot {
	path: PathBuf,
	path_canon: PathBuf,
	display: String,
	default: bool,
	blocked: bool,
	policy_immutable: Vec<String>,
	deny: Vec<String>,
	policy_allow: Vec<String>,
	immutable_set: Option<GlobSet>,
	policy_immutable_set: Option<GlobSet>,
	deny_set: Option<GlobSet>,
	allow_set: Option<GlobSet>,
	policy_allow_set: Option<GlobSet>,
}

#[derive(Clone, Debug)]
struct CallConfig {
	roots: Vec<CallRoot>,
	default_root: PathBuf,
	allow_escape: bool,
	policy_active: bool,
	find_limit: Option<usize>,
	search_max_bytes: Option<usize>,
	search_summary_top: Option<usize>,
	read_max_bytes: Option<usize>,
	read_max_line_bytes: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Config {
	pub roots: Vec<RootConfig>,
	pub default_root: PathBuf,
	pub default_root_canon: PathBuf,
	pub allow_escape: bool,
	pub find_limit: Option<usize>,
	pub search_max_bytes: Option<usize>,
	pub search_summary_top: Option<usize>,
	pub read_max_bytes: Option<usize>,
	pub read_max_line_bytes: Option<usize>,
	pub preview_cache_size: Option<usize>,
	pub otel_enabled: bool,
	pub otel_endpoint: String,
	pub otel_service_name: String,
	pub session_id: String,
}

#[derive(Clone, Debug)]
struct RootInput {
	path: String,
	default: Option<bool>,
	immutable: Vec<String>,
	deny: Vec<String>,
	allow: Vec<String>,
	blocked: Option<bool>,
}

pub fn load_config() -> Result<Config> {
	let mut root: Option<String> = None;
	let mut allow_escape = false;
	let mut find_limit: Option<usize> = Some(200);
	let mut search_max_bytes: Option<usize> = Some(50 * 1024);
	let mut search_summary_top: Option<usize> = Some(20);
	let mut read_max_bytes: Option<usize> = Some(50 * 1024);
	let mut read_max_line_bytes: Option<usize> = Some(25 * 1024);
	let mut allowed_roots_raw: Vec<String> = Vec::new();
	let mut preview_cache_size: Option<usize> = Some(100);
	let mut otel_enabled = true;
	let mut otel_endpoint = String::from("http://127.0.0.1:4317");
	let mut otel_service_name = String::from("mcp-fs");
	let mut config_path: Option<String> = None;
	let mut print_schema = false;
	let mut args = std::env::args().skip(1);
	while let Some(arg) = args.next() {
		match arg.as_str() {
			"--root" => {
				let value = args.next().ok_or_else(|| anyhow!("--root requires a value"))?;
				root = Some(value);
			}
			"--allow-escape" => {
				allow_escape = true;
			}
			"--config" => {
				let value = args.next().ok_or_else(|| anyhow!("--config requires a value"))?;
				config_path = Some(value);
			}
			"--print-config-schema" => {
				print_schema = true;
			}
			"--find-limit" => {
				let value = args.next().ok_or_else(|| anyhow!("--find-limit requires a value"))?;
				find_limit = parse_find_limit(&value, "--find-limit")?;
			}
			"--search-max-bytes" => {
				let value = args.next().ok_or_else(|| anyhow!("--search-max-bytes requires a value"))?;
				search_max_bytes = parse_byte_limit(&value, "--search-max-bytes")?;
			}
			"--search-summary-top" => {
				let value = args.next().ok_or_else(|| anyhow!("--search-summary-top requires a value"))?;
				search_summary_top = parse_byte_limit(&value, "--search-summary-top")?;
			}
			"--read-max-bytes" => {
				let value = args.next().ok_or_else(|| anyhow!("--read-max-bytes requires a value"))?;
				read_max_bytes = parse_byte_limit(&value, "--read-max-bytes")?;
			}
			"--read-max-line-bytes" => {
				let value = args.next().ok_or_else(|| anyhow!("--read-max-line-bytes requires a value"))?;
				read_max_line_bytes = parse_byte_limit(&value, "--read-max-line-bytes")?;
			}
			"--allow-root" => {
				let value = args.next().ok_or_else(|| anyhow!("--allow-root requires a value"))?;
				if !value.trim().is_empty() {
					allowed_roots_raw.push(value);
				}
			}
			"--preview-cache-size" => {
				let value = args.next().ok_or_else(|| anyhow!("--preview-cache-size requires a value"))?;
				preview_cache_size = parse_optional_limit(&value, "--preview-cache-size")?;
			}
			"--otel-enabled" => {
				let value = args.next().ok_or_else(|| anyhow!("--otel-enabled requires a value"))?;
				otel_enabled = parse_bool(&value, "--otel-enabled")?;
			}
			"--otel-endpoint" => {
				let value = args.next().ok_or_else(|| anyhow!("--otel-endpoint requires a value"))?;
				otel_endpoint = value;
			}
			"--otel-service-name" => {
				let value = args.next().ok_or_else(|| anyhow!("--otel-service-name requires a value"))?;
				otel_service_name = value;
			}
			_ => return Err(anyhow!("unknown argument: {}", arg)),
		}
	}
	if root.is_none() {
		if let Ok(env_root) = std::env::var("MCP_ROOT") {
			if !env_root.trim().is_empty() {
				root = Some(env_root);
			}
		}
	}
	if config_path.is_none() {
		if let Ok(env_config) = std::env::var("MCP_CONFIG") {
			if !env_config.trim().is_empty() {
				config_path = Some(env_config);
			}
		}
	}
	if !allow_escape {
		if let Ok(env_allow) = std::env::var("MCP_ALLOW_ESCAPE") {
			let value = env_allow.to_lowercase();
			allow_escape = value == "1" || value == "true" || value == "yes";
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_FIND_LIMIT") {
		if !env_limit.trim().is_empty() {
			find_limit = parse_find_limit(&env_limit, "MCP_FIND_LIMIT")?;
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_SEARCH_MAX_BYTES") {
		if !env_limit.trim().is_empty() {
			search_max_bytes = parse_byte_limit(&env_limit, "MCP_SEARCH_MAX_BYTES")?;
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_SEARCH_SUMMARY_TOP") {
		if !env_limit.trim().is_empty() {
			search_summary_top = parse_byte_limit(&env_limit, "MCP_SEARCH_SUMMARY_TOP")?;
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_READ_MAX_BYTES") {
		if !env_limit.trim().is_empty() {
			read_max_bytes = parse_byte_limit(&env_limit, "MCP_READ_MAX_BYTES")?;
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_READ_MAX_LINE_BYTES") {
		if !env_limit.trim().is_empty() {
			read_max_line_bytes = parse_byte_limit(&env_limit, "MCP_READ_MAX_LINE_BYTES")?;
		}
	}
	if let Ok(env_roots) = std::env::var("MCP_ALLOWED_ROOTS") {
		for value in env_roots.split(',') {
			let trimmed = value.trim();
			if !trimmed.is_empty() {
				allowed_roots_raw.push(trimmed.to_string());
			}
		}
	}
	if let Ok(env_limit) = std::env::var("MCP_PREVIEW_CACHE_SIZE") {
		if !env_limit.trim().is_empty() {
			preview_cache_size = parse_optional_limit(&env_limit, "MCP_PREVIEW_CACHE_SIZE")?;
		}
	}
	if let Ok(env_enabled) = std::env::var("MCP_OTEL_ENABLED") {
		if !env_enabled.trim().is_empty() {
			otel_enabled = parse_bool(&env_enabled, "MCP_OTEL_ENABLED")?;
		}
	}
	if let Ok(env_endpoint) = std::env::var("MCP_OTEL_ENDPOINT") {
		if !env_endpoint.trim().is_empty() {
			otel_endpoint = env_endpoint;
		}
	}
	if let Ok(env_service) = std::env::var("MCP_OTEL_SERVICE_NAME") {
		if !env_service.trim().is_empty() {
			otel_service_name = env_service;
		}
	}
	if print_schema {
		let schema = config_schema();
		let payload = serde_json::to_string_pretty(&schema)?;
		println!("{}", payload);
		std::process::exit(0);
	}
	let cwd = std::env::current_dir()?;
	let root = root.unwrap_or_else(|| cwd.to_string_lossy().to_string());
	let mut roots_input = Vec::new();
	roots_input.push(RootInput {
		path: root,
		default: Some(true),
		immutable: Vec::new(),
		deny: Vec::new(),
		allow: Vec::new(),
		blocked: None,
	});
	for value in allowed_roots_raw {
		if !value.trim().is_empty() {
			roots_input.push(RootInput {
				path: value,
				default: Some(false),
				immutable: Vec::new(),
				deny: Vec::new(),
				allow: Vec::new(),
				blocked: None,
			});
		}
	}
	let roots = build_root_configs(&roots_input, &cwd, false)?;
	let (roots, default_root, default_root_canon) = finalize_roots(roots)?;
	let base = Config {
		roots,
		default_root,
		default_root_canon,
		allow_escape,
		find_limit,
		search_max_bytes,
		search_summary_top,
		read_max_bytes,
		read_max_line_bytes,
		preview_cache_size,
		otel_enabled,
		otel_endpoint,
		otel_service_name,
		session_id: uuid::Uuid::new_v4().to_string(),
	};
	if let Some(path) = config_path {
		let override_value = load_config_value(&path)?;
		return apply_config_override(base, &override_value, &cwd);
	}
	Ok(base)
}

pub fn init_preview_cache(config: &Config) {
	let mut cache = PREVIEW_CACHE.lock().expect("preview cache lock");
	cache.set_capacity(config.preview_cache_size);
}

pub fn init_tracing(config: &Config) {
	let _ = global::set_error_handler(|_| {});
	let resource = Resource::new(
		vec![
		opentelemetry::KeyValue::new(semconv::SERVICE_NAME, config.otel_service_name.clone()),
		opentelemetry::KeyValue::new(semconv::SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
		opentelemetry::KeyValue::new("mcp.session_id", config.session_id.clone()),
		opentelemetry::KeyValue::new("mcp.root", config.default_root.display().to_string()),
		]
	);
	let tracing_layer = if config.otel_enabled {
		let exporter = opentelemetry_otlp::new_exporter().tonic().with_endpoint(config.otel_endpoint.clone());
		let provider = opentelemetry_otlp::new_pipeline()
			.tracing()
			.with_exporter(exporter)
			.with_trace_config(sdktrace::Config::default().with_resource(resource))
			.install_batch(opentelemetry_sdk::runtime::Tokio)
			.ok();
		if let Some(provider) = provider {
			let tracer = provider.tracer(config.otel_service_name.clone());
			global::set_tracer_provider(provider);
			Some(OpenTelemetryLayer::new(tracer))
		}
		else {
			None
		}
	}
	else {
		None
	};
	let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
	let subscriber = tracing_subscriber::registry().with(fmt_layer);
	if let Some(layer) = tracing_layer {
		subscriber.with(layer).init();
	}
	else {
		subscriber.init();
	}
}

pub async fn run(config: Config) -> Result<()> {
	let stdin = io::stdin();
	let stdout = io::stdout();
	let mut reader = BufReader::new(stdin).lines();
	let mut writer = io::BufWriter::new(stdout);
	let mut config = config;
	while let Some(line) = reader.next_line().await? {
		if line.trim().is_empty() {
			continue;
		}
		let req: Request = match serde_json::from_str(&line) {
			Ok(req) => req,
			Err(err) => {
				let resp = Response::err(Value::Null, -32700, err.to_string());
				write_response(&mut writer, resp).await?;
				continue;
			}
		};
		if req.method == "initialize" {
			if let Err(err) = apply_initialize_config(&mut config, &req) {
				let resp = if let Some(protocol) = err.downcast_ref::<ProtocolError>() {
					Response::err(req.id.clone(), protocol.code, protocol.message.clone())
				}
				else {
					Response::err(req.id.clone(), -32000, err.to_string())
				};
				write_response(&mut writer, resp).await?;
				continue;
			}
			init_preview_cache(&config);
		}
		let resp = handle_request(&config, req).await;
		write_response(&mut writer, resp).await?;
	}
	Ok(())
}

fn apply_initialize_config(config: &mut Config, req: &Request) -> Result<()> {
	let Some(value) = req.params
		.get("capabilities")
		.and_then(|caps| caps.get("experimental"))
		.and_then(|exp| exp.get("configuration")) else {
		return Ok(());
	};
	let cwd = std::env::current_dir()?;
	let updated = apply_config_override(config.clone(), value, &cwd)
		.map_err(|err| ProtocolError::new(-32602, err.to_string()))?;
	*config = updated;
	Ok(())
}

struct ToolOutcome {
	value: Value,
	meta: Option<Value>,
}

async fn handle_request(config: &Config, req: Request) -> Response {
	let method = req.method.clone();
	let tool_name = extract_tool_name(&method, &req.params);
	let request_root = extract_request_root(&method, &req.params);
	let preview_meta = if method == "tools/call" {
		parse_meta_preview(
			req.params
				.get("_meta")
				.and_then(|meta| meta.get("preview"))
		)
	}
	else {
		false
	};
	let span = info_span!(
		"mcp.request",
		"mcp.session_id" = %config.session_id,
		"mcp.method" = %method,
		"mcp.tool_name" = tool_name.as_deref().unwrap_or(""),
		"mcp.root" = %config.default_root.display(),
		"mcp.request_root" = request_root.as_deref().unwrap_or(""),
		"mcp.is_error" = tracing::field::Empty,
		"mcp.error_code" = tracing::field::Empty,
		"mcp.mode" = tracing::field::Empty,
		"mcp.count" = tracing::field::Empty,
		"mcp.response_bytes" = tracing::field::Empty,
	);
	let _guard = span.enter();
	match route(config, &req).await {
		Ok(outcome) => {
			record_result(&span, &outcome.value);
			let merged_meta = merge_meta(preview_meta, outcome.meta);
			if let Some(meta) = merged_meta {
				Response::ok_with_meta(req.id, outcome.value, meta)
			}
			else {
				Response::ok(req.id, outcome.value)
			}
		}
		Err(err) => {
			if let Some(protocol) = err.downcast_ref::<ProtocolError>() {
				Response::err(req.id, protocol.code, protocol.message.clone())
			}
			else {
				Response::err(req.id, -32000, err.to_string())
			}
		}
	}
}

async fn route(config: &Config, req: &Request) -> Result<ToolOutcome> {
	match req.method.as_str() {
		"initialize" => Ok(
			ToolOutcome {
				value: json!({
					"serverInfo": {
                "name": "mcp-fs",
                "version": "0.1.0"
            },
					"configSchema": config_schema(),
				"capabilities": {
                "resources": {
                    "read": true,
                    "list": true
                },
                "tools": {
                    "list": true,
                    "call": true
                },
                "experimental": {
                    "policy": true
                },
                "_meta": {
                    "server": "mcp-fs",
                    "vendor": "celerex"
                }
            }
				}),
				meta: None
			}
		),
		"tools/list" => Ok(ToolOutcome {
			value: json!({
				"tools": tool_definitions(),
			}),
			meta: None
		}),
		"tools/call" => {
			let name = req.params
				.get("name")
				.and_then(Value::as_str)
				.ok_or_else(|| ProtocolError::new(-32602, "name is required"))?;
			let arguments = req.params
				.get("arguments")
				.cloned()
				.unwrap_or_else(|| json!({}));
			let meta = req.params
				.get("_meta")
				.cloned()
				.unwrap_or_else(|| json!({}));
			execute_tool(
				config,
				name,
				&arguments,
				&meta
			).await
		}
		"resources/list" => Ok(ToolOutcome {
			value: resources_list(),
			meta: None
		}),
		"resources/read" => Ok(ToolOutcome {
			value: resources_read(req)?,
			meta: None
		}),
		_ => Err(ProtocolError::new(-32601, "method not found").into()),
	}
}

async fn run_tool<F, Fut>(
	name: &str,
	config: &CallConfig,
	preview: Option<bool>,
	handler: F) -> ToolOutcome
where
	F: FnOnce() -> Fut,
	Fut: std::future::Future<Output = Result<Value>>, {
	match handler().await {
		Ok(structured) => ToolOutcome {
			value: tool_success(
				name,
				structured,
				config,
				preview
			),
			meta: None
		},
		Err(err) => {
			let meta = err.downcast_ref::<RequestedScopeError>().map(|error| json!({
				"requested_scopes": error.scopes
			}));
			ToolOutcome {
				value: tool_error(name, &err),
				meta
			}
		}
	}
}

fn resources_list() -> Value {
	let mut resources = vec![json!({
		"uri": "ui://static/syntect.css",
		"name": "syntect.css",
		"mimeType": "text/css"
	}),
	json!({
		"uri": "ui://browser/index.html",
		"name": "File Browser",
		"mimeType": "text/html",
		"annotations": {
            "type": "application"
        }
	}),
	json!({
		"uri": "ui://browser/app.css",
		"name": "browser styles",
		"mimeType": "text/css"
	}),
	json!({
		"uri": "ui://browser/app.js",
		"name": "browser script",
		"mimeType": "text/javascript"
	})];
	let cache = PREVIEW_CACHE.lock().expect("preview cache lock");
	for entry in cache.list() {
		let label = if entry.uri.starts_with("ui://write_file/") {
			"write"
		}
		else {
			"edit"
		};
		resources.push(
			json!({
				"uri": entry.uri,
				"name": format!("{} review for {}", label, entry.path),
				"mimeType": "text/html"
			})
		);
		resources.push(
			json!({
				"uri": format!("{}.diff", entry.uri),
				"name": format!("{} diff for {}", label, entry.path),
				"mimeType": "text/x-diff"
			})
		);
	}
	json!({
		"resources": resources
	})
}

fn resources_read(req: &Request) -> Result<Value> {
	let uri = req.params
		.get("uri")
		.and_then(Value::as_str)
		.ok_or_else(|| ProtocolError::new(-32602, "uri is required"))?;
	if uri.starts_with("ui://edit_file/") || uri.starts_with("ui://write_file/") {
		if let Some(base_uri) = uri.strip_suffix(".diff") {
			let mut cache = PREVIEW_CACHE.lock().expect("preview cache lock");
			if let Some(entry) = cache.get(base_uri) {
				return Ok(json!({
					"contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/x-diff",
                            "text": entry.diff
                        }
                    ]
				}));
			}
			return Err(ProtocolError::new(-32000, "resource not found").into());
		}
		let mut cache = PREVIEW_CACHE.lock().expect("preview cache lock");
		if let Some(entry) = cache.get(uri) {
			return Ok(json!({
				"contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/html",
                        "text": entry.html
                    }
                ]
			}));
		}
		return Err(ProtocolError::new(-32000, "resource not found").into());
	}
	if uri == "ui://browser/index.html" {
		return Ok(json!({
			"contents": [
                {
                    "uri": uri,
                    "mimeType": "text/html",
                    "text": browser_index_html()
                }
            ]
		}));
	}
	if uri == "ui://browser/app.css" {
		return Ok(json!({
			"contents": [
                {
                    "uri": uri,
                    "mimeType": "text/css",
                    "text": browser_app_css()
                }
            ]
		}));
	}
	if uri == "ui://browser/app.js" {
		return Ok(json!({
			"contents": [
                {
                    "uri": uri,
                    "mimeType": "text/javascript",
                    "text": browser_app_js()
                }
            ]
		}));
	}
	if uri == "ui://static/syntect.css" {
		return Ok(json!({
			"contents": [
                {
                    "uri": uri,
                    "mimeType": "text/css",
                    "text": static_syntect_css()
                }
            ]
		}));
	}
	Err(ProtocolError::new(-32000, "resource not found").into())
}

fn tool_success(
	name: &str,
	structured: Value,
	config: &CallConfig,
	preview: Option<bool>) -> Value {
	let message = tool_message(
		name,
		&structured,
		config,
		preview
	);
	let mut structured_content = structured;
	let mut content = vec![json!({
		"type": "text",
		"text": message
	})];
	if name == "edit_file" || name == "write_file" {
		let edit_id = structured_content.get("edit_id")
			.and_then(Value::as_str)
			.map(|value| value.to_string());
		if let Some(obj) = structured_content.as_object_mut() {
			obj.remove("edit_id");
		}
		if let Some(edit_id) = edit_id {
			let prefix = if name == "write_file" {
				"ui://write_file"
			}
			else {
				"ui://edit_file"
			};
			let review_uri = format!("{}/{}", prefix, edit_id);
			let diff_uri = format!("{}.diff", review_uri);
			content.push(json!({
				"type": "review",
				"url": review_uri,
				"mimeType": "text/html"
			}));
			content.push(json!({
				"type": "diff",
				"url": diff_uri,
				"mimeType": "text/x-diff"
			}));
		}
	}
	else {
		if let Some(uri) = structured_content.get("review_uri").and_then(Value::as_str) {
			content.push(json!({
				"type": "review",
				"url": uri,
				"mimeType": "text/html"
			}));
		}
		if let Some(uri) = structured_content.get("diff_uri").and_then(Value::as_str) {
			content.push(json!({
				"type": "diff",
				"url": uri,
				"mimeType": "text/x-diff"
			}));
		}
	}
	json!({
		"structuredContent": structured_content,
		"content": content
	})
}

fn tool_error(_name: &str, err: &anyhow::Error) -> Value {
	let message = err.to_string();
	let code = error_code(&message);
	json!({
		"isError": true,
		"structuredContent": {
            "code": code
        },
		"content": [
            {
                "type": "text",
                "text": message
            }
        ]
	})
}

async fn edit_file_tool(
	config: &CallConfig,
	args: &Value,
	preview: bool,
	default_root: &PathBuf) -> Result<Value> {
	let path = args.get("path")
		.and_then(Value::as_str)
		.ok_or_else(|| anyhow!("path is required"))?;
	let edits = args.get("edits").ok_or_else(|| anyhow!("edits is required"))?.as_array()
		.ok_or_else(|| anyhow!("edits must be an array"))?;
	if edits.is_empty() {
		return Err(anyhow!("edits is empty"));
	}
	let edits = edits.iter()
		.enumerate()
		.map(
			|(index, edit)| {
				let find = edit.get("find")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("find is required"))?;
				let replace = edit.get("replace")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("replace is required"))?;
				if find.is_empty() {
					return Err(anyhow!("find text is empty at index {}", index));
				}
				Ok((find.to_string(), replace.to_string()))
			})
		.collect::<Result<Vec<_>>>()?;
	let resolved = resolve_path_for_call(config, path)
		.map_err(
			|err| {
				if err.to_string().contains("path outside root") && !config.allow_escape && !config.policy_active {
					let scope = requested_scope_for_path("write", path, default_root);
					return RequestedScopeError {
						scopes: vec![scope]
					}.into();
				}
				anyhow!("invalid path {}: {}", path, err)
			}
		)?;
	ensure_writable_root(config, &resolved)?;
	let rel_path = match resolved.root_index {
		Some(index) => relative_to_root(&config.roots[index].path, &resolved.absolute),
		None => resolved.absolute.to_string_lossy().to_string(),
	};
	let existing = tokio::fs::read_to_string(&resolved.absolute).await.map_err(|err| format_io_error("read", &rel_path, err.into()))?;
	let mut updated = existing.clone();
	let mut total_matches = 0usize;
	for (index, (find, replace)) in edits.iter().enumerate() {
		let match_count = updated.match_indices(find).count();
		if match_count == 0 {
			return Err(anyhow!("find text not found at index {}", index));
		}
		if match_count > 1 {
			return Err(anyhow!("find text not unique at index {}", index));
		}
		updated = updated.replacen(find, replace, 1);
		total_matches += match_count;
	}
	let diff = make_diff(&existing, &updated, &rel_path);
	let edit_id = uuid::Uuid::new_v4().to_string();
	let review_uri = format!("ui://edit_file/{}", edit_id);
	let structured = json!({
		"path": rel_path,
		"edit_id": edit_id,
		"match_count": total_matches
	});
	let html = render_diff_html(
		&existing,
		&updated,
		&rel_path,
		&review_uri
	);
	let entry = PreviewEntry {
		uri: review_uri,
		html,
		diff,
		path: structured.get("path")
			.and_then(Value::as_str)
			.unwrap_or("file")
			.to_string()
	};
	let mut cache = PREVIEW_CACHE.lock().expect("preview cache lock");
	cache.insert(entry);
	if !preview {
		tokio::fs::write(&resolved.absolute, updated).await.map_err(|err| format_io_error("write", &rel_path, err.into()))?;
	}
	Ok(structured)
}

fn tool_message(
	name: &str,
	structured: &Value,
	config: &CallConfig,
	preview: Option<bool>) -> String {
	match name {
		"list_roots" => {
			let count = structured.get("roots")
				.and_then(Value::as_array)
				.map(|items| items.len())
				.unwrap_or(0);
			format!("Listed {} root(s).", count)
		}
		"find_files" => {
			let count = get_u64(structured, "count").unwrap_or(0);
			let truncated = structured.get("truncated")
				.and_then(Value::as_bool)
				.unwrap_or(false);
			let limit = structured.get("limit")
				.and_then(Value::as_u64)
				.map(|value| value.to_string());
			if truncated {
				if let Some(limit) = limit {
					format!("Found {} file(s). Results truncated at limit {}.", count, limit)
				}
				else {
					format!("Found {} file(s). Results truncated.", count)
				}
			}
			else {
				format!("Found {} file(s).", count)
			}
		}
		"search_files" => {
			let count = get_u64(structured, "count").unwrap_or(0);
			let total_files = get_u64(structured, "total_files").unwrap_or(count);
			let mode = structured.get("mode")
				.and_then(Value::as_str)
				.unwrap_or("full");
			match mode {
				"full" => format!("Returned matches for {} file(s).", count),
				"reduced" => {
					let max_bytes = config.search_max_bytes.unwrap_or(0);
					format!(
						"Result exceeded {} bytes; context lines were removed. Returned matches for {} file(s).",
						max_bytes, count
					)
				}
				"summary" => {
					let max_bytes = config.search_max_bytes.unwrap_or(0);
					if count < total_files {
						format!(
							"Result exceeded {} bytes even without context. Returning counts for {} of {} files.",
							max_bytes, count, total_files
						)
					}
					else {
						format!(
							"Result exceeded {} bytes even without context. Returning counts for {} file(s).",
							max_bytes, count
						)
					}
				}
				_ => format!("Returned matches for {} file(s).", count),
			}
		}
		"read_file" => {
			let count = get_u64(structured, "count").unwrap_or(0);
			let total = get_u64(structured, "total").unwrap_or(count);
			let start_line = get_u64(structured, "start_line").unwrap_or(1);
			let path = structured.get("path")
				.and_then(Value::as_str)
				.unwrap_or("file");
			if structured.get("code")
				.and_then(Value::as_str)
				.map(|code| code == "EMPTY_RANGE")
				.unwrap_or(false) {
				return format!(
					"No lines returned from {}: start_line {} exceeds total {}.",
					path, start_line, total
				);
			}
			format!(
				"Read {} line(s) from {} (start line {}, total {}).",
				count, path, start_line, total
			)
		}
		"read_multiple_files" => {
			let count = structured.get("files")
				.and_then(Value::as_array)
				.map(|files| files.len())
				.unwrap_or(0);
			format!("Read {} file(s).", count)
		}
		"move_file" => {
			let from = structured.get("from")
				.and_then(Value::as_str)
				.unwrap_or("source");
			let to = structured.get("to")
				.and_then(Value::as_str)
				.unwrap_or("destination");
			format!("Moved {} to {}.", from, to)
		}
		"delete_file" => {
			let path = structured.get("path")
				.and_then(Value::as_str)
				.unwrap_or("file");
			format!("Deleted {}.", path)
		}
		"write_file" => {
			let path = structured.get("path")
				.and_then(Value::as_str)
				.unwrap_or("file");
			if preview.unwrap_or(false) {
				format!("Previewed changes for {}.", path)
			}
			else {
				format!("Wrote {}.", path)
			}
		}
		"edit_file" => {
			let path = structured.get("path")
				.and_then(Value::as_str)
				.unwrap_or("file");
			if preview.unwrap_or(false) {
				format!("Generated review for edit in {}.", path)
			}
			else {
				format!("Applied edit in {}.", path)
			}
		}
		_ => "Completed tool call.".to_string(),
	}
}

fn get_u64(value: &Value, key: &str) -> Option<u64> {
	value.get(key).and_then(Value::as_u64)
}

fn parse_meta_preview(value: Option<&Value>) -> bool {
	match value {
		Some(Value::Bool(flag)) => *flag,
		Some(Value::String(text)) => text.eq_ignore_ascii_case("true"),
		_ => false,
	}
}

fn parse_meta_highlight(value: Option<&Value>) -> bool {
	match value {
		Some(Value::Bool(flag)) => *flag,
		Some(Value::String(text)) => text.eq_ignore_ascii_case("true"),
		_ => false,
	}
}

fn merge_meta(preview: bool, extra: Option<Value>) -> Option<Value> {
	let mut obj = serde_json::Map::new();
	if preview {
		obj.insert("preview".to_string(), Value::Bool(true));
	}
	if let Some(Value::Object(map)) = extra {
		for (key, value) in map {
			obj.insert(key, value);
		}
	}
	if obj.is_empty() {
		None
	}
	else {
		Some(Value::Object(obj))
	}
}

fn config_schema() -> Value {
	json!({
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title": "mcp-fs configuration",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"roots": {
				"type": "array",
				"minItems": 1,
				"description": "Allowed roots. The default root is used for relative paths.",
				"items": {
					"type": "object",
					"additionalProperties": false,
					"properties": {
						"path": { "type": "string", "description": "Absolute or root-relative path." },
						"default": { "type": "boolean", "description": "Exactly one root should be default." },
						"immutable": {
							"type": "array",
							"items": { "type": "string" },
							"description": "Glob patterns that disallow write/edit/move/delete. If empty or missing, everything is mutable."
						},
						"deny": {
							"type": "array",
							"items": { "type": "string" },
							"description": "Glob patterns to exclude from all operations."
						},
						"allow": {
							"type": "array",
							"items": { "type": "string" },
							"description": "Glob patterns to include; anything not matching is denied."
						},
						"blocked": {
							"type": "boolean",
							"description": "Block this root when used in _meta.policy.",
							"scope": "policy"
						}
					},
					"required": ["path"]
				}
			},
			"allow_escape": {
				"type": "boolean",
				"description": "Allow paths outside configured roots.",
				"scope": "configuration"
			},
			"find_limit": {
				"type": "integer",
				"minimum": 0,
				"description": "Default limit for find_files.",
				"audience": "human"
			},
			"search_max_bytes": {
				"type": "integer",
				"minimum": 0,
				"description": "Max output bytes for search_files.",
				"audience": "human"
			},
			"search_summary_top": {
				"type": "integer",
				"minimum": 0,
				"description": "Top N files for summary.",
				"audience": "human"
			},
			"read_max_bytes": {
				"type": "integer",
				"minimum": 0,
				"description": "Max output bytes for read_file.",
				"audience": "human"
			},
			"read_max_line_bytes": {
				"type": "integer",
				"minimum": 0,
				"description": "Max bytes per line.",
				"audience": "human"
			},
			"preview_cache_size": {
				"type": "integer",
				"minimum": 0,
				"description": "Preview cache size.",
				"scope": "configuration"
			},
			"otel_enabled": {
				"type": "boolean",
				"description": "Enable tracing.",
				"scope": "configuration"
			},
			"otel_endpoint": {
				"type": "string",
				"description": "OTLP endpoint.",
				"scope": "configuration"
			},
			"otel_service_name": {
				"type": "string",
				"description": "OTEL service.name.",
				"scope": "configuration"
			}
		},
		"required": ["roots"]
	})
}

fn load_config_value(path: &str) -> Result<Value> {
	let content = std::fs::read_to_string(path)
		.map_err(|err| anyhow!("failed to read config {}: {}", path, err))?;
	let value: Value = serde_json::from_str(&content)
		.map_err(|err| anyhow!("failed to parse config {}: {}", path, err))?;
	Ok(value)
}

fn apply_config_override(base: Config, value: &Value, cwd: &PathBuf) -> Result<Config> {
	let obj = value.as_object().ok_or_else(|| anyhow!("config must be an object"))?;
	let mut next = base.clone();
	for (key, value) in obj {
		match key.as_str() {
			"roots" => {
				let inputs = parse_root_inputs(value, false)?;
				let roots = build_root_configs(&inputs, cwd, false)?;
				let (roots, default_root, default_root_canon) = finalize_roots(roots)?;
				next.roots = roots;
				next.default_root = default_root;
				next.default_root_canon = default_root_canon;
			}
			"allow_escape" => {
				if !value.is_null() {
					next.allow_escape = value.as_bool().ok_or_else(|| anyhow!("allow_escape must be a boolean"))?;
				}
			}
			"find_limit" => {
				next.find_limit = parse_optional_usize_value(value, "find_limit")?;
			}
			"search_max_bytes" => {
				next.search_max_bytes = parse_optional_usize_value(value, "search_max_bytes")?;
			}
			"search_summary_top" => {
				next.search_summary_top = parse_optional_usize_value(value, "search_summary_top")?;
			}
			"read_max_bytes" => {
				next.read_max_bytes = parse_optional_usize_value(value, "read_max_bytes")?;
			}
			"read_max_line_bytes" => {
				next.read_max_line_bytes = parse_optional_usize_value(value, "read_max_line_bytes")?;
			}
			"preview_cache_size" => {
				next.preview_cache_size = parse_optional_usize_value(value, "preview_cache_size")?;
			}
			"otel_enabled" => {
				if !value.is_null() {
					next.otel_enabled = value.as_bool().ok_or_else(|| anyhow!("otel_enabled must be a boolean"))?;
				}
			}
			"otel_endpoint" => {
				if !value.is_null() {
					next.otel_endpoint = value.as_str().ok_or_else(|| anyhow!("otel_endpoint must be a string"))?.to_string();
				}
			}
			"otel_service_name" => {
				if !value.is_null() {
					next.otel_service_name = value.as_str().ok_or_else(|| anyhow!("otel_service_name must be a string"))?.to_string();
				}
			}
			_ => return Err(anyhow!("unknown config key: {}", key)),
		}
	}
	Ok(next)
}

fn parse_optional_usize_value(value: &Value, label: &str) -> Result<Option<usize>> {
	if value.is_null() {
		return Ok(None);
	}
	let number = value.as_u64().ok_or_else(|| anyhow!("{} must be a non-negative integer", label))?;
	if number == 0 {
		return Ok(None);
	}
	Ok(Some(number as usize))
}

fn parse_root_inputs(value: &Value, allow_blocked: bool) -> Result<Vec<RootInput>> {
	let items = value.as_array().ok_or_else(|| anyhow!("roots must be an array"))?;
	let mut roots = Vec::new();
	for item in items {
		let obj = item.as_object().ok_or_else(|| anyhow!("root entries must be objects"))?;
		let mut path: Option<String> = None;
		let mut default: Option<bool> = None;
		let mut immutable: Vec<String> = Vec::new();
		let mut deny: Vec<String> = Vec::new();
		let mut allow: Vec<String> = Vec::new();
		let mut blocked: Option<bool> = None;
		for (key, value) in obj {
			match key.as_str() {
				"path" => {
					path = Some(value.as_str().ok_or_else(|| anyhow!("root.path must be a string"))?.to_string());
				}
				"default" => {
					default = Some(value.as_bool().ok_or_else(|| anyhow!("root.default must be a boolean"))?);
				}
				"immutable" => {
					immutable = parse_string_list(value, "root.immutable")?;
				}
				"deny" => {
					deny = parse_string_list(value, "root.deny")?;
				}
				"allow" => {
					allow = parse_string_list(value, "root.allow")?;
				}
				"blocked" => {
					if allow_blocked {
						blocked = Some(value.as_bool().ok_or_else(|| anyhow!("root.blocked must be a boolean"))?);
					}
				}
				_ => return Err(anyhow!("unknown root field: {}", key)),
			}
		}
		let path = path.ok_or_else(|| anyhow!("root.path is required"))?;
		roots.push(RootInput {
			path,
			default,
			immutable,
			deny,
			allow,
			blocked,
		});
	}
	Ok(roots)
}

fn parse_string_list(value: &Value, label: &str) -> Result<Vec<String>> {
	let list = value.as_array().ok_or_else(|| anyhow!("{} must be an array", label))?;
	Ok(list.iter()
		.filter_map(|item| item.as_str().map(|value| value.to_string()))
		.collect())
}

fn build_root_configs(inputs: &[RootInput], cwd: &PathBuf, allow_blocked: bool) -> Result<Vec<RootConfig>> {
	let mut roots = Vec::new();
	for input in inputs {
		if input.blocked.is_some() && !allow_blocked {
			return Err(anyhow!("root.blocked is only allowed in policy"));
		}
		let mut path = PathBuf::from(&input.path);
		if !path.is_absolute() {
			path = cwd.join(path);
		}
		let normalized = fs::normalize_path(&path);
		let canonical = if normalized.exists() {
			normalized.canonicalize().unwrap_or(normalized.clone())
		}
		else {
			normalized.clone()
		};
		let display = normalized.to_string_lossy().to_string();
		roots.push(RootConfig {
			path: normalized,
			path_canon: canonical,
			display,
			default: input.default.unwrap_or(false),
			immutable: input.immutable.clone(),
			deny: input.deny.clone(),
			allow: input.allow.clone(),
		});
	}
	Ok(roots)
}

fn finalize_roots(mut roots: Vec<RootConfig>) -> Result<(Vec<RootConfig>, PathBuf, PathBuf)> {
	if roots.is_empty() {
		return Err(anyhow!("roots must not be empty"));
	}
	let default_count = roots.iter().filter(|root| root.default).count();
	if default_count == 0 {
		if let Some(first) = roots.first_mut() {
			first.default = true;
		}
	}
	else if default_count > 1 {
		let mut saw_default = false;
		for root in &mut roots {
			if root.default {
				if !saw_default {
					saw_default = true;
				}
				else {
					root.default = false;
				}
			}
		}
		warn!("multiple default roots configured; using the first and clearing the rest");
	}
	let default_root = roots.iter()
		.find(|root| root.default)
		.map(|root| root.path.clone())
		.ok_or_else(|| anyhow!("default root missing"))?;
	let default_root_canon = roots.iter()
		.find(|root| root.default)
		.map(|root| root.path_canon.clone())
		.ok_or_else(|| anyhow!("default root missing"))?;
	Ok((roots, default_root, default_root_canon))
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
	if patterns.is_empty() {
		return Ok(None);
	}
	let mut builder = GlobSetBuilder::new();
	for pattern in patterns {
		let glob = GlobBuilder::new(pattern)
			.literal_separator(true)
			.build()
			.map_err(|err| anyhow!("invalid glob {}: {}", pattern, err))?;
		builder.add(glob);
	}
	Ok(Some(builder.build().map_err(|err| anyhow!("invalid glob set: {}", err))?))
}

fn resolve_call_config(config: &Config, meta: &Value, tool: &str) -> Result<CallConfig> {
	let policy = meta.get("policy");
	let mut roots = Vec::new();
	for root in &config.roots {
		roots.push(build_call_root(root)?);
	}
	if let Some(policy_value) = policy {
		apply_policy_to_roots(&mut roots, policy_value, config)?;
		return Ok(CallConfig {
			roots: roots.into_iter().filter(|root| !root.blocked).collect(),
			default_root: config.default_root.clone(),
			allow_escape: false,
			policy_active: true,
			find_limit: config.find_limit,
			search_max_bytes: config.search_max_bytes,
			search_summary_top: config.search_summary_top,
			read_max_bytes: config.read_max_bytes,
			read_max_line_bytes: config.read_max_line_bytes,
		});
	}
	let granted_roots = granted_roots_for_tool(config, tool, meta);
	if !config.allow_escape {
		for granted in granted_roots {
		roots.push(CallRoot {
			path: granted.clone(),
			path_canon: granted.clone(),
			display: granted.to_string_lossy().to_string(),
			default: false,
			blocked: false,
			policy_immutable: Vec::new(),
			deny: Vec::new(),
			policy_allow: Vec::new(),
			immutable_set: None,
			policy_immutable_set: None,
			deny_set: None,
			allow_set: None,
			policy_allow_set: None,
		});
	}
	}
	Ok(CallConfig {
		roots,
		default_root: config.default_root.clone(),
		allow_escape: config.allow_escape,
		policy_active: false,
		find_limit: config.find_limit,
		search_max_bytes: config.search_max_bytes,
		search_summary_top: config.search_summary_top,
		read_max_bytes: config.read_max_bytes,
		read_max_line_bytes: config.read_max_line_bytes,
	})
}

fn build_call_root(root: &RootConfig) -> Result<CallRoot> {
	Ok(CallRoot {
		path: root.path.clone(),
		path_canon: root.path_canon.clone(),
		display: root.display.clone(),
		default: root.default,
		blocked: false,
		policy_immutable: Vec::new(),
		deny: root.deny.clone(),
		policy_allow: Vec::new(),
		immutable_set: build_glob_set(&root.immutable)?,
		policy_immutable_set: None,
		deny_set: build_glob_set(&root.deny)?,
		allow_set: build_glob_set(&root.allow)?,
		policy_allow_set: None,
	})
}

fn apply_policy_to_roots(roots: &mut [CallRoot], policy: &Value, config: &Config) -> Result<()> {
	let obj = policy.as_object().ok_or_else(|| ProtocolError::new(-32602, "policy must be an object"))?;
	let mut policy_roots: Vec<RootInput> = Vec::new();
	for (key, value) in obj {
		match key.as_str() {
			"roots" => {
				policy_roots = parse_root_inputs(value, true)?;
			}
			_ => return Err(ProtocolError::new(-32602, format!("unknown policy key: {}", key)).into()),
		}
	}
	let cwd = std::env::current_dir().unwrap_or_else(|_| config.default_root.clone());
	for policy_root in policy_roots {
		if policy_root.default.is_some() {
			return Err(ProtocolError::new(-32602, "policy roots must not include default").into());
		}
		let normalized = normalize_root_path(&policy_root.path, &cwd);
		let (index, _) = roots.iter().enumerate()
			.find(|(_, root)| root.path_canon == normalized || root.path == normalized)
			.ok_or_else(|| ProtocolError::new(-32602, format!("policy root not found: {}", policy_root.path)))?;
		if let Some(blocked) = policy_root.blocked {
			if blocked {
				if roots[index].default {
					return Err(ProtocolError::new(-32602, "policy cannot block the default root").into());
				}
				roots[index].blocked = true;
			}
		}
		if !policy_root.immutable.is_empty() {
			roots[index].policy_immutable.extend(policy_root.immutable);
			roots[index].policy_immutable_set = build_glob_set(&roots[index].policy_immutable)?;
		}
		if !policy_root.deny.is_empty() {
			roots[index].deny.extend(policy_root.deny);
			roots[index].deny_set = build_glob_set(&roots[index].deny)?;
		}
		if !policy_root.allow.is_empty() {
			roots[index].policy_allow.extend(policy_root.allow);
			roots[index].policy_allow_set = build_glob_set(&roots[index].policy_allow)?;
		}
	}
	Ok(())
}

fn normalize_root_path(path: &str, cwd: &PathBuf) -> PathBuf {
	let mut root_path = PathBuf::from(path);
	if !root_path.is_absolute() {
		root_path = cwd.join(root_path);
	}
	let normalized = fs::normalize_path(&root_path);
	if normalized.exists() {
		normalized.canonicalize().unwrap_or(normalized)
	}
	else {
		normalized
	}
}

fn tool_verb(tool: &str) -> Option<&'static str> {
	match tool {
		"list_roots" | "find_files" | "search_files" | "read_file" | "read_multiple_files" => Some("read"),
		"write_file" | "edit_file" | "move_file" | "delete_file" => Some("write"),
		_ => None,
	}
}

fn parse_scope_list(value: Option<&Value>) -> Vec<String> {
	match value {
		Some(Value::String(text)) => vec![text.to_string()],
		Some(Value::Array(items)) => items.iter()
			.filter_map(|item| item.as_str().map(|s| s.to_string()))
			.collect(),
		_ => Vec::new(),
	}
}

fn granted_roots_for_tool(config: &Config, tool: &str, meta: &Value) -> Vec<PathBuf> {
	let Some(verb) = tool_verb(tool) else {
		return Vec::new();
	};
	let scopes = parse_scope_list(meta.get("granted_scopes"));
	scopes.into_iter()
		.filter_map(|scope| parse_scope_root(config, &scope, verb))
		.collect()
}

fn parse_scope_root(config: &Config, scope: &str, verb: &str) -> Option<PathBuf> {
	let mut parts = scope.splitn(3, ':');
	let scope_verb = parts.next()?;
	let scope_kind = parts.next()?;
	let scope_path = parts.next()?;
	if scope_verb != verb || scope_kind != "file" {
		return None;
	}
	if scope_path.trim().is_empty() {
		return None;
	}
	let path = PathBuf::from(scope_path);
	let absolute = if path.is_absolute() {
		path
	}
	else {
		config.default_root.join(path)
	};
	Some(fs::normalize_path(&absolute))
}

fn requested_scope_for_root(verb: &str, root_param: &str, default_root: &PathBuf) -> String {
	let path = PathBuf::from(root_param);
	let absolute = if path.is_absolute() {
		path
	}
	else {
		default_root.join(path)
	};
	let normalized = fs::normalize_path(&absolute);
	format!("{}:file:{}", verb, normalized.display())
}

fn requested_scope_for_path(verb: &str, path_param: &str, default_root: &PathBuf) -> String {
	let path = PathBuf::from(path_param);
	let absolute = if path.is_absolute() {
		path
	}
	else {
		default_root.join(path)
	};
	let normalized = fs::normalize_path(&absolute);
	let scope_root = if path_param.ends_with('/') {
		normalized
	}
	else {
		normalized.parent()
			.map(|parent| parent.to_path_buf())
			.unwrap_or(normalized)
	};
	format!("{}:file:{}", verb, scope_root.display())
}

fn build_roots_output(config: &CallConfig) -> Vec<Value> {
	let mut roots = BTreeSet::new();
	for root in &config.roots {
		roots.insert((root.display.clone(), root.default));
	}
	roots.into_iter()
		.map(|(path, default)| {
			json!({
				"path": path,
				"default": default
			})
		})
		.collect()
}

fn relative_to_root(root: &PathBuf, path: &PathBuf) -> String {
	if let Ok(rel) = path.strip_prefix(root) {
		return rel.to_string_lossy().to_string();
	}
	let root_components: Vec<_> = root.components().collect();
	let path_components: Vec<_> = path.components().collect();
	let mut common = 0usize;
	while common < root_components.len()
		&& common < path_components.len()
		&& root_components[common] == path_components[common] {
		common += 1;
	}
	let mut rel = PathBuf::new();
	for _ in common..root_components.len() {
		rel.push("..");
	}
	for comp in &path_components[common..] {
		rel.push(comp.as_os_str());
	}
	let rel_str = rel.to_string_lossy().to_string();
	if rel_str.is_empty() {
		".".to_string()
	}
	else {
		rel_str
	}
}

struct ResolvedPath {
	absolute: PathBuf,
	root_index: Option<usize>,
}

fn resolve_path_for_call(call: &CallConfig, path_param: &str) -> Result<ResolvedPath> {
	let raw = PathBuf::from(path_param);
	let candidate = if raw.is_absolute() {
		raw
	}
	else {
		call.default_root.join(raw)
	};
	let normalized = fs::normalize_path(&candidate);
	let checked = if normalized.exists() {
		normalized.canonicalize().unwrap_or(normalized.clone())
	}
	else {
		normalized.clone()
	};
	let root_index = find_root_for_path(call, &checked);
	if root_index.is_none() && !call.allow_escape {
		return Err(anyhow!("path outside root"));
	}
	if let Some(index) = root_index {
		let root = &call.roots[index];
		let rel = relative_to_root(&root.path, &checked);
		if !is_path_allowed(root, &rel) {
			return Err(anyhow!("path blocked by policy"));
		}
	}
	Ok(ResolvedPath {
		absolute: checked,
		root_index,
	})
}

fn ensure_writable_root(call: &CallConfig, resolved: &ResolvedPath) -> Result<()> {
	let Some(index) = resolved.root_index else {
		return Ok(());
	};
	let root = &call.roots[index];
	let rel = relative_to_root(&root.path, &resolved.absolute);
	if is_path_immutable(root, &rel) {
		return Err(anyhow!("path is immutable; write operations are not allowed"));
	}
	Ok(())
}

fn is_path_immutable(root: &CallRoot, rel: &str) -> bool {
	if rel.is_empty() {
		return false;
	}
	if let Some(set) = &root.immutable_set {
		if set.is_match(rel) {
			return true;
		}
	}
	if let Some(set) = &root.policy_immutable_set {
		if set.is_match(rel) {
			return true;
		}
	}
	false
}

fn resolve_root_param(call: &CallConfig, root_param: &str) -> Result<(PathBuf, Option<usize>, String, String)> {
	let raw = PathBuf::from(root_param);
	let candidate = if raw.is_absolute() {
		raw
	}
	else {
		call.default_root.join(raw)
	};
	let normalized = fs::normalize_path(&candidate);
	let checked = if normalized.exists() {
		normalized.canonicalize().unwrap_or(normalized.clone())
	}
	else {
		normalized.clone()
	};
	let root_index = find_root_for_path(call, &checked);
	if root_index.is_none() && !call.allow_escape {
		return Err(anyhow!("path outside root"));
	}
	if let Some(index) = root_index {
		let root = &call.roots[index];
		let rel = relative_to_root(&root.path, &checked);
		if !is_path_allowed(root, &rel) {
			return Err(anyhow!("root blocked by policy"));
		}
		let root_label = if std::path::Path::new(root_param).is_absolute() {
			root_param.to_string()
		}
		else {
			fs::normalize_relative(root_param)
		};
		return Ok((checked, Some(index), root_label, rel));
	}
	let root_label = if std::path::Path::new(root_param).is_absolute() {
		root_param.to_string()
	}
	else {
		fs::normalize_relative(root_param)
	};
	Ok((checked, None, root_label, String::new()))
}

fn find_root_for_path(call: &CallConfig, path: &PathBuf) -> Option<usize> {
	let mut best: Option<(usize, usize)> = None;
	for (index, root) in call.roots.iter().enumerate() {
		if path.starts_with(&root.path_canon) {
			let depth = root.path_canon.components().count();
			if best.map(|(_, best_depth)| depth > best_depth).unwrap_or(true) {
				best = Some((index, depth));
			}
		}
	}
	best.map(|(index, _)| index)
}

fn is_path_allowed(root: &CallRoot, rel: &str) -> bool {
	if rel.is_empty() {
		return true;
	}
	if let Some(set) = &root.deny_set {
		if set.is_match(rel) {
			return false;
		}
	}
	if let Some(set) = &root.allow_set {
		if !set.is_match(rel) {
			return false;
		}
	}
	if let Some(set) = &root.policy_allow_set {
		if !set.is_match(rel) {
			return false;
		}
	}
	true
}

fn filter_find_results(call: &CallConfig, root_index: Option<usize>, root_prefix: &str, value: Value) -> Result<Value> {
	let Some(index) = root_index else {
		return Ok(value);
	};
	let root = &call.roots[index];
	let mut obj = value.as_object().cloned().ok_or_else(|| anyhow!("find result must be object"))?;
	let matches = obj.get("matches").and_then(Value::as_array).cloned().unwrap_or_default();
	let mut filtered: Vec<Value> = Vec::new();
	for item in matches {
		let Some(text) = item.as_str() else {
			continue;
		};
		let combined = if root_prefix.is_empty() || root_prefix == "." {
			text.to_string()
		}
		else {
			format!("{}/{}", root_prefix.trim_end_matches('/'), text)
		};
		if is_path_allowed(root, &combined) {
			filtered.push(Value::String(text.to_string()));
		}
	}
	obj.insert("matches".to_string(), Value::Array(filtered.clone()));
	obj.insert("count".to_string(), Value::Number(filtered.len().into()));
	Ok(Value::Object(obj))
}

fn filter_search_results(call: &CallConfig, root_index: Option<usize>, root_prefix: &str, value: Value) -> Result<Value> {
	let Some(index) = root_index else {
		return Ok(value);
	};
	let root = &call.roots[index];
	let mut obj = value.as_object().cloned().ok_or_else(|| anyhow!("search result must be object"))?;
	let files = obj.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
	let mut filtered_files: Vec<Value> = Vec::new();
	let mut total_matches = 0usize;
	for file in files {
		let Some(path) = file.get("path").and_then(Value::as_str) else {
			continue;
		};
		let combined = if root_prefix.is_empty() || root_prefix == "." {
			path.to_string()
		}
		else {
			format!("{}/{}", root_prefix.trim_end_matches('/'), path)
		};
		if is_path_allowed(root, &combined) {
			if let Some(matches) = file.get("matches").and_then(Value::as_array) {
				total_matches += matches.len();
			}
			else if let Some(count) = file.get("count").and_then(Value::as_u64) {
				total_matches += count as usize;
			}
			filtered_files.push(file);
		}
	}
	obj.insert("files".to_string(), Value::Array(filtered_files.clone()));
	obj.insert("count".to_string(), Value::Number(filtered_files.len().into()));
	obj.insert("total_files".to_string(), Value::Number(filtered_files.len().into()));
	obj.insert("total_matches".to_string(), Value::Number(total_matches.into()));
	Ok(Value::Object(obj))
}

fn error_code(message: &str) -> &'static str {
	let lower = message.to_lowercase();
	if lower.contains("path is required") {
		"MISSING_PATH"
	}
	else if lower.contains("invalid path") {
		"INVALID_PATH"
	}
	else if lower.contains("pattern is required") {
		"MISSING_PATTERN"
	}
	else if lower.contains("content is required") {
		"MISSING_CONTENT"
	}
	else if lower.contains("find is required") {
		"MISSING_FIND"
	}
	else if lower.contains("replace is required") {
		"MISSING_REPLACE"
	}
	else if lower.contains("edits is required") {
		"MISSING_EDITS"
	}
	else if lower.contains("edits must be an array") {
		"INVALID_EDITS"
	}
	else if lower.contains("edits is empty") {
		"EMPTY_EDITS"
	}
	else if lower.contains("find text is empty") {
		"FIND_EMPTY"
	}
	else if lower.contains("find text not found") {
		"FIND_NOT_FOUND"
	}
	else if lower.contains("find text not unique") {
		"FIND_NOT_UNIQUE"
	}
	else if lower.contains("from is required") {
		"MISSING_FROM"
	}
	else if lower.contains("to is required") {
		"MISSING_TO"
	}
	else if lower.contains("target exists") {
		"TARGET_EXISTS"
	}
	else if lower.contains("cannot delete root") {
		"DELETE_ROOT_DENIED"
	}
	else if lower.contains("cannot move root") {
		"MOVE_ROOT_DENIED"
	}
	else if lower.contains("absolute paths not allowed") {
		"ABSOLUTE_PATH_NOT_ALLOWED"
	}
	else if lower.contains("path outside root") {
		"PATH_OUTSIDE_ROOT"
	}
	else if lower.contains("mode must be overwrite") {
		"INVALID_MODE"
	}
	else if lower.contains("limit must be greater than 0") {
		"INVALID_LIMIT"
	}
	else if lower.contains("invalid glob") {
		"INVALID_GLOB"
	}
	else if lower.contains("invalid pattern") {
		"INVALID_PATTERN"
	}
	else if lower.contains("rg failed") {
		"RG_FAILED"
	}
	else if lower.contains("no such file") {
		"FILE_NOT_FOUND"
	}
	else if lower.contains("permission denied") {
		"PERMISSION_DENIED"
	}
	else {
		"EXECUTION_ERROR"
	}
}

fn format_io_error(action: &str, path: &str, err: anyhow::Error) -> anyhow::Error {
	if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
		let reason = match io_err.kind() {
			std::io::ErrorKind::NotFound => "not found",
			std::io::ErrorKind::PermissionDenied => "permission denied",
			std::io::ErrorKind::InvalidInput => "invalid input",
			_ => "io error",
		};
		return anyhow!("{} {}: {}", action, path, reason);
	}
	anyhow!("{} {}: {}", action, path, err)
}

fn make_diff(existing: &str, updated: &str, rel_path: &str) -> String {
	let diff = similar::TextDiff::from_lines(existing, updated);
	diff.unified_diff()
		.context_radius(3)
		.header(&format!("a/{}", rel_path), &format!("b/{}", rel_path))
		.to_string()
}

fn render_diff_html(
	existing: &str,
	updated: &str,
	rel_path: &str,
	review_uri: &str) -> String {
	let diff = similar::TextDiff::from_lines(existing, updated);
	let syntax = syntax_for_path(rel_path);
	let mut left_hl = ParseState::new(syntax);
	let mut right_hl = ParseState::new(syntax);
	let mut left_line = 1;
	let mut right_line = 1;
	let mut rows = String::new();
	let mut unified_rows = String::new();
	for change in diff.iter_all_changes() {
		let tag = change.tag();
		let raw = change.value();
		let line = raw.trim_end_matches(['\n', '\r']);
		match tag {
			similar::ChangeTag::Delete => {
				let left_html = highlight_line_html(&mut left_hl, line);
				rows.push_str(
					&format!(
						"<tr class='del'><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td><td class='ln'></td><td class='code'></td></tr>",
						left_line, left_html
					)
				);
				unified_rows.push_str(
					&format!(
						"<tr class='del'><td class='ln'>{}</td><td class='ln'></td><td class='code'><pre><code>{}</code></pre></td></tr>",
						left_line, left_html
					)
				);
				left_line += 1;
			}
			similar::ChangeTag::Insert => {
				let right_html = highlight_line_html(&mut right_hl, line);
				rows.push_str(
					&format!(
						"<tr class='ins'><td class='ln'></td><td class='code'></td><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td></tr>",
						right_line, right_html
					)
				);
				unified_rows.push_str(
					&format!(
						"<tr class='ins'><td class='ln'></td><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td></tr>",
						right_line, right_html
					)
				);
				right_line += 1;
			}
			similar::ChangeTag::Equal => {
				let left_html = highlight_line_html(&mut left_hl, line);
				let right_html = highlight_line_html(&mut right_hl, line);
				rows.push_str(
					&format!(
						"<tr class='eq'><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td></tr>",
						left_line, left_html, right_line, right_html
					)
				);
				unified_rows.push_str(
					&format!(
						"<tr class='eq'><td class='ln'>{}</td><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td></tr>",
						left_line, right_line, left_html
					)
				);
				left_line += 1;
				right_line += 1;
			}
		}
	}
	let mut html = diff_html_template().to_string();
	html = html.replace("__CSS__", diff_css());
	html = html.replace("__PATH__", &html_escape(rel_path));
	html = html.replace("__RESOURCE__", &html_escape(review_uri));
	html = html.replace("__UNIFIED__", &unified_rows);
	html = html.replace("__SPLIT__", &rows);
	html
}

fn html_escape(input: &str) -> String {
	let mut out = String::new();
	for ch in input.chars() {
		match ch {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			_ => out.push(ch),
		}
	}
	out
}

fn syntax_for_path(path: &str) -> &'static syntect::parsing::SyntaxReference {
	let ext = std::path::Path::new(path).extension().and_then(|value| value.to_str());
	if let Some(ext) = ext {
		if let Some(syntax) = SYNTAX_SET.find_syntax_by_extension(ext) {
			return syntax;
		}
	}
	SYNTAX_SET.find_syntax_plain_text()
}

fn highlight_line_html(hl: &mut ParseState, line: &str) -> String {
	let ops = match hl.parse_line(line, &SYNTAX_SET) {
		Ok(ops) => ops,
		Err(_) => return html_escape(line),
	};
	let mut stack = ScopeStack::new();
	match line_tokens_to_classed_spans(
		line,
		&ops,
		ClassStyle::Spaced,
		&mut stack
	) {
		Ok((mut html, _)) => {
			if html.ends_with('\n') {
				html.pop();
			}
			html
		}
		Err(_) => html_escape(line),
	}
}

fn diff_css() -> &'static str {
	include_str!("../assets/diff.css")
}

fn static_syntect_css() -> &'static str {
	include_str!("../assets/syntect.css")
}

fn browser_index_html() -> &'static str {
	include_str!("../assets/ui/browser/index.html")
}

fn browser_app_css() -> &'static str {
	include_str!("../assets/ui/browser/app.css")
}

fn browser_app_js() -> &'static str {
	include_str!("../assets/ui/browser/app.js")
}

fn diff_html_template() -> &'static str {
	include_str!("../assets/diff.html")
}

fn tool_definitions() -> Vec<Value> {
	vec![
	json!({
		"name": "list_roots",
		"description": "list configured roots and per-call read grants",
		"annotations": {
                "scopes": ["read:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "roots": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "path": { "type": "string", "description": "Absolute root path." },
                                        "default": { "type": "boolean", "description": "True when this is the default root used by relative paths." }
                                    },
                                    "required": ["path", "default"]
                                }
                            },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "move_file",
		"description": "move/rename a file or directory (fails if destination exists)",
		"annotations": {
                "scopes": ["write:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "from": { "type": "string", "description": "Source path. Relative paths use the default root; absolute paths override when allowed." },
                    "to": { "type": "string", "description": "Destination path. Relative paths use the default root; absolute paths override when allowed." }
                },
                "required": ["from", "to"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "from": { "type": "string", "description": "Source path relative to the configured server root." },
                            "to": { "type": "string", "description": "Destination path relative to the configured server root." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "delete_file",
		"description": "delete a file or directory recursively",
		"annotations": {
                "scopes": ["write:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to delete. Relative paths use the default root; absolute paths override when allowed." }
                },
                "required": ["path"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Path relative to the configured server root." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "find_files",
		"description": "Find files with this fd compatible tool",
		"annotations": {
                "scopes": ["read:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Pattern to match against file names. Regex by default; if glob=true, this is interpreted as a glob. Default: '' (match all)." },
                    "root": { "type": "string", "description": "Root directory. Relative paths use the default root; absolute paths override." },
                    "type": { "type": "string", "enum": ["file", "dir", "symlink"], "description": "Filter by entry type." },
                    "max_depth": { "type": "integer", "minimum": 0, "description": "Maximum directory depth to traverse from the request root." },
                    "follow": { "type": "boolean", "description": "Follow symlinks during traversal." },
                    "glob": { "type": "boolean", "description": "If true, interpret pattern as a glob instead of a regex (fd-style)." },
                    "case_sensitive": { "type": ["string", "boolean"], "description": "Case sensitivity: auto|true|false. auto uses smart-case." },
                    "exclude": { "type": "array", "items": { "type": "string" }, "description": "Glob patterns to exclude from results." },
                    "limit": { "type": "integer", "minimum": 1, "description": "Maximum number of results to return (>0). Overrides server default (200) if set." },
                    "offset": { "type": "integer", "minimum": 0, "description": "Number of matching results to skip before returning results." }
                }
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "matches": { "type": "array", "items": { "type": "string" }, "description": "Matched paths relative to the request root. Directories end with '/'" },
                            "pattern": { "type": "string", "description": "The pattern that was applied." },
                            "root": { "type": "string", "description": "Normalized request root used for this search." },
                            "count": { "type": "integer", "minimum": 0, "description": "Number of results returned in this response." },
                            "offset": { "type": "integer", "minimum": 0, "description": "Number of matches skipped before returning results." },
                            "limit": { "type": ["integer", "null"], "description": "Effective limit applied (null if unlimited)." },
                            "truncated": { "type": "boolean", "description": "True when results were cut off because limit was reached." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" },
                                "url": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "search_files",
		"description": "Search file contents using ripgrep-compatible patterns",
		"annotations": {
                "scopes": ["read:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regex pattern to search for (ripgrep syntax)." },
                    "root": { "type": "string", "description": "Root directory. Relative paths use the default root; absolute paths override." },
                    "glob": { "type": "array", "items": { "type": "string" }, "description": "File globs to include or exclude (ripgrep --glob)." },
                    "case_sensitive": { "type": ["string", "boolean"], "description": "Case sensitivity: auto|true|false. auto uses smart-case." },
                    "before_context": { "type": "integer", "minimum": 0, "description": "Lines of context before each match." },
                    "after_context": { "type": "integer", "minimum": 0, "description": "Lines of context after each match." },
                    "context": { "type": "integer", "minimum": 0, "description": "Lines of context before and after each match (overrides before_context/after_context)." }
                },
                "required": ["pattern"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "files": {
                                "type": "array",
                                "description": "Per-file matches (full/reduced) or counts (summary).",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "path": { "type": "string", "description": "Path relative to the request root." },
                                        "matches": { "type": "array", "items": { "type": "string" }, "description": "Chunk strings with line numbers and match/context markers (full/reduced modes)." },
                                        "count": { "type": "integer", "minimum": 0, "description": "Match count for this file (summary mode)." }
                                    },
                                    "required": ["path"]
                                }
                            },
                            "pattern": { "type": "string", "description": "The pattern that was searched." },
                            "root": { "type": "string", "description": "Normalized request root used for this search." },
                            "count": { "type": "integer", "minimum": 0, "description": "Number of files returned in this response." },
                            "total_files": { "type": "integer", "minimum": 0, "description": "Total number of matched files before any reduction." },
                            "total_matches": { "type": "integer", "minimum": 0, "description": "Total number of match chunks before any reduction." },
                            "truncated": { "type": "boolean", "description": "True when output was reduced or summarized to fit size limits." },
                            "mode": { "type": "string", "description": "Output mode: full, reduced, or summary." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" },
                                "url": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "read_file",
		"description": "read a text file",
		"annotations": {
                "scopes": ["read:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file. Relative paths use the default root; absolute paths override when allowed." },
                    "start_line": { "type": "integer", "minimum": 1, "description": "1-based line number to start reading from. Default: 1." },
                    "limit": { "type": "integer", "minimum": 1, "description": "Maximum number of lines to return (>0). Default: 200." }
                },
                "required": ["path"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Path relative to the configured server root." },
                            "content": { "type": "string", "description": "Line-numbered text with format 'N: content'." },
                            "count": { "type": "integer", "minimum": 0, "description": "Number of lines returned." },
                            "total": { "type": "integer", "minimum": 0, "description": "Total number of lines in the file." },
                            "start_line": { "type": "integer", "minimum": 1, "description": "1-based line number used for this response." },
                            "truncated": { "type": "boolean", "description": "True when not all lines were returned." },
                            "truncated_reason": { "type": "array", "items": { "type": "string" }, "description": "Reasons for truncation when truncated is true." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" },
                                "url": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "read_multiple_files",
		"description": "read multiple files (per-file output is capped); use read_file for single-file reads",
		"annotations": {
                "scopes": ["read:file"],
                "group": "filesystem"
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "paths": { "type": "array", "items": { "type": "string" }, "description": "Paths to files. Relative paths use the default root; absolute paths override when allowed." }
                },
                "required": ["paths"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "files": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "path": { "type": "string", "description": "Path relative to the configured server root." },
                                        "content": { "type": "string", "description": "Line-numbered text with format 'N: content'." },
                                        "count": { "type": "integer", "minimum": 0 },
                                        "total": { "type": "integer", "minimum": 0 },
                                        "truncated": { "type": "boolean" },
                                        "code": { "type": "string", "description": "Error code when the file could not be read." }
                                    },
                                    "required": ["path"]
                                }
                            },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "write_file",
		"description": "use this tool only to append/prepend or overwrite a small file as a whole; prefer edit_file for targeted replacement",
		"annotations": {
                "scopes": ["write:file"],
                "priority": 0,
                "group": "filesystem",
                "preview": true
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file. Relative paths use the default root; absolute paths override when allowed." },
                    "content": { "type": "string", "description": "New file content to write or preview." },
                    "mode": { "type": "string", "enum": ["overwrite", "append", "prepend"], "description": "Write mode. Default: overwrite." }
                },
                "required": ["path", "content"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Path relative to the configured server root." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	}),
	json!({
		"name": "edit_file",
		"description": "replace exact matches in a file",
		"annotations": {
                "scopes": ["write:file"],
                "priority": 1,
                "group": "filesystem",
                "preview": true
            },
		"inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file. Relative paths use the default root; absolute paths override when allowed." },
                    "edits": {
                        "type": "array",
                        "description": "List of exact find/replace edits to apply in order.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "find": { "type": "string", "description": "Exact text to find (must match exactly once)." },
                                "replace": { "type": "string", "description": "Replacement text." }
                            },
                            "required": ["find", "replace"]
                        }
                    }
                },
                "required": ["path", "edits"]
            },
		"outputSchema": {
                "type": "object",
                "properties": {
                    "structuredContent": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Path relative to the configured server root." },
                            "match_count": { "type": "integer", "minimum": 0, "description": "Number of matches found (must be 1)." },
                            "code": { "type": "string", "description": "Error code when isError is true." }
                        }
                    },
                    "content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "text": { "type": "string" },
                                "url": { "type": "string" }
                            },
                            "required": ["type"]
                        }
                    },
                    "isError": { "type": "boolean" }
                },
                "required": ["structuredContent", "content"]
            }
	})
	]
}

async fn execute_tool(
	config: &Config,
	name: &str,
	arguments: &Value,
	meta: &Value) -> Result<ToolOutcome> {
	let params = arguments.as_object().ok_or_else(|| ProtocolError::new(-32602, "arguments must be an object"))?;
	let args = Value::Object(params.clone());
	let preview = parse_meta_preview(meta.get("preview"));
	let call_config = resolve_call_config(config, meta, name)?;
	let result = match name {
		"list_roots" => run_tool(
			"list_roots",
			&call_config,
			None,
			|| async {
				let roots = build_roots_output(&call_config);
				Ok(json!({
					"roots": roots
				}))
			}
		).await,
		"search_files" => run_tool(
			"search_files",
			&call_config,
			None,
			|| async {
				let pattern = args.get("pattern")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("pattern is required"))?;
				let root_param = args.get("root")
					.and_then(Value::as_str)
					.unwrap_or(".");
				let (root_path, root_index, root_label, root_rel) = resolve_root_param(&call_config, root_param)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_root("read", root_param, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						err
					})?;
				if !root_path.exists() {
					return Err(anyhow!("root not found: {}", root_param));
				}
				let glob = args.get("glob")
					.and_then(Value::as_array)
					.map(
						|values| {
							values.iter()
								.filter_map(Value::as_str)
								.map(|value| value.to_string())
								.collect::<Vec<_>>()
						})
					.unwrap_or_default();
				let case_sensitive = parse_case_sensitivity(args.get("case_sensitive"))?;
				let before_context = args.get("before_context")
					.and_then(Value::as_u64)
					.map(|value| value as usize);
				let after_context = args.get("after_context")
					.and_then(Value::as_u64)
					.map(|value| value as usize);
				let context = args.get("context")
					.and_then(Value::as_u64)
					.map(|value| value as usize);
				let options = fs::SearchOptions {
					glob,
					case_sensitive,
					before_context,
					after_context,
					context,
					max_bytes: call_config.search_max_bytes,
					summary_top: call_config.search_summary_top
				};
				let result = fs::rg_search(
					&root_path,
					&root_label,
					pattern,
					options
				).await?;
				filter_search_results(&call_config, root_index, &root_rel, result)
			}
		).await,
		"find_files" => run_tool(
			"find_files",
			&call_config,
			None,
			|| async {
				let pattern = args.get("pattern")
					.and_then(Value::as_str)
					.unwrap_or("");
				let root_param = args.get("root")
					.and_then(Value::as_str)
					.unwrap_or(".");
				let (root_path, root_index, root_label, root_rel) = resolve_root_param(&call_config, root_param)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_root("read", root_param, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						err
					})?;
				if !root_path.exists() {
					return Err(anyhow!("root not found: {}", root_param));
				}
				let file_type = args.get("type")
					.and_then(Value::as_str)
					.map(|value| value.to_string());
				let max_depth = args.get("max_depth")
					.and_then(Value::as_u64)
					.map(|value| value as usize);
				let follow = args.get("follow")
					.and_then(Value::as_bool)
					.unwrap_or(false);
				let glob = args.get("glob")
					.and_then(Value::as_bool)
					.unwrap_or(false);
				let case_sensitive = parse_case_sensitivity(args.get("case_sensitive"))?;
				let exclude = args.get("exclude")
					.and_then(Value::as_array)
					.map(
						|values| {
							values.iter()
								.filter_map(Value::as_str)
								.map(|value| value.to_string())
					.collect::<Vec<_>>()
				})
				.unwrap_or_default();
				let limit = parse_limit(args.get("limit"))?.or(call_config.find_limit);
				let offset = args.get("offset")
					.and_then(Value::as_u64)
					.unwrap_or(0) as usize;
				let options = fs::FindOptions {
					file_type,
					max_depth,
					follow,
					glob,
					case_sensitive,
					exclude,
					limit,
					offset
				};
				let result = fs::find(
					&root_path,
					&root_label,
					pattern,
					options
				).await?;
				filter_find_results(&call_config, root_index, &root_rel, result)
			}
		).await,
		"read_file" => run_tool(
			"read_file",
			&call_config,
			None,
			|| async {
				let path = args.get("path")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("path is required"))?;
				let start_line = args.get("start_line")
					.and_then(Value::as_u64)
					.unwrap_or(1) as usize;
				let limit = parse_read_limit(args.get("limit"))?.unwrap_or(200);
				let highlight = parse_meta_highlight(meta.get("highlight"));
				let resolved = resolve_path_for_call(&call_config, path)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_path("read", path, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						anyhow!("invalid path {}: {}", path, err)
					})?;
				let rel_path = match resolved.root_index {
					Some(index) => relative_to_root(&call_config.roots[index].path, &resolved.absolute),
					None => resolved.absolute.to_string_lossy().to_string(),
				};
				let max_total = call_config.read_max_bytes.unwrap_or(usize::MAX);
				let max_line = call_config.read_max_line_bytes.unwrap_or(usize::MAX);
				if highlight {
					let raw = tokio::fs::read_to_string(&resolved.absolute).await.map_err(|err| format_io_error("read", &rel_path, err.into()))?;
					let (lines, count, total, truncated, truncated_reason, long_lines) = fs::format_line_slices(
						&raw,
						start_line,
						limit,
						max_total,
						max_line
					);
					let line_truncated = start_line.saturating_sub(1) + count < total;
					let truncated = truncated || line_truncated;
					let mut rows = String::new();
					let syntax = syntax_for_path(&rel_path);
					let mut hl = ParseState::new(syntax);
					for line in lines {
						let html = highlight_line_html(&mut hl, &line.text);
						rows.push_str(
							&format!(
								"<tr class='eq'><td class='ln'>{}</td><td class='code'><pre><code>{}</code></pre></td></tr>",
								line.number, html
							)
						);
					}
					let mut obj = serde_json::Map::new();
					obj.insert("path".to_string(), Value::String(rel_path));
					obj.insert(
						"content".to_string(),
						Value::String(format!("<table class=\"diff unified\"><tbody>{}</tbody></table>", rows))
					);
					obj.insert("count".to_string(), Value::Number(count.into()));
					obj.insert("total".to_string(), Value::Number(total.into()));
					obj.insert("start_line".to_string(), Value::Number(start_line.into()));
					obj.insert("truncated".to_string(), Value::Bool(truncated));
					if count == 0 && start_line > total && total > 0 {
						obj.insert("code".to_string(), Value::String("EMPTY_RANGE".to_string()));
					}
					if truncated {
						if let Some(reason) = truncated_reason {
							obj.insert("truncated_reason".to_string(), Value::Array(reason));
						}
						else if line_truncated {
							obj.insert("truncated_reason".to_string(), Value::Array(vec![Value::String("line_limit".to_string())]));
						}
					}
					if long_lines {
						obj.insert("code".to_string(), Value::String("TRUNCATED_LONG_LINES".to_string()));
					}
					Ok(Value::Object(obj))
				}
				else {
					let data = fs::read_file(
						&resolved.absolute,
						start_line,
						limit,
						max_total,
						max_line
					).await.map_err(|err| format_io_error("read", &rel_path, err))?;
					Ok(
						json!({
							"path": rel_path,
							"content": data.get("content").cloned().unwrap_or(Value::Null),
							"count": data.get("count").cloned().unwrap_or(Value::Null),
							"total": data.get("total").cloned().unwrap_or(Value::Null),
							"start_line": data.get("start_line").cloned().unwrap_or(Value::Null),
							"truncated": data.get("truncated").cloned().unwrap_or(Value::Null),
							"truncated_reason": data.get("truncated_reason").cloned().unwrap_or(Value::Null),
							"code": data.get("code").cloned().unwrap_or(Value::Null)
						})
					)
				}
			}
		).await,
		"read_multiple_files" => run_tool(
			"read_multiple_files",
			&call_config,
			None,
			|| async {
				let paths = args.get("paths").ok_or_else(|| anyhow!("paths is required"))?.as_array()
					.ok_or_else(|| anyhow!("paths must be an array"))?;
				if paths.is_empty() {
					return Err(anyhow!("paths is empty"));
				}
				let max_total = call_config.read_max_bytes.unwrap_or(usize::MAX);
				let max_line = call_config.read_max_line_bytes.unwrap_or(usize::MAX);
				let per_file = if max_total == usize::MAX {
					usize::MAX
				}
				else {
					max_total / paths.len().max(1)
				};
				let mut files = Vec::new();
				let mut requested_scopes = Vec::new();
				for path_value in paths {
					let path = match path_value.as_str() {
						Some(value) => value,
						None => continue,
					};
					let resolved = match resolve_path_for_call(&call_config, path) {
						Ok(resolved) => resolved,
						Err(err) => {
							if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
								requested_scopes.push(requested_scope_for_path("read", path, &config.default_root));
							}
							let rel_path = relative_to_root(&call_config.default_root, &PathBuf::from(path));
							files.push(json!({
								"path": rel_path,
								"code": "INVALID_PATH"
							}));
							continue;
						}
					};
					let rel_path = match resolved.root_index {
						Some(index) => relative_to_root(&call_config.roots[index].path, &resolved.absolute),
						None => resolved.absolute.to_string_lossy().to_string(),
					};
					match fs::read_file_head(&resolved.absolute, per_file, max_line).await {
						Ok((content, count, total, truncated, long_lines)) => {
							let mut entry = serde_json::Map::new();
							entry.insert("path".to_string(), Value::String(rel_path));
							entry.insert("content".to_string(), Value::String(content));
							entry.insert("count".to_string(), Value::Number(count.into()));
							entry.insert("total".to_string(), Value::Number(total.into()));
							entry.insert("truncated".to_string(), Value::Bool(truncated));
							if long_lines {
								entry.insert("code".to_string(), Value::String("TRUNCATED_LONG_LINES".to_string()));
							}
							files.push(Value::Object(entry));
						}
						Err(err) => {
							let code = if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
								if io_err.kind() == std::io::ErrorKind::NotFound {
									"FILE_NOT_FOUND"
								}
								else if io_err.kind() == std::io::ErrorKind::PermissionDenied {
									"PERMISSION_DENIED"
								}
								else {
									"EXECUTION_ERROR"
								}
							}
							else {
								"EXECUTION_ERROR"
							};
							files.push(json!({
								"path": rel_path,
								"code": code
							}));
						}
					}
				}
				if !requested_scopes.is_empty() && !call_config.allow_escape && !call_config.policy_active {
					return Err(RequestedScopeError {
						scopes: requested_scopes
					}.into());
				}
				Ok(json!({
					"files": files
				}))
			}
		).await,
		"move_file" => run_tool(
			"move_file",
			&call_config,
			None,
			|| async {
				let from = args.get("from")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("from is required"))?;
				let to = args.get("to")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("to is required"))?;
				let resolved_from = resolve_path_for_call(&call_config, from)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_path("write", from, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						anyhow!("invalid path {}: {}", from, err)
					})?;
				ensure_writable_root(&call_config, &resolved_from)?;
				let resolved_to = resolve_path_for_call(&call_config, to)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_path("write", to, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						anyhow!("invalid path {}: {}", to, err)
					})?;
				ensure_writable_root(&call_config, &resolved_to)?;
				if call_config.roots.iter().any(|root| resolved_from.absolute == root.path_canon || resolved_to.absolute == root.path_canon) {
					return Err(anyhow!("cannot move root"));
				}
				let rel_from = match resolved_from.root_index {
					Some(index) => relative_to_root(&call_config.roots[index].path, &resolved_from.absolute),
					None => resolved_from.absolute.to_string_lossy().to_string(),
				};
				let rel_to = match resolved_to.root_index {
					Some(index) => relative_to_root(&call_config.roots[index].path, &resolved_to.absolute),
					None => resolved_to.absolute.to_string_lossy().to_string(),
				};
				fs::move_path(&resolved_from.absolute, &resolved_to.absolute).await.map_err(|err| format_io_error("move", &rel_from, err))?;
				Ok(json!({
					"from": rel_from, "to": rel_to
				}))
			}
		).await,
		"delete_file" => run_tool(
			"delete_file",
			&call_config,
			None,
			|| async {
				let path = args.get("path")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("path is required"))?;
				let resolved = resolve_path_for_call(&call_config, path)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_path("write", path, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						anyhow!("invalid path {}: {}", path, err)
					})?;
				ensure_writable_root(&call_config, &resolved)?;
				if call_config.roots.iter().any(|root| resolved.absolute == root.path_canon) {
					return Err(anyhow!("cannot delete root"));
				}
				let rel_path = match resolved.root_index {
					Some(index) => relative_to_root(&call_config.roots[index].path, &resolved.absolute),
					None => resolved.absolute.to_string_lossy().to_string(),
				};
				fs::delete_path(&resolved.absolute).await.map_err(|err| format_io_error("delete", &rel_path, err))?;
				Ok(json!({
					"path": rel_path
				}))
			}
		).await,
		"write_file" => run_tool(
			"write_file",
			&call_config,
			Some(preview),
			|| async {
				let path = args.get("path")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("path is required"))?;
				let content = args.get("content")
					.and_then(Value::as_str)
					.ok_or_else(|| anyhow!("content is required"))?;
				let mode = args.get("mode")
					.and_then(Value::as_str)
					.unwrap_or("overwrite");
				let apply = !preview;
				let resolved = resolve_path_for_call(&call_config, path)
					.map_err(|err| {
						if err.to_string().contains("path outside root") && !call_config.allow_escape && !call_config.policy_active {
							let scope = requested_scope_for_path("write", path, &config.default_root);
							return RequestedScopeError {
								scopes: vec![scope]
							}.into();
						}
						anyhow!("invalid path {}: {}", path, err)
					})?;
				ensure_writable_root(&call_config, &resolved)?;
				let rel_path = match resolved.root_index {
					Some(index) => relative_to_root(&call_config.roots[index].path, &resolved.absolute),
					None => resolved.absolute.to_string_lossy().to_string(),
				};
				let data = fs::write_file(
					&resolved.absolute,
					content,
					mode,
					apply
				).await.map_err(|err| format_io_error("write", &rel_path, err))?;
				let mut structured = json!({
					"path": rel_path
				});
				if preview {
					let before = data.get("before")
						.and_then(Value::as_str)
						.unwrap_or("");
					let after = data.get("after")
						.and_then(Value::as_str)
						.unwrap_or("");
					let edit_id = uuid::Uuid::new_v4().to_string();
					let review_uri = format!("ui://write_file/{}", edit_id);
					let html = render_diff_html(
						before,
						after,
						&rel_path,
						&review_uri
					);
					let entry = PreviewEntry {
						uri: review_uri,
						html,
						diff: data.get("diff")
							.and_then(Value::as_str)
							.unwrap_or("")
							.to_string(),
						path: structured.get("path")
							.and_then(Value::as_str)
							.unwrap_or("file")
							.to_string()
					};
					let mut cache = PREVIEW_CACHE.lock().expect("preview cache lock");
					cache.insert(entry);
					if let Some(obj) = structured.as_object_mut() {
						obj.insert("edit_id".to_string(), Value::String(edit_id));
					}
				}
				Ok(structured)
			}
		).await,
		"edit_file" => run_tool(
			"edit_file",
			&call_config,
			Some(preview),
			|| async { edit_file_tool(&call_config, &args, preview, &config.default_root).await }
		).await,
		_ => return Err(ProtocolError::new(-32601, "unknown tool").into()),
	};
	Ok(result)
}

fn parse_case_sensitivity(value: Option<&Value>) -> Result<fs::CaseSensitivity> {
	let Some(value) = value else {
		return Ok(fs::CaseSensitivity::Auto);
	};
	if let Some(boolean) = value.as_bool() {
		return Ok(if boolean {
			fs::CaseSensitivity::Sensitive
		}
		else {
			fs::CaseSensitivity::Insensitive
		});
	}
	let text = value.as_str().ok_or_else(|| anyhow!("case_sensitive must be bool or string"))?;
	match text.to_lowercase().as_str() {
		"auto" => Ok(fs::CaseSensitivity::Auto),
		"true" | "sensitive" => Ok(fs::CaseSensitivity::Sensitive),
		"false" | "insensitive" => Ok(fs::CaseSensitivity::Insensitive),
		_ => Err(anyhow!("case_sensitive must be auto|true|false")),
	}
}

fn parse_limit(value: Option<&Value>) -> Result<Option<usize>> {
	let Some(value) = value else {
		return Ok(None);
	};
	let limit = value.as_u64().ok_or_else(|| anyhow!("limit must be a positive integer"))?;
	if limit == 0 {
		return Ok(None);
	}
	Ok(Some(limit as usize))
}

fn parse_read_limit(value: Option<&Value>) -> Result<Option<usize>> {
	let Some(value) = value else {
		return Ok(None);
	};
	let limit = value.as_u64().ok_or_else(|| anyhow!("limit must be a non-negative integer"))?;
	if limit == 0 {
		return Ok(Some(usize::MAX));
	}
	Ok(Some(limit as usize))
}

fn parse_usize(value: &str, label: &str) -> Result<usize> {
	value.trim().parse::<usize>().map_err(|_| anyhow!("{} must be a non-negative integer", label))
}

fn parse_find_limit(value: &str, label: &str) -> Result<Option<usize>> {
	let parsed = parse_usize(value, label)?;
	if parsed == 0 {
		return Ok(None);
	}
	Ok(Some(parsed))
}

fn parse_optional_limit(value: &str, label: &str) -> Result<Option<usize>> {
	let parsed = parse_usize(value, label)?;
	if parsed == 0 {
		return Ok(None);
	}
	Ok(Some(parsed))
}

fn parse_byte_limit(value: &str, label: &str) -> Result<Option<usize>> {
	let parsed = parse_usize(value, label)?;
	if parsed == 0 {
		return Ok(None);
	}
	Ok(Some(parsed))
}

fn parse_bool(value: &str, label: &str) -> Result<bool> {
	let value = value.trim().to_lowercase();
	match value.as_str() {
		"1" | "true" | "yes" | "on" => Ok(true),
		"0" | "false" | "no" | "off" => Ok(false),
		_ => Err(anyhow!("{} must be a boolean", label)),
	}
}

fn extract_tool_name(method: &str, params: &Value) -> Option<String> {
	if method != "tools/call" {
		return None;
	}
	params.get("name")
		.and_then(Value::as_str)
		.map(|value| value.to_string())
}

fn extract_request_root(method: &str, params: &Value) -> Option<String> {
	if method != "tools/call" {
		return None;
	}
	let name = params.get("name").and_then(Value::as_str)?;
	let args = params.get("arguments")?;
	match name {
		"find_files" | "search_files" => args.get("root")
			.and_then(Value::as_str)
			.map(|value| value.to_string()),
		_ => None,
	}
}

fn record_result(span: &Span, result: &Value) {
	let response_bytes = serde_json::to_string(result).map(|value| value.as_bytes().len() as u64).ok();
	if let Some(bytes) = response_bytes {
		span.record("mcp.response_bytes", bytes);
	}
	let is_error = result.get("isError")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	span.record("mcp.is_error", is_error);
	if let Some(code) = result.get("structuredContent")
		.and_then(|value| value.get("code"))
		.and_then(Value::as_str) {
		span.record("mcp.error_code", code);
	}
	if let Some(mode) = result.get("structuredContent")
		.and_then(|value| value.get("mode"))
		.and_then(Value::as_str) {
		span.record("mcp.mode", mode);
	}
	if let Some(count) = result.get("structuredContent")
		.and_then(|value| value.get("count"))
		.and_then(Value::as_u64) {
		span.record("mcp.count", count);
	}
}

async fn write_response(writer: &mut io::BufWriter<io::Stdout>, resp: Response) -> Result<()> {
	let line = serde_json::to_string(&resp)?;
	writer.write_all(line.as_bytes()).await?;
	writer.write_all(b"\n").await?;
	writer.flush().await?;
	Ok(())
}
