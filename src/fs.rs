use anyhow::{anyhow, Result};
use globset::{GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use similar::TextDiff;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::fs;
use filetime::{FileTime, set_file_times};
use std::future::Future;
use std::pin::Pin;

pub async fn read_file(
	path: &Path,
	start_line: usize,
	limit: usize,
	max_total_bytes: usize,
	max_line_bytes: usize) -> Result<Value> {
	let content = tokio::fs::read_to_string(path).await?;
	let (formatted, count, total, truncated, truncated_reason, long_lines) = format_lines(
		&content,
		start_line,
		limit,
		max_total_bytes,
		max_line_bytes
	);
	let line_truncated = start_line.saturating_sub(1) + count < total;
	let truncated = truncated || line_truncated;
	let mut obj = serde_json::Map::new();
	obj.insert("content".to_string(), Value::String(formatted));
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

pub async fn read_file_head(
	path: &Path,
	max_total_bytes: usize,
	max_line_bytes: usize) -> Result<(String, usize, usize, bool, bool)> {
	let content = tokio::fs::read_to_string(path).await?;
	let (formatted, count, total, truncated, _reason, long_lines) = format_lines(
		&content,
		1,
		usize::MAX,
		max_total_bytes,
		max_line_bytes
	);
	Ok((formatted, count, total, truncated, long_lines))
}

pub async fn move_path(from: &Path, to: &Path) -> Result<()> {
	if fs::metadata(to).await.is_ok() {
		return Err(anyhow!("target exists"));
	}
	match fs::rename(from, to).await {
		Ok(_) => return Ok(()),
		Err(err) => {
			if !is_cross_device(&err) {
				return Err(err.into());
			}
		}
	}
	let meta = fs::metadata(from).await?;
	if meta.is_dir() {
		copy_dir_recursive(from.to_path_buf(), to.to_path_buf()).await?;
		fs::remove_dir_all(from).await?;
	}
	else {
		copy_file_with_meta(from, to).await?;
		fs::remove_file(from).await?;
	}
	Ok(())
}

pub async fn delete_path(path: &Path) -> Result<()> {
	let meta = fs::metadata(path).await?;
	if meta.is_dir() {
		fs::remove_dir_all(path).await?;
	}
	else {
		fs::remove_file(path).await?;
	}
	Ok(())
}

async fn copy_file_with_meta(from: &Path, to: &Path) -> Result<()> {
	if let Some(parent) = to.parent() {
		fs::create_dir_all(parent).await?;
	}
	fs::copy(from, to).await?;
	let meta = fs::metadata(from).await?;
	fs::set_permissions(to, meta.permissions()).await?;
	let atime = FileTime::from_last_access_time(&meta);
	let mtime = FileTime::from_last_modification_time(&meta);
	set_file_times(to, atime, mtime)?;
	Ok(())
}

fn copy_dir_recursive(from: PathBuf, to: PathBuf) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
	Box::pin(
		async move {
			fs::create_dir_all(&to).await?;
			let mut entries = fs::read_dir(&from).await?;
			while let Some(entry) = entries.next_entry().await? {
				let src = entry.path();
				let dst = to.join(entry.file_name());
				let meta = fs::metadata(&src).await?;
				if meta.is_dir() {
					copy_dir_recursive(src, dst).await?;
				}
				else {
					copy_file_with_meta(&src, &dst).await?;
				}
			}
			let meta = fs::metadata(&from).await?;
			fs::set_permissions(&to, meta.permissions()).await?;
			let atime = FileTime::from_last_access_time(&meta);
			let mtime = FileTime::from_last_modification_time(&meta);
			set_file_times(&to, atime, mtime)?;
			Ok(())
		}
	)
}

fn is_cross_device(err: &std::io::Error) -> bool {
	err.raw_os_error() == Some(libc::EXDEV)
}

pub async fn write_file(
	path: &Path,
	content: &str,
	mode: &str,
	apply: bool) -> Result<Value> {
	let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
	let next = match mode {
		"overwrite" => content.to_string(),
		"append" => {
			if existing.is_empty() || content.is_empty() {
				format!("{}{}", existing, content)
			}
			else if existing.ends_with('\n') {
				format!("{}{}", existing, content)
			}
			else {
				format!("{}\n{}", existing, content)
			}
		}
		"prepend" => {
			if existing.is_empty() || content.is_empty() {
				format!("{}{}", content, existing)
			}
			else if content.ends_with('\n') {
				format!("{}{}", content, existing)
			}
			else {
				format!("{}\n{}", content, existing)
			}
		}
		_ => return Err(anyhow!("mode must be overwrite, append, or prepend")),
	};
	let diff = make_diff(&existing, &next, path);
	if apply {
		if let Some(parent) = path.parent() {
			tokio::fs::create_dir_all(parent).await?;
		}
		tokio::fs::write(path, &next).await?;
	}
	Ok(json!({
		"applied": apply,
		"diff": diff,
		"before": existing,
		"after": next,
	}))
}

pub struct SearchOptions {
	pub glob: Vec<String>,
	pub case_sensitive: CaseSensitivity,
	pub before_context: Option<usize>,
	pub after_context: Option<usize>,
	pub context: Option<usize>,
	pub max_bytes: Option<usize>,
	pub summary_top: Option<usize>,
}

pub async fn rg_search(
	root: &Path,
	root_label: &str,
	pattern: &str,
	options: SearchOptions) -> Result<Value> {
	let mut cmd = Command::new("rg");
	cmd.arg("--json");
	match options.case_sensitive {
		CaseSensitivity::Sensitive => {
			cmd.arg("--case-sensitive");
		}
		CaseSensitivity::Insensitive => {
			cmd.arg("--ignore-case");
		}
		CaseSensitivity::Auto => {
			cmd.arg("--smart-case");
		}
	}
	if let Some(context) = options.context {
		cmd.arg("-C").arg(context.to_string());
	}
	else {
		if let Some(before) = options.before_context {
			cmd.arg("-B").arg(before.to_string());
		}
		if let Some(after) = options.after_context {
			cmd.arg("-A").arg(after.to_string());
		}
	}
	for glob in &options.glob {
		cmd.arg("--glob").arg(glob);
	}
	cmd.arg(pattern).arg(root);
	cmd.stdout(Stdio::piped());
	cmd.stderr(Stdio::piped());
	let mut child = cmd.spawn()?;
	let stdout = child.stdout
		.take()
		.ok_or_else(|| anyhow!("rg stdout missing"))?;
	let stderr = child.stderr
		.take()
		.ok_or_else(|| anyhow!("rg stderr missing"))?;
	let mut reader = BufReader::new(stdout);
	let mut output = String::new();
	reader.read_to_string(&mut output).await?;
	let mut err_reader = BufReader::new(stderr);
	let mut err_output = String::new();
	err_reader.read_to_string(&mut err_output).await?;
	let status = child.wait().await?;
	if !status.success() && status.code() != Some(1) {
		return Err(anyhow!("rg failed: {}", err_output.trim()));
	}
	let mut files: Vec<Value> = Vec::new();
	let mut current_path: Option<String> = None;
	let mut current_chunks: Vec<String> = Vec::new();
	let mut current_chunk = String::new();
	let mut last_line: Option<u64> = None;
	let flush_chunk = |chunks: &mut Vec<String>, chunk: &mut String, last_line_ref: &mut Option<u64>| {
		if !chunk.is_empty() {
			chunks.push(chunk.trim_end().to_string());
			chunk.clear();
			*last_line_ref = None;
		}
	};
	let mut flush_file = |path: Option<String>, chunks: &mut Vec<String>| {
		if let Some(path) = path {
			if !chunks.is_empty() {
				files.push(json!({
					"path": path,
					"matches": chunks.clone(),
				}));
				chunks.clear();
			}
		}
	};
	for line in output.lines() {
		let value: Value = serde_json::from_str(line)?;
		let value_type = value.get("type")
			.and_then(Value::as_str)
			.unwrap_or("");
		if value_type == "begin" {
			let data = value.get("data").ok_or_else(|| anyhow!("rg begin missing data"))?;
			let path = data.get("path")
				.and_then(|p| p.get("text"))
				.and_then(Value::as_str)
				.ok_or_else(|| anyhow!("rg begin missing path"))?.to_string();
			let path = normalize_search_path(root, &path);
			flush_chunk(&mut current_chunks, &mut current_chunk, &mut last_line);
			flush_file(current_path.take(), &mut current_chunks);
			current_path = Some(path);
			continue;
		}
		if value_type == "end" {
			flush_chunk(&mut current_chunks, &mut current_chunk, &mut last_line);
			flush_file(current_path.take(), &mut current_chunks);
			continue;
		}
		if value_type != "match" && value_type != "context" {
			continue;
		}
		let data = value.get("data").ok_or_else(|| anyhow!("rg entry missing data"))?;
		let line_number = data.get("line_number")
			.and_then(Value::as_u64)
			.ok_or_else(|| anyhow!("rg entry missing line number"))?;
		let line_text = data.get("lines")
			.and_then(|lines| lines.get("text"))
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow!("rg entry missing line text"))?;
		if let Some(last) = last_line {
			if line_number != last + 1 {
				flush_chunk(&mut current_chunks, &mut current_chunk, &mut last_line);
			}
		}
		let prefix = if value_type == "match" {
			':'
		}
		else {
			'-'
		};
		let trimmed = line_text.trim_end_matches('\n');
		current_chunk.push_str(&format!("{}{} {}\n", line_number, prefix, trimmed));
		last_line = Some(line_number);
	}
	flush_chunk(&mut current_chunks, &mut current_chunk, &mut last_line);
	flush_file(current_path.take(), &mut current_chunks);
	let total_files = files.len();
	let total_matches = files.iter()
		.filter_map(|file| file.get("matches").and_then(Value::as_array))
		.map(|chunks| chunks.len())
		.sum::<usize>();
	let max_bytes = options.max_bytes.unwrap_or(0);
	let mode = if max_bytes == 0 {
		OutputMode::Full
	}
	else if estimate_output_size(&files, pattern, root_label) <= max_bytes {
		OutputMode::Full
	}
	else {
		OutputMode::Reduced
	};
	let (files, mode) = match mode {
		OutputMode::Full => (files, OutputMode::Full),
		OutputMode::Reduced => {
			let reduced = reduce_context(&files);
			if max_bytes == 0 || estimate_output_size(&reduced, pattern, root_label) <= max_bytes {
				(reduced, OutputMode::Reduced)
			}
			else {
				let summary = summarize_files(&files);
				let summary = reduce_summary(summary, max_bytes, options.summary_top);
				(summary, OutputMode::Summary)
			}
		}
		OutputMode::Summary => {
			let summary = summarize_files(&files);
			let summary = reduce_summary(summary, max_bytes, options.summary_top);
			(summary, OutputMode::Summary)
		}
	};
	let count = files.len();
	Ok(
		json!({
			"files": files,
			"pattern": pattern,
			"root": root_label,
			"count": count,
			"total_files": total_files,
			"total_matches": total_matches,
			"truncated": mode != OutputMode::Full,
			"mode": mode.as_str()
		})
	)
}

#[derive(Clone, Copy, PartialEq)]
enum OutputMode {
	Full,
	Reduced,
	Summary,
}

impl OutputMode {
	fn as_str(self) -> &'static str {
		match self {
			OutputMode::Full => "full",
			OutputMode::Reduced => "reduced",
			OutputMode::Summary => "summary",
		}
	}
}

fn reduce_context(files: &[Value]) -> Vec<Value> {
	let mut reduced = Vec::new();
	for file in files {
		let path = file.get("path")
			.cloned()
			.unwrap_or(Value::Null);
		let chunks = file.get("matches")
			.and_then(Value::as_array)
			.cloned()
			.unwrap_or_default();
		let mut reduced_chunks = Vec::new();
		for chunk in chunks {
			let chunk_str = chunk.as_str().unwrap_or("");
			let mut out = String::new();
			for line in chunk_str.lines() {
				let mut chars = line.chars();
				let mut saw_digit = false;
				let mut marker: Option<char> = None;
				while let Some(ch) = chars.next() {
					if ch.is_ascii_digit() {
						saw_digit = true;
						continue;
					}
					if saw_digit {
						marker = Some(ch);
						break;
					}
				}
				if marker == Some(':') {
					out.push_str(line);
					out.push('\n');
				}
			}
			if !out.trim().is_empty() {
				reduced_chunks.push(Value::String(out.trim_end().to_string()));
			}
		}
		if !reduced_chunks.is_empty() {
			reduced.push(json!({
				"path": path,
				"matches": reduced_chunks,
			}));
		}
	}
	reduced
}

fn summarize_files(files: &[Value]) -> Vec<Value> {
	let mut summary = Vec::new();
	for file in files {
		let path = file.get("path")
			.cloned()
			.unwrap_or(Value::Null);
		let count = file.get("matches")
			.and_then(Value::as_array)
			.map(|chunks| chunks.len())
			.unwrap_or(0);
		summary.push(json!({
			"path": path,
			"count": count,
		}));
	}
	summary
}

fn reduce_summary(mut summary: Vec<Value>, max_bytes: usize, top: Option<usize>) -> Vec<Value> {
	if max_bytes == 0 {
		return summary;
	}
	if estimate_summary_size(&summary) <= max_bytes {
		return summary;
	}
	let Some(top) = top else {
		return summary;
	};
	if top == 0 {
		return summary;
	}
	summary.sort_by(
		|a, b| {
			let a_count = a.get("count")
				.and_then(Value::as_u64)
				.unwrap_or(0);
			let b_count = b.get("count")
				.and_then(Value::as_u64)
				.unwrap_or(0);
			b_count.cmp(&a_count)
		}
	);
	summary.truncate(top);
	summary
}

fn estimate_output_size(files: &[Value], pattern: &str, root: &str) -> usize {
	let candidate = json!({
		"files": files,
		"pattern": pattern,
		"root": root,
	});
	serde_json::to_string(&candidate).map(|value| value.as_bytes().len()).unwrap_or(usize::MAX)
}

fn estimate_summary_size(files: &[Value]) -> usize {
	let candidate = json!({
		"files": files,
	});
	serde_json::to_string(&candidate).map(|value| value.as_bytes().len()).unwrap_or(usize::MAX)
}

fn normalize_search_path(root: &Path, path_text: &str) -> String {
	let path = Path::new(path_text);
	let absolute = if path.is_absolute() {
		path.to_path_buf()
	}
	else {
		root.join(path)
	};
	if let Ok(rel) = absolute.strip_prefix(root) {
		return rel.to_string_lossy().to_string();
	}
	path_text.to_string()
}

pub struct FindOptions {
	pub file_type: Option<String>,
	pub max_depth: Option<usize>,
	pub follow: bool,
	pub glob: bool,
	pub case_sensitive: CaseSensitivity,
	pub exclude: Vec<String>,
	pub limit: Option<usize>,
	pub offset: usize,
}

#[derive(Clone, Copy)]
pub enum CaseSensitivity {
	Auto,
	Sensitive,
	Insensitive,
}

pub async fn find(
	root: &Path,
	root_label: &str,
	pattern: &str,
	options: FindOptions) -> Result<Value> {
	let matcher = build_matcher(pattern, options.glob, options.case_sensitive)?;
	let exclude_set = build_exclude_set(&options.exclude)?;
	let mut remaining = options.limit;
	let mut truncated = false;
	let mut skipped = 0usize;
	let mut builder = WalkBuilder::new(root);
	builder.hidden(true);
	builder.follow_links(options.follow);
	if let Some(depth) = options.max_depth {
		builder.max_depth(Some(depth));
	}
	let mut matches = Vec::new();
	for entry in builder.build() {
		let entry = entry?;
		let path = entry.path();
		if path == root {
			continue;
		}
		if !matches_type(&entry, options.file_type.as_deref())? {
			continue;
		}
		let file_name = match path.file_name().and_then(|name| name.to_str()) {
			Some(name) => name,
			None => continue,
		};
		if let Some(excludes) = &exclude_set {
			let rel = relative_display(root, path);
			if excludes.is_match(&rel) {
				continue;
			}
		}
		if let Some(matcher) = &matcher {
			if !matcher.is_match(file_name) {
				continue;
			}
		}
		if skipped < options.offset {
			skipped += 1;
			continue;
		}
		if let Some(remaining_count) = remaining {
			if remaining_count == 0 {
				truncated = true;
				break;
			}
		}
		let mut rel = relative_display(root, path);
		if is_dir_entry(&entry) {
			if !rel.ends_with('/') {
				rel.push('/');
			}
		}
		matches.push(rel);
		if let Some(remaining_count) = remaining.as_mut() {
			*remaining_count = remaining_count.saturating_sub(1);
		}
	}
	let count = matches.len();
	Ok(
		json!({
			"matches": matches,
			"pattern": pattern,
			"root": root_label,
			"count": count,
			"offset": options.offset,
			"limit": options.limit,
			"truncated": truncated
		})
	)
}

fn make_diff(existing: &str, updated: &str, path: &Path) -> String {
	let diff = TextDiff::from_lines(existing, updated);
	diff.unified_diff()
		.context_radius(3)
		.header(&format!("a/{}", path.display()), &format!("b/{}", path.display()))
		.to_string()
}

pub struct LineSlice {
	pub number: usize,
	pub text: String,
}

pub fn format_line_slices(
	content: &str,
	start_line: usize,
	limit: usize,
	max_total_bytes: usize,
	max_line_bytes: usize) -> (Vec<LineSlice>, usize, usize, bool, Option<Vec<Value>>, bool) {
	let total = content.lines().count();
	let mut out: Vec<LineSlice> = Vec::new();
	let mut taken = 0usize;
	let mut total_bytes = 0usize;
	let mut truncated = false;
	let mut long_lines = false;
	let mut reasons: Vec<Value> = Vec::new();
	let start_index = start_line.saturating_sub(1);
	for (index, line) in content.lines().enumerate() {
		if index < start_index {
			continue;
		}
		if taken >= limit {
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("line_limit")) {
				reasons.push(Value::String("line_limit".to_string()));
			}
			break;
		}
		let mut line_text = line.to_string();
		let mut hidden = 0usize;
		let line_bytes = line.as_bytes().len();
		if line_bytes > max_line_bytes {
			let (truncated_line, kept_bytes) = truncate_to_bytes(line, max_line_bytes);
			hidden = line_bytes.saturating_sub(kept_bytes);
			line_text = format!(
				"{} [TRUNCATED: {} bytes hidden]",
				truncated_line, hidden
			);
			long_lines = true;
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("long_lines")) {
				reasons.push(Value::String("long_lines".to_string()));
			}
		}
		let formatted = format!("{}: {}", index + 1, line_text);
		let line_output_bytes = formatted.as_bytes().len();
		let separator_bytes = if out.is_empty() {
			0
		}
		else {
			1
		};
		if total_bytes + separator_bytes + line_output_bytes > max_total_bytes {
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("max_bytes")) {
				reasons.push(Value::String("max_bytes".to_string()));
			}
			break;
		}
		total_bytes += separator_bytes + line_output_bytes;
		out.push(LineSlice {
			number: index + 1,
			text: line_text
		});
		taken += 1;
		if hidden > 0 {
			// already marked above
		}
	}
	let truncated_reason = if truncated {
		Some(reasons)
	}
	else {
		None
	};
	(out, taken, total, truncated, truncated_reason, long_lines)
}

fn format_lines(
	content: &str,
	start_line: usize,
	limit: usize,
	max_total_bytes: usize,
	max_line_bytes: usize) -> (String, usize, usize, bool, Option<Vec<Value>>, bool) {
	let total = content.lines().count();
	let mut out = String::new();
	let mut taken = 0usize;
	let mut total_bytes = 0usize;
	let mut truncated = false;
	let mut long_lines = false;
	let mut reasons: Vec<Value> = Vec::new();
	let start_index = start_line.saturating_sub(1);
	for (index, line) in content.lines().enumerate() {
		if index < start_index {
			continue;
		}
		if taken >= limit {
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("line_limit")) {
				reasons.push(Value::String("line_limit".to_string()));
			}
			break;
		}
		let mut line_text = line.to_string();
		let mut hidden = 0usize;
		let line_bytes = line.as_bytes().len();
		if line_bytes > max_line_bytes {
			let (truncated_line, kept_bytes) = truncate_to_bytes(line, max_line_bytes);
			hidden = line_bytes.saturating_sub(kept_bytes);
			line_text = format!(
				"{} [TRUNCATED: {} bytes hidden]",
				truncated_line, hidden
			);
			long_lines = true;
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("long_lines")) {
				reasons.push(Value::String("long_lines".to_string()));
			}
		}
		let formatted = format!("{}: {}", index + 1, line_text);
		let line_output_bytes = formatted.as_bytes().len();
		let separator_bytes = if out.is_empty() {
			0
		}
		else {
			1
		};
		if total_bytes + separator_bytes + line_output_bytes > max_total_bytes {
			truncated = true;
			if !reasons.iter().any(|v| v.as_str() == Some("max_bytes")) {
				reasons.push(Value::String("max_bytes".to_string()));
			}
			break;
		}
		if !out.is_empty() {
			out.push('\n');
			total_bytes += 1;
		}
		out.push_str(&formatted);
		total_bytes += line_output_bytes;
		taken += 1;
		if hidden > 0 {
			// already marked above
		}
	}
	let truncated_reason = if truncated {
		Some(reasons)
	}
	else {
		None
	};
	(out, taken, total, truncated, truncated_reason, long_lines)
}

fn truncate_to_bytes(input: &str, max_bytes: usize) -> (String, usize) {
	if input.as_bytes().len() <= max_bytes {
		return (input.to_string(), input.as_bytes().len());
	}
	let mut end = 0usize;
	for (idx, ch) in input.char_indices() {
		let next = idx + ch.len_utf8();
		if next > max_bytes {
			break;
		}
		end = next;
	}
	(input[..end].to_string(), end)
}

fn matches_type(entry: &ignore::DirEntry, file_type: Option<&str>) -> Result<bool> {
	let Some(kind) = file_type else {
		return Ok(true);
	};
	let ftype = entry.file_type();
	match kind {
		"file" => Ok(ftype.map(|t| t.is_file()).unwrap_or(false)),
		"dir" | "directory" => Ok(is_dir_entry(entry)),
		"symlink" => Ok(ftype.map(|t| t.is_symlink()).unwrap_or(false)),
		_ => Err(anyhow!("unsupported type: {}", kind)),
	}
}

pub fn resolve_path(
	root: &Path,
	root_canon: &Path,
	rel: &str,
	allow_escape: bool,
	allowed_roots: &[PathBuf]) -> Result<PathBuf> {
	let rel_path = Path::new(rel);
	let candidate = if rel_path.is_absolute() {
		rel_path.to_path_buf()
	}
	else {
		root.join(rel_path)
	};
	let normalized = normalize_path(&candidate);
	if allow_escape {
		return Ok(normalized);
	}
	let checked = if normalized.exists() {
		normalized.canonicalize().unwrap_or(normalized.clone())
	}
	else {
		normalized.clone()
	};
	if checked.starts_with(root_canon) {
		return Ok(checked);
	}
	for allowed in allowed_roots {
		if checked.starts_with(allowed) {
			return Ok(checked);
		}
	}
	Err(anyhow!("path outside root"))
}

pub fn normalize_relative(rel: &str) -> String {
	let path = Path::new(rel);
	let normalized = normalize_path(path);
	let mut output = normalized.to_string_lossy().to_string();
	if output.is_empty() {
		output.push('.');
	}
	output
}

pub fn normalize_path(path: &Path) -> PathBuf {
	use std::path::Component;
	let mut stack: Vec<std::ffi::OsString> = Vec::new();
	let mut prefix: Option<std::ffi::OsString> = None;
	let mut absolute = false;
	for component in path.components() {
		match component {
			Component::Prefix(prefix_component) => {
				prefix = Some(prefix_component.as_os_str().to_os_string());
			}
			Component::RootDir => {
				absolute = true;
				stack.clear();
			}
			Component::CurDir => {}
			Component::ParentDir => {
				if !stack.is_empty() {
					stack.pop();
				}
				else if !absolute {
					stack.push(std::ffi::OsString::from(".."));
				}
			}
			Component::Normal(part) => stack.push(part.to_os_string()),
		}
	}
	let mut out = PathBuf::new();
	if let Some(prefix) = prefix {
		out.push(prefix);
	}
	if absolute {
		out.push(Path::new("/"));
	}
	for part in stack {
		out.push(part);
	}
	out
}

fn is_dir_entry(entry: &ignore::DirEntry) -> bool {
	let ftype = entry.file_type();
	if ftype.map(|t| t.is_dir()).unwrap_or(false) {
		return true;
	}
	if ftype.map(|t| t.is_symlink()).unwrap_or(false) {
		if let Ok(meta) = std::fs::metadata(entry.path()) {
			return meta.is_dir();
		}
	}
	false
}

fn relative_display(root: &Path, path: &Path) -> String {
	if let Ok(rel) = path.strip_prefix(root) {
		return rel.to_string_lossy().to_string();
	}
	path.to_string_lossy().to_string()
}

enum Matcher {
	Regex(Regex),
	Glob(GlobMatcher),
}

impl Matcher {
	fn is_match(&self, text: &str) -> bool {
		match self {
			Matcher::Regex(re) => re.is_match(text),
			Matcher::Glob(glob) => glob.is_match(text),
		}
	}
}

fn build_matcher(pattern: &str, glob: bool, case: CaseSensitivity) -> Result<Option<Matcher>> {
	let case_sensitive = match case {
		CaseSensitivity::Sensitive => true,
		CaseSensitivity::Insensitive => false,
		CaseSensitivity::Auto => pattern.chars().any(|c| c.is_uppercase()),
	};
	if glob {
		if pattern.is_empty() {
			return Ok(None);
		}
		let mut builder = GlobBuilder::new(pattern);
		builder.case_insensitive(!case_sensitive);
		let glob = builder.build().map_err(|err| anyhow!("invalid glob: {}", err))?;
		Ok(Some(Matcher::Glob(glob.compile_matcher())))
	}
	else {
		if pattern.is_empty() {
			return Ok(None);
		}
		let mut builder = RegexBuilder::new(pattern);
		builder.case_insensitive(!case_sensitive);
		let re = builder.build().map_err(|err| anyhow!("invalid pattern: {}", err))?;
		Ok(Some(Matcher::Regex(re)))
	}
}

fn build_exclude_set(patterns: &[String]) -> Result<Option<GlobSet>> {
	if patterns.is_empty() {
		return Ok(None);
	}
	let mut builder = GlobSetBuilder::new();
	for pattern in patterns {
		let glob = GlobBuilder::new(pattern)
			.literal_separator(true)
			.build()
			.map_err(|err| anyhow!("invalid exclude glob: {}", err))?;
		builder.add(glob);
	}
	Ok(Some(builder.build().map_err(|err| anyhow!("invalid exclude set: {}", err))?))
}
