use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Request {
	pub id: Value,
	pub method: String,
	#[serde(default)]
	pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct Response {
	pub id: Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub result: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<ErrorObject>,
	#[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
	pub meta: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorObject {
	pub code: i64,
	pub message: String,
}

impl Response {
	pub fn ok(id: Value, result: Value) -> Self {
		Self {
			id,
			result: Some(result),
			error: None,
			meta: None
		}
	}
	pub fn ok_with_meta(id: Value, result: Value, meta: Value) -> Self {
		Self {
			id,
			result: Some(result),
			error: None,
			meta: Some(meta)
		}
	}
	pub fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
		Self {
			id,
			result: None,
			error: Some(ErrorObject {
				code,
				message: message.into()
			}),
			meta: None
		}
	}
}
