use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub method: String,
    pub ip: String,
    pub mac: String,
    pub result: Value,
}