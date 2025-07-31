use std::collections::HashMap;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::RwLock;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct LibInfo {
    pub description: String,
    pub version: String,
    pub expected_lucia_version: String,
}

pub struct LibRegistry {
    inner: RwLock<HashMap<String, LibInfo>>,
}

impl LibRegistry {
    pub fn new() -> Self {
        LibRegistry {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, name: &str) -> Option<LibInfo> {
        self.inner.read().ok()?.get(name).cloned()
    }

    pub fn contains_key(&self, name: &str) -> bool {
        self.inner.read().ok().expect("Failed to acquire read lock").contains_key(name)
    }

    pub fn set_all(&self, new_libs: HashMap<String, LibInfo>) {
        if let Ok(mut inner) = self.inner.write() {
            *inner = new_libs;
        }
    }
}

pub fn load_std_libs(path: &Path) -> Result<(), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read libs file: {}", e))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    let std_libs = json.get("std_libs")
        .ok_or("Missing 'std_libs' field in JSON".to_string())?;

    let parsed: HashMap<String, LibInfo> = serde_json::from_value(std_libs.clone())
        .map_err(|e| format!("Failed to parse 'std_libs': {}", e))?;

    STD_LIBS.set_all(parsed.clone());

    Ok(())
}

pub static STD_LIBS: Lazy<LibRegistry> = Lazy::new(|| {
    LibRegistry::new()
});