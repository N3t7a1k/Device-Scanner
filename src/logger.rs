use chrono::Local;


use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Mutex, OnceLock};
use anyhow::{Context, Result, anyhow};
use serde::Serialize;

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

struct Logger {
    writer: BufWriter<File>,
}

impl Logger {
    fn new(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .context("Failed to open log file")?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

pub fn get_log_filename() -> String {
    let now = Local::now();
    format!("{}", now.format("%Y-%m-%d_%H-%M-%S.log"))
}

pub fn init(path: &str) -> Result<()> {
    let logger = Logger::new(path)?;
    
    LOGGER.set(Mutex::new(logger))
        .map_err(|_| anyhow!("Logger is already initialized"))?;
        
    Ok(())
}

pub fn write<T: Serialize>(data: &T) -> Result<()> {
    let mutex = LOGGER.get().ok_or_else(|| anyhow!("Logger not initialized"))?;
    let mut guard = mutex.lock().map_err(|_| anyhow!("Failed to lock logger"))?;
    
    let json_string = serde_json::to_string(data)?;

    writeln!(guard.writer, "{}", json_string).context("Failed to write log")?;
    
    Ok(())
}

pub fn close() -> Result<()> {
    let mutex = LOGGER.get().ok_or_else(|| anyhow!("Logger not initialized"))?;
    let mut guard = mutex.lock().map_err(|_| anyhow!("Failed to lock logger"))?;
    
    guard.writer.flush().context("Failed to flush log buffer")?;
    Ok(())
}
