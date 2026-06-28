//! Clipboard synchronization between paired devices.
//!
//! Provides bidirectional clipboard monitoring using the `arboard` crate.
//! Each clipboard update is assigned a sequence number and source device ID
//! to prevent echo loops when syncing between devices.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

/// Represents a clipboard change event with dedup metadata.
#[derive(Debug, Clone)]
pub struct ClipboardEvent {
    /// Monotonically increasing sequence number per device.
    pub sequence: u64,
    /// Device ID of the originator (to prevent echo loops).
    pub source_device_id: [u8; 32],
    /// The clipboard content (text only for now).
    pub content: ClipboardContent,
}

/// Supported clipboard content types.
#[derive(Debug, Clone)]
pub enum ClipboardContent {
    /// UTF-8 text content.
    Text(String),
    /// Raw image bytes (PNG-encoded).
    Image(Vec<u8>),
}

/// Watches the local clipboard for changes and emits events.
pub struct ClipboardWatcher {
    device_id: [u8; 32],
    sequence: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    poll_interval: Duration,
}

impl ClipboardWatcher {
    /// Create a new clipboard watcher for the given device.
    pub fn new(device_id: [u8; 32], poll_interval_ms: u64) -> Self {
        Self {
            device_id,
            sequence: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            poll_interval: Duration::from_millis(poll_interval_ms),
        }
    }

    /// Start watching the clipboard in a background task.
    /// Returns a receiver that emits `ClipboardEvent` whenever the clipboard changes.
    pub fn start(&self) -> tokio::sync::mpsc::Receiver<ClipboardEvent> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let running = self.running.clone();
        let device_id = self.device_id;
        let poll_interval = self.poll_interval;
        let sequence = self.sequence.clone();

        running.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            let mut clipboard = match arboard::Clipboard::new() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to initialize clipboard watcher: {e}");
                    return;
                }
            };

            // Initialize with current clipboard text to prevent immediate leakage of existing content
            let mut last_text = clipboard.get_text().unwrap_or_default();

            while running.load(Ordering::SeqCst) {
                if let Some(text) = clipboard.get_text().ok().filter(|t| t != &last_text && !t.is_empty()) {
                    let seq = sequence.fetch_add(1, Ordering::SeqCst) + 1;
                    last_text = text.clone();
                    let event = ClipboardEvent {
                        sequence: seq,
                        source_device_id: device_id,
                        content: ClipboardContent::Text(text),
                    };
                    if tx.blocking_send(event).is_err() {
                        break; // receiver dropped
                    }
                }
                std::thread::sleep(poll_interval);
            }
        });

        rx
    }

    /// Stop the clipboard watcher.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Apply a remote clipboard event to the local clipboard.
/// Returns `true` if the clipboard was updated, `false` if it was an echo.
pub fn apply_remote_clipboard(
    event: &ClipboardEvent,
    local_device_id: &[u8; 32],
) -> Result<bool, anyhow::Error> {
    // Prevent echo: don't apply events from ourselves
    if &event.source_device_id == local_device_id {
        return Ok(false);
    }

    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| anyhow::anyhow!("Failed to access clipboard: {e}"))?;

    match &event.content {
        ClipboardContent::Text(text) => {
            // SEC-8: Sanitize terminal escape sequences (ESC character '\x1b')
            let sanitized = text.replace('\x1b', "?");
            clipboard
                .set_text(sanitized)
                .map_err(|e| anyhow::anyhow!("Failed to set clipboard text: {e}"))?;
        }
        ClipboardContent::Image(_data) => {
            // Image clipboard sync is a future enhancement
            tracing::debug!("Image clipboard sync not yet implemented");
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_event_echo_prevention() {
        let device_id = [0xAA; 32];
        let event = ClipboardEvent {
            sequence: 1,
            source_device_id: device_id,
            content: ClipboardContent::Text("hello".to_string()),
        };
        // Same device: should be filtered
        assert!(!apply_remote_clipboard(&event, &device_id).unwrap_or(false)
            || apply_remote_clipboard(&event, &device_id).is_err());
    }

    #[test]
    fn test_clipboard_content_variants() {
        let text = ClipboardContent::Text("hello world".to_string());
        assert!(matches!(text, ClipboardContent::Text(_)));

        let img = ClipboardContent::Image(vec![0x89, 0x50, 0x4E, 0x47]);
        assert!(matches!(img, ClipboardContent::Image(_)));
    }
}
