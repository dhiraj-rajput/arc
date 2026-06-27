//! Security utilities: filename sanitization, path validation, and invariant checks.
//!
//! # Security Invariants (§16.5 of master plan)
//!
//! These invariants MUST hold for every protocol message:
//!
//! - INV-1:  File content MUST NOT appear outside ChaCha20-Poly1305 ciphertext
//! - INV-2:  File names MUST NOT appear in relay-visible signaling messages
//! - INV-3:  Device identities MUST NOT be disclosed before pairing
//! - INV-4:  Session keys MUST be derived from ephemeral material (forward secrecy)
//! - INV-5:  Nonces MUST NOT repeat within a session
//! - INV-6:  Room IDs MUST NOT contain or derive from the raw pairing nonce
//! - INV-7:  Filenames MUST be sanitized of control characters BEFORE any display
//! - INV-8:  File paths MUST be validated to not traverse outside destination
//! - INV-9:  A relay room with > 2 members MUST cause immediate abort
//! - INV-10: Secrets MUST NOT appear in process argv, env vars, or log output

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Errors from security validation.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("path traversal detected: {0}")]
    PathTraversal(String),
    #[error("invalid path component: {0}")]
    InvalidPath(String),
    #[error("relay room compromised: {0} members in a 2-party room")]
    RelayCompromised(u8),

}

/// INV-7: Sanitize a filename for safe display in a terminal.
///
/// Replaces all control characters (0x00–0x1F, 0x7F) and ANSI escape sequences
/// (ESC / CSI) with '?'. Truncates to 255 characters.
///
/// This MUST be called before printing any filename received from a peer,
/// even in progress bars (croc CVE GO-2023-2068).
///
/// # Example
/// ```
/// use arc_core::security::safe_display_name;
/// assert_eq!(safe_display_name("\x1b[2Jmalicious"), "?[2Jmalicious");
/// assert_eq!(safe_display_name("normal_file.jpg"), "normal_file.jpg");
/// ```
pub fn safe_display_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_control() {
                '?'
            } else {
                c
            }
        })
        .take(255)
        .collect()
}

/// INV-8: Validate that a path component is safe to write under `destination`.
///
/// Blocks:
/// - `..` components (path traversal)  
/// - Absolute paths (e.g., `/etc/passwd`)
/// - Windows-style drive roots (`C:\`)
/// - Null bytes, control characters
///
/// Returns the canonicalized safe sub-path, or an error.
///
/// This defends against croc CVE GO-2023-2071.
pub fn validate_path_component(path: &str) -> Result<PathBuf, SecurityError> {
    let p = Path::new(path);

    for component in p.components() {
        match component {
            Component::ParentDir => {
                return Err(SecurityError::PathTraversal(path.to_string()));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(SecurityError::InvalidPath(format!(
                    "absolute path not allowed: {path}"
                )));
            }
            Component::CurDir => {
                // '.' is fine — it refers to the current directory (no traversal)
            }
            Component::Normal(name) => {
                let name_str = name.to_string_lossy();
                // Block null bytes and control characters in filename
                if name_str.chars().any(|c| c.is_control()) {
                    return Err(SecurityError::InvalidPath(format!(
                        "control character in path component: {name_str}"
                    )));
                }
                // Block Windows reserved names
                if is_windows_reserved_name(&name_str) {
                    return Err(SecurityError::InvalidPath(format!(
                        "reserved filename: {name_str}"
                    )));
                }
            }
        }
    }

    Ok(p.to_path_buf())
}

/// Resolve a received file path to an absolute path under `destination`.
///
/// Ensures the result is a child of `destination` after path normalization.
/// Fails if the path tries to escape the destination directory.
pub fn resolve_safe_path(
    destination: &Path,
    received_path: &str,
) -> Result<PathBuf, SecurityError> {
    let relative = validate_path_component(received_path)?;
    if !destination.exists() {
        let _ = std::fs::create_dir_all(destination);
    }
    let canon_dest = std::fs::canonicalize(destination).map_err(|e| {
        SecurityError::PathTraversal(format!("failed to canonicalize destination: {e}"))
    })?;
    let full = canon_dest.join(&relative);

    if full.strip_prefix(&canon_dest).is_err() {
        return Err(SecurityError::PathTraversal(received_path.to_string()));
    }

    Ok(full)
}

/// INV-9: Verify that a relay room does not have more than 2 members.
///
/// If the relay reports 3 or more members, abort immediately.
/// This prevents active relay MITM attacks (magic-wormhole "scary" error equivalent).
pub fn check_room_integrity(member_count: u8) -> Result<(), SecurityError> {
    if member_count > 2 {
        return Err(SecurityError::RelayCompromised(member_count));
    }
    Ok(())
}

/// A sandbox policy to enforce safety constraints on file operations.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Allowed directories to write into. If empty, any path resolved under destination is allowed.
    pub allowed_dirs: Vec<PathBuf>,
    /// Blocked file extensions (case-insensitive).
    pub blocked_extensions: Vec<String>,
}

impl SandboxPolicy {
    /// Create a new sandbox policy.
    pub fn new(allowed_dirs: Vec<PathBuf>, blocked_extensions: Vec<String>) -> Self {
        Self {
            allowed_dirs,
            blocked_extensions,
        }
    }

    /// Enforce the sandbox policy on the target path.
    /// Returns Ok(()) if the path is allowed, or an error if it violates the policy.
    pub fn enforce(&self, target_path: &Path) -> Result<(), anyhow::Error> {
        // 1. Check blocked extensions
        if let Some(ext) = target_path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self.blocked_extensions.iter().any(|b| b.to_lowercase() == ext_str) {
                return Err(anyhow::anyhow!("File extension '.{}' is blocked by sandbox policy", ext_str));
            }
        }

        // 2. Check if the path is within one of the allowed directories (if whitelist is not empty)
        if !self.allowed_dirs.is_empty() {
            let mut allowed = false;
            let target_canon = if target_path.exists() {
                std::fs::canonicalize(target_path)?
            } else {
                if let Some(parent) = target_path.parent() {
                    let parent_canon = if parent.exists() {
                        std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
                    } else {
                        parent.to_path_buf()
                    };
                    parent_canon.join(target_path.file_name().unwrap_or_default())
                } else {
                    target_path.to_path_buf()
                }
            };
            
            // Helper to strip Windows UNC prefix for consistent matching
            let clean_path = |p: &Path| -> PathBuf {
                let s = p.to_string_lossy();
                if s.starts_with(r"\\?\") {
                    PathBuf::from(&s[4..])
                } else {
                    p.to_path_buf()
                }
            };
            
            let target_clean = clean_path(&target_canon);
            for dir in &self.allowed_dirs {
                if !dir.exists() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let dir_canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
                let dir_clean = clean_path(&dir_canon);
                if target_clean.starts_with(&dir_clean) {
                    allowed = true;
                    break;
                }
            }

            if !allowed {
                return Err(anyhow::anyhow!("Path {:?} is outside the allowed sandbox directories", target_path));
            }
        }

        Ok(())
    }
}

/// Unpack a tar archive safely to the destination directory, validating every entry to prevent path traversal (SEC-3).
pub fn safe_unpack_tar(archive_file: std::fs::File, destination: &Path) -> Result<(), anyhow::Error> {
    let mut archive = tar::Archive::new(archive_file);
    if !destination.exists() {
        let _ = std::fs::create_dir_all(destination);
    }
    let canon_dest = std::fs::canonicalize(destination)?;
    
    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(anyhow::anyhow!("Tar symlinks or hardlinks are not allowed for security reasons"));
        }
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy();
        let safe_relative = validate_path_component(&path_str)?;
        let dest_path = canon_dest.join(&safe_relative);
        
        if dest_path.strip_prefix(&canon_dest).is_err() {
            return Err(anyhow::anyhow!("Tar path traversal detected in entry: {}", path_str));
        }
        
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry.unpack(&dest_path)?;
    }
    Ok(())
}

/// Check if a filename is a Windows reserved name (CON, PRN, AUX, NUL, COM1–9, LPT1–9).
fn is_windows_reserved_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    let base = upper.split('.').next().unwrap_or(&upper);
    matches!(
        base,
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5"
            | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5"
            | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── INV-7: Filename display sanitization ────────────────────────────────

    #[test]
    fn test_safe_display_name_strips_escape() {
        // croc CVE GO-2023-2068: ESC sequence must be replaced with '?'
        let raw = "\x1b[2Jmalicious_filename";
        let safe = safe_display_name(raw);
        assert!(!safe.contains('\x1b'), "ESC must be stripped");
        assert_eq!(safe.chars().next(), Some('?'));
    }

    #[test]
    fn test_safe_display_name_strips_control_chars() {
        let raw = "file\x00with\x01nulls\x7fand\x0adel";
        let safe = safe_display_name(raw);
        assert!(!safe.chars().any(|c| c.is_control()), "no control chars in output");
    }

    #[test]
    fn test_safe_display_name_normal_file() {
        let raw = "photo-2026-06-26.jpg";
        assert_eq!(safe_display_name(raw), raw);
    }

    #[test]
    fn test_safe_display_name_unicode() {
        let raw = "日本語ファイル.txt";
        let safe = safe_display_name(raw);
        assert_eq!(safe, raw, "normal unicode must pass through unchanged");
    }

    #[test]
    fn test_safe_display_name_truncates() {
        let raw = "a".repeat(1000);
        let safe = safe_display_name(&raw);
        assert_eq!(safe.chars().count(), 255, "must truncate to 255 chars");
    }

    // ─── INV-8: Path traversal prevention ───────────────────────────────────

    #[test]
    fn test_path_traversal_blocked() {
        // croc CVE GO-2023-2071
        assert!(validate_path_component("../etc/passwd").is_err());
        assert!(validate_path_component("../../secret").is_err());
        assert!(validate_path_component("subdir/../../etc/passwd").is_err());
    }

    #[test]
    fn test_absolute_path_blocked() {
        assert!(validate_path_component("/etc/passwd").is_err());
        // Note: on Windows, C:\... would also be caught
    }

    #[test]
    fn test_normal_paths_allowed() {
        assert!(validate_path_component("documents/photo.jpg").is_ok());
        assert!(validate_path_component("file.txt").is_ok());
        assert!(validate_path_component("a/b/c/d.bin").is_ok());
        assert!(validate_path_component("./relative.txt").is_ok());
    }

    #[test]
    fn test_control_char_in_path_blocked() {
        assert!(validate_path_component("file\x00.txt").is_err());
        assert!(validate_path_component("dir/\x01malicious").is_err());
    }

    #[test]
    fn test_windows_reserved_names_blocked() {
        assert!(validate_path_component("CON").is_err());
        assert!(validate_path_component("NUL").is_err());
        assert!(validate_path_component("COM1").is_err());
        assert!(validate_path_component("LPT9.txt").is_err());
    }

    #[test]
    fn test_resolve_safe_path_blocks_traversal() {
        let dest = Path::new("/tmp/arc_recv");
        assert!(resolve_safe_path(dest, "../etc/passwd").is_err());
    }

    // ─── INV-9: Room integrity ───────────────────────────────────────────────

    #[test]
    fn test_room_integrity_two_members_ok() {
        assert!(check_room_integrity(2).is_ok());
        assert!(check_room_integrity(1).is_ok());
    }

    #[test]
    fn test_room_integrity_three_members_rejected() {
        // Relay MITM detection — equivalent to magic-wormhole "scary" error
        assert!(check_room_integrity(3).is_err());
        assert!(check_room_integrity(10).is_err());
    }

    #[test]
    fn test_sandbox_policy_enforcement() {
        let temp_dir = tempfile::tempdir().unwrap();
        let allowed_path = temp_dir.path().to_path_buf();
        let policy = SandboxPolicy::new(
            vec![allowed_path.clone()],
            vec!["exe".to_string(), "bat".to_string()],
        );

        // Valid file in allowed directory
        let safe_file = allowed_path.join("file.txt");
        assert!(policy.enforce(&safe_file).is_ok());

        // File with blocked extension
        let blocked_file = allowed_path.join("run.exe");
        assert!(policy.enforce(&blocked_file).is_err());

        // File outside allowed directory
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_file = outside_dir.path().join("outside.txt");
        assert!(policy.enforce(&outside_file).is_err());
    }
}
