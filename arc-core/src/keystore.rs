//! Cross-platform secure keystore integration.
//!
//! Stores the device's private identity keys in the OS credential manager (Keychain on macOS,
//! Credential Manager on Windows, and Secret Service on Linux). Falls back to config file
//! storage if the OS keystore is unavailable.

use keyring::Entry;

const SERVICE_NAME: &str = "sh.arc.identity";
const USER_NAME: &str = "device_key";

/// Retrieve the 32-byte device identity secret from the OS keystore.
pub fn get_identity_secret() -> Result<[u8; 32], anyhow::Error> {
    let entry = Entry::new(SERVICE_NAME, USER_NAME)?;
    let password = entry.get_password()?;
    let decoded = hex::decode(password)?;
    if decoded.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    } else {
        Err(anyhow::anyhow!("invalid identity secret length"))
    }
}

/// Store the 32-byte device identity secret in the OS keystore.
pub fn set_identity_secret(secret: &[u8; 32]) -> Result<(), anyhow::Error> {
    let entry = Entry::new(SERVICE_NAME, USER_NAME)?;
    let encoded = hex::encode(secret);
    entry.set_password(&encoded)?;
    Ok(())
}

/// Delete the device identity secret from the OS keystore.
pub fn delete_identity_secret() -> Result<(), anyhow::Error> {
    let entry = Entry::new(SERVICE_NAME, USER_NAME)?;
    entry.delete_credential()?;
    Ok(())
}
