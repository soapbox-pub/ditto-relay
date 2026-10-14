//! The relay's own key, which signs the NIP-85 assertions it serves and the
//! trends it labels, kept in a file as 64 lowercase hex.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::Context;
use secp256k1::Keypair;

use crate::event::decode_hex;

/// The key in the file at `path`, which is made, with a new key, if there's
/// nothing there.
pub fn open(path: &Path) -> anyhow::Result<Keypair> {
    if let Some(keypair) = read(path)? {
        return Ok(keypair);
    }
    let keypair = generate();
    create(&keypair, path)
        .with_context(|| format!("couldn't write a new secret key to {}", path.display()))?;
    tracing::info!("made a new secret key in {}", path.display());
    Ok(keypair)
}

/// The key in the file at `path`, if there's one.
pub fn read(path: &Path) -> anyhow::Result<Option<Keypair>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("couldn't read the secret key {}", path.display()));
        }
    };
    decode_hex(text.trim())
        .and_then(|key| Keypair::from_secret_bytes(key).ok())
        .map(Some)
        .with_context(|| {
            format!(
                "{} must hold a secret key in 64 lowercase hex",
                path.display()
            )
        })
}

/// The pubkey of `keypair`, in hex.
pub fn pubkey(keypair: &Keypair) -> String {
    hex::encode(keypair.x_only_public_key().0.to_byte_array())
}

fn generate() -> Keypair {
    loop {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).expect("the OS has randomness");
        // Zero, or past the curve's order, about once in 2^128 tries.
        if let Ok(keypair) = Keypair::from_secret_bytes(secret) {
            return keypair;
        }
    }
}

/// Write `keypair` to a new file at `path`, which only its owner may read,
/// in a directory only they may enter, if it has to be made.
fn create(keypair: &Keypair, path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", hex::encode(keypair.to_secret_bytes()))?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_a_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/secret.key");
        let made = open(&path).unwrap();
        let mode = |path: &Path| {
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions())
                & 0o777
        };
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(open(&path).unwrap(), made);

        std::fs::write(&path, "nope").unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn reads_a_key_written_by_hand() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        std::fs::write(&path, format!("{key}\n")).unwrap();
        let keypair = read(&path).unwrap().unwrap();
        assert_eq!(hex::encode(keypair.to_secret_bytes()), key);
        assert!(read(&dir.path().join("missing")).unwrap().is_none());
    }
}
