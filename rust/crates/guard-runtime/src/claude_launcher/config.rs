use super::{discovery::PeerIdentity, files, response::Failure, target};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(super) const MAX_CONFIG: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub(super) schema: String,
    pub(super) guard_home: PathBuf,
    pub(super) home: PathBuf,
    pub(super) workspace: Option<PathBuf>,
    pub(super) query: String,
    pub(super) runtime_path: PathBuf,
    pub(super) runtime_size: u64,
    pub(super) runtime_sha256: String,
    pub(super) manifest_sha256: String,
    pub(super) package_version: String,
    pub(super) target: String,
    pub(super) manifest_target: String,
    pub(super) build_sha: String,
    pub(super) rule_digest: String,
    pub(super) daemon: PeerIdentity,
}

pub(super) fn load(path: &Path, digest: &str) -> Result<Config, Failure> {
    if !hex_digest(digest, 64) {
        return Err(Failure::Integrity("launcher config digest is invalid"));
    }
    let bytes = files::read(path, MAX_CONFIG, true)
        .map_err(|_| Failure::Integrity("launcher private config is unavailable"))?;
    if hex::encode(Sha256::digest(&bytes)) != digest {
        return Err(Failure::Integrity("launcher config digest changed"));
    }
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| Failure::Integrity("launcher config JSON is invalid"))?;
    let config: Config = serde_json::from_value(value)
        .map_err(|_| Failure::Integrity("launcher config schema is invalid"))?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> Result<(), Failure> {
        let capabilities = crate::capabilities();
        if self.schema != "hol-guard.claude-launcher-pilot.v1"
            || self.package_version != capabilities.runtime_version
            || self.target != capabilities.target
            || target::compiled_manifest_target() != Some(self.manifest_target.as_str())
            || self.build_sha != capabilities.build_sha
            || self.rule_digest != capabilities.rule_digest
            || !hex_digest(&self.runtime_sha256, 64)
            || !hex_digest(&self.manifest_sha256, 64)
            || !(1..=128 * 1024 * 1024).contains(&self.runtime_size)
            || !hex_digest(&self.build_sha, 40)
            || !hex_digest(&self.rule_digest, 64)
            || !hex_digest(&self.daemon.runtime_fingerprint, 64)
            || self.daemon.compatibility_version != 2
            || self.daemon.package_version != self.package_version
            || self.daemon.source_root.is_empty()
        {
            return Err(Failure::Integrity(
                "launcher package configuration is incompatible",
            ));
        }
        for path in [
            Some(&self.guard_home),
            Some(&self.home),
            self.workspace.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            canonical(path)?;
        }
        canonical(&self.runtime_path)?;
        if self.query != query(&self.guard_home, &self.home, self.workspace.as_deref())? {
            return Err(Failure::Integrity(
                "launcher query does not match its bound context",
            ));
        }
        let current = std::env::current_exe()
            .map_err(|_| Failure::Integrity("launcher executable identity is unavailable"))?;
        if current.canonicalize().ok() != self.runtime_path.canonicalize().ok()
            || current
                .metadata()
                .map_err(|_| Failure::Integrity("launcher executable is unavailable"))?
                .len()
                != self.runtime_size
            || crate::resident_state::runtime_digest()
                .map_err(|_| Failure::Integrity("launcher executable hash failed"))?
                != self.runtime_sha256
        {
            return Err(Failure::Integrity("launcher executable identity changed"));
        }
        let manifest = files::read(
            &self.runtime_path.with_file_name("runtime-manifest.json"),
            MAX_CONFIG,
            false,
        )
        .map_err(|_| Failure::Integrity("launcher package manifest is unavailable"))?;
        if hex::encode(Sha256::digest(&manifest)) != self.manifest_sha256 {
            return Err(Failure::Integrity("launcher package manifest changed"));
        }
        let manifest = crate::strict_json_value(&manifest)
            .map_err(|_| Failure::Integrity("launcher manifest JSON is invalid"))?;
        self.validate_manifest(&manifest)
    }

    fn validate_manifest(&self, value: &Value) -> Result<(), Failure> {
        if value.get("schema").and_then(Value::as_str) != Some("hol-guard-native-runtime.v1")
            || value.get("protocol_version").and_then(Value::as_u64) != Some(1)
            || value.get("runtime_size").and_then(Value::as_u64) != Some(self.runtime_size)
        {
            return Err(Failure::Integrity("launcher manifest identity is invalid"));
        }
        for (field, expected) in [
            ("package_version", &self.package_version),
            ("target", &self.manifest_target),
            ("source_sha", &self.build_sha),
            ("rule_digest", &self.rule_digest),
            ("runtime_sha256", &self.runtime_sha256),
        ] {
            if value.get(field).and_then(Value::as_str) != Some(expected) {
                return Err(Failure::Integrity(
                    "launcher manifest identity is incompatible",
                ));
            }
        }
        Ok(())
    }
}

fn canonical(path: &Path) -> Result<(), Failure> {
    let resolved = path
        .canonicalize()
        .map_err(|_| Failure::Integrity("launcher context path is not canonical"))?;
    if !path.is_absolute() || path.to_str().is_none() || normalized(&resolved) != normalized(path) {
        return Err(Failure::Integrity("launcher context path is not canonical"));
    }
    Ok(())
}

#[cfg(not(windows))]
fn normalized(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(windows)]
fn normalized(path: &Path) -> PathBuf {
    // Python's resolved drive paths and Rust canonicalize differ only by the
    // Win32 verbatim prefix here. Do not lowercase arbitrary Unicode paths.
    let text = path.as_os_str().to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(drive) = text.strip_prefix(r"\\?\") {
        PathBuf::from(drive)
    } else {
        path.to_path_buf()
    }
}

pub(super) fn query(
    guard_home: &Path,
    home: &Path,
    workspace: Option<&Path>,
) -> Result<String, Failure> {
    let mut values = vec![("guard-home", guard_home), ("home", home)];
    if let Some(workspace) = workspace {
        values.push(("workspace", workspace));
    }
    let mut pairs = Vec::new();
    for (name, path) in values {
        let value = path
            .to_str()
            .ok_or(Failure::Integrity("launcher path is not Unicode"))?;
        pairs.push(format!("{name}={}", quote(value)));
    }
    Ok(pairs.join("&"))
}

fn quote(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            output.push(char::from(byte));
        } else if byte == b' ' {
            output.push('+');
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
    output
}

fn hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config_value() -> Value {
        json!({
            "schema": "hol-guard.claude-launcher-pilot.v1",
            "guard_home": "/guard", "home": "/home", "workspace": null,
            "query": "fixture", "runtime_path": "/runtime", "runtime_size": 12,
            "runtime_sha256": "a".repeat(64), "manifest_sha256": "b".repeat(64),
            "package_version": "3.0.1", "target": "x86_64-linux",
            "manifest_target": "x86_64-unknown-linux-musl",
            "build_sha": "c".repeat(40), "rule_digest": "d".repeat(64),
            "daemon": {"compatibility_version": 2, "package_version": "3.0.1",
                "source_root": "/package", "runtime_fingerprint": "e".repeat(64)}
        })
    }

    #[test]
    fn old_config_without_separate_manifest_target_is_not_admitted() {
        let mut value = config_value();
        assert!(serde_json::from_value::<Config>(value.clone()).is_ok());
        value.as_object_mut().unwrap().remove("manifest_target");
        assert!(serde_json::from_value::<Config>(value).is_err());
    }

    #[test]
    fn manifest_uses_exact_cargo_identity_and_retains_other_identity_fences() {
        let config: Config = serde_json::from_value(config_value()).unwrap();
        let manifest = json!({
            "schema": "hol-guard-native-runtime.v1", "protocol_version": 1,
            "runtime_size": config.runtime_size, "package_version": config.package_version,
            "target": config.manifest_target, "source_sha": config.build_sha,
            "rule_digest": config.rule_digest, "runtime_sha256": config.runtime_sha256
        });
        assert!(config.validate_manifest(&manifest).is_ok());
        for field in [
            "target",
            "package_version",
            "source_sha",
            "rule_digest",
            "runtime_sha256",
        ] {
            let mut changed = manifest.clone();
            changed[field] = json!(config.target);
            assert!(config.validate_manifest(&changed).is_err(), "{field}");
        }
        for field in ["protocol_version", "runtime_size"] {
            let mut changed = manifest.clone();
            changed[field] = json!(0);
            assert!(config.validate_manifest(&changed).is_err(), "{field}");
        }
    }
}
