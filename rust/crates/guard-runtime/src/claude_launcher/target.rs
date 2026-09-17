//! Manifest Cargo triples and runtime ARCH-OS identifiers are separate domains.

fn shipping_target(arch: &str, os: &str, environment: &str) -> Option<&'static str> {
    match (arch, os, environment) {
        ("x86_64", "linux", "musl") => Some("x86_64-unknown-linux-musl"),
        ("x86_64", "macos", "") => Some("x86_64-apple-darwin"),
        ("aarch64", "macos", "") => Some("aarch64-apple-darwin"),
        ("x86_64", "windows", "msvc") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

pub(super) fn compiled_manifest_target() -> Option<&'static str> {
    let environment = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else if cfg!(target_env = "") {
        ""
    } else {
        "unsupported"
    };
    shipping_target(std::env::consts::ARCH, std::env::consts::OS, environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_declared_architecture_os_and_abi_tuples_are_admitted() {
        for (arch, os, environment, expected) in [
            ("x86_64", "linux", "musl", "x86_64-unknown-linux-musl"),
            ("x86_64", "macos", "", "x86_64-apple-darwin"),
            ("aarch64", "macos", "", "aarch64-apple-darwin"),
            ("x86_64", "windows", "msvc", "x86_64-pc-windows-msvc"),
        ] {
            assert_eq!(shipping_target(arch, os, environment), Some(expected));
        }
        for (arch, os, environment) in [
            ("x86_64", "linux", "gnu"),
            ("x86_64", "linux", ""),
            ("x86_64", "windows", "gnu"),
            ("aarch64", "windows", "msvc"),
            ("aarch64", "linux", "musl"),
            ("x86_64", "macos", "musl"),
        ] {
            assert_eq!(shipping_target(arch, os, environment), None);
        }
    }

    #[test]
    fn host_selection_is_derived_from_compiler_cfg_not_environment_variables() {
        let actual = compiled_manifest_target();
        if cfg!(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_env = "musl"
        )) {
            assert_eq!(actual, Some("x86_64-unknown-linux-musl"));
        } else if cfg!(all(
            target_arch = "x86_64",
            target_os = "windows",
            target_env = "msvc"
        )) {
            assert_eq!(actual, Some("x86_64-pc-windows-msvc"));
        } else if cfg!(all(
            target_arch = "x86_64",
            target_os = "macos",
            target_env = ""
        )) {
            assert_eq!(actual, Some("x86_64-apple-darwin"));
        } else if cfg!(all(
            target_arch = "aarch64",
            target_os = "macos",
            target_env = ""
        )) {
            assert_eq!(actual, Some("aarch64-apple-darwin"));
        } else {
            assert_eq!(actual, None);
        }
    }
}
