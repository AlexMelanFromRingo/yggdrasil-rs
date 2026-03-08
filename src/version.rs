//! Build metadata — injected at link time via RUSTFLAGS or build.rs.
//!
//! Port of yggdrasil-go/src/version/version.go

/// Returns the build name (e.g. "yggdrasil"), or `"unknown"`.
pub fn build_name() -> &'static str {
    match option_env!("YGGDRASIL_BUILD_NAME") {
        Some(s) => s,
        None => "unknown",
    }
}

/// Returns the build version (e.g. "0.5.13"), or `"unknown"`.
pub fn build_version() -> &'static str {
    match option_env!("YGGDRASIL_BUILD_VERSION") {
        Some(s) => s,
        None => "unknown",
    }
}
