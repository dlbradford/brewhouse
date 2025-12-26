use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Package {
    pub name: String,
    pub version: Option<String>,
    pub desc: Option<String>,
    pub homepage: Option<String>,
    pub installed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrewInfoFormula {
    pub name: String,
    pub full_name: Option<String>,
    pub tap: Option<String>,
    pub oldname: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub versioned_formulae: Option<Vec<String>>,
    pub desc: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub versions: BrewVersions,
    pub urls: Option<BrewUrls>,
    pub revision: Option<i32>,
    pub version_scheme: Option<i32>,
    pub bottle: Option<serde_json::Value>,
    pub keg_only: Option<bool>,
    pub keg_only_reason: Option<serde_json::Value>,
    pub options: Option<Vec<serde_json::Value>>,
    pub build_dependencies: Option<Vec<String>>,
    pub dependencies: Option<Vec<String>>,
    pub test_dependencies: Option<Vec<String>>,
    pub recommended_dependencies: Option<Vec<String>>,
    pub optional_dependencies: Option<Vec<String>>,
    pub uses_from_macos: Option<Vec<serde_json::Value>>,
    pub requirements: Option<Vec<serde_json::Value>>,
    pub conflicts_with: Option<Vec<String>>,
    pub conflicts_with_reasons: Option<Vec<String>>,
    pub link_overwrite: Option<Vec<String>>,
    pub caveats: Option<String>,
    pub installed: Option<Vec<BrewInstalled>>,
    pub linked_keg: Option<String>,
    pub pinned: Option<bool>,
    pub outdated: Option<bool>,
    pub deprecated: Option<bool>,
    pub deprecation_date: Option<String>,
    pub deprecation_reason: Option<String>,
    pub disabled: Option<bool>,
    pub disable_date: Option<String>,
    pub disable_reason: Option<String>,
    pub analytics: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrewVersions {
    pub stable: String,
    pub head: Option<String>,
    pub bottle: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrewUrls {
    pub stable: Option<BrewUrl>,
    pub head: Option<BrewUrl>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrewUrl {
    pub url: String,
    pub tag: Option<String>,
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrewInstalled {
    pub version: String,
    pub used_options: Vec<String>,
    pub built_as_bottle: bool,
    pub poured_from_bottle: bool,
    pub time: Option<i64>,
    pub runtime_dependencies: Option<Vec<serde_json::Value>>,
    pub installed_as_dependency: bool,
    pub installed_on_request: bool,
}

#[derive(Debug)]
pub enum BrewError {
    CommandFailed(String),
    ParseError(String),
    NotInstalled,
}

impl std::fmt::Display for BrewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrewError::CommandFailed(msg) => write!(f, "Brew command failed: {}", msg),
            BrewError::ParseError(msg) => write!(f, "Failed to parse brew output: {}", msg),
            BrewError::NotInstalled => write!(f, "Homebrew is not installed or not in PATH"),
        }
    }
}

impl std::error::Error for BrewError {}

pub type BrewResult<T> = Result<T, BrewError>;

/// Simple rate limiter to prevent rapid repeated operations.
/// Uses atomic operations for thread safety.
pub struct RateLimiter {
    last_operation: AtomicU64,
    min_interval_ms: u64,
}

impl RateLimiter {
    pub const fn new(min_interval_ms: u64) -> Self {
        Self {
            last_operation: AtomicU64::new(0),
            min_interval_ms,
        }
    }

    /// Check if an operation is allowed. Returns Ok(()) if allowed,
    /// or Err with the number of milliseconds to wait.
    pub fn check(&self) -> Result<(), u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let last = self.last_operation.load(Ordering::SeqCst);
        let elapsed = now.saturating_sub(last);

        if elapsed >= self.min_interval_ms {
            self.last_operation.store(now, Ordering::SeqCst);
            Ok(())
        } else {
            Err(self.min_interval_ms - elapsed)
        }
    }

    /// Check rate limit and return a BrewError if rate limited
    pub fn check_or_error(&self) -> BrewResult<()> {
        self.check().map_err(|wait_ms| {
            BrewError::CommandFailed(format!(
                "Rate limited. Please wait {} ms before retrying.",
                wait_ms
            ))
        })
    }
}

// Global rate limiters for different operation types
// Install/uninstall operations: minimum 2 seconds between operations
pub static INSTALL_RATE_LIMITER: RateLimiter = RateLimiter::new(2000);
// Search operations: minimum 500ms between operations
pub static SEARCH_RATE_LIMITER: RateLimiter = RateLimiter::new(500);
// Info operations: minimum 200ms between operations
pub static INFO_RATE_LIMITER: RateLimiter = RateLimiter::new(200);

/// Check if brew is installed and accessible
pub fn is_brew_installed() -> bool {
    Command::new("brew")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Get list of all installed packages (single batch call)
pub async fn get_installed_packages() -> BrewResult<Vec<Package>> {
    let output = tokio::process::Command::new("brew")
        .args(["info", "--json=v2", "--installed"])
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);

    #[derive(Deserialize)]
    struct BrewInfoResponse {
        formulae: Vec<BrewInfoFormula>,
    }

    let response: BrewInfoResponse = serde_json::from_str(&json_str)
        .map_err(|e| BrewError::ParseError(e.to_string()))?;

    let packages = response
        .formulae
        .into_iter()
        .map(|info| Package {
            name: info.name,
            version: Some(info.versions.stable),
            desc: info.desc,
            homepage: info.homepage,
            installed: true,
        })
        .collect();

    Ok(packages)
}

/// Search for packages (returns all if query is empty)
pub async fn search_packages(query: &str) -> BrewResult<Vec<String>> {
    SEARCH_RATE_LIMITER.check_or_error()?;
    validate_search_query(query)?;

    let mut cmd = tokio::process::Command::new("brew");
    cmd.args(["search", "--formula"]);

    if !query.is_empty() {
        cmd.arg(query);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let packages = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with("==>"))
        .collect();

    Ok(packages)
}

/// Get detailed info about a specific package
pub async fn get_package_info(package_name: &str) -> BrewResult<BrewInfoFormula> {
    INFO_RATE_LIMITER.check_or_error()?;
    validate_package_name(package_name)?;

    let output = tokio::process::Command::new("brew")
        .args(["info", "--json=v2", package_name])
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    
    #[derive(Deserialize)]
    struct BrewInfoResponse {
        formulae: Vec<BrewInfoFormula>,
    }
    
    let response: BrewInfoResponse = serde_json::from_str(&json_str)
        .map_err(|e| BrewError::ParseError(e.to_string()))?;

    response.formulae.into_iter().next()
        .ok_or_else(|| BrewError::ParseError("No formula found in response".to_string()))
}

/// Install a package
pub async fn install_package(package_name: &str) -> BrewResult<String> {
    INSTALL_RATE_LIMITER.check_or_error()?;
    validate_package_name(package_name)?;

    let output = tokio::process::Command::new("brew")
        .args(["install", package_name])
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Uninstall a package
pub async fn uninstall_package(package_name: &str) -> BrewResult<String> {
    INSTALL_RATE_LIMITER.check_or_error()?;
    validate_package_name(package_name)?;

    let output = tokio::process::Command::new("brew")
        .args(["uninstall", package_name])
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Update brew itself - returns (stdout, stderr) for display
pub async fn update_brew() -> BrewResult<(String, String)> {
    let output = tokio::process::Command::new("brew")
        .arg("update")
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // brew update writes progress to stderr, so we return both
    if !output.status.success() {
        return Err(BrewError::CommandFailed(format!("{}\n{}", stdout, stderr)));
    }

    Ok((stdout, stderr))
}

/// Upgrade all packages or a specific package
pub async fn upgrade_packages(package_name: Option<&str>) -> BrewResult<String> {
    INSTALL_RATE_LIMITER.check_or_error()?;
    if let Some(name) = package_name {
        validate_package_name(name)?;
    }

    let mut cmd = tokio::process::Command::new("brew");
    cmd.arg("upgrade");

    if let Some(name) = package_name {
        cmd.arg(name);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get brew statistics for status overview
pub async fn get_brew_stats() -> BrewResult<BrewStats> {
    let installed = tokio::process::Command::new("brew")
        .args(["list", "--formula", "-1"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    let casks = tokio::process::Command::new("brew")
        .args(["list", "--cask", "-1"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    let outdated = tokio::process::Command::new("brew")
        .args(["outdated", "--formula"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    let formulae = tokio::process::Command::new("brew")
        .args(["formulae"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    let leaves = tokio::process::Command::new("brew")
        .args(["leaves"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    let taps = tokio::process::Command::new("brew")
        .args(["tap"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);

    Ok(BrewStats {
        installed,
        casks,
        outdated,
        formulae,
        leaves,
        taps,
    })
}

#[derive(Debug, Clone)]
pub struct BrewStats {
    pub installed: usize,
    pub casks: usize,
    pub outdated: usize,
    pub formulae: usize,
    pub leaves: usize,
    pub taps: usize,
}

/// Get list of outdated packages
pub async fn get_outdated_packages() -> BrewResult<Vec<String>> {
    let output = tokio::process::Command::new("brew")
        .args(["outdated", "--formula"])
        .output()
        .await
        .map_err(|e| BrewError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(BrewError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let packages = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(packages)
}

/// Sanitize error messages to remove sensitive information like file paths.
/// This prevents leaking system information to users.
pub fn sanitize_error(error: &str) -> String {
    let mut sanitized = error.to_string();

    // Remove absolute paths (Unix-style)
    // Matches paths starting with common system directories
    let path_regex = regex_lite::Regex::new(r"/(?:home|Users|usr|var|tmp|opt|etc)/[^\s:]+").unwrap();
    sanitized = path_regex.replace_all(&sanitized, "[path]").to_string();

    // Remove home directory references (tilde paths)
    let home_regex = regex_lite::Regex::new(r"~/[^\s:]*").unwrap();
    sanitized = home_regex.replace_all(&sanitized, "[path]").to_string();

    sanitized
}

/// Validate a package name to prevent injection attacks.
/// Valid package names: alphanumeric, dashes, underscores, dots, slashes (for taps), @
/// Examples: "git", "node@18", "homebrew/core/wget"
pub fn validate_package_name(name: &str) -> Result<(), BrewError> {
    if name.is_empty() {
        return Err(BrewError::ParseError("Package name cannot be empty".to_string()));
    }

    if name.len() > 256 {
        return Err(BrewError::ParseError("Package name too long".to_string()));
    }

    // Check for valid characters only
    let valid = name.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == '@'
    });

    if !valid {
        return Err(BrewError::ParseError(format!(
            "Invalid characters in package name: {}",
            name
        )));
    }

    // Prevent path traversal attempts
    if name.contains("..") {
        return Err(BrewError::ParseError("Invalid package name: contains '..'".to_string()));
    }

    // Prevent absolute paths
    if name.starts_with('/') {
        return Err(BrewError::ParseError("Invalid package name: cannot start with '/'".to_string()));
    }

    Ok(())
}

/// Validate a search query
pub fn validate_search_query(query: &str) -> Result<(), BrewError> {
    if query.len() > 256 {
        return Err(BrewError::ParseError("Search query too long".to_string()));
    }

    // Allow regex-like patterns (^, $, ., *, etc.) but block shell metacharacters
    // Note: $ alone is safe for regex anchoring, dangerous patterns like $(...) are caught by blocking ()
    let forbidden = ['`', '(', ')', '{', '}', '<', '>', '|', ';', '&', '\n', '\r', '\0'];
    for c in forbidden {
        if query.contains(c) {
            return Err(BrewError::ParseError(format!(
                "Invalid character in search query: {:?}",
                c
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Input Validation Tests
    // ==========================================================================

    #[test]
    fn test_validate_package_name_valid() {
        assert!(validate_package_name("git").is_ok());
        assert!(validate_package_name("node").is_ok());
        assert!(validate_package_name("node@18").is_ok());
        assert!(validate_package_name("llvm@15").is_ok());
        assert!(validate_package_name("homebrew/core/wget").is_ok());
        assert!(validate_package_name("user/tap/formula").is_ok());
        assert!(validate_package_name("my-package").is_ok());
        assert!(validate_package_name("my_package").is_ok());
        assert!(validate_package_name("package.name").is_ok());
    }

    #[test]
    fn test_validate_package_name_empty() {
        assert!(validate_package_name("").is_err());
    }

    #[test]
    fn test_validate_package_name_too_long() {
        let long_name = "a".repeat(257);
        assert!(validate_package_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_package_name_shell_injection() {
        // These should all be rejected
        assert!(validate_package_name("; rm -rf /").is_err());
        assert!(validate_package_name("git; echo pwned").is_err());
        assert!(validate_package_name("$(whoami)").is_err());
        assert!(validate_package_name("`whoami`").is_err());
        assert!(validate_package_name("git | cat /etc/passwd").is_err());
        assert!(validate_package_name("git && rm -rf /").is_err());
        assert!(validate_package_name("git\nrm -rf /").is_err());
        assert!(validate_package_name("git\0rm").is_err());
    }

    #[test]
    fn test_validate_package_name_path_traversal() {
        assert!(validate_package_name("../../../etc/passwd").is_err());
        assert!(validate_package_name("foo/../bar").is_err());
        assert!(validate_package_name("/etc/passwd").is_err());
    }

    #[test]
    fn test_validate_search_query_valid() {
        assert!(validate_search_query("git").is_ok());
        assert!(validate_search_query("node").is_ok());
        assert!(validate_search_query("json parser").is_ok());
        assert!(validate_search_query("^git").is_ok());  // regex allowed
        assert!(validate_search_query("git$").is_ok());
        assert!(validate_search_query("").is_ok());  // empty is ok for search
    }

    #[test]
    fn test_validate_search_query_shell_injection() {
        assert!(validate_search_query("; rm -rf /").is_err());
        assert!(validate_search_query("$(whoami)").is_err());  // blocked by ()
        assert!(validate_search_query("`whoami`").is_err());
        assert!(validate_search_query("git | cat").is_err());
        assert!(validate_search_query("git && rm").is_err());
        assert!(validate_search_query("git\nrm").is_err());
    }

    #[test]
    fn test_validate_search_query_too_long() {
        let long_query = "a".repeat(257);
        assert!(validate_search_query(&long_query).is_err());
    }

    // ==========================================================================
    // Error Display Tests
    // ==========================================================================

    #[test]
    fn test_brew_error_display() {
        let err = BrewError::CommandFailed("test error".to_string());
        assert_eq!(format!("{}", err), "Brew command failed: test error");

        let err = BrewError::ParseError("parse error".to_string());
        assert_eq!(format!("{}", err), "Failed to parse brew output: parse error");

        let err = BrewError::NotInstalled;
        assert_eq!(format!("{}", err), "Homebrew is not installed or not in PATH");
    }

    // ==========================================================================
    // JSON Parsing Tests
    // ==========================================================================

    #[test]
    fn test_parse_brew_info_response() {
        let json = r#"{
            "formulae": [{
                "name": "git",
                "desc": "Distributed revision control system",
                "homepage": "https://git-scm.com",
                "versions": {
                    "stable": "2.43.0",
                    "head": null,
                    "bottle": true
                }
            }]
        }"#;

        #[derive(Deserialize)]
        struct BrewInfoResponse {
            formulae: Vec<BrewInfoFormula>,
        }

        let response: BrewInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.formulae.len(), 1);
        assert_eq!(response.formulae[0].name, "git");
        assert_eq!(response.formulae[0].versions.stable, "2.43.0");
        assert_eq!(response.formulae[0].desc, Some("Distributed revision control system".to_string()));
    }

    #[test]
    fn test_parse_brew_info_minimal() {
        // Test with minimal required fields
        let json = r#"{
            "formulae": [{
                "name": "minimal",
                "versions": {
                    "stable": "1.0.0"
                }
            }]
        }"#;

        #[derive(Deserialize)]
        struct BrewInfoResponse {
            formulae: Vec<BrewInfoFormula>,
        }

        let response: BrewInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.formulae[0].name, "minimal");
        assert!(response.formulae[0].desc.is_none());
        assert!(response.formulae[0].homepage.is_none());
    }

    #[test]
    fn test_parse_brew_info_with_dependencies() {
        let json = r#"{
            "formulae": [{
                "name": "git",
                "versions": {
                    "stable": "2.43.0"
                },
                "dependencies": ["curl", "expat", "openssl", "perl"],
                "build_dependencies": ["gettext", "cmake"]
            }]
        }"#;

        #[derive(Deserialize)]
        struct BrewInfoResponse {
            formulae: Vec<BrewInfoFormula>,
        }

        let response: BrewInfoResponse = serde_json::from_str(json).unwrap();
        let formula = &response.formulae[0];

        // Verify runtime dependencies
        let deps = formula.dependencies.as_ref().unwrap();
        assert_eq!(deps.len(), 4);
        assert!(deps.contains(&"curl".to_string()));
        assert!(deps.contains(&"openssl".to_string()));

        // Verify build dependencies
        let build_deps = formula.build_dependencies.as_ref().unwrap();
        assert_eq!(build_deps.len(), 2);
        assert!(build_deps.contains(&"gettext".to_string()));
        assert!(build_deps.contains(&"cmake".to_string()));
    }

    #[test]
    fn test_parse_brew_info_empty_dependencies() {
        let json = r#"{
            "formulae": [{
                "name": "simple",
                "versions": { "stable": "1.0.0" },
                "dependencies": [],
                "build_dependencies": []
            }]
        }"#;

        #[derive(Deserialize)]
        struct BrewInfoResponse {
            formulae: Vec<BrewInfoFormula>,
        }

        let response: BrewInfoResponse = serde_json::from_str(json).unwrap();
        let formula = &response.formulae[0];

        assert!(formula.dependencies.as_ref().unwrap().is_empty());
        assert!(formula.build_dependencies.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_parse_package_struct() {
        let pkg = Package {
            name: "test".to_string(),
            version: Some("1.0.0".to_string()),
            desc: Some("Test package".to_string()),
            homepage: Some("https://example.com".to_string()),
            installed: true,
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: Package = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.version, Some("1.0.0".to_string()));
        assert!(parsed.installed);
    }

    // ==========================================================================
    // Integration Tests (require brew to be installed)
    // ==========================================================================

    #[test]
    fn test_is_brew_installed() {
        // This test just verifies the function runs without panic
        // Result depends on whether brew is actually installed
        let _ = is_brew_installed();
    }

    #[tokio::test]
    #[ignore] // Run with: cargo test -- --ignored
    async fn test_get_installed_packages_integration() {
        let result = get_installed_packages().await;
        // Should succeed if brew is installed
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_packages_integration() {
        let result = search_packages("git").await;
        assert!(result.is_ok());
        let packages = result.unwrap();
        // "git" should return at least one result
        assert!(!packages.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_package_info_integration() {
        let result = get_package_info("git").await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "git");
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_brew_stats_integration() {
        let result = get_brew_stats().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_outdated_packages_integration() {
        let result = get_outdated_packages().await;
        assert!(result.is_ok());
    }

    // ==========================================================================
    // Security Tests - Verify malicious input doesn't execute
    // ==========================================================================

    #[tokio::test]
    #[ignore]
    async fn test_search_with_shell_metacharacters() {
        // Even if we don't validate, the Command API should not execute shell commands
        // This test verifies brew just treats it as a literal search term
        let result = search_packages("; echo PWNED").await;
        // Should either fail gracefully or return no results, but never execute "echo PWNED"
        match result {
            Ok(packages) => {
                // Should not contain "PWNED" as a package name from shell execution
                assert!(!packages.iter().any(|p| p.contains("PWNED")));
            }
            Err(_) => {
                // Error is acceptable - brew may reject the query
            }
        }
    }

    // ==========================================================================
    // Tests verifying validation is enforced by functions
    // ==========================================================================

    #[tokio::test]
    async fn test_search_packages_validates_input() {
        // Should fail - either rate limited or validation error
        // Both are acceptable as security measures
        let result = search_packages("; malicious").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_package_info_validates_input() {
        let result = get_package_info("$(whoami)").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_install_package_validates_input() {
        let result = install_package("; rm -rf /").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_uninstall_package_validates_input() {
        let result = uninstall_package("pkg && echo pwned").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upgrade_packages_validates_input() {
        let result = upgrade_packages(Some("`whoami`")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_install_package_path_traversal() {
        let result = install_package("../../../etc/passwd").await;
        assert!(result.is_err());
    }

    // Test that validation functions themselves work correctly (not affected by rate limiting)
    #[test]
    fn test_validation_rejects_malicious_install_input() {
        assert!(validate_package_name("; rm -rf /").is_err());
        assert!(validate_package_name("$(whoami)").is_err());
        assert!(validate_package_name("pkg && echo pwned").is_err());
        assert!(validate_package_name("`whoami`").is_err());
        assert!(validate_package_name("../../../etc/passwd").is_err());
    }

    // ==========================================================================
    // Error Sanitization Tests
    // ==========================================================================

    #[test]
    fn test_sanitize_error_removes_home_paths() {
        let error = "Error: /home/username/projects/file.txt not found";
        let sanitized = sanitize_error(error);
        assert!(!sanitized.contains("username"));
        assert!(!sanitized.contains("/home/"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_removes_users_paths() {
        let error = "Error: /Users/john/Library/something failed";
        let sanitized = sanitize_error(error);
        assert!(!sanitized.contains("john"));
        assert!(!sanitized.contains("/Users/"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_removes_var_paths() {
        let error = "Failed to write to /var/log/brew.log";
        let sanitized = sanitize_error(error);
        assert!(!sanitized.contains("/var/log"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_removes_tilde_paths() {
        let error = "Cannot access ~/.config/brew/settings";
        let sanitized = sanitize_error(error);
        assert!(!sanitized.contains("~/.config"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_preserves_non_path_content() {
        let error = "Package 'git' not found in repository";
        let sanitized = sanitize_error(error);
        assert_eq!(sanitized, error);
    }

    #[test]
    fn test_sanitize_error_multiple_paths() {
        let error = "Error copying /home/user/src to /tmp/dest";
        let sanitized = sanitize_error(error);
        assert!(!sanitized.contains("/home/user"));
        assert!(!sanitized.contains("/tmp/dest"));
        assert_eq!(sanitized.matches("[path]").count(), 2);
    }

    // ==========================================================================
    // Rate Limiter Tests
    // ==========================================================================

    #[test]
    fn test_rate_limiter_allows_first_request() {
        let limiter = RateLimiter::new(1000);
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_rate_limiter_blocks_rapid_requests() {
        let limiter = RateLimiter::new(1000);  // 1 second interval
        assert!(limiter.check().is_ok());
        // Immediate second request should be blocked
        let result = limiter.check();
        assert!(result.is_err());
        // Should return remaining wait time
        let wait_ms = result.unwrap_err();
        assert!(wait_ms > 0 && wait_ms <= 1000);
    }

    #[test]
    fn test_rate_limiter_check_or_error() {
        let limiter = RateLimiter::new(1000);
        assert!(limiter.check_or_error().is_ok());
        let result = limiter.check_or_error();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BrewError::CommandFailed(_)));
    }

    #[test]
    fn test_rate_limiter_zero_interval_allows_all() {
        let limiter = RateLimiter::new(0);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
    }
}
