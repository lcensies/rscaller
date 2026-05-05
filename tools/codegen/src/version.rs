use std::path::{Path, PathBuf};
use anyhow::{bail, Result};

/// Parsed kernel version
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub fn parse(version_str: &str) -> Result<Self> {
        // Strip trailing suffix like "-generic", "-arch1", etc.
        let base = version_str.split('-').next().unwrap_or(version_str);
        let parts: Vec<&str> = base.split('.').collect();

        if parts.len() < 2 {
            bail!("Cannot parse kernel version from '{}'", version_str);
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        let patch: u32 = if parts.len() >= 3 {
            parts[2].parse().unwrap_or(0)
        } else {
            0
        };

        Ok(KernelVersion { major, minor, patch })
    }

    /// Read kernel version from `uname -r` output
    pub fn from_uname() -> Result<Self> {
        let output = std::process::Command::new("uname")
            .arg("-r")
            .output()?;
        let version_str = String::from_utf8(output.stdout)?.trim().to_string();
        Self::parse(&version_str)
    }
}

/// Select the appropriate .tbl filename based on kernel version.
/// - kernel >= 6.x  -> syscall_64_6_13.tbl
/// - kernel 5.x     -> syscall_64_5_4.tbl
/// - default        -> syscall_64_6_13.tbl
pub fn select_tbl_name(version: &KernelVersion) -> &'static str {
    if version.major >= 6 {
        "syscall_64_6_13.tbl"
    } else if version.major == 5 {
        "syscall_64_5_4.tbl"
    } else {
        // Default to newest known
        "syscall_64_6_13.tbl"
    }
}

/// Return the full path to the selected .tbl file.
pub fn select_tbl_path(tbl_dir: &Path, version: &KernelVersion) -> PathBuf {
    tbl_dir.join(select_tbl_name(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_select_tbl() {
        let v6_14 = KernelVersion { major: 6, minor: 14, patch: 0 };
        assert_eq!(select_tbl_name(&v6_14), "syscall_64_6_13.tbl");

        let v5_4 = KernelVersion { major: 5, minor: 4, patch: 0 };
        assert_eq!(select_tbl_name(&v5_4), "syscall_64_5_4.tbl");

        let v5_15 = KernelVersion { major: 5, minor: 15, patch: 0 };
        assert_eq!(select_tbl_name(&v5_15), "syscall_64_5_4.tbl");

        let v4_x = KernelVersion { major: 4, minor: 19, patch: 0 };
        assert_eq!(select_tbl_name(&v4_x), "syscall_64_6_13.tbl");
    }

    #[test]
    fn test_version_parse() {
        let v = KernelVersion::parse("6.14.0-15-generic").unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 14);

        let v2 = KernelVersion::parse("5.4.0").unwrap();
        assert_eq!(v2.major, 5);
        assert_eq!(v2.minor, 4);
    }
}
