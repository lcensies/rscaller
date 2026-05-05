use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

/// Parsed entry from a syscall .tbl file
#[derive(Debug, Clone)]
pub struct SyscallEntry {
    pub number: u32,
    pub abi: String,
    pub name: String,
    pub entry_point: String,
}

/// Parse a syscall .tbl file. Format per line:
///   <number> <abi> <name> <entry_point>
/// Lines starting with '#' or empty lines are ignored.
pub fn parse_tbl(path: &Path) -> Result<Vec<SyscallEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read tbl file: {}", path.display()))?;

    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            // Some lines may have only 3 parts (no entry point) — skip
            if parts.len() < 3 {
                continue;
            }
        }

        let number: u32 = parts[0]
            .parse()
            .with_context(|| format!("Invalid syscall number '{}' in line: {}", parts[0], line))?;

        let entry = SyscallEntry {
            number,
            abi: parts[1].to_string(),
            name: parts[2].to_string(),
            entry_point: if parts.len() >= 4 {
                parts[3].to_string()
            } else {
                String::new()
            },
        };

        entries.push(entry);
    }

    Ok(entries)
}

/// Build name -> number map from parsed entries.
/// If a name appears multiple times, keep the first (lowest-abi) entry.
pub fn build_name_map(entries: &[SyscallEntry]) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for e in entries {
        map.entry(e.name.clone()).or_insert(e.number);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tbl_path(name: &str) -> PathBuf {
        // Tests run from tools/codegen/
        PathBuf::from("../../files").join(name)
    }

    #[test]
    fn test_parse_tbl_kill() {
        let path = tbl_path("syscall_64_6_13.tbl");
        let entries = parse_tbl(&path).expect("parse failed");
        let map = build_name_map(&entries);

        assert_eq!(map.get("kill").copied(), Some(62), "kill should be 62");
        assert_eq!(map.get("execve").copied(), Some(59), "execve should be 59");
        assert_eq!(map.get("open").copied(), Some(2), "open should be 2");
        assert_eq!(map.get("openat").copied(), Some(257), "openat should be 257");
    }

    #[test]
    fn test_parse_tbl_5_4() {
        let path = tbl_path("syscall_64_5_4.tbl");
        let entries = parse_tbl(&path).expect("parse failed");
        assert!(entries.len() > 300, "Expected > 300 entries, got {}", entries.len());
    }
}
