use std::process::Command;
use std::path::PathBuf;
use std::io;

// Function to get the Git root directory
pub fn get_git_root() -> io::Result<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    // Ok(PathBuf::from(git_root))
}