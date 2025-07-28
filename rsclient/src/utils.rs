use std::process::Command;

// Function to get the Git root directory
fn get_git_root() -> io::Result<PathBuf> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()?;

    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(git_root))
}