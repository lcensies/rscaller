use std::collections::HashMap;

/// Bidirectional inode ↔ path mapping.
/// Root "/" is always inode 1.
pub struct InodeTable {
    next_ino: u64,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
}

impl InodeTable {
    pub fn new() -> Self {
        let mut t = InodeTable {
            next_ino: 2,
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
        };
        t.ino_to_path.insert(1, "/".to_string());
        t.path_to_ino.insert("/".to_string(), 1);
        t
    }

    pub fn get_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(|s| s.as_str())
    }

    /// Return existing inode for path, or allocate a new one.
    pub fn get_or_create(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }

    /// Construct child path from parent inode + name component.
    pub fn join(&self, parent_ino: u64, name: &str) -> Option<String> {
        let parent = self.ino_to_path.get(&parent_ino)?;
        if parent == "/" {
            Some(format!("/{}", name))
        } else {
            Some(format!("{}/{}", parent, name))
        }
    }
}
