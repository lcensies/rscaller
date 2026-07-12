use std::collections::HashMap;

/// File handle table: maps local fh → remote fd (beacon) or local fd (real /proc).
pub struct FhTable {
    next_fh: u64,
    fh_to_rfd: HashMap<u64, i64>,
    local_fds: HashMap<u64, i32>,
}

impl FhTable {
    pub fn new() -> Self {
        FhTable {
            next_fh: 1,
            fh_to_rfd: HashMap::new(),
            local_fds: HashMap::new(),
        }
    }

    /// Allocate a new file handle for the given remote (beacon) fd.
    pub fn alloc(&mut self, remote_fd: i64) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.fh_to_rfd.insert(fh, remote_fd);
        fh
    }

    /// Look up the remote fd for a file handle.
    pub fn get(&self, fh: u64) -> Option<i64> {
        self.fh_to_rfd.get(&fh).copied()
    }

    /// Remove and return the remote fd for a file handle.
    pub fn release(&mut self, fh: u64) -> Option<i64> {
        self.fh_to_rfd.remove(&fh)
    }

    /// Allocate a new file handle for a local (real /proc) fd.
    pub fn alloc_local(&mut self, local_fd: i32) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.local_fds.insert(fh, local_fd);
        fh
    }

    /// Look up the local fd for a file handle.
    pub fn get_local(&self, fh: u64) -> Option<i32> {
        self.local_fds.get(&fh).copied()
    }

    /// Remove and return the local fd for a file handle.
    pub fn release_local(&mut self, fh: u64) -> Option<i32> {
        self.local_fds.remove(&fh)
    }

    pub fn is_local(&self, fh: u64) -> bool {
        self.local_fds.contains_key(&fh)
    }
}
