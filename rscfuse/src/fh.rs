use std::collections::HashMap;

/// File handle table: maps local fh → remote fd.
pub struct FhTable {
    next_fh: u64,
    fh_to_rfd: HashMap<u64, i64>,
}

impl FhTable {
    pub fn new() -> Self {
        FhTable {
            next_fh: 1,
            fh_to_rfd: HashMap::new(),
        }
    }

    /// Allocate a new file handle for the given remote fd.
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
}
