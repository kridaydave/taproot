use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use libc::{c_int, EROFS};

use crate::error::TaprootError;
use crate::state::SignedState;

// ---------------------------------------------------------------------------
// Inode table
// ---------------------------------------------------------------------------

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

#[derive(Debug, Clone)]
struct Inode {
    ino: u64,
    parent: u64,
    name: String,
    kind: FileType,
    data: Vec<u8>,
    children: Vec<u64>,
    /// Writable inodes accept writes; everything else stays read-only.
    writable: bool,
}

/// Captures writes to the env file so drift can be extracted after unmount.
#[derive(Debug, Default)]
struct Journal {
    env_original: Vec<u8>,
    env_data: Vec<u8>,
}

impl Journal {
    fn drifted(&self) -> bool {
        self.env_data != self.env_original
    }
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn file_attr(ino: u64, size: u64, kind: FileType, writable: bool) -> FileAttr {
    let t = now();
    let perm = if kind == FileType::Directory {
        0o555
    } else if writable {
        0o644
    } else {
        0o444
    };
    FileAttr {
        ino,
        size,
        blocks: size
            .div_ceil(512)
            .max(if kind == FileType::Directory { 1 } else { 0 }),
        atime: t,
        mtime: t,
        ctime: t,
        crtime: t,
        kind,
        perm,
        nlink: if kind == FileType::Directory { 2 } else { 1 },
        uid: unsafe { libc::getuid() } as u32,
        gid: unsafe { libc::getgid() } as u32,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn is_safe_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    if name.contains('/') || name.contains('\0') || name.contains('\\') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// ---------------------------------------------------------------------------
// TaprootFS
// ---------------------------------------------------------------------------

pub struct TaprootFS {
    inodes: HashMap<u64, Inode>,
    /// (parent_ino, name) -> ino
    lookup: HashMap<(u64, String), u64>,
    next_ino: u64,
    env_ino: Option<u64>,
    journal: Arc<Mutex<Journal>>,
}

impl TaprootFS {
    pub fn new(signed: &SignedState) -> Self {
        let mut fs = Self {
            inodes: HashMap::new(),
            lookup: HashMap::new(),
            next_ino: ROOT_INO + 1,
            env_ino: None,
            journal: Arc::new(Mutex::new(Journal::default())),
        };

        fs.inodes.insert(
            ROOT_INO,
            Inode {
                ino: ROOT_INO,
                parent: ROOT_INO,
                name: String::new(),
                kind: FileType::Directory,
                data: Vec::new(),
                children: Vec::new(),
                writable: false,
            },
        );

        let readme = Self::readme_content(signed);
        let state_json = serde_json::to_string_pretty(signed).unwrap_or_else(|_| "{}".into());
        let env_content = Self::env_content(signed);

        fs.add_file(ROOT_INO, "README.taproot", readme.into_bytes(), false);
        fs.add_file(ROOT_INO, "state.json", state_json.into_bytes(), false);
        let env_ino = fs.add_file(ROOT_INO, "env", env_content.clone().into_bytes(), true);
        fs.env_ino = Some(env_ino);
        {
            let mut j = fs.journal.lock().unwrap();
            j.env_original = env_content.into_bytes();
            j.env_data = j.env_original.clone();
        }
        fs.add_file(ROOT_INO, "hash", signed.hash.clone().into_bytes(), false);
        fs.add_file(
            ROOT_INO,
            "version",
            signed.state.version.clone().into_bytes(),
            false,
        );

        let runtimes_ino = fs.add_dir(ROOT_INO, "runtimes");
        for r in &signed.state.runtimes {
            if !is_safe_filename(&r.name) {
                continue;
            }
            let content = format!(
                "name: {}\nversion: {}\npinned: {}\n",
                r.name, r.version, r.pinned
            );
            let fname = format!("{}.txt", r.name);
            if fs.lookup.contains_key(&(runtimes_ino, fname.clone())) {
                continue;
            }
            fs.add_file(runtimes_ino, &fname, content.into_bytes(), false);
        }

        let containers_ino = fs.add_dir(ROOT_INO, "containers");
        for c in &signed.state.containers {
            if !is_safe_filename(&c.name) {
                continue;
            }
            let content = format!(
                "name: {}\nversion: {}\nimage: {}\nsigned: {}\n",
                c.name, c.version, c.image, c.signed
            );
            let fname = format!("{}.txt", c.name);
            if fs.lookup.contains_key(&(containers_ino, fname.clone())) {
                continue;
            }
            fs.add_file(containers_ino, &fname, content.into_bytes(), false);
        }

        fs
    }

    fn readme_content(signed: &SignedState) -> String {
        let s = &signed.state;
        let sig = if signed.signature.is_some() {
            "signed"
        } else {
            "unsigned"
        };
        format!(
            "taproot mount\n\
             =============\n\
             repo: {}  branch: {}  commit: {}\n\
             state: {sig}  sha256:{}\n\
             runtimes: {}  containers: {}  env-vars: {}\n\
             \n\
             Read-only, except one file:\n\
               env — edit key=value lines to change env-vars.\n\
               On unmount, edits are captured as drift; run\n\
               `taproot sync` to review, sign, and adopt them.\n\
             \n\
             Files:\n\
               state.json  — pretty-printed SignedState\n\
               env         — key=value list (WRITABLE)\n\
               hash        — sha256 hex\n\
               version     — schema version\n\
               runtimes/   — per-runtime virtual files\n\
               containers/ — per-container virtual files\n",
            s.base.repo,
            s.base.branch,
            s.base.commit,
            signed.hash,
            s.runtimes.len(),
            s.containers.len(),
            s.env_vars.len(),
        )
    }

    fn env_content(signed: &SignedState) -> String {
        if signed.state.env_vars.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (k, v) in &signed.state.env_vars {
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
        out
    }

    fn add_file(&mut self, parent: u64, name: &str, data: Vec<u8>, writable: bool) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        let inode = Inode {
            ino,
            parent,
            name: name.to_string(),
            kind: FileType::RegularFile,
            data,
            children: Vec::new(),
            writable,
        };
        self.inodes.insert(ino, inode);
        self.lookup.insert((parent, name.to_string()), ino);
        if let Some(p) = self.inodes.get_mut(&parent) {
            p.children.push(ino);
        }
        ino
    }

    fn add_dir(&mut self, parent: u64, name: &str) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        let inode = Inode {
            ino,
            parent,
            name: name.to_string(),
            kind: FileType::Directory,
            data: Vec::new(),
            children: Vec::new(),
            writable: false,
        };
        self.inodes.insert(ino, inode);
        self.lookup.insert((parent, name.to_string()), ino);
        if let Some(p) = self.inodes.get_mut(&parent) {
            p.children.push(ino);
        }
        ino
    }

    #[cfg(test)]
    pub fn inode_count(&self) -> usize {
        self.inodes.len()
    }

    #[cfg(test)]
    #[allow(private_interfaces)]
    pub fn get_inode(&self, ino: u64) -> Option<&Inode> {
        self.inodes.get(&ino)
    }

    #[cfg(test)]
    pub fn lookup_ino(&self, parent: u64, name: &str) -> Option<u64> {
        self.lookup.get(&(parent, name.to_string())).copied()
    }

    fn getattr_for(&self, ino: u64) -> Option<FileAttr> {
        let inode = self.inodes.get(&ino)?;
        let size = if inode.kind == FileType::Directory {
            0
        } else {
            inode.data.len() as u64
        };
        Some(file_attr(ino, size, inode.kind, inode.writable))
    }

    /// Apply a write to a writable inode. Shared by the FUSE `write` handler
    /// and tests so the journal/overlay logic is testable without a mount.
    fn apply_write(&mut self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, libc::c_int> {
        let inode = self.inodes.get_mut(&ino).ok_or(libc::ENOENT)?;
        if inode.kind == FileType::Directory {
            return Err(libc::EISDIR);
        }
        if !inode.writable {
            return Err(EROFS);
        }
        if offset < 0 {
            return Err(libc::EINVAL);
        }
        let off = offset as usize;
        if off > inode.data.len() {
            inode.data.resize(off, 0);
        }
        let end = off + data.len();
        if end > inode.data.len() {
            inode.data.resize(end, 0);
        }
        inode.data[off..end].copy_from_slice(data);
        if self.env_ino == Some(ino) {
            let mut j = self.journal.lock().unwrap();
            j.env_data = inode.data.clone();
        }
        Ok(data.len() as u32)
    }

    /// Truncate/extend a writable inode to `size` (FUSE setattr with size).
    fn apply_truncate(&mut self, ino: u64, size: u64) -> Result<(), libc::c_int> {
        let inode = self.inodes.get_mut(&ino).ok_or(libc::ENOENT)?;
        if inode.kind == FileType::Directory {
            return Err(libc::EISDIR);
        }
        if !inode.writable {
            return Err(EROFS);
        }
        inode.data.resize(size as usize, 0);
        if self.env_ino == Some(ino) {
            let mut j = self.journal.lock().unwrap();
            j.env_data = inode.data.clone();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Filesystem impl — read-only
// ---------------------------------------------------------------------------

impl Filesystem for TaprootFS {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_string_lossy().to_string();
        if let Some(&ino) = self.lookup.get(&(parent, name_str)) {
            if let Some(attr) = self.getattr_for(ino) {
                reply.entry(&TTL, &attr, 0);
                return;
            }
        }
        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if let Some(attr) = self.getattr_for(ino) {
            reply.attr(&TTL, &attr);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(inode) = self.inodes.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let wants_write = {
            let accmode = flags & libc::O_ACCMODE;
            (flags & libc::O_TRUNC) != 0 || accmode == libc::O_WRONLY || accmode == libc::O_RDWR
        };
        if wants_write && !inode.writable {
            reply.error(EROFS);
            return;
        }
        if (flags & libc::O_TRUNC) != 0 {
            if let Err(e) = self.apply_truncate(ino, 0) {
                reply.error(e);
                return;
            }
        }
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(inode) = self.inodes.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if inode.kind == FileType::Directory {
            reply.error(libc::EISDIR);
            return;
        }
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let data = &inode.data;
        let off = offset as usize;
        if off >= data.len() {
            reply.data(&[]);
            return;
        }
        let end = (off + size as usize).min(data.len());
        reply.data(&data[off..end]);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let Some(inode) = self.inodes.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };
        if inode.kind != FileType::Directory {
            reply.error(libc::ENOTDIR);
            return;
        }

        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        entries.push((ino, FileType::Directory, ".".to_string()));
        entries.push((
            if ino == ROOT_INO {
                ROOT_INO
            } else {
                inode.parent
            },
            FileType::Directory,
            "..".to_string(),
        ));
        for &child_ino in &inode.children {
            if let Some(child) = self.inodes.get(&child_ino) {
                entries.push((child.ino, child.kind, child.name.clone()));
            }
        }

        for (i, (child_ino, kind, name)) in entries.into_iter().enumerate() {
            let idx = (i + 1) as i64;
            if idx <= offset {
                continue;
            }
            if reply.add(child_ino, idx, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        match self.apply_write(ino, offset, data) {
            Ok(n) => reply.written(n),
            Err(e) => reply.error(e),
        }
    }

    // --- read-only denials ---
    fn create(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        reply.error(EROFS);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(EROFS);
    }

    fn mknod(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(EROFS);
    }

    fn unlink(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(EROFS);
    }

    fn rmdir(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(EROFS);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        _newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(EROFS);
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Only size changes on writable inodes are honored (truncate).
        if let Some(sz) = size {
            match self.apply_truncate(ino, sz) {
                Ok(()) => {
                    if let Some(attr) = self.getattr_for(ino) {
                        reply.attr(&TTL, &attr);
                    } else {
                        reply.error(libc::ENOENT);
                    }
                    return;
                }
                Err(e) => {
                    reply.error(e);
                    return;
                }
            }
        }
        reply.error(EROFS);
    }
}

// ---------------------------------------------------------------------------
// Public mount helper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Drift extraction
// ---------------------------------------------------------------------------

/// Parse a `key=value` env file back into a map. Blank lines are skipped;
/// anything without `=` is an error.
pub fn parse_env(content: &str) -> Result<BTreeMap<String, String>, TaprootError> {
    let mut map = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(TaprootError::Mount(format!(
                "malformed env line {}: expected key=value",
                idx + 1
            )));
        };
        let k = k.trim();
        if k.is_empty() {
            return Err(TaprootError::Mount(format!(
                "malformed env line {}: empty key",
                idx + 1
            )));
        }
        if map.contains_key(k) {
            return Err(TaprootError::Mount(format!(
                "malformed env line {}: duplicate key {k}",
                idx + 1
            )));
        }
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

/// Build a drifted (unsigned) SignedState from the mounted env file contents.
/// The new state gets a fresh hash; signature is dropped because the state
/// no longer matches the signed baseline.
pub fn extract_env_drift(
    signed: &SignedState,
    env_content: &[u8],
) -> Result<SignedState, TaprootError> {
    let text = std::str::from_utf8(env_content)
        .map_err(|e| TaprootError::Mount(format!("env file is not utf-8: {e}")))?;
    let env_vars = parse_env(text)?;
    let mut state = signed.state.clone();
    state.env_vars = env_vars;
    state.created_at = chrono::Utc::now();
    let hash = crate::engine::StateEngine::hash(&state)?;
    Ok(SignedState {
        state,
        hash,
        signature: None,
        public_key: None,
    })
}

/// Result of a mount session after unmount.
#[derive(Debug)]
pub struct MountOutcome {
    /// Present when the env file was edited and parsed back into a state.
    pub drift: Option<SignedState>,
    /// Raw edited env bytes, present when parsing into a state failed.
    /// The session's edits survive in these bytes even though no state
    /// could be built from them.
    pub raw_env: Option<Vec<u8>>,
    /// Parse error accompanying `raw_env`.
    pub parse_error: Option<TaprootError>,
}

/// Mount a FUSE filesystem at `mountpoint` reflecting `signed`.
///
/// Blocks until unmounted. Read-only everywhere except the `env` file;
/// edits to `env` are returned as drift in the outcome.
pub fn mount_readonly(
    mountpoint: &Path,
    signed: &SignedState,
) -> Result<MountOutcome, TaprootError> {
    let meta = std::fs::symlink_metadata(mountpoint).map_err(|e| {
        TaprootError::Mount(format!(
            "mountpoint does not exist: {}: {e}",
            mountpoint.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(TaprootError::Mount(format!(
            "mountpoint is a symlink (refusing): {}",
            mountpoint.display()
        )));
    }
    if !meta.is_dir() {
        return Err(TaprootError::Mount(format!(
            "mountpoint is not a directory: {}",
            mountpoint.display()
        )));
    }
    let fs = TaprootFS::new(signed);
    let journal = Arc::clone(&fs.journal);
    let options = [
        fuser::MountOption::FSName("taproot".to_string()),
        fuser::MountOption::Subtype("taproot".to_string()),
    ];
    fuser::mount2(fs, mountpoint, &options).map_err(|e| TaprootError::Mount(e.to_string()))?;

    let j = journal.lock().unwrap();
    Ok(outcome_from_journal(&j, signed))
}

/// Decide the mount outcome from the journal. Extracted from
/// `mount_readonly` so the drift/raw-env branches are testable without a
/// real mount.
fn outcome_from_journal(j: &Journal, signed: &SignedState) -> MountOutcome {
    if j.drifted() {
        match extract_env_drift(signed, &j.env_data) {
            Ok(drift) => MountOutcome {
                drift: Some(drift),
                raw_env: None,
                parse_error: None,
            },
            // Unparseable env must not destroy the session: hand back the
            // raw bytes so the CLI can persist them.
            Err(e) => MountOutcome {
                drift: None,
                raw_env: Some(j.env_data.clone()),
                parse_error: Some(e),
            },
        }
    } else {
        MountOutcome {
            drift: None,
            raw_env: None,
            parse_error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::TaprootState;

    fn sample_signed() -> SignedState {
        let state = TaprootState::new("myapp", "main", "abc123")
            .with_runtime("python", "3.11.4")
            .with_env("FOO", "bar")
            .with_container("postgres", "15.3", "postgres:15.3");
        let hash = crate::engine::StateEngine::hash(&state).unwrap();
        SignedState {
            state,
            hash,
            signature: None,
            public_key: None,
        }
    }

    #[test]
    fn inode_table_has_expected_files() {
        let signed = sample_signed();
        let fs = TaprootFS::new(&signed);
        assert!(fs.inode_count() >= 8);
        assert!(fs.lookup_ino(ROOT_INO, "state.json").is_some());
        assert!(fs.lookup_ino(ROOT_INO, "README.taproot").is_some());
        assert!(fs.lookup_ino(ROOT_INO, "env").is_some());
        assert!(fs.lookup_ino(ROOT_INO, "hash").is_some());
        assert!(fs.lookup_ino(ROOT_INO, "runtimes").is_some());
        assert!(fs.lookup_ino(ROOT_INO, "containers").is_some());
    }

    #[test]
    fn file_content_correct() {
        let signed = sample_signed();
        let fs = TaprootFS::new(&signed);
        let ino = fs.lookup_ino(ROOT_INO, "env").unwrap();
        let inode = fs.get_inode(ino).unwrap();
        let text = String::from_utf8_lossy(&inode.data);
        assert!(text.contains("FOO=bar"));

        let ino2 = fs.lookup_ino(ROOT_INO, "hash").unwrap();
        let inode2 = fs.get_inode(ino2).unwrap();
        assert_eq!(String::from_utf8_lossy(&inode2.data), signed.hash);
    }

    #[test]
    fn per_runtime_container_files() {
        let signed = sample_signed();
        let fs = TaprootFS::new(&signed);
        let runtimes = fs.lookup_ino(ROOT_INO, "runtimes").unwrap();
        assert!(fs.lookup_ino(runtimes, "python.txt").is_some());
        let containers = fs.lookup_ino(ROOT_INO, "containers").unwrap();
        assert!(fs.lookup_ino(containers, "postgres.txt").is_some());
    }

    #[test]
    fn getattr_root_is_dir() {
        let signed = sample_signed();
        let fs = TaprootFS::new(&signed);
        let attr = fs.getattr_for(ROOT_INO).unwrap();
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o555);
    }

    #[test]
    fn env_is_writable_others_are_not() {
        let signed = sample_signed();
        let mut fs = TaprootFS::new(&signed);
        let env_ino = fs.lookup_ino(ROOT_INO, "env").unwrap();
        let state_ino = fs.lookup_ino(ROOT_INO, "state.json").unwrap();

        assert_eq!(fs.getattr_for(env_ino).unwrap().perm, 0o644);
        assert_eq!(fs.getattr_for(state_ino).unwrap().perm, 0o444);

        // env accepts writes
        let n = fs.apply_write(env_ino, 0, b"FOO=baz\n").unwrap();
        assert_eq!(n, 8);
        // state.json rejects writes
        assert_eq!(fs.apply_write(state_ino, 0, b"x"), Err(EROFS));
    }

    #[test]
    fn env_write_updates_journal_and_drift_extracts() {
        let signed = sample_signed();
        let mut fs = TaprootFS::new(&signed);
        let env_ino = fs.lookup_ino(ROOT_INO, "env").unwrap();

        // rewrite whole file via truncate + write
        fs.apply_truncate(env_ino, 0).unwrap();
        fs.apply_write(env_ino, 0, b"FOO=baz\nNEW=1\n").unwrap();

        {
            let j = fs.journal.lock().unwrap();
            assert!(j.drifted());
            let drift = extract_env_drift(&signed, &j.env_data).unwrap();
            assert_eq!(drift.state.env_vars.get("FOO").unwrap(), "baz");
            assert_eq!(drift.state.env_vars.get("NEW").unwrap(), "1");
            assert!(drift.signature.is_none());
            assert_ne!(drift.hash, signed.hash);
            // untouched fields survive
            assert_eq!(drift.state.runtimes, signed.state.runtimes);
        }
    }

    #[test]
    fn identical_env_rewrite_is_not_drift() {
        let signed = sample_signed();
        let mut fs = TaprootFS::new(&signed);
        let env_ino = fs.lookup_ino(ROOT_INO, "env").unwrap();
        // rewrite the exact original content
        let original: Vec<u8> = fs
            .get_inode(env_ino)
            .map(|i| i.data.clone())
            .unwrap_or_default();
        fs.apply_truncate(env_ino, 0).unwrap();
        fs.apply_write(env_ino, 0, &original).unwrap();
        assert!(!fs.journal.lock().unwrap().drifted());
    }

    #[test]
    fn parse_env_rejects_malformed_lines() {
        assert!(parse_env("A=1\nB=2\n").is_ok());
        assert!(parse_env("\n\nA=1\n").is_ok());
        assert!(parse_env("=1\n").is_err());
        assert!(parse_env("JUSTKEY\n").is_err());
        // value may contain '='
        let m = parse_env("URL=http://x?a=b\n").unwrap();
        assert_eq!(m.get("URL").unwrap(), "http://x?a=b");
    }

    #[test]
    fn parse_env_rejects_duplicate_keys_after_trimming() {
        let error = parse_env("FOO=first\n FOO =second\n").unwrap_err();
        assert!(error.to_string().contains("line 2: duplicate key FOO"));
    }

    #[test]
    fn outcome_preserves_unparseable_env_as_raw_bytes() {
        let signed = sample_signed();
        let mut fs = TaprootFS::new(&signed);
        let env_ino = fs.lookup_ino(ROOT_INO, "env").unwrap();
        // binary garbage with no newline and no '='
        fs.apply_truncate(env_ino, 0).unwrap();
        fs.apply_write(env_ino, 0, &[0xFF, 0xFE, 0x00, 0x01])
            .unwrap();

        let j = fs.journal.lock().unwrap();
        let outcome = outcome_from_journal(&j, &signed);
        assert!(outcome.drift.is_none());
        assert!(outcome.raw_env.is_some());
        assert!(outcome.parse_error.is_some());
        assert_eq!(
            outcome.raw_env.as_deref().unwrap(),
            &[0xFF, 0xFE, 0x00, 0x01]
        );

        // clean journal → no drift, no raw
        drop(j);
        let fs2 = TaprootFS::new(&signed);
        let j2 = fs2.journal.lock().unwrap();
        let outcome2 = outcome_from_journal(&j2, &signed);
        assert!(outcome2.drift.is_none());
        assert!(outcome2.raw_env.is_none());
        assert!(outcome2.parse_error.is_none());
    }

    #[test]
    fn mount_readonly_errors_on_missing_path() {
        let signed = sample_signed();
        let res = mount_readonly(Path::new("/tmp/does-not-exist-taproot-test-xyz"), &signed);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), TaprootError::Mount(_)));
    }
}
