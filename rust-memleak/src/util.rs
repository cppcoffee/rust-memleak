use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use libc::pid_t;

pub fn get_binary_path_by_pid(pid: pid_t) -> Result<PathBuf> {
    let proc_path = format!("/proc/{}/exe", pid);
    let real_path = fs::read_link(&proc_path)
        .context(anyhow!("failed to read symlink for process: {}", proc_path))?;

    if !real_path.exists() {
        bail!("binary file does not exist: {:?}", real_path)
    }

    Ok(real_path)
}
