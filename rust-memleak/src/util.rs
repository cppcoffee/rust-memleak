use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use libc::pid_t;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

pub async fn get_binary_path_by_pid(pid: pid_t) -> Result<PathBuf> {
    let proc_path = format!("/proc/{}/exe", pid);
    let real_path = fs::read_link(&proc_path)
        .await
        .context(anyhow!("failed to read symlink for process: {}", proc_path))?;

    if !real_path.exists() {
        bail!("binary file does not exist: {:?}", real_path)
    }

    Ok(real_path)
}

pub async fn dump_to_file(path: &Path, map: &HashMap<String, u64>) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .context(format!("failed to open file: {:?}", path))?;

    for (k, v) in map.iter() {
        let s = format!("{} {}\n", k, v);

        file.write_all(s.as_bytes())
            .await
            .context(format!("failed to write file: {:?}", path))?;
    }

    Ok(())
}
