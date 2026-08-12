use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tempfile::NamedTempFile;

pub(crate) fn load_json<T: DeserializeOwned + Default>(path: &Path) -> anyhow::Result<T> {
    match File::open(path) {
        Ok(file) => Ok(serde_json::from_reader(file)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    replace_file(path, |file| {
        serde_json::to_writer(&mut *file, value).map_err(io::Error::other)?;
        Ok(())
    })
}

/// Write a new file durably, failing if the destination already exists.
pub(crate) fn write_new(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    sync_parent(path)?;
    Ok(())
}

fn replace_file(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state path has no parent"))?;
    let mut temporary = NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_parent(path)?;
    Ok(())
}

fn sync_parent(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("state path has no parent"))?;
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_write_keeps_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        fs::write(&path, b"previous").unwrap();

        let result = replace_file(&path, |file| {
            file.write_all(b"part")?;
            Err(io::Error::other("injected partial write"))
        });

        assert!(result.is_err());
        assert_eq!(fs::read(path).unwrap(), b"previous");
    }
}
