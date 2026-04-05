use crate::core::{DepotError, ErrorCode, RemotePath, SandboxPolicy, ServerRoot};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    pub root: PathBuf,
    pub requested: RemotePath,
    pub resolved: PathBuf,
}

pub fn ensure_server_root(path: impl AsRef<Path>) -> std::io::Result<ServerRoot> {
    let root = std::fs::canonicalize(path)?;
    Ok(ServerRoot::new(root))
}

pub fn resolve_remote_path(
    root: &ServerRoot,
    requested: &RemotePath,
    sandbox: SandboxPolicy,
) -> Result<ResolvedPath, DepotError> {
    if requested.is_empty() {
        return Err(DepotError::code_only(ErrorCode::BadPath));
    }

    let request_path = Path::new(requested.as_str());
    let root = root.as_path().to_path_buf();

    let resolved = if sandbox.is_enforced() {
        if request_path.is_absolute() {
            return Err(DepotError::new(
                ErrorCode::Absolute,
                requested.as_str().to_owned(),
            ));
        }
        resolve_sandboxed(&root, request_path, requested)?
    } else if request_path.is_absolute() {
        normalize_lexically(request_path)
    } else {
        normalize_lexically(root.join(request_path))
    };

    Ok(ResolvedPath {
        root,
        requested: requested.clone(),
        resolved,
    })
}

fn resolve_sandboxed(
    root: &Path,
    request_path: &Path,
    requested: &RemotePath,
) -> Result<PathBuf, DepotError> {
    let mut candidate = root.to_path_buf();

    for component in request_path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => {
                candidate.push(segment);
                reject_symlink_component(&candidate, requested)?;
            }
            Component::ParentDir => {
                return Err(DepotError::new(
                    ErrorCode::UnsafePath,
                    requested.as_str().to_owned(),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(DepotError::new(
                    ErrorCode::Absolute,
                    requested.as_str().to_owned(),
                ));
            }
        }
    }

    Ok(candidate)
}

fn reject_symlink_component(path: &Path, requested: &RemotePath) -> Result<(), DepotError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(DepotError::new(
                ErrorCode::OpenFail,
                format!("{}: {err}", requested.as_str()),
            ));
        }
    };

    if metadata.file_type().is_symlink() {
        return Err(DepotError::new(
            ErrorCode::UnsafePath,
            requested.as_str().to_owned(),
        ));
    }

    Ok(())
}

fn normalize_lexically(path: impl AsRef<Path>) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.as_ref().components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_absolute_remote_paths_in_sandbox() {
        let temp = tempfile::tempdir().unwrap();
        let root = ensure_server_root(temp.path()).unwrap();
        let err = resolve_remote_path(
            &root,
            &RemotePath::new("/tmp/file"),
            SandboxPolicy::Enforced,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Absolute);
    }

    #[test]
    fn rejects_parent_traversal_in_sandbox() {
        let temp = tempfile::tempdir().unwrap();
        let root = ensure_server_root(temp.path()).unwrap();
        let err = resolve_remote_path(
            &root,
            &RemotePath::new("../outside"),
            SandboxPolicy::Enforced,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsafePath);
    }

    #[test]
    fn rejects_symlink_components_in_sandbox() {
        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            let root = ensure_server_root(temp.path()).unwrap();
            let target = temp.path().join("real");
            fs::create_dir(&target).unwrap();
            let link = temp.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let err = resolve_remote_path(
                &root,
                &RemotePath::new("link/child.txt"),
                SandboxPolicy::Enforced,
            )
            .unwrap_err();
            assert_eq!(err.code, ErrorCode::UnsafePath);
        }
    }
}
