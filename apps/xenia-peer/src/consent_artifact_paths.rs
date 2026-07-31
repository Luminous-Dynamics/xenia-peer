//! Canonical path protection for consent maintenance artifacts.
//!
//! Maintenance commands commonly read several signed inputs and then publish a
//! new artifact.  Every output must be checked against canonical input paths,
//! key files, and protected evidence trees before an atomic writer is invoked.
//! Keeping that normalization in one module avoids subtle differences between
//! lifecycle commands and makes symlink aliases fail closed.

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct ProtectedPathSet {
    label: String,
    exact: Vec<PathBuf>,
    trees: Vec<PathBuf>,
}

impl ProtectedPathSet {
    pub(crate) fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            exact: Vec::new(),
            trees: Vec::new(),
        }
    }

    pub(crate) fn protect_file(mut self, path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        self.exact.push(std::fs::canonicalize(path).map_err(|err| {
            format!(
                "failed to canonicalize protected {} input {}: {err}",
                self.label,
                path.display()
            )
        })?);
        Ok(self)
    }

    pub(crate) fn protect_files<'a>(
        mut self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        for path in paths {
            self = self.protect_file(path)?;
        }
        Ok(self)
    }

    pub(crate) fn protect_tree(mut self, path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        self.trees.push(std::fs::canonicalize(path).map_err(|err| {
            format!(
                "failed to canonicalize protected {} tree {}: {err}",
                self.label,
                path.display()
            )
        })?);
        Ok(self)
    }

    pub(crate) fn ensure_output(
        &self,
        output_path: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let normalized_output = normalized_output_path(output_path)?;
        if let Some(input) = self.exact.iter().find(|input| **input == normalized_output) {
            return Err(format!(
                "{} output aliases protected input: {}",
                self.label,
                input.display()
            )
            .into());
        }
        if let Some(root) = self
            .trees
            .iter()
            .find(|root| normalized_output == **root || normalized_output.starts_with(root))
        {
            return Err(format!(
                "{} output lies inside protected evidence: {}",
                self.label,
                root.display()
            )
            .into());
        }
        Ok(normalized_output)
    }
}

pub(crate) fn normalized_output_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(std::fs::canonicalize(path)?);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("output path has no file name: {}", path.display()))?;
    Ok(canonical_parent.join(file_name))
}

pub(crate) fn ensure_output_disjoint_from_inputs(
    output_path: &Path,
    protected_inputs: &[&Path],
    protected_root: Option<&Path>,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = ProtectedPathSet::new(label).protect_files(protected_inputs.iter().copied())?;
    if let Some(root) = protected_root {
        paths = paths.protect_tree(root)?;
    }
    paths.ensure_output(output_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "xenia-consent-artifact-paths-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_exact_input_alias() {
        let dir = TestDir::new();
        let input = dir.0.join("input.json");
        fs::write(&input, b"evidence").unwrap();
        let protected = ProtectedPathSet::new("test").protect_file(&input).unwrap();
        assert!(protected.ensure_output(&input).is_err());
    }

    #[test]
    fn rejects_output_inside_protected_tree() {
        let dir = TestDir::new();
        let evidence = dir.0.join("rollback-package");
        fs::create_dir(&evidence).unwrap();
        let protected = ProtectedPathSet::new("test")
            .protect_tree(&evidence)
            .unwrap();
        assert!(
            protected
                .ensure_output(&evidence.join("replacement.json"))
                .is_err()
        );
    }

    #[test]
    fn allows_sibling_output() {
        let dir = TestDir::new();
        let input = dir.0.join("input.json");
        fs::write(&input, b"evidence").unwrap();
        let output = dir.0.join("output.json");
        let protected = ProtectedPathSet::new("test").protect_file(&input).unwrap();
        assert_eq!(protected.ensure_output(&output).unwrap(), output);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_alias_of_protected_input() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        let input = dir.0.join("input.json");
        let alias = dir.0.join("alias.json");
        fs::write(&input, b"evidence").unwrap();
        symlink(&input, &alias).unwrap();
        let protected = ProtectedPathSet::new("test").protect_file(&input).unwrap();
        assert!(protected.ensure_output(&alias).is_err());
    }
}
