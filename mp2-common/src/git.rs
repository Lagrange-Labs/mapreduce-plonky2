use git_version::git_version;

/// The full git version of mapreduce-plonky2
///
/// `git` is required when compiling. This is the string returned from the command
/// `git describe --abbrev=7 --always`, e.g. `v1.1.1-8-g77fa458`.
pub const GIT_VERSION: &str = git_version!(args = ["--abbrev=7", "--always"]);

/// Get the short git version of mapreduce-plonky2.
///
/// Return `77fa458` if the full git version is `v1.1.1-8-g77fa458`.
pub fn short_git_version() -> String {
    let commit_version = GIT_VERSION.split('-').last().unwrap();

    // Check if use commit object as fallback.
    if commit_version.len() < 8 {
        commit_version.to_string()
    } else {
        commit_version[1..8].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_git_version() {
        let v = short_git_version();

        assert_eq!(v.len(), 7);
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
