//! What each kind of access observed of an input, recomputed the same way
//! on every run.

use super::{Access, name_pattern};
use crate::cli_args::pipeline::cache::{
    create_hex_hash, create_hex_hash_bytes, create_hex_hash_from_file,
};
use std::{fs, io, path::Path};

/// What `access` observed of `path`, recomputed the same way on every run.
pub(super) fn fingerprint(path: &Path, access: Access) -> String {
    if access == Access::Match {
        return matching_entries(path);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if is_missing(&error) => return "missing".to_string(),
        Err(error) => return format!("unreadable:{:?}", error.kind()),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return fs::read_link(path)
            .map_or_else(
                |_| "symlink".to_string(),
                |target| {
                    format!(
                        "symlink:{}",
                        create_hex_hash_bytes(target.as_os_str().as_encoded_bytes())
                    )
                },
            );
    }
    match (access, file_type.is_file(), file_type.is_dir()) {
        (Access::Read, true, _) => create_hex_hash_from_file(path)
            .map_or_else(|_| "unreadable".to_string(), |hash| format!("file:{hash}")),
        (Access::List, _, true) => format!("dir:{}", listing_hash(path, |_| true)),
        (_, true, _) => "file".to_string(),
        (_, _, true) => "dir".to_string(),
        _ => "other".to_string(),
    }
}

/// The fingerprint of the entries matching the pattern that ends
/// `pattern_path`, in the directory it names.
fn matching_entries(pattern_path: &Path) -> String {
    let (Some(dir), Some(pattern)) = (pattern_path.parent(), pattern_path.file_name()) else {
        return "other".to_string();
    };
    let pattern = pattern.to_string_lossy();
    match fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {
            format!("dir:{}", listing_hash(dir, |name| name_pattern::matches(&pattern, name)))
        }
        Ok(_) => "other".to_string(),
        Err(error) if is_missing(&error) => "missing".to_string(),
        Err(error) => format!("unreadable:{:?}", error.kind()),
    }
}

fn listing_hash(dir: &Path, include: impl Fn(&str) -> bool) -> String {
    let Ok(entries) = fs::read_dir(dir) else { return "unreadable".to_string() };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| include(&entry.file_name().to_string_lossy()))
        .map(|entry| {
            let kind = entry
                .file_type()
                .map_or('?', |kind| if kind.is_dir() { 'd' } else { 'f' });
            format!("{}{kind}", entry.file_name().to_string_lossy())
        })
        .collect();
    names.sort();
    create_hex_hash(&names.join("\0"))
}

fn is_missing(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}
