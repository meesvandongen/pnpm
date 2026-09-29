//! Paths as the Windows file calls name them, turned into the absolute DOS
//! paths pnpm compares with its workspace. Other platforms build it only
//! for its tests.

/// `path` as an absolute DOS path, or `None` when it names no file system
/// location pnpm can compare. The NT and long-path prefixes go (`\??\C:\a`
/// and `\\?\C:\a` become `C:\a`, the `UNC` forms `\\server\share`), a bare
/// drive (`\??\C:`, the volume) becomes its root, and what remains must be
/// a drive or UNC path. Device names (`\??\pipe\…`, `\Device\…`) are not in
/// any workspace.
pub(crate) fn dos_path(path: &[u16]) -> Option<Vec<u16>> {
    for prefix in [r"\??\UNC\", r"\\?\UNC\"] {
        if let Some(rest) = strip(path, prefix) {
            let mut unc: Vec<u16> = r"\\".encode_utf16().collect();
            unc.extend_from_slice(rest);
            return Some(unc);
        }
    }
    let path = [r"\??\", r"\\?\"]
        .into_iter()
        .find_map(|prefix| strip(path, prefix))
        .unwrap_or(path);
    if path.len() == 2 && is_drive(path) {
        let mut root = path.to_vec();
        root.push(u16::from(b'\\'));
        return Some(root);
    }
    let is_drive_path = path.len() >= 3 && is_drive(&path[..2]) && is_separator(path[2]);
    let is_unc = path.len() >= 2 && is_separator(path[0]) && is_separator(path[1]);
    (is_drive_path || is_unc).then(|| path.to_vec())
}

/// Whether `units` are a drive letter and a colon.
fn is_drive(units: &[u16]) -> bool {
    matches!(units, [letter, colon]
        if *colon == u16::from(b':')
            && u8::try_from(*letter).is_ok_and(|letter| letter.is_ascii_alphabetic()))
}

fn strip<'a>(path: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let prefix: Vec<u16> = prefix.encode_utf16().collect();
    path.strip_prefix(prefix.as_slice())
}

fn is_separator(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == u16::from(b'/')
}

#[cfg(test)]
mod tests;
