use super::dos_path;

fn dos(path: &str) -> Option<String> {
    let units: Vec<u16> = path.encode_utf16().collect();
    dos_path(&units).map(|units| String::from_utf16(&units).unwrap())
}

#[test]
fn prefixes_are_removed_from_absolute_paths() {
    assert_eq!(dos(r"\??\C:\work\a.txt").as_deref(), Some(r"C:\work\a.txt"));
    assert_eq!(dos(r"\\?\C:\work\a.txt").as_deref(), Some(r"C:\work\a.txt"));
    assert_eq!(dos(r"C:\work\a.txt").as_deref(), Some(r"C:\work\a.txt"));
    assert_eq!(dos(r"C:/work/a.txt").as_deref(), Some(r"C:/work/a.txt"));
}

#[test]
fn unc_paths_keep_their_server_and_share() {
    assert_eq!(dos(r"\??\UNC\server\share\a").as_deref(), Some(r"\\server\share\a"));
    assert_eq!(dos(r"\\?\UNC\server\share\a").as_deref(), Some(r"\\server\share\a"));
    assert_eq!(dos(r"\\server\share\a").as_deref(), Some(r"\\server\share\a"));
}

#[test]
fn a_bare_drive_is_its_root() {
    // A drive-relative `D:` would resolve against each process's own
    // current directory.
    assert_eq!(dos(r"\??\D:").as_deref(), Some(r"D:\"));
    assert_eq!(dos(r"\\?\D:").as_deref(), Some(r"D:\"));
    assert_eq!(dos("D:").as_deref(), Some(r"D:\"));
    assert_eq!(dos(r"\??\D:\").as_deref(), Some(r"D:\"));
}

#[test]
fn names_that_are_not_file_system_paths_are_none() {
    for path in [
        r"\??\pipe\name",
        r"\??\Volume{1234}\a",
        r"\??\nul",
        r"\Device\HarddiskVolume1\a",
        r"D:relative",
        r"relative\a.txt",
        "",
    ] {
        assert_eq!(dos(path), None, "{path}");
    }
}
