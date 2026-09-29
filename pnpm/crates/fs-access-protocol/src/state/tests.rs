use super::PathState;
use std::fs;

#[test]
fn a_state_survives_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file.txt");
    fs::write(&file, "contents").unwrap();
    for path in [file, dir.path().to_path_buf(), dir.path().join("missing")] {
        let state = PathState::of(&path);
        let mut bytes = [0u8; PathState::ENCODED_LEN];
        state.encode(&mut bytes);
        assert_eq!(PathState::decode(&bytes), Some(state), "{}", path.display());
    }
}

#[test]
fn a_rewritten_file_has_a_different_state() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file.txt");
    fs::write(&file, "old").unwrap();
    let before = PathState::of(&file);
    assert_eq!(before, PathState::of(&file));
    fs::write(&file, "new contents").unwrap();
    let after = PathState::of(&file);
    assert_ne!(before, after);
    assert!(before.same_entry(&after));
    assert!(!before.same_entry(&PathState::of(&dir.path().join("missing"))));
}
