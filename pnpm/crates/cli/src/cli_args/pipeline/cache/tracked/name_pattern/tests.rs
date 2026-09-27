use super::matches;

#[test]
fn star_and_question_mark_match_any_characters() {
    assert!(matches("*", "anything.txt"));
    assert!(matches("*.log", "local.log"));
    assert!(!matches("*.log", "local.txt"));
    assert!(matches("a?c", "abc"));
    assert!(!matches("a?c", "ac"));
}

#[test]
fn names_match_without_regard_to_case() {
    assert!(matches("README.md", "readme.MD"));
    assert!(matches("*.TXT", "notes.txt"));
}

#[test]
fn dos_dot_matches_a_period_or_the_end_of_the_name() {
    // `FindFirstFileW("node.*")` asks for `node"*`.
    for name in ["node", "node.exe", "NODE.CMD", "node."] {
        assert!(matches("node\"*", name), "{name}");
    }
    for name in ["nodes", "node-gyp.cmd", "xnode"] {
        assert!(!matches("node\"*", name), "{name}");
    }
}

#[test]
fn dos_star_stops_at_the_last_period() {
    // `FindFirstFileW("*.txt")` asks for `<.txt`.
    assert!(matches("<.txt", "a.b.txt"));
    assert!(matches("<.txt", ".txt"));
    assert!(!matches("<.txt", "a.txt.bak"));
    assert!(matches("a<", "abc"));
}

#[test]
fn dos_question_mark_matches_nothing_at_a_period_or_the_end() {
    // `FindFirstFileW("??.txt")` asks for `>>.txt`.
    assert!(matches(">>.txt", "ab.txt"));
    assert!(matches(">>.txt", "a.txt"));
    assert!(!matches(">>.txt", "abc.txt"));
    assert!(matches("ab>>", "ab"));
}
