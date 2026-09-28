use super::{AutoTracking, TaskFilePattern, TaskFiles};
use crate::TaskSettings;
use pretty_assertions::assert_eq;

fn task(yaml: &str) -> TaskSettings {
    serde_saphyr::from_str(yaml).expect("parse the task settings")
}

#[test]
fn entries_are_globs_or_the_auto_marker() {
    let settings = task("inputs: [{ auto: true }, '!dist/**', 'src/**']\noutputs: ['dist/**']\n");
    assert_eq!(
        settings.inputs,
        Some(vec![
            TaskFilePattern::Auto(AutoTracking { auto: true }),
            TaskFilePattern::Glob("!dist/**".to_string()),
            TaskFilePattern::Glob("src/**".to_string()),
        ]),
    );
    assert_eq!(
        settings.input_files(),
        Some(TaskFiles { auto: true, globs: vec!["src/**"], exclusions: vec!["dist/**"] }),
    );
    assert_eq!(
        settings.output_files(),
        Some(TaskFiles { auto: false, globs: vec!["dist/**"], exclusions: Vec::new() }),
    );
}

#[test]
fn auto_false_tracks_nothing() {
    let settings = task("outputs: [{ auto: false }]\n");
    assert_eq!(settings.output_files(), Some(TaskFiles::default()));
    assert_eq!(settings.input_files(), None);
}

#[test]
fn an_unknown_object_entry_is_rejected() {
    assert!(serde_saphyr::from_str::<TaskSettings>("inputs: [{ track: true }]\n").is_err());
}
