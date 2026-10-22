use std::{fs, path::Path};

use ramsi_com::{ScanStatus, Scanner, ScriptType};

fn assert_samples(dir: &str, expected: ScanStatus) {
    let scanner = Scanner::default();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(dir);
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let script = fs::read_to_string(&path).unwrap();
        let result = scanner.scan(&script, ScriptType::PsScript);
        assert_eq!(result.status, expected, "{}: {result:?}", path.display());
        count += 1;
    }
    assert!(count > 0, "no samples in {}", dir.display());
}

#[test]
fn benign_samples_are_not_detected() {
    assert_samples("benign", ScanStatus::NotDetected);
}

#[test]
fn suspicious_samples_are_suspicious() {
    assert_samples("suspicious", ScanStatus::Suspicious);
}

#[test]
fn detected_samples_are_detected() {
    assert_samples("detected", ScanStatus::Detected);
}
