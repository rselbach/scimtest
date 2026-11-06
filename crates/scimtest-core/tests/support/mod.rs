use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub fn bridge(operation: &str, path: &Path) -> Vec<u8> {
    bridge_input(operation, path, &[])
}

pub fn bridge_input(operation: &str, path: &Path, input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("go")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["run", "./tests/fixtures/statebridge", operation])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Go is required for the shared state compatibility check");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
