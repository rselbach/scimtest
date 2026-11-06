use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{cell::Cell, path::PathBuf, process::Command};

pub struct GoFixture {
    directory: tempfile::TempDir,
    pub binary: PathBuf,
    next: Cell<usize>,
}

impl GoFixture {
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("server-contract.test");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = Command::new("go")
            .current_dir(root)
            .args(["test", "-mod=readonly", "-c", "-o"])
            .arg(&binary)
            .arg("./internal/server")
            .output()
            .expect("Go is required for hosted-service compatibility tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            directory,
            binary,
            next: Cell::new(0),
        }
    }

    pub fn run(&self, input: Value) -> Value {
        let index = self.next.get();
        self.next.set(index + 1);
        let request = self.directory.path().join(format!("request-{index}.json"));
        let response = self.directory.path().join(format!("response-{index}.json"));
        std::fs::write(&request, serde_json::to_vec(&input).unwrap()).unwrap();
        let output = Command::new(&self.binary)
            .arg("-test.run=^TestRustHostedContractFixture$")
            .env("SCIMTEST_RUST_HOSTED_CONTRACT", request)
            .env("SCIMTEST_RUST_HOSTED_RESULT", &response)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&std::fs::read(response).unwrap()).unwrap()
    }
}

pub fn public_key(seed: u8) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    let mut blob = Vec::from(11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(key.as_bytes());
    format!("ssh-ed25519 {}", STANDARD.encode(blob))
}
