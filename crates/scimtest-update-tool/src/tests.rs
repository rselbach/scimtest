use super::*;
use ed25519_dalek::Signature;

fn invoke(arguments: &[String], seed: u8) -> Result<()> {
    let command = Cli::try_parse_from(arguments)?.command;
    let pinned = STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    run(command, STANDARD.encode([seed; 32]).as_bytes(), &pinned)
}

#[test]
fn signed_feed_opens_and_wrong_keys_or_metadata_leave_no_output() {
    let temporary = tempfile::tempdir().unwrap();
    let archive = temporary.path().join("scimtest.zip");
    let notes = temporary.path().join("notes.md");
    let output = temporary.path().join("update.json");
    fs::write(&archive, b"Greendale Community College").unwrap();
    fs::write(&notes, "# Changes\n\n- **Troy Barnes**\n* `Abed Nadir`\n").unwrap();
    let arguments = vec![
        "scimtest-update-tool".into(),
        "sign-feed".into(),
        "--version".into(),
        "2.7.0".into(),
        "--build".into(),
        "42".into(),
        "--published-at".into(),
        "2026-11-03T12:00:00Z".into(),
        "--notes".into(),
        notes.to_str().unwrap().into(),
        "--artifact".into(),
        format!(
            "macos,arm64,app-zip,26.0,{},https://github.com/rselbach/scimtest/releases/download/v2.7.0/scimtest.zip",
            archive.display()
        ),
        "--out".into(),
        output.to_str().unwrap().into(),
    ];
    assert!(
        invoke(&arguments, 9)
            .unwrap_err()
            .to_string()
            .contains("pinned public key")
    );
    assert!(!output.exists());
    invoke(&arguments, 7).unwrap();
    let pinned = STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    let release = update::verify_feed(&fs::read(&output).unwrap(), &pinned).unwrap();
    assert_eq!(release.version, "2.7.0");
    assert_eq!(release.build, 42);
    assert_eq!(release.highlights, ["Troy Barnes", "Abed Nadir"]);
    assert_eq!(release.artifacts[0].size, 27);
    assert_eq!(
        release.artifacts[0].sha256,
        format!("{:x}", Sha256::digest(b"Greendale Community College"))
    );
    fs::remove_file(&output).unwrap();
    let mut invalid = arguments.clone();
    let build = invalid.iter().position(|arg| arg == "42").unwrap();
    invalid[build] = "0".into();
    assert!(invoke(&invalid, 7).is_err());
    assert!(!output.exists());
}

#[test]
fn appcast_signs_the_archive_bytes_and_keeps_the_bundle_public_key() {
    let temporary = tempfile::tempdir().unwrap();
    let archive = temporary.path().join("scimtest.zip");
    let output = temporary.path().join("appcast.xml");
    let bytes = b"Greendale Community College";
    fs::write(&archive, bytes).unwrap();
    let arguments = vec![
        "scimtest-update-tool".into(),
        "appcast".into(),
        "--version".into(),
        "2.7.0".into(),
        "--build".into(),
        "42".into(),
        "--minimum-os".into(),
        "26.0".into(),
        "--published-at".into(),
        "2026-11-03T12:00:00Z".into(),
        "--archive".into(),
        archive.to_str().unwrap().into(),
        "--url".into(),
        "https://github.com/rselbach/scimtest/releases/download/v2.7.0/scimtest.zip".into(),
        "--out".into(),
        output.to_str().unwrap().into(),
    ];
    invoke(&arguments, 7).unwrap();
    let xml = fs::read_to_string(output).unwrap();
    let encoded = xml
        .split("sparkle:edSignature=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let signature = Signature::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    public.verify_strict(bytes, &signature).unwrap();
    assert!(public.verify_strict(b"City College", &signature).is_err());
    assert!(xml.contains("Tue, 03 Nov 2026 12:00:00 +0000"));
    assert!(xml.contains("<sparkle:version>42</sparkle:version>"));
    assert!(include_str!("../../../packaging/macos/Info.plist").contains(update::PUBLIC_KEY));
}
