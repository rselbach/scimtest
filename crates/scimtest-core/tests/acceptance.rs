#[test]
fn shared_acceptance_scenarios_pass_against_go_and_rust() {
    let output = std::process::Command::new("go")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .args([
            "test",
            "./internal/web",
            "-run",
            "^(TestAPIAcceptance|TestRustAPIAcceptance|TestSharedIdentityAcceptance|TestSharedTunnelAcceptance)",
            "-count=1",
            "-timeout=180s",
            "-v",
        ])
        .env(
            "SCIMTEST_ACCEPTANCE_RUST_BIN",
            env!("CARGO_BIN_EXE_scimtest-rust"),
        )
        .env("SCIMTEST_ACCEPTANCE_RUST_TUNNEL_FIXTURE", std::env::current_exe().expect("locate the test fixture executable"))
        .output()
        .expect("run the shared Go/Rust acceptance suite");
    assert!(
        output.status.success(),
        "Go/Rust shared acceptance failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "subprocess fixture for the shared Go/Rust tunnel acceptance suite"]
async fn serve_tunnel_acceptance_fixture() {
    use scimtest_core::{
        runtime::{Options, Runtime},
        tunnel::Config,
    };
    let state_file = std::env::var_os("SCIMTEST_TUNNEL_ACCEPTANCE_STATE")
        .expect("shared fixture requires disposable state");
    let server = std::env::var("SCIMTEST_TUNNEL_ACCEPTANCE_SERVER")
        .expect("shared fixture requires a local tunnel server");
    let runtime = Runtime::start_with_profile(
        Options {
            state_file: Some(state_file.into()),
            port: 0,
            no_open: true,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
        Some(Config {
            server_base_url: server,
            application_profile_id: "0123456789abcdef0123456789abcdef".into(),
            require_account: true,
        }),
    )
    .expect("start disposable tunnel runtime");
    scimtest_core::runtime::wait_for_termination()
        .await
        .expect("wait for fixture shutdown");
    runtime
        .shutdown()
        .await
        .expect("shut down disposable tunnel runtime");
}
