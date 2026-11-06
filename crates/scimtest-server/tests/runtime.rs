mod support;

use reqwest::{Client, StatusCode};
use serde_json::json;
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use support::{GoFixture, public_key};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cli_reads_go_state_and_restarts_on_the_same_port_after_sigterm() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.json");
    GoFixture::new().run(json!({"kind":"seed","path":path,"settings":{"name":"Greendale Community College","public_key":public_key(42),"routes":[{"methods":["GET"],"path":"/oidc/{slug}/jwks"}],"requests_per_minute":60,"request_burst":10,"concurrent_requests":4}}));
    let before = std::fs::read(&path).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let client = Client::builder().no_proxy().build().unwrap();
    for run in 0..2 {
        let log =
            std::fs::File::create(directory.path().join(format!("server-{run}.log"))).unwrap();
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_scimtest-server"))
                .args([
                    "-addr",
                    &address.to_string(),
                    "-domain",
                    "localhost",
                    "-dashboard-domain",
                    "admin.localhost",
                    "-data",
                ])
                .arg(&path)
                .args([
                    "-logs=false",
                    "-log-format=invalid-but-disabled",
                    "-max-body=-1",
                ])
                .env_remove("SCIMTEST_GITHUB_CLIENT_ID")
                .env_remove("SCIMTEST_GITHUB_CLIENT_SECRET")
                .stdout(Stdio::null())
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "server exited before readiness"
                );
                if let Ok(response) = client.get(format!("http://{address}/ready")).send().await
                    && response.status() == StatusCode::OK
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let response = client
            .get(format!("http://{address}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap(),
            json!({"status":"ok"})
        );
        assert!(
            Command::new("kill")
                .args(["-TERM", &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            std::net::TcpStream::connect(address).is_err(),
            "listener must close"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "starting and stopping must preserve Go state"
        );
    }
}
