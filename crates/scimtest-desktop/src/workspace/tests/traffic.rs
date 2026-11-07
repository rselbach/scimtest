use std::net::SocketAddr;

use scimtest_core::configuration::SettingsPatch;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{scim::serve, *};

/// The Traffic page of an OIDC environment whose protocol endpoints are served locally.
struct Traffic {
    fixture: Fixture,
    address: SocketAddr,
    slug: String,
}

impl Traffic {
    fn new() -> Self {
        let mut fixture = Fixture::new();
        let id = fixture.state().selected.clone().expect("an environment");
        let environment = fixture
            .store
            .update_environment(
                &id,
                EnvironmentPatch {
                    settings: SettingsPatch {
                        oidc_enabled: Some(true),
                        oidc_client_id: Some("greendale".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .expect("enable OIDC");
        let (store, identity) = (fixture.store.clone(), fixture.state().identity.clone());
        let address = serve(&fixture, |address| {
            scimtest_core::api::router_with_identity(
                store,
                "greendale-instance".into(),
                address.to_string(),
                identity,
            )
        });
        fixture.click("nav-Traffic");
        fixture.wait("the traffic", |state| !state.traffic.refreshing);
        Self {
            fixture,
            address,
            slug: environment.slug,
        }
    }

    /// Fetches the environment's OIDC discovery document, as a relying party would.
    fn discover(&self) {
        let address = self.address;
        let request = format!(
            "GET /oidc/{}/.well-known/openid-configuration HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
            self.slug
        );
        let response = self.fixture.state().executor.block_on(async move {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect to the protocol endpoints");
            stream
                .write_all(request.as_bytes())
                .await
                .expect("send the request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read the response");
            response
        });
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
}

#[test]
fn recording_lists_oidc_exchanges_and_clearing_empties_the_list() {
    let mut traffic = Traffic::new();
    assert!(traffic.fixture.has("traffic-empty"));
    assert!(!traffic.fixture.state().traffic.snapshot.record);
    traffic.discover();
    traffic.fixture.land();
    assert!(
        traffic.fixture.state().traffic.snapshot.entries.is_empty(),
        "nothing is kept until recording starts"
    );
    traffic.fixture.click("record");
    assert_eq!(traffic.fixture.state().message, "Traffic settings updated");
    traffic
        .fixture
        .wait("recording", |state| state.traffic.snapshot.record);
    traffic.discover();
    traffic.fixture.wait("the exchange", |state| {
        state.traffic.snapshot.entries.len() == 1
    });
    assert!(traffic.fixture.has("traffic-entry-0"));
    let transcript = traffic.fixture.text("transcript").expect("a transcript");
    assert!(
        transcript.contains(&format!(
            "GET /oidc/{}/.well-known/openid-configuration",
            traffic.slug
        )),
        "{transcript}"
    );
    traffic.fixture.click("clear-traffic");
    assert_eq!(traffic.fixture.state().message, "Traffic cleared");
    traffic.fixture.wait("the clear", |state| {
        !state.traffic.refreshing && state.traffic.snapshot.entries.is_empty()
    });
    assert!(traffic.fixture.has("traffic-empty"));
}

#[test]
fn the_selected_exchange_stays_selected_as_new_ones_arrive() {
    let mut traffic = Traffic::new();
    traffic.fixture.click("record");
    traffic
        .fixture
        .wait("recording", |state| state.traffic.snapshot.record);
    traffic.discover();
    traffic.discover();
    traffic.fixture.wait("two exchanges", |state| {
        !state.traffic.refreshing && state.traffic.snapshot.entries.len() == 2
    });
    traffic.fixture.click("traffic-entry-1");
    assert_eq!(traffic.fixture.state().traffic.selected, 1);
    let selected = traffic.fixture.state().traffic.snapshot.entries[1].clone();
    traffic.discover();
    traffic.fixture.wait("a third exchange", |state| {
        !state.traffic.refreshing && state.traffic.snapshot.entries.len() == 3
    });
    let state = traffic.fixture.state();
    assert_eq!(state.traffic.selected, 2, "newest first pushes it down");
    assert_eq!(state.traffic.snapshot.entries[2], selected);
}

#[test]
fn raw_secrets_need_recording_first() {
    let mut traffic = Traffic::new();
    traffic.fixture.click("secrets");
    assert!(!traffic.fixture.state().traffic.snapshot.record_secrets);
    traffic.fixture.click("record");
    traffic
        .fixture
        .wait("recording", |state| state.traffic.snapshot.record);
    traffic.fixture.click("secrets");
    traffic.fixture.wait("secret recording", |state| {
        state.traffic.snapshot.record_secrets
    });
    traffic.fixture.click("record");
    traffic.fixture.wait("recording to stop", |state| {
        !state.traffic.refreshing && !state.traffic.snapshot.record
    });
    assert!(
        !traffic.fixture.state().traffic.snapshot.record_secrets,
        "stopping recording also stops recording secrets"
    );
}
