use super::*;

#[tokio::test]
async fn authenticated_limit_change_preserves_a_pipelined_buffered_frame() {
    let (server, client) = tokio::io::duplex(512 << 10);
    let config = WebSocketConfig::default()
        .max_message_size(Some(REGISTRATION_LIMIT))
        .max_frame_size(Some(REGISTRATION_LIMIT));
    let mut server = WebSocketStream::from_raw_socket(server, Role::Server, Some(config)).await;
    let mut client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    client
        .send(tungstenite::Message::Text(
            "Greendale authentication".into(),
        ))
        .await
        .unwrap();
    let large = "Troy and Abed ".repeat(10_000);
    client
        .send(tungstenite::Message::Text(large.clone().into()))
        .await
        .unwrap();
    assert_eq!(
        server.next().await.unwrap().unwrap().into_text().unwrap(),
        "Greendale authentication"
    );
    server.set_config(|config| {
        config.max_message_size = Some(512 << 10);
        config.max_frame_size = Some(512 << 10);
    });
    assert_eq!(
        server.next().await.unwrap().unwrap().into_text().unwrap(),
        large
    );
}

#[tokio::test]
async fn unauthenticated_frame_keeps_the_small_limit() {
    let (server, client) = tokio::io::duplex(512 << 10);
    let config = WebSocketConfig::default()
        .max_message_size(Some(REGISTRATION_LIMIT))
        .max_frame_size(Some(REGISTRATION_LIMIT));
    let mut server = WebSocketStream::from_raw_socket(server, Role::Server, Some(config)).await;
    let mut client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    client
        .send(tungstenite::Message::Text(
            "Greendale ".repeat(10_000).into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        server.next().await.unwrap(),
        Err(tungstenite::Error::Capacity(_))
    ));
}

#[test]
fn registration_guards_bound_global_and_per_network_capacity() {
    let pool = Arc::new(RegistrationPool::default());
    let mut slots = Vec::new();
    for network in 0..16 {
        for _ in 0..8 {
            slots.push(pool.acquire(format!("greendale-{network}")).unwrap());
        }
        assert!(pool.acquire(format!("greendale-{network}")).is_none());
    }
    assert!(pool.acquire("troy-new-network".into()).is_none());
    slots.pop();
    assert!(pool.acquire("troy-new-network".into()).is_some());
    drop(slots);
    assert!(lock(&pool.counts).is_empty());
}
