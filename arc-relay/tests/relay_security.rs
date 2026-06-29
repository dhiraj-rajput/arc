mod support;

use std::thread;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use support::{InProcessRelay, relay_url};

async fn relay_ws_url() -> String {
    let relay = InProcessRelay::new();
    relay_url(relay.start("127.0.0.1:0").await)
}

async fn join_room(ws_url: &str, room_id: &str) -> bool {
    let (ws_stream, _) = connect_async(ws_url).await.unwrap();
    let (mut write, mut read) = ws_stream.split();
    let join_msg = serde_json::json!({
        "type": "join",
        "room_id": room_id,
        "max_members": 2
    });
    write
        .send(Message::Text(join_msg.to_string().into()))
        .await
        .unwrap();
    while let Some(Ok(Message::Text(text))) = read.next().await {
        if text.contains("joined") || text.contains("member_count") {
            return true;
        }
        if text.contains("full") || text.contains("error") {
            return false;
        }
    }
    false
}

#[tokio::test]
async fn test_relay_rejects_third_member() {
    let ws_url = relay_ws_url().await;
    let room_id = "a".repeat(64);

    assert!(join_room(&ws_url, &room_id).await);
    assert!(join_room(&ws_url, &room_id).await);
    assert!(!join_room(&ws_url, &room_id).await);
}

#[test]
fn test_relay_malformed_message_does_not_panic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ws_url = rt.block_on(relay_ws_url());

    let handle = thread::spawn(move || {
        rt.block_on(async {
            let (ws_stream, _) = connect_async(&ws_url).await.unwrap();
            let (mut write, _read) = ws_stream.split();
            write.send(Message::Text("not-json".into())).await.unwrap();
        });
    });
    handle.join().unwrap();
}

#[test]
fn test_relay_accepts_websocket_connection() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ws_url = rt.block_on(relay_ws_url());
    rt.block_on(async {
        let result = connect_async(&ws_url).await;
        assert!(result.is_ok());
    });
}
