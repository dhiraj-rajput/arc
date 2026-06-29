mod support;

use std::thread;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use support::{InProcessRelay, relay_url};

async fn relay_ws_url() -> String {
    let relay = InProcessRelay::new();
    relay_url(relay.start("127.0.0.1:0").await)
}

async fn join_room(
    ws_url: &str,
    room_id: &str,
) -> Option<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let (mut ws_stream, _) = connect_async(ws_url).await.unwrap();
    let join_msg = serde_json::json!({
        "type": "join",
        "room_id": room_id,
        "max_members": 2
    });
    ws_stream
        .send(Message::Text(join_msg.to_string().into()))
        .await
        .unwrap();
    while let Some(msg_res) = ws_stream.next().await {
        if let Ok(Message::Text(text)) = msg_res {
            if text.contains("joined") || text.contains("member_count") {
                return Some(ws_stream);
            }
            if text.contains("full") || text.contains("error") {
                return None;
            }
        }
    }
    None
}

#[tokio::test]
async fn test_relay_rejects_third_member() {
    let ws_url = relay_ws_url().await;
    let room_id = "a".repeat(64);

    let client1 = join_room(&ws_url, &room_id).await;
    assert!(client1.is_some());

    let client2 = join_room(&ws_url, &room_id).await;
    assert!(client2.is_some());

    let client3 = join_room(&ws_url, &room_id).await;
    assert!(client3.is_none());
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
