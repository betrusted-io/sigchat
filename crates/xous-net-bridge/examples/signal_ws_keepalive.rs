//! Smoke test: open a WSS connection to Signal's unauth provisioning
//! endpoint, prove the handshake succeeds, then close.
//!
//! Endpoint is `/v1/websocket/provisioning/` (the WS upgrade target used
//! by `libsignal-service-rs/src/provisioning/mod.rs:163-170`'s
//! `link_device` flow). Auth-required paths (`/v1/websocket/`) reject
//! without credentials; the provisioning channel is unauth.
//!
//! We don't drive the in-WS Signal protocol here — we just confirm the
//! handshake completes (101 Switching Protocols), wait briefly for any
//! server-pushed frame (or timeout), and close. That's enough to prove
//! tungstenite + rustls + our `tls_connect` can speak to chat.signal.org.

use std::time::Duration;

use tungstenite::Message;
use tungstenite::protocol::CloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;
use xous_net_bridge::{signal_production_roots, ws_connect};

fn main() -> std::io::Result<()> {
    let (mut ws, resp) =
        ws_connect("chat.signal.org", 443, "/v1/websocket/provisioning/", signal_production_roots())?;
    println!("handshake: {}", resp.status());

    // Set a read timeout on the underlying TcpStream so the read below
    // doesn't block indefinitely if the server has nothing to push yet.
    ws.get_mut().get_ref().set_read_timeout(Some(Duration::from_secs(5))).ok();

    match ws.read() {
        Ok(Message::Ping(_)) => println!("got: server ping"),
        Ok(Message::Pong(_)) => println!("got: server pong"),
        Ok(Message::Binary(b)) => println!("got: binary frame ({} bytes)", b.len()),
        Ok(Message::Text(t)) => println!("got: text frame ({} chars)", t.chars().count()),
        Ok(Message::Close(_)) => println!("got: server close"),
        Ok(Message::Frame(_)) => println!("got: raw frame"),
        Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
            println!("idle: server didn't push within 5s (expected for unauth)");
        }
        Err(e) => println!("read error: {e}"),
    }

    let _ = ws.close(Some(CloseFrame { code: CloseCode::Normal, reason: "stage 3 smoke test done".into() }));
    println!("closed");
    Ok(())
}
