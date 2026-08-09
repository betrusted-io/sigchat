//! Smoke test: open a sync TLS connection to example.com, send a
//! minimal HTTP/1.1 GET, print the status line.

use std::io::{Read, Write};

use xous_net_bridge::{tls_connect, webpki_roots};

fn main() -> std::io::Result<()> {
    let mut stream = tls_connect("example.com", 443, webpki_roots(), &[])?;

    stream.write_all(
        b"GET / HTTP/1.1\r\n\
          Host: example.com\r\n\
          Connection: close\r\n\
          \r\n",
    )?;
    stream.flush()?;

    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf)?;

    // First line is the status line.
    let status_line = buf
        .split(|&b| b == b'\n')
        .next()
        .map(|s| String::from_utf8_lossy(s).trim_end_matches('\r').to_string())
        .unwrap_or_default();

    println!("{status_line}");
    Ok(())
}
