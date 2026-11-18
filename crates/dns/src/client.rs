//! A tiny DNS client for verification (#31): query a nameserver for TXT records
//! over **TCP** (a length-prefixed DNS message), reusing the codec. Used by the
//! deSEC self-test to confirm a challenge is actually live at `ns1.desec.io`,
//! independent of global propagation.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message;

/// #997: bounds the whole exchange below (connect + write + both reads). A
/// nameserver that accepts the connection and never answers, or a filtered
/// outbound :53 that silently drops packets, otherwise blocks indefinitely --
/// the selftest's retry loop (main.rs) never advances and never cleans up its
/// published test record while it hangs.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Query `server` (`host:port`, e.g. `ns1.desec.io:53`) for the TXT records at
/// `name`, over TCP. Returns the TXT values (empty if none).
pub async fn query_txt(server: &str, name: &str) -> std::io::Result<Vec<String>> {
    tokio::time::timeout(QUERY_TIMEOUT, query_txt_inner(server, name))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS TXT query over TCP timed out"))?
}

async fn query_txt_inner(server: &str, name: &str) -> std::io::Result<Vec<String>> {
    let query = message::build_query(0x1234, name, message::TYPE_TXT);
    let mut stream = tokio::net::TcpStream::connect(server).await?;
    // TCP DNS frames are prefixed with a 2-byte big-endian length.
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await?;

    let mut lenb = [0u8; 2];
    stream.read_exact(&mut lenb).await?;
    let n = u16::from_be_bytes(lenb) as usize;
    let mut resp = vec![0u8; n];
    stream.read_exact(&mut resp).await?;
    Ok(message::parse_txt_answers(&resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AcmeDnsStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn query_txt_reads_txt_records_over_tcp() {
        // Serve with our own :53 responder (AD2) and query it back with the client.
        let store = Arc::new(AcmeDnsStore::new());
        store.add_txt("_acme-challenge.host.test", "tok-1");
        store.add_txt("_acme-challenge.host.test", "tok-2");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(crate::server::tcp_loop(store, listener));

        let got = query_txt(&addr.to_string(), "_acme-challenge.host.test").await.unwrap();
        assert_eq!(got, vec!["tok-1".to_string(), "tok-2".to_string()]);

        // An unknown name resolves to no TXT records.
        let none = query_txt(&addr.to_string(), "_acme-challenge.absent.test").await.unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn query_txt_times_out_on_a_server_that_accepts_and_never_answers_997() {
        // #997: exactly the failure this issue describes -- a nameserver that accepts
        // the connection and never answers. Paused clock -> tokio auto-advances
        // virtual time (same proven pattern as server.rs's own #300 stall test), so
        // this is deterministic and fast despite the real multi-second QUERY_TIMEOUT.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Accept and hold the connection open -- never write anything back.
            std::future::pending::<()>().await;
        });

        let start = tokio::time::Instant::now();
        let result = query_txt(&addr.to_string(), "_acme-challenge.host.test").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "a server that never answers must end in an error, not hang forever");
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut,
            "the error must be attributable to the timeout, not some other I/O failure"
        );
        assert!(elapsed >= QUERY_TIMEOUT, "must wait out the query deadline before giving up, elapsed {elapsed:?}");
        accept_task.abort();
    }
}
