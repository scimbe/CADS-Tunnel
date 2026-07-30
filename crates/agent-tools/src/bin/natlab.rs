//! #136 N-rig-2b — **test-only** DCUtR cross-NAT punch harness (cargo feature `nat-lab`).
//!
//! Runs ONE role of the libp2p Circuit-Relay v2 + DCUtR punch so `scripts/nat-lab.sh` can
//! orchestrate three processes across the lab's network namespaces (relay in the public
//! segment; two clients behind separate NATs) and prove a real cross-NAT hole-punch — the one
//! thing the cargo gate structurally cannot exercise (no NAT on loopback).
//!
//! **Not a production capability.** The relay is UNGUARDED (invariant #3's `C-membership-gate`
//! is not wired), so this binary exists only behind `--features nat-lab` and is never shipped
//! as a `ct-agent` subcommand. See `ct_agent::p2p::nat_lab_relay`.
//!
//! Roles:
//!   * `relay [<listen-multiaddr>]`  — run the Circuit-Relay v2 relay; prints `<addr>/p2p/<id>`.
//!   * `listen`/`dial`               — the two punch clients (N-rig-2b part 2).

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("relay") => {
            let listen = args.next().unwrap_or_else(|| "/ip4/0.0.0.0/tcp/4001".to_string());
            ct_agent::p2p::nat_lab_relay(&listen).await
        }
        Some("listen") => {
            let relay = args.next().ok_or("listen needs <relay-multiaddr>")?;
            ct_agent::p2p::nat_lab_listen(relay.parse()?).await
        }
        Some("dial") => {
            let peer = args.next().ok_or("dial needs <peer-via-relay-multiaddr>")?;
            ct_agent::p2p::nat_lab_dial(peer.parse()?).await
        }
        other => {
            eprintln!(
                "natlab: test-only #136 DCUtR punch harness (feature nat-lab)\n\
                 usage: natlab relay  [<listen-multiaddr>]\n\
                        natlab listen <relay-multiaddr>\n\
                        natlab dial   <peer-via-relay-multiaddr>"
            );
            eprintln!("unknown role: {other:?}");
            std::process::exit(2);
        }
    }
}
