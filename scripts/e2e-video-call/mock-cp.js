// Minimal stand-in for the control plane's POST /internal/channel/authorize
// (crates/edge/src/channel_authorize.rs) -- the ONE endpoint ChannelAuthorizer
// calls. Everything else in this test exercises the REAL ct-edge binary, the
// REAL channel_broker admission/pairing/relay, and the REAL ct-agent-wasm
// module. This mock only stands in for the control plane's channel-membership
// registry (itself tested separately in ct-control-plane's own suite), which
// this integration test doesn't stand up -- that needs a real OIDC session, a
// separate, later increment.
const http = require('http');

const ADMIN_TOKEN_HEX = process.env.MOCK_CP_ADMIN_TOKEN_HEX;
const MEMBERS = JSON.parse(process.env.MOCK_CP_MEMBERS_JSON); // { "<channel_hex>:<holder_hex>": {operator_pubkey, noise_pubkey, noise_attestation} }
const PORT = Number(process.env.MOCK_CP_PORT);

const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/internal/channel/authorize') {
    res.writeHead(404).end();
    return;
  }
  if (req.headers['x-ct-admin-token'] !== ADMIN_TOKEN_HEX) {
    res.writeHead(401).end();
    return;
  }
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const { channel, holder } = JSON.parse(body);
    const entry = MEMBERS[`${channel}:${holder}`];
    if (!entry) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(entry));
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock-cp: listening on 127.0.0.1:${PORT}`);
});
