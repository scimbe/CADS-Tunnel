// Generates real holder + Noise identities for "Alice"/"Bob" via the actual
// compiled ct-agent-wasm module, mints their channel grants locally (this test
// harness plays the channel OPERATOR's part -- see mintSignedGrant below, the
// same wire format ct_common::channel::SignedChannelGrant::encode() produces,
// cross-checked in crates/agent-wasm's own tests against that real Rust code),
// and writes everything the e2e test's shell orchestration needs to
// /tmp/e2e-env.sh (sourceable by run.sh). Self-contained: no dependency on any
// tool outside this repo (the operator-side grant-minting CLI now lives in the
// separate CADS-webconference-demo repo, since minting grants for a live deployment
// is demo tooling, not something this core regression test should depend on).
//
// Env in: WASM_PKG_DIR (dir containing the wasm-bindgen nodejs-target output).
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const wasm = require(path.join(process.env.WASM_PKG_DIR, 'ct_agent_wasm.js'));

function hex(buf) {
  return Buffer.from(buf).toString('hex');
}

// Node's own independent Ed25519 implementation (not ed25519-dalek) -- wraps a raw
// 32-byte private key in the minimal PKCS8 DER envelope crypto.createPrivateKey
// accepts, mirroring the SPKI-wrapping trick already used for public-key
// verification in the wasm-verify scripts this session.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519SignRaw(privateKeyHex, message) {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(privateKeyHex, 'hex')]);
  const keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, message, keyObj);
}

// Mirrors ct_common::channel::ChannelGrant::signing_bytes() exactly:
// "ct-grant:v1|<channel>|<holder>|<direction>|<rights>|<delegable>|<expires_at>"
function grantSigningBytes(channelHex, holderHex, direction, rights, delegable, expiresAt) {
  return Buffer.from(`ct-grant:v1|${channelHex}|${holderHex}|${direction}|${rights}|${delegable ? 1 : 0}|${expiresAt}`, 'utf8');
}

// Mirrors ct_common::channel::SignedChannelGrant::encode() exactly:
// signature(64) | channel(32) | holder(32) | direction(1) | rights(1) | delegable(1) | expires_at(u64 LE)
function mintSignedGrant(operatorPrivateHex, channelHex, holderHex, ttlSecs, nowSecs) {
  const expiresAt = BigInt(nowSecs) + BigInt(ttlSecs);
  const direction = 3; // Both
  const rights = 3; // ReadWrite
  const delegable = false;
  const signingBytes = grantSigningBytes(channelHex, holderHex, 'both', 'rw', delegable, expiresAt.toString());
  const signature = ed25519SignRaw(operatorPrivateHex, signingBytes);
  const expiresAtLE = Buffer.alloc(8);
  expiresAtLE.writeBigUInt64LE(expiresAt);
  return Buffer.concat([
    signature,
    Buffer.from(channelHex, 'hex'),
    Buffer.from(holderHex, 'hex'),
    Buffer.from([direction]),
    Buffer.from([rights]),
    Buffer.from([delegable ? 1 : 0]),
    expiresAtLE,
  ]);
}

const holderA = wasm.generate_holder_identity();
const holderB = wasm.generate_holder_identity();
const noiseA = wasm.generate_noise_identity();
const noiseB = wasm.generate_noise_identity();

// A fresh operator identity for this test run -- reuses the SAME real Ed25519
// keypair generator wasm exports (generate_holder_identity happens to produce a
// plain ed25519 keypair, exactly what an operator key is too).
const operator = wasm.generate_holder_identity();
const channelHex = wasm.channel_id_for_link(operator.public_hex, holderA.public_hex, holderB.public_hex);

const nowSecs = Math.floor(Date.now() / 1000);
const grantA = mintSignedGrant(operator.private_hex, channelHex, holderA.public_hex, 3600, nowSecs);
const grantB = mintSignedGrant(operator.private_hex, channelHex, holderB.public_hex, 3600, nowSecs);

const adminTokenHex = crypto.randomBytes(32).toString('hex');
const dummyAttestHex = '00'.repeat(64);

const members = {
  [`${channelHex}:${holderA.public_hex}`]: {
    operator_pubkey: operator.public_hex,
    noise_pubkey: noiseA.public_hex,
    noise_attestation: dummyAttestHex,
  },
  [`${channelHex}:${holderB.public_hex}`]: {
    operator_pubkey: operator.public_hex,
    noise_pubkey: noiseB.public_hex,
    noise_attestation: dummyAttestHex,
  },
};

const env = {
  MOCK_CP_ADMIN_TOKEN_HEX: adminTokenHex,
  MOCK_CP_MEMBERS_JSON: JSON.stringify(members),
  GRANT_A_HEX: hex(grantA),
  GRANT_B_HEX: hex(grantB),
  HOLDER_A_PRIVATE_HEX: holderA.private_hex,
  HOLDER_B_PRIVATE_HEX: holderB.private_hex,
  NOISE_A_PRIVATE_HEX: noiseA.private_hex,
  NOISE_A_PUBLIC_HEX: noiseA.public_hex,
  NOISE_B_PRIVATE_HEX: noiseB.private_hex,
  NOISE_B_PUBLIC_HEX: noiseB.public_hex,
};

const lines = Object.entries(env).map(([k, v]) => `export ${k}='${v}'`);
fs.writeFileSync('/tmp/e2e-env.sh', lines.join('\n') + '\n');
console.log('setup: wrote /tmp/e2e-env.sh');
console.log('setup: channel_id_hex=' + channelHex);
console.log('setup: operator_public_hex=' + operator.public_hex);
