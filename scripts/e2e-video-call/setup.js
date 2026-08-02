// Generates real holder + Noise identities for "Alice"/"Bob" via the actual
// compiled ct-agent-wasm module, mints their channel grants via the real
// ct-video-call-grant CLI binary (crates/agent-tools/src/bin/video_call_grant.rs),
// and writes everything the e2e test's shell orchestration needs to
// /tmp/e2e-env.sh (sourceable by run.sh).
//
// Env in: WASM_PKG_DIR (dir containing the wasm-bindgen nodejs-target output),
//         GRANT_BIN (path to the built ct-video-call-grant binary).
const { execFileSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const wasm = require(path.join(process.env.WASM_PKG_DIR, 'ct_agent_wasm.js'));

const holderA = wasm.generate_holder_identity();
const holderB = wasm.generate_holder_identity();
const noiseA = wasm.generate_noise_identity();
const noiseB = wasm.generate_noise_identity();

const grantOut = execFileSync(process.env.GRANT_BIN, [holderA.public_hex, holderB.public_hex, '--ttl-secs', '3600'], {
  encoding: 'utf8',
});
const fields = {};
for (const line of grantOut.trim().split('\n')) {
  const idx = line.indexOf('=');
  fields[line.slice(0, idx)] = line.slice(idx + 1);
}

const adminTokenHex = crypto.randomBytes(32).toString('hex');
const dummyAttestHex = '00'.repeat(64);

const members = {
  [`${fields.channel_id_hex}:${holderA.public_hex}`]: {
    operator_pubkey: fields.operator_public_hex,
    noise_pubkey: noiseA.public_hex,
    noise_attestation: dummyAttestHex,
  },
  [`${fields.channel_id_hex}:${holderB.public_hex}`]: {
    operator_pubkey: fields.operator_public_hex,
    noise_pubkey: noiseB.public_hex,
    noise_attestation: dummyAttestHex,
  },
};

const env = {
  MOCK_CP_ADMIN_TOKEN_HEX: adminTokenHex,
  MOCK_CP_MEMBERS_JSON: JSON.stringify(members),
  GRANT_A_HEX: fields.grant_a_hex,
  GRANT_B_HEX: fields.grant_b_hex,
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
console.log('setup: channel_id_hex=' + fields.channel_id_hex);
console.log('setup: operator_public_hex=' + fields.operator_public_hex);
