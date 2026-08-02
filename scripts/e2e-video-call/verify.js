// Real end-to-end proof of the video-conferencing channel-join + Noise + signaling
// pipeline: two independent "browser peers" (Alice, Bob), each driving their OWN
// instance of the actual compiled ct-agent-wasm module and a real WebSocket
// connection, joining the SAME channel through the REAL, unmodified ct-edge
// binary's ws_channel.rs listener -- real admission (possession-challenge
// signing), real channel_broker pairing/relay, a real Noise_IK handshake, real
// encrypted WebRTC signaling message exchange (offer/answer/ICE-candidate/bye).
// See run.sh's header comment for the full scope note (what's real vs. mocked).
//
// Env in: WASM_PKG_DIR, WS_URL, and the identity/grant vars setup.js writes to
// /tmp/e2e-env.sh (GRANT_A_HEX, GRANT_B_HEX, HOLDER_*_PRIVATE_HEX, NOISE_*_HEX).
const path = require('path');
const { wsConnect, WsByteStream } = require('./ws-byte-stream.js');
const wasm = require(path.join(process.env.WASM_PKG_DIR, 'ct_agent_wasm.js'));

const WS_URL = process.env.WS_URL;

async function writeFramed(stream, bytes) {
  stream.write(wasm.frame_message(bytes));
}

async function readFramed(stream) {
  const lenBytes = await stream.readExact(2);
  const len = lenBytes.readUInt16BE(0);
  return stream.readExact(len);
}

// The join response is either a 2-byte b"NO" refusal or a 32-byte challenge --
// two different fixed lengths with no framing to disambiguate up front. Read the
// first 2 bytes; if they spell "NO" it's a refusal, otherwise they're the start
// of the 32-byte challenge and 30 more bytes complete it.
async function readChallengeOrRefusal(stream) {
  const first2 = await stream.readExact(2);
  if (first2.toString('latin1') === 'NO') {
    return { refused: true };
  }
  const rest = await stream.readExact(30);
  return { refused: false, challenge: Buffer.concat([first2, rest]) };
}

async function joinChannel(name, grantHex, holderPrivateHex) {
  const ws = await wsConnect(WS_URL);
  const stream = new WsByteStream(ws);

  const joinReq = wasm.buildChannelJoinRequest(grantHex, 'relay-only');
  await writeFramed(stream, joinReq);

  const resp = await readChallengeOrRefusal(stream);
  if (resp.refused) {
    throw new Error(`${name}: join refused (NO)`);
  }
  const sig = wasm.holderSign(holderPrivateHex, resp.challenge);
  stream.write(Buffer.from(sig));

  const ackLine = await stream.readLine();
  console.log(`${name}: ack = ${ackLine.trim()}`);
  if (!ackLine.startsWith('OK ')) {
    throw new Error(`${name}: unexpected ack line: ${ackLine}`);
  }
  const parts = ackLine.trim().split(' ');
  // "OK <endpoint>" or "OK <endpoint> <noise_hex> <holder_hex> <attest_hex>"
  let peerNoiseHex = null;
  if (parts.length === 5) {
    peerNoiseHex = parts[2];
  }
  return { stream, peerNoiseHex };
}

async function runAlice(grantHex, holderPrivateHex, noiseIdentity) {
  const { stream, peerNoiseHex } = await joinChannel('alice', grantHex, holderPrivateHex);
  if (!peerNoiseHex) throw new Error('alice: no peer noise key in ack');

  const hs = wasm.NoiseHandshake.newInitiator(noiseIdentity.private_hex, peerNoiseHex);
  const m1 = hs.writeMessage(new Uint8Array(0));
  await writeFramed(stream, m1);
  const m2 = await readFramed(stream);
  hs.readMessage(m2);
  if (!hs.isFinished()) throw new Error('alice: handshake not finished after 2 messages');
  const transport = hs.intoTransport();

  const offerSdp = 'v=0\r\no=- ALICE-OFFER 2 IN IP4 127.0.0.1\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
  await writeFramed(stream, transport.encrypt(wasm.encodeSignalOffer(offerSdp)));

  const answerCipher = await readFramed(stream);
  const answerPlain = transport.decrypt(answerCipher);
  const answer = wasm.decodeSignalMessage(answerPlain);
  if (answer.kind !== 'answer') throw new Error('alice: expected answer, got ' + answer.kind);
  const expectedAnswer = 'v=0\r\no=- BOB-ANSWER 2 IN IP4 127.0.0.1\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
  if (answer.sdp !== expectedAnswer) throw new Error('alice: answer sdp mismatch');

  await writeFramed(
    stream,
    transport.encrypt(wasm.encodeSignalIceCandidate('candidate:1 1 udp 12345 203.0.113.9 55000 typ host', 'audio', 0))
  );

  const byeCipher = await readFramed(stream);
  const byePlain = transport.decrypt(byeCipher);
  const bye = wasm.decodeSignalMessage(byePlain);
  if (bye.kind !== 'bye') throw new Error('alice: expected bye, got ' + bye.kind);

  stream.ws.close();
  return { ok: true };
}

async function runBob(grantHex, holderPrivateHex, noiseIdentity) {
  const { stream } = await joinChannel('bob', grantHex, holderPrivateHex);

  const hs = wasm.NoiseHandshake.newResponder(noiseIdentity.private_hex);
  const m1 = await readFramed(stream);
  hs.readMessage(m1);
  const m2 = hs.writeMessage(new Uint8Array(0));
  await writeFramed(stream, m2);
  if (!hs.isFinished()) throw new Error('bob: handshake not finished after 2 messages');
  const transport = hs.intoTransport();

  const offerCipher = await readFramed(stream);
  const offerPlain = transport.decrypt(offerCipher);
  const offer = wasm.decodeSignalMessage(offerPlain);
  if (offer.kind !== 'offer') throw new Error('bob: expected offer, got ' + offer.kind);
  const expectedOffer = 'v=0\r\no=- ALICE-OFFER 2 IN IP4 127.0.0.1\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
  if (offer.sdp !== expectedOffer) throw new Error('bob: offer sdp mismatch');

  const answerSdp = 'v=0\r\no=- BOB-ANSWER 2 IN IP4 127.0.0.1\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
  await writeFramed(stream, transport.encrypt(wasm.encodeSignalAnswer(answerSdp)));

  const iceCipher = await readFramed(stream);
  const icePlain = transport.decrypt(iceCipher);
  const ice = wasm.decodeSignalMessage(icePlain);
  if (ice.kind !== 'ice-candidate') throw new Error('bob: expected ice-candidate, got ' + ice.kind);
  if (!ice.candidate.startsWith('candidate:1 1 udp 12345')) throw new Error('bob: ice candidate mismatch: ' + ice.candidate);
  if (ice.sdpMid !== 'audio' || ice.sdpMlineIndex !== 0) throw new Error('bob: ice mid/mline mismatch');

  await writeFramed(stream, transport.encrypt(wasm.encodeSignalBye()));

  stream.ws.close();
  return { ok: true };
}

async function main() {
  const grantAHex = process.env.GRANT_A_HEX;
  const grantBHex = process.env.GRANT_B_HEX;
  const holderAPriv = process.env.HOLDER_A_PRIVATE_HEX;
  const holderBPriv = process.env.HOLDER_B_PRIVATE_HEX;
  const noiseA = { private_hex: process.env.NOISE_A_PRIVATE_HEX, public_hex: process.env.NOISE_A_PUBLIC_HEX };
  const noiseB = { private_hex: process.env.NOISE_B_PRIVATE_HEX, public_hex: process.env.NOISE_B_PUBLIC_HEX };

  const [aliceResult, bobResult] = await Promise.all([
    runAlice(grantAHex, holderAPriv, noiseA),
    runBob(grantBHex, holderBPriv, noiseB),
  ]);

  console.log('alice result:', JSON.stringify(aliceResult));
  console.log('bob result:', JSON.stringify(bobResult));
  if (!aliceResult.ok || !bobResult.ok) {
    throw new Error('one or both members did not complete the full flow');
  }
  console.log('E2E-OK: real edge admission + pairing + Noise handshake + encrypted WebRTC signaling all verified');
}

main().catch((e) => {
  console.error('E2E-FAIL:', e.stack || e);
  process.exit(1);
});
