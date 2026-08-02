// The video-conferencing browser demo page's client logic: a real browser tab
// joining an Agent-Fabric channel over ws_channel.rs, running a real Noise_IK
// handshake, and using encrypted WebRTC signaling (crates/agent-wasm's
// SignalMessage) to drive a real RTCPeerConnection. This mirrors exactly the
// sequence proved end-to-end (against the real ct-edge binary) by
// scripts/e2e-video-call -- the same primitives, driven by real browser APIs
// (WebSocket, RTCPeerConnection, getUserMedia) instead of a Node.js test
// double for the WebSocket transport and no WebRTC stack at all.
//
// Configured entirely via URL query params (no build step, no bundler, matching
// this repo's other examples/*):
//   ws          the ws_channel.rs WebSocket URL (e.g. wss://host/ws/channel)
//   grant       this peer's hex-encoded SignedChannelGrant (ct-video-call-grant)
//   holderPriv  this peer's holder private key hex
//   noisePriv   this peer's Noise static private key hex
//   role        "caller" (Noise initiator, sends the SDP offer) or "callee"
//               (Noise responder, sends the SDP answer)

import init, * as wasm from './pkg/ct_agent_wasm.js';

const statusEl = document.getElementById('status');
const iceEl = document.getElementById('ice-state');
const logEl = document.getElementById('log');

function log(msg) {
  const line = document.createElement('div');
  line.textContent = msg;
  logEl.appendChild(line);
  console.log(msg);
}

function setStatus(s) {
  statusEl.textContent = s;
  statusEl.dataset.status = s;
}

function setIceState(s) {
  iceEl.textContent = s;
  iceEl.dataset.iceState = s;
}

// A byte-stream reader over a browser WebSocket's inbound binary messages --
// concatenates every inbound message into one buffer and serves however many
// bytes are asked for, matching the server's own WsByteStream semantics
// exactly (message boundaries carry no meaning on this transport).
class WsByteStream {
  constructor(ws) {
    this.ws = ws;
    this.chunks = [];
    this.totalLen = 0;
    this.waiters = [];
    this.closed = false;
    ws.binaryType = 'arraybuffer';
    ws.addEventListener('message', (ev) => {
      this.chunks.push(new Uint8Array(ev.data));
      this.totalLen += ev.data.byteLength;
      this._wake();
    });
    ws.addEventListener('close', () => {
      this.closed = true;
      this._wake();
    });
  }
  _concat() {
    if (this.chunks.length <= 1) return this.chunks[0] || new Uint8Array(0);
    const out = new Uint8Array(this.totalLen);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    this.chunks = [out];
    return out;
  }
  _wake() {
    while (this.waiters.length && (this.totalLen > 0 || this.closed)) {
      const w = this.waiters.shift();
      w();
    }
  }
  async _waitForBytes() {
    if (this.totalLen > 0 || this.closed) return;
    await new Promise((resolve) => this.waiters.push(resolve));
  }
  async readExact(n) {
    while (this.totalLen < n) {
      if (this.closed) throw new Error(`connection closed while reading ${n} bytes`);
      await this._waitForBytes();
    }
    const buf = this._concat();
    const out = buf.slice(0, n);
    this.chunks = [buf.slice(n)];
    this.totalLen -= n;
    return out;
  }
  async readLine() {
    while (true) {
      const buf = this._concat();
      const idx = buf.indexOf(0x0a);
      if (idx !== -1) {
        const out = buf.slice(0, idx + 1);
        this.chunks = [buf.slice(idx + 1)];
        this.totalLen -= idx + 1;
        return new TextDecoder().decode(out);
      }
      if (this.closed) throw new Error('connection closed while reading a line');
      await this._waitForBytes();
    }
  }
  send(bytes) {
    this.ws.send(bytes);
  }
}

async function writeFramed(stream, bytes) {
  stream.send(wasm.frame_message(bytes));
}

async function readFramed(stream) {
  const lenBytes = await stream.readExact(2);
  const len = (lenBytes[0] << 8) | lenBytes[1];
  return stream.readExact(len);
}

// The join response is either a 2-byte b"NO" refusal or a 32-byte challenge --
// two fixed lengths with no framing to disambiguate up front.
async function readChallengeOrRefusal(stream) {
  const first2 = await stream.readExact(2);
  if (first2[0] === 0x4e && first2[1] === 0x4f) {
    return { refused: true };
  }
  const rest = await stream.readExact(30);
  const challenge = new Uint8Array(32);
  challenge.set(first2, 0);
  challenge.set(rest, 2);
  return { refused: false, challenge };
}

async function joinChannel(wsUrl, grantHex, holderPrivHex) {
  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', () => reject(new Error('WebSocket connection failed')), { once: true });
  });
  const stream = new WsByteStream(ws);

  const joinReq = wasm.buildChannelJoinRequest(grantHex, 'relay-only');
  await writeFramed(stream, joinReq);

  const resp = await readChallengeOrRefusal(stream);
  if (resp.refused) throw new Error('channel join refused');
  const sig = wasm.holderSign(holderPrivHex, resp.challenge);
  stream.send(sig);

  const ackLine = await stream.readLine();
  log(`ack: ${ackLine.trim()}`);
  if (!ackLine.startsWith('OK ')) throw new Error(`unexpected ack line: ${ackLine}`);
  const parts = ackLine.trim().split(' ');
  const peerNoiseHex = parts.length === 5 ? parts[2] : null;

  return { ws, stream, peerNoiseHex };
}

async function getLocalMedia() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    log('real camera/microphone acquired');
    return { kind: 'media', stream };
  } catch (e) {
    log(`getUserMedia unavailable (${e.name || e}); falling back to a data channel probe -- \
the same RTCPeerConnection/ICE machinery a real audio/video call uses, just without a \
capture device attached in this environment`);
    return { kind: 'probe' };
  }
}

async function run() {
  await init('./pkg/ct_agent_wasm_bg.wasm');

  const params = new URLSearchParams(location.search);
  const wsUrl = params.get('ws');
  const grantHex = params.get('grant');
  const holderPrivHex = params.get('holderPriv');
  const noisePrivHex = params.get('noisePriv');
  const role = params.get('role'); // 'caller' | 'callee'

  setStatus('joining');
  const { stream, peerNoiseHex } = await joinChannel(wsUrl, grantHex, holderPrivHex);
  if (!peerNoiseHex) throw new Error('no peer Noise key in ack -- peer not registered with a Noise key');

  setStatus('noise-handshake');
  const isCaller = role === 'caller';
  const hs = isCaller ? wasm.NoiseHandshake.newInitiator(noisePrivHex, peerNoiseHex) : wasm.NoiseHandshake.newResponder(noisePrivHex);
  if (isCaller) {
    await writeFramed(stream, hs.writeMessage(new Uint8Array(0)));
    hs.readMessage(await readFramed(stream));
  } else {
    hs.readMessage(await readFramed(stream));
    await writeFramed(stream, hs.writeMessage(new Uint8Array(0)));
  }
  if (!hs.isFinished()) throw new Error('Noise handshake did not finish after 2 messages');
  const transport = hs.intoTransport();
  log('Noise_IK handshake complete -- signaling channel is now authenticated + encrypted');

  setStatus('connecting-webrtc');
  const pc = new RTCPeerConnection({ iceServers: [] });
  pc.oniceconnectionstatechange = () => setIceState(pc.iceConnectionState);
  pc.onconnectionstatechange = () => log(`connection state: ${pc.connectionState}`);

  function sendSignal(bytes) {
    // Synchronous start-to-finish (no `await` inside) so concurrent callers
    // (onicecandidate firing while the main flow awaits a peer message) can
    // never interleave two transport.encrypt() calls out of nonce order.
    writeFramed(stream, transport.encrypt(bytes));
  }

  pc.onicecandidate = (ev) => {
    if (!ev.candidate) return;
    sendSignal(wasm.encodeSignalIceCandidate(ev.candidate.candidate, ev.candidate.sdpMid || undefined, ev.candidate.sdpMLineIndex ?? undefined));
  };

  const media = await getLocalMedia();
  if (media.kind === 'media') {
    for (const track of media.stream.getTracks()) pc.addTrack(track, media.stream);
  } else {
    pc.createDataChannel('probe');
  }

  // Background loop: every subsequent signaling message (from here on the
  // Noise session is established, so everything is encrypted) is decrypted,
  // decoded, and dispatched to the peer connection.
  (async () => {
    while (true) {
      let cipher;
      try {
        cipher = await readFramed(stream);
      } catch {
        return; // connection closed
      }
      const plain = transport.decrypt(cipher);
      const msg = wasm.decodeSignalMessage(plain);
      if (msg.kind === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        sendSignal(wasm.encodeSignalAnswer(answer.sdp));
      } else if (msg.kind === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
      } else if (msg.kind === 'ice-candidate') {
        await pc.addIceCandidate({ candidate: msg.candidate, sdpMid: msg.sdpMid, sdpMLineIndex: msg.sdpMlineIndex });
      } else if (msg.kind === 'bye') {
        setStatus('peer-hung-up');
        pc.close();
        return;
      }
    }
  })();

  if (isCaller) {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendSignal(wasm.encodeSignalOffer(offer.sdp));
  }

  setStatus('signaling-active');
  window.__ctVideoCallDemo = { pc, transport };
}

run().catch((e) => {
  console.error(e);
  setStatus('error: ' + (e.message || e));
});
