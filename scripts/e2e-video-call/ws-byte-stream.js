// A minimal, dependency-free RFC6455 WebSocket client + byte-stream reader, built
// from Node's `net`/`crypto` core modules only (no npm install, no experimental
// flags -- this test harness stands in for a real browser tab, which would just
// use the native `WebSocket` API; this hand-rolled client exists ONLY so this
// Node-based integration test can drive the real edge over a real WebSocket in a
// fully offline/hermetic container). Exposes byte-stream semantics
// (readExact/readLine) matching exactly what WsByteStream on the server side does
// with inbound frames -- concatenate every inbound Binary payload into one
// buffer, serve however many bytes are asked for, regardless of how the server's
// outbound writes were chunked across WS messages.
const net = require('net');
const crypto = require('crypto');
const { URL } = require('url');

function wsConnect(urlStr) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const socket = net.connect(Number(u.port), u.hostname, () => {
      const key = crypto.randomBytes(16).toString('base64');
      const req =
        `GET ${u.pathname}${u.search} HTTP/1.1\r\n` +
        `Host: ${u.host}\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`;
      socket.write(req);
      let buf = Buffer.alloc(0);
      function onHandshakeData(chunk) {
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        const headerText = buf.subarray(0, idx).toString('utf8');
        const rest = buf.subarray(idx + 4);
        socket.removeListener('data', onHandshakeData);
        if (!/^HTTP\/1\.1 101/.test(headerText)) {
          reject(new Error('WS handshake failed: ' + headerText));
          return;
        }
        resolve(new WsConn(socket, rest));
      }
      socket.on('data', onHandshakeData);
      socket.on('error', reject);
    });
    socket.on('error', reject);
  });
}

class WsConn {
  constructor(socket, initialBuf) {
    this.socket = socket;
    this.recvBuf = initialBuf;
    this.messages = [];
    this.waiters = [];
    this.closed = false;
    socket.on('data', (chunk) => {
      this.recvBuf = Buffer.concat([this.recvBuf, chunk]);
      this._drainFrames();
    });
    const onEnd = () => {
      this.closed = true;
      this._wake();
    };
    socket.on('close', onEnd);
    socket.on('error', onEnd);
    this._drainFrames();
  }
  _drainFrames() {
    while (true) {
      const frame = this._tryParseFrame();
      if (!frame) break;
      if (frame.opcode === 0x8) {
        this.closed = true;
        break;
      }
      if (frame.opcode === 0x2 || frame.opcode === 0x1) {
        this.messages.push(frame.payload);
      }
    }
    this._wake();
  }
  _wake() {
    while (this.messages.length && this.waiters.length) {
      this.waiters.shift().resolve(this.messages.shift());
    }
    if (this.closed) {
      while (this.waiters.length) this.waiters.shift().resolve(null);
    }
  }
  _tryParseFrame() {
    const buf = this.recvBuf;
    if (buf.length < 2) return null;
    const byte0 = buf[0];
    const byte1 = buf[1];
    const opcode = byte0 & 0x0f;
    const masked = (byte1 & 0x80) !== 0;
    let len = byte1 & 0x7f;
    let offset = 2;
    if (len === 126) {
      if (buf.length < 4) return null;
      len = buf.readUInt16BE(2);
      offset = 4;
    } else if (len === 127) {
      if (buf.length < 10) return null;
      len = Number(buf.readBigUInt64BE(2));
      offset = 10;
    }
    let maskKey = null;
    if (masked) {
      if (buf.length < offset + 4) return null;
      maskKey = buf.subarray(offset, offset + 4);
      offset += 4;
    }
    if (buf.length < offset + len) return null;
    let payload = Buffer.from(buf.subarray(offset, offset + len));
    if (masked) {
      for (let i = 0; i < len; i++) payload[i] ^= maskKey[i % 4];
    }
    this.recvBuf = buf.subarray(offset + len);
    return { opcode, payload };
  }
  nextMessage() {
    if (this.messages.length) return Promise.resolve(this.messages.shift());
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push({ resolve }));
  }
  sendBinary(payload) {
    const len = payload.length;
    const maskKey = crypto.randomBytes(4);
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x80 | 0x02;
      header[1] = 0x80 | len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | 0x02;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | 0x02;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ maskKey[i % 4];
    this.socket.write(Buffer.concat([header, maskKey, masked]));
  }
  close() {
    this.socket.destroy();
  }
}

class WsByteStream {
  constructor(wsConn) {
    this.ws = wsConn;
    this.byteBuf = Buffer.alloc(0);
  }
  async readExact(n) {
    while (this.byteBuf.length < n) {
      const msg = await this.ws.nextMessage();
      if (msg === null) throw new Error('connection closed while reading ' + n + ' bytes');
      this.byteBuf = Buffer.concat([this.byteBuf, msg]);
    }
    const out = Buffer.from(this.byteBuf.subarray(0, n));
    this.byteBuf = this.byteBuf.subarray(n);
    return out;
  }
  async readLine() {
    while (true) {
      const idx = this.byteBuf.indexOf(0x0a);
      if (idx !== -1) {
        const out = Buffer.from(this.byteBuf.subarray(0, idx + 1)).toString('utf8');
        this.byteBuf = this.byteBuf.subarray(idx + 1);
        return out;
      }
      const msg = await this.ws.nextMessage();
      if (msg === null) throw new Error('connection closed while reading a line');
      this.byteBuf = Buffer.concat([this.byteBuf, msg]);
    }
  }
  write(bytes) {
    this.ws.sendBinary(Buffer.from(bytes));
  }
}

module.exports = { wsConnect, WsByteStream };
