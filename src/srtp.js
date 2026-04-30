// src/srtp.js
// SRTP encrypt/decrypt — RFC 3711 (AES-128-CM + HMAC-SHA1-80).
/**
 * srtp — Secure RTP (RFC 3711).
 *
 * Cipher: AES-128-CM (Counter Mode)
 * Auth:   HMAC-SHA1-80 (80-bit truncated)
 *
 * Supports both RTP and RTCP protection.
 * ROC (Rollover Counter) is tracked per-SSRC, so a single session can
 * handle multiple media streams.
 *
 * Two construction forms:
 *
 *   // Duplex form (WebRTC / DTLS-SRTP — separate keys for each direction)
 *   var session = new SrtpSession({
 *     clientKey, serverKey, clientSalt, serverSalt, isServer,
 *   });
 *
 *   // Symmetric form (SDES, RTSP, custom signaling — same key both ways)
 *   var session = new SrtpSession(masterKey, masterSalt);
 *
 * Usage:
 *   var srtp = session.encryptRtp(rtpPacket);     // Buffer → Buffer
 *   var rtp  = session.decryptRtp(srtpPacket);    // returns null on auth fail
 *   var srtcp = session.encryptRtcp(rtcpPacket);
 *   var rtcp  = session.decryptRtcp(srtcpPacket);
 */

import crypto from 'node:crypto';


// ═══════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════

// Key derivation labels (RFC 3711 §4.3.1)
var LABEL_RTP_CIPHER  = 0x00;
var LABEL_RTP_AUTH    = 0x01;
var LABEL_RTP_SALT    = 0x02;
var LABEL_RTCP_CIPHER = 0x03;
var LABEL_RTCP_AUTH   = 0x04;
var LABEL_RTCP_SALT   = 0x05;

// Sizes
var AUTH_TAG_LEN        = 10;   // 80-bit HMAC-SHA1
var SESSION_KEY_LEN     = 16;   // AES-128
var SESSION_SALT_LEN    = 14;
var AUTH_KEY_LEN        = 20;   // HMAC-SHA1 key


// ═══════════════════════════════════════════════════════════════════
//  SrtpSession
// ═══════════════════════════════════════════════════════════════════

/**
 * Create an SRTP session.
 *
 * @param {object|Buffer} arg1
 *   - Duplex form: { clientKey, serverKey, clientSalt, serverSalt, isServer }
 *     Used by WebRTC (DTLS-SRTP) where each direction has its own key.
 *   - Symmetric form: Buffer (16 bytes) — master key
 * @param {Buffer} [arg2]
 *   - Symmetric form only: master salt (14 bytes)
 */
function SrtpSession(arg1, arg2) {
  if (!(this instanceof SrtpSession)) return new SrtpSession(arg1, arg2);

  var encMasterKey, encMasterSalt, decMasterKey, decMasterSalt;

  if (Buffer.isBuffer(arg1)) {
    // Symmetric form — same key for both directions
    if (arg1.length !== 16) throw new Error('SrtpSession: masterKey must be 16 bytes');
    if (!arg2 || arg2.length !== 14) throw new Error('SrtpSession: masterSalt must be 14 bytes');
    encMasterKey = decMasterKey = arg1;
    encMasterSalt = decMasterSalt = arg2;
  } else if (arg1 && typeof arg1 === 'object') {
    // Duplex form — separate keys per direction
    if (!arg1.clientKey || !arg1.serverKey || !arg1.clientSalt || !arg1.serverSalt) {
      throw new Error('SrtpSession: duplex form requires clientKey, serverKey, clientSalt, serverSalt');
    }
    var isServer = !!arg1.isServer;
    encMasterKey  = isServer ? arg1.serverKey  : arg1.clientKey;
    encMasterSalt = isServer ? arg1.serverSalt : arg1.clientSalt;
    decMasterKey  = isServer ? arg1.clientKey  : arg1.serverKey;
    decMasterSalt = isServer ? arg1.clientSalt : arg1.serverSalt;
  } else {
    throw new Error('SrtpSession: expected a Buffer (symmetric) or keys object (duplex)');
  }

  // Derive all six session keys for each direction (RTP: cipher/auth/salt, RTCP: cipher/auth/salt)
  this._encRtpKey   = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTP_CIPHER,  SESSION_KEY_LEN);
  this._encRtpSalt  = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTP_SALT,    SESSION_SALT_LEN);
  this._encRtpAuth  = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTP_AUTH,    AUTH_KEY_LEN);
  this._encRtcpKey  = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTCP_CIPHER, SESSION_KEY_LEN);
  this._encRtcpSalt = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTCP_SALT,   SESSION_SALT_LEN);
  this._encRtcpAuth = _deriveKey(encMasterKey, encMasterSalt, LABEL_RTCP_AUTH,   AUTH_KEY_LEN);

  this._decRtpKey   = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTP_CIPHER,  SESSION_KEY_LEN);
  this._decRtpSalt  = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTP_SALT,    SESSION_SALT_LEN);
  this._decRtpAuth  = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTP_AUTH,    AUTH_KEY_LEN);
  this._decRtcpKey  = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTCP_CIPHER, SESSION_KEY_LEN);
  this._decRtcpSalt = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTCP_SALT,   SESSION_SALT_LEN);
  this._decRtcpAuth = _deriveKey(decMasterKey, decMasterSalt, LABEL_RTCP_AUTH,   AUTH_KEY_LEN);

  // Per-SSRC state for RTP ROC tracking. WebRTC streams carry multiple SSRCs
  // (video + audio + RTX + data), each with its own sequence space.
  this._rocMap = {};  // ssrc → { roc, lastSeq }

  // SRTCP has its own monotonically-increasing 31-bit index (not ssrc-keyed)
  this._srtcpSendIndex = 0;
  this._srtcpSeenIndices = {};  // basic replay protection for SRTCP

  // Scratch buffers reused across every encrypt/decrypt call — avoids
  // allocating an IV and a ROC buffer on every packet (38K pkts/sec = 38K
  // allocations/sec saved). Safe because we're single-threaded and each
  // method finishes using the scratch before returning.
  this._ivScratch = Buffer.allocUnsafe(16);
  this._rocScratch = Buffer.allocUnsafe(4);
}


// ═══════════════════════════════════════════════════════════════════
//  RTP protection
// ═══════════════════════════════════════════════════════════════════

/**
 * Encrypt an RTP packet → SRTP packet.
 * @param {Buffer} rtpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.encryptRtp = function (rtpPacket) {
  if (!rtpPacket || rtpPacket.length < 12) return null;

  var seq  = rtpPacket.readUInt16BE(2);
  var ssrc = rtpPacket.readUInt32BE(8);

  // Inline ROC tracking — avoids the _getSenderIndex/_commitRoc helper call
  // overhead plus the {roc, index} object allocation on every packet.
  var state = this._rocMap[ssrc];
  var roc;
  if (state) {
    roc = state.roc;
    if (seq < 0x8000 && state.lastSeq > 0xC000) roc = (roc + 1) >>> 0;
    state.roc = roc;
    state.lastSeq = seq;
  } else {
    roc = 0;
    this._rocMap[ssrc] = { roc: 0, lastSeq: seq };
  }
  var index = roc * 0x10000 + seq;

  var headerLen = _rtpHeaderLength(rtpPacket);
  var payload = rtpPacket.subarray(headerLen);

  // AES-128-CM encrypt payload (native CTR — 15× faster than a JS loop)
  _buildRtpIv(this._ivScratch, this._encRtpSalt, ssrc, index);
  var encPayload = _aesCmEncrypt(this._encRtpKey, this._ivScratch, payload);

  // Assemble output: header (clear) | encrypted payload | auth tag
  var out = Buffer.allocUnsafe(rtpPacket.length + AUTH_TAG_LEN);
  rtpPacket.copy(out, 0, 0, headerLen);
  encPayload.copy(out, headerLen);

  // HMAC-SHA1 over (header + encrypted || ROC). Reuse ROC scratch buffer.
  this._rocScratch.writeUInt32BE(roc >>> 0, 0);
  var hmac = crypto.createHmac('sha1', this._encRtpAuth);
  hmac.update(out.subarray(0, rtpPacket.length));
  hmac.update(this._rocScratch);
  hmac.digest().copy(out, rtpPacket.length, 0, AUTH_TAG_LEN);

  return out;
};

/**
 * Decrypt an SRTP packet → RTP packet.
 * Returns null if authentication fails.
 * @param {Buffer} srtpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.decryptRtp = function (srtpPacket) {
  if (!srtpPacket || srtpPacket.length < 12 + AUTH_TAG_LEN) return null;

  var authTagStart = srtpPacket.length - AUTH_TAG_LEN;
  var authenticated = srtpPacket.subarray(0, authTagStart);
  var authTag = srtpPacket.subarray(authTagStart);

  var seq  = authenticated.readUInt16BE(2);
  var ssrc = authenticated.readUInt32BE(8);

  // Compute ROC tentatively — do NOT update state. A forged packet with a
  // crafted seq could otherwise desync the session for legitimate packets.
  var state = this._rocMap[ssrc];
  var tentativeRoc = 0;
  if (state) {
    tentativeRoc = state.roc;
    if (seq < 0x8000 && state.lastSeq > 0xC000) tentativeRoc = (tentativeRoc + 1) >>> 0;
  }
  var index = tentativeRoc * 0x10000 + seq;

  // Verify auth tag: HMAC-SHA1(authKey, authenticated || ROC)
  this._rocScratch.writeUInt32BE(tentativeRoc >>> 0, 0);
  var hmac = crypto.createHmac('sha1', this._decRtpAuth);
  hmac.update(authenticated);
  hmac.update(this._rocScratch);
  var expectedTag = hmac.digest().subarray(0, AUTH_TAG_LEN);

  if (!_constantTimeEquals(authTag, expectedTag)) return null;

  // Auth passed — commit ROC state
  if (state) {
    state.roc = tentativeRoc;
    state.lastSeq = seq;
  } else {
    this._rocMap[ssrc] = { roc: tentativeRoc, lastSeq: seq };
  }

  // Decrypt payload
  var headerLen = _rtpHeaderLength(authenticated);
  var encPayload = authenticated.subarray(headerLen);
  _buildRtpIv(this._ivScratch, this._decRtpSalt, ssrc, index);
  var decPayload = _aesCmEncrypt(this._decRtpKey, this._ivScratch, encPayload);

  var out = Buffer.allocUnsafe(headerLen + decPayload.length);
  authenticated.copy(out, 0, 0, headerLen);
  decPayload.copy(out, headerLen);
  return out;
};


// ═══════════════════════════════════════════════════════════════════
//  RTCP protection
// ═══════════════════════════════════════════════════════════════════

/**
 * Encrypt an RTCP packet → SRTCP packet.
 * @param {Buffer} rtcpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.encryptRtcp = function (rtcpPacket) {
  if (!rtcpPacket || rtcpPacket.length < 8) return null;

  var ssrc = rtcpPacket.readUInt32BE(4);
  var index = this._srtcpSendIndex;
  this._srtcpSendIndex = (this._srtcpSendIndex + 1) & 0x7FFFFFFF;

  var headerLen = 8;   // sender SSRC + packet type header
  var payload = rtcpPacket.subarray(headerLen);

  _buildRtcpIv(this._ivScratch, this._encRtcpSalt, ssrc, index);
  var encPayload = _aesCmEncrypt(this._encRtcpKey, this._ivScratch, payload);

  // Single allocation for the full output: header | encrypted | E+index | tag
  var outLen = rtcpPacket.length + 4 + AUTH_TAG_LEN;
  var out = Buffer.allocUnsafe(outLen);
  rtcpPacket.copy(out, 0, 0, headerLen);
  encPayload.copy(out, headerLen);
  out.writeUInt32BE((0x80000000 | index) >>> 0, rtcpPacket.length);

  // HMAC covers encrypted packet + index (everything before the tag)
  var hmac = crypto.createHmac('sha1', this._encRtcpAuth);
  hmac.update(out.subarray(0, rtcpPacket.length + 4));
  hmac.digest().copy(out, rtcpPacket.length + 4, 0, AUTH_TAG_LEN);

  return out;
};

/**
 * Decrypt an SRTCP packet → RTCP packet.
 * @param {Buffer} srtcpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.decryptRtcp = function (srtcpPacket) {
  if (!srtcpPacket || srtcpPacket.length < 8 + 4 + AUTH_TAG_LEN) return null;

  var authTagStart = srtcpPacket.length - AUTH_TAG_LEN;
  var indexStart = authTagStart - 4;

  var authenticated = srtcpPacket.subarray(0, authTagStart);
  var authTag = srtcpPacket.subarray(authTagStart);
  var indexWord = srtcpPacket.readUInt32BE(indexStart);
  var isEncrypted = !!(indexWord & 0x80000000);
  var index = indexWord & 0x7FFFFFFF;

  // Verify auth
  var hmac = crypto.createHmac('sha1', this._decRtcpAuth);
  hmac.update(authenticated);
  var expectedTag = hmac.digest().subarray(0, AUTH_TAG_LEN);
  if (!_constantTimeEquals(authTag, expectedTag)) return null;

  // Basic replay check — reject if we've seen this index before
  if (this._srtcpSeenIndices[index]) return null;
  this._srtcpSeenIndices[index] = true;
  var seenKeys = Object.keys(this._srtcpSeenIndices);
  if (seenKeys.length > 1024) {
    // Evict oldest half
    seenKeys.sort(function (a, b) { return (+a) - (+b); });
    for (var i = 0; i < 512; i++) delete this._srtcpSeenIndices[seenKeys[i]];
  }

  var ssrc = srtcpPacket.readUInt32BE(4);

  if (!isEncrypted) {
    // E flag clear — packet was authenticated only, not encrypted
    return Buffer.from(srtcpPacket.subarray(0, indexStart));
  }

  var headerLen = 8;
  _buildRtcpIv(this._ivScratch, this._decRtcpSalt, ssrc, index);
  var encPayload = srtcpPacket.subarray(headerLen, indexStart);
  var decPayload = _aesCmEncrypt(this._decRtcpKey, this._ivScratch, encPayload);

  var out = Buffer.allocUnsafe(headerLen + decPayload.length);
  srtcpPacket.copy(out, 0, 0, headerLen);
  decPayload.copy(out, headerLen);
  return out;
};


// ═══════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════

/**
 * Determine RTP header length including CSRC list and extension block.
 */
function _rtpHeaderLength(buf) {
  var cc = buf[0] & 0x0F;
  var hasExtension = !!(buf[0] & 0x10);
  var headerLen = 12 + cc * 4;

  if (hasExtension && headerLen + 4 <= buf.length) {
    var extWords = buf.readUInt16BE(headerLen + 2);
    headerLen += 4 + extWords * 4;
  }
  return headerLen;
}

/**
 * Build the RTP IV into `iv` (RFC 3711 §4.1.1):
 *   IV = (ssrc at bytes 4-7) || (packet_index as 48-bit at bytes 8-13)
 * XOR'd with the session salt.
 *
 * Caller provides the IV buffer (16 bytes) so we can reuse a scratch
 * across every call — avoids allocation on the hot path.
 */
function _buildRtpIv(iv, salt, ssrc, packetIndex) {
  // Start from salt (14 bytes), zero the last 2
  salt.copy(iv, 0, 0, 14);
  iv[14] = 0;
  iv[15] = 0;

  // XOR with SSRC at bytes 4-7
  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8) & 0xFF;
  iv[7] ^= ssrc & 0xFF;

  // XOR with 48-bit packet index at bytes 8-13
  var hi = (packetIndex / 0x10000) >>> 0;
  var lo = packetIndex & 0xFFFF;
  iv[8]  ^= (hi >>> 8) & 0xFF;
  iv[9]  ^= hi & 0xFF;
  // iv[10], iv[11] = 0 ^ salt[10..11] = salt[10..11] — already set above
  iv[12] ^= (lo >>> 8) & 0xFF;
  iv[13] ^= lo & 0xFF;
}

function _buildRtcpIv(iv, salt, ssrc, index) {
  // RFC 3711 §4.1.1 — SRTCP IV construction:
  //   IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  //
  // Where i is the 31-bit SRTCP index, and i*2^16 means the index value
  // shifted LEFT 16 bits in a 128-bit integer. Decomposing that to bytes
  // (big-endian, 16-byte buffer):
  //
  //   [0..3]   = 0 0 0 0         (zero padding)
  //   [4..7]   = SSRC (big-endian)
  //   [8..11]  = ROC = i >> 16   (upper 16 bits of 31-bit index, zero-padded to 4 bytes)
  //   [12..13] = SEQ = i & 0xFFFF (lower 16 bits of index)
  //   [14..15] = 0 0             (counter start — CTR mode increments here)
  //
  // This matches the Cisco libsrtp / pion reference implementations. Note that
  // while RFC 3711's formula i*2^16 places the full 31-bit index at bits
  // 16..46 from the LSB of the 128-bit value, the canonical decomposition
  // splits i into ROC (upper 15 bits, padded to 32) at bytes 8-11 and SEQ
  // (lower 16 bits) at bytes 12-13. The salt is XOR'd into bytes 0..13.
  salt.copy(iv, 0, 0, 14);
  iv[14] = 0;
  iv[15] = 0;

  // XOR SSRC into bytes 4..7
  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8)  & 0xFF;
  iv[7] ^=  ssrc         & 0xFF;

  // SRTCP index is 31 bits (strip E flag if set)
  var idx = index & 0x7FFFFFFF;
  var roc = (idx >>> 16) & 0xFFFF;  // upper 15 bits of 31-bit index
  var seq = idx & 0xFFFF;            // lower 16 bits

  // XOR ROC into bytes 8..11 (as 32-bit big-endian, zero-padded above the 15 bits)
  iv[8]  ^= 0;
  iv[9]  ^= 0;
  iv[10] ^= (roc >>> 8) & 0xFF;
  iv[11] ^=  roc        & 0xFF;

  // XOR SEQ into bytes 12..13
  iv[12] ^= (seq >>> 8) & 0xFF;
  iv[13] ^=  seq        & 0xFF;
}

/**
 * AES-128-CM keystream applied to a payload.
 *
 * SRTP's AES-CM mode (RFC 3711 §4.1.1) is identical in behavior to Node's
 * built-in AES-CTR: both XOR the plaintext with a keystream generated by
 * AES-ECB'ing an incrementing counter. The only semantic difference is how
 * the counter is initialized — SRTP computes the IV from (ssrc, packetIndex,
 * salt), but that's exactly what gets passed as the "IV" to aes-128-ctr.
 *
 * Using the native cipher gives us a ~15× speedup over a hand-rolled ECB
 * loop (openssl in C vs. JS object-churn per 16-byte block).
 */
function _aesCmEncrypt(key, iv, payload) {
  var cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
  var out = cipher.update(payload);
  cipher.final();
  return out;
}

/**
 * SRTP session key derivation (RFC 3711 §4.3).
 *
 * Derivation:
 *   x        = masterSalt (14 bytes) XOR (label at byte 7, 0 elsewhere)
 *   IV       = x || 0x0000                 (pad with 2 zero bytes → 16 bytes)
 *   output   = AES-CTR(masterKey, IV, 0)   (encrypt `length` zero bytes)
 *
 * Node's aes-128-ctr increments the IV's low bytes as the counter, which
 * matches RFC 3711 because our IV ends in `0x0000` — the counter starts at 0.
 */
function _deriveKey(masterKey, masterSalt, label, length) {
  var iv = Buffer.alloc(16);
  masterSalt.copy(iv, 0);   // bytes 0..13: salt (label XOR applied below)
  iv[7] ^= label;            // byte 7: salt[7] XOR label
  // bytes 14..15 stay zero — this is the counter start

  var cipher = crypto.createCipheriv('aes-128-ctr', masterKey, iv);
  var derived = cipher.update(Buffer.alloc(length));
  cipher.final();
  return derived.subarray(0, length);
}

/**
 * Constant-time buffer comparison — protects against timing attacks on auth tag.
 */
function _constantTimeEquals(a, b) {
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}


export { SrtpSession, AUTH_TAG_LEN };
export default SrtpSession;
