// src/srtp.js
// SRTP encrypt/decrypt — RFC 3711 (AES-128-CM + HMAC-SHA1-80)
//                       + RFC 7714 (AEAD AES-128-GCM).
/**
 * srtp — Secure RTP.
 *
 * Profiles:
 *   'AES_CM_128_HMAC_SHA1_80' (default) — AES-128-CM cipher, HMAC-SHA1-80
 *       auth tag (10 bytes). Master salt: 14 bytes. RFC 3711.
 *   'AEAD_AES_128_GCM' — AES-128-GCM AEAD, 16-byte tag, no separate auth
 *       key. Master salt: 12 bytes. RFC 7714. This is what Chrome offers
 *       first in DTLS-SRTP negotiation.
 *
 * Security features (both profiles):
 *   - Per-SSRC ROC (rollover counter) tracking with libwebrtc-style index
 *     guessing, so late packets that straddle a seq-number wraparound are
 *     still decrypted with the correct ROC.
 *   - RFC 3711 §3.3.2 replay protection: a 128-entry sliding window per
 *     SSRC rejects replayed RTP packets. SRTCP has index-based replay
 *     protection. Enabled by default; pass { replayProtection: false }
 *     to disable (e.g. for offline decryption of capture files).
 *
 * Construction forms:
 *
 *   // Symmetric (SDES, RTSP, HomeKit — same key both ways):
 *   new SrtpSession(masterKey, masterSalt)
 *   new SrtpSession(masterKey, masterSalt, { profile, replayProtection })
 *
 *   // Options-object symmetric (same as above, named fields):
 *   new SrtpSession({ profile, masterKey, masterSalt, replayProtection })
 *
 *   // Duplex (WebRTC / DTLS-SRTP — separate keys per direction):
 *   new SrtpSession({
 *     clientKey, serverKey, clientSalt, serverSalt, isServer,
 *     profile, replayProtection,
 *   })
 *
 * Usage:
 *   var srtp  = session.encryptRtp(rtpPacket);    // Buffer → Buffer
 *   var rtp   = session.decryptRtp(srtpPacket);   // null on auth fail / replay
 *   var srtcp = session.encryptRtcp(rtcpPacket);
 *   var rtcp  = session.decryptRtcp(srtcpPacket);
 *
 *   // Aliases (libsrtp-style naming):
 *   session.protectRtp / unprotectRtp / protectRtcp / unprotectRtcp
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

// AES-CM profile sizes
var AUTH_TAG_LEN     = 10;   // 80-bit HMAC-SHA1
var SESSION_KEY_LEN  = 16;   // AES-128
var CM_SALT_LEN      = 14;
var AUTH_KEY_LEN     = 20;   // HMAC-SHA1 key

// AES-GCM profile sizes (RFC 7714)
var GCM_TAG_LEN      = 16;
var GCM_SALT_LEN     = 12;

// Replay window size in packets (RFC 3711 recommends >= 64; libsrtp
// uses 128). Packets older than maxIndex - REPLAY_WINDOW are rejected.
var REPLAY_WINDOW = 128;

var PROFILE_CM  = 'AES_CM_128_HMAC_SHA1_80';
var PROFILE_GCM = 'AEAD_AES_128_GCM';

/**
 * Normalize a profile identifier to the canonical string form.
 *
 * Accepted spellings, all equivalent:
 *   - Canonical:      'AES_CM_128_HMAC_SHA1_80' | 'AEAD_AES_128_GCM'
 *   - DTLS-SRTP name: 'SRTP_AES128_CM_HMAC_SHA1_80' | 'SRTP_AEAD_AES_128_GCM'
 *     (the names TLS libraries surface from the use_srtp extension)
 *   - IANA number:    0x0001 | 0x0007
 *     (what DTLS implementations often hand back as the negotiated
 *      SRTPProtectionProfile — pass it straight through)
 */
function _normalizeProfile(p) {
  if (p == null) return PROFILE_CM;
  if (typeof p === 'number') {
    if (p === 0x0001) return PROFILE_CM;
    if (p === 0x0007) return PROFILE_GCM;
    throw new Error('SrtpSession: unsupported DTLS-SRTP profile number 0x' +
      p.toString(16).padStart(4, '0') +
      ' (supported: 0x0001 SRTP_AES128_CM_HMAC_SHA1_80, 0x0007 SRTP_AEAD_AES_128_GCM)');
  }
  var s = String(p);
  if (s === PROFILE_CM || s === 'SRTP_AES128_CM_HMAC_SHA1_80') return PROFILE_CM;
  if (s === PROFILE_GCM || s === 'SRTP_AEAD_AES_128_GCM') return PROFILE_GCM;
  throw new Error('SrtpSession: unknown profile "' + s +
    '" (supported: ' + PROFILE_CM + ', ' + PROFILE_GCM + ')');
}


// ═══════════════════════════════════════════════════════════════════
//  SrtpSession
// ═══════════════════════════════════════════════════════════════════

function SrtpSession(arg1, arg2, arg3) {
  if (!(this instanceof SrtpSession)) return new SrtpSession(arg1, arg2, arg3);

  var encMasterKey, encMasterSalt, decMasterKey, decMasterSalt;
  var opts = null;

  if (Buffer.isBuffer(arg1) || arg1 instanceof Uint8Array) {
    // Positional symmetric form: (masterKey, masterSalt[, opts])
    encMasterKey = decMasterKey = _asBuffer(arg1, 'masterKey');
    encMasterSalt = decMasterSalt = _asBuffer(arg2, 'masterSalt');
    opts = arg3 || null;
  } else if (arg1 && typeof arg1 === 'object') {
    opts = arg1;
    if (arg1.masterKey) {
      // Options-object symmetric form: { profile, masterKey, masterSalt }
      encMasterKey = decMasterKey = _asBuffer(arg1.masterKey, 'masterKey');
      encMasterSalt = decMasterSalt = _asBuffer(arg1.masterSalt, 'masterSalt');
    } else {
      // Duplex form — separate keys per direction
      if (!arg1.clientKey || !arg1.serverKey || !arg1.clientSalt || !arg1.serverSalt) {
        throw new Error('SrtpSession: duplex form requires clientKey, serverKey, clientSalt, serverSalt');
      }
      var isServer = !!arg1.isServer;
      encMasterKey  = _asBuffer(isServer ? arg1.serverKey  : arg1.clientKey, 'key');
      encMasterSalt = _asBuffer(isServer ? arg1.serverSalt : arg1.clientSalt, 'salt');
      decMasterKey  = _asBuffer(isServer ? arg1.clientKey  : arg1.serverKey, 'key');
      decMasterSalt = _asBuffer(isServer ? arg1.clientSalt : arg1.serverSalt, 'salt');
    }
  } else {
    throw new Error('SrtpSession: expected (key, salt) Buffers or an options object');
  }

  var profile = _normalizeProfile(opts && opts.profile);
  this.profile = profile;
  this._gcm = (profile === PROFILE_GCM);
  this._tagLen = this._gcm ? GCM_TAG_LEN : AUTH_TAG_LEN;
  this._replayEnabled = !(opts && opts.replayProtection === false);

  var wantSalt = this._gcm ? GCM_SALT_LEN : CM_SALT_LEN;
  if (encMasterKey.length !== 16) throw new Error('SrtpSession: masterKey must be 16 bytes');
  if (decMasterKey.length !== 16) throw new Error('SrtpSession: masterKey must be 16 bytes');
  if (encMasterSalt.length !== wantSalt || decMasterSalt.length !== wantSalt) {
    throw new Error('SrtpSession: masterSalt must be ' + wantSalt + ' bytes for ' + profile);
  }

  var saltLen = wantSalt;

  // Derive session keys. RFC 7714 §11.1: with a 96-bit master salt the
  // RFC 3711 KDF is used unchanged, with the salt zero-padded on the
  // right to 112 bits (libsrtp does exactly this).
  var encKdfSalt = _kdfSalt(encMasterSalt);
  var decKdfSalt = _kdfSalt(decMasterSalt);

  this._encRtpKey   = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTP_CIPHER,  SESSION_KEY_LEN);
  this._encRtpSalt  = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTP_SALT,    saltLen);
  this._encRtcpKey  = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTCP_CIPHER, SESSION_KEY_LEN);
  this._encRtcpSalt = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTCP_SALT,   saltLen);

  this._decRtpKey   = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTP_CIPHER,  SESSION_KEY_LEN);
  this._decRtpSalt  = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTP_SALT,    saltLen);
  this._decRtcpKey  = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTCP_CIPHER, SESSION_KEY_LEN);
  this._decRtcpSalt = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTCP_SALT,   saltLen);

  if (!this._gcm) {
    // Auth keys only exist in the CM profile — GCM is AEAD.
    this._encRtpAuth  = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTP_AUTH,  AUTH_KEY_LEN);
    this._encRtcpAuth = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTCP_AUTH, AUTH_KEY_LEN);
    this._decRtpAuth  = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTP_AUTH,  AUTH_KEY_LEN);
    this._decRtcpAuth = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTCP_AUTH, AUTH_KEY_LEN);
  }

  // Per-SSRC state, separated by direction:
  //   send side: { maxIndex }                      — monotonic sender index
  //   recv side: { maxIndex, replay: Uint32Array } — highest authenticated
  //     index + 128-bit sliding replay bitmap (bit d = "index maxIndex-d
  //     was seen"). Kept per direction so a symmetric-key session (same
  //     key both ways) doesn't have its receive window poisoned by its
  //     own transmissions.
  this._sendState = {};   // ssrc → { maxIndex }
  this._recvState = {};   // ssrc → { maxIndex, replay }

  // SRTCP has its own monotonically-increasing 31-bit index (not ssrc-keyed)
  this._srtcpSendIndex = 0;
  this._srtcpSeenIndices = {};  // replay protection for SRTCP
  this._srtcpSeenCount = 0;

  // Scratch buffers reused across every encrypt/decrypt call — avoids
  // allocating an IV and a ROC buffer on every packet. Safe because
  // we're single-threaded and each method finishes with the scratch
  // before returning.
  this._ivScratch = Buffer.allocUnsafe(16);   // CM uses 16; GCM uses first 12
  this._rocScratch = Buffer.allocUnsafe(4);
  this._aadScratch = Buffer.allocUnsafe(12);  // SRTCP GCM AAD: header(8) + index(4)
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

  // Sender index: strictly monotonic. Guess the ROC from the previous
  // max index — a wrap is detected when the new (roc, seq) pair with the
  // same ROC would move the index backwards past the wrap threshold.
  var st = this._sendState[ssrc];
  var roc, index;
  if (st) {
    roc = Math.floor(st.maxIndex / 0x10000);
    var lastSeq = st.maxIndex & 0xFFFF;
    if (seq < 0x8000 && lastSeq > 0xC000) roc = (roc + 1) >>> 0;
    index = roc * 0x10000 + seq;
    if (index > st.maxIndex) st.maxIndex = index;
  } else {
    roc = 0;
    index = seq;
    this._sendState[ssrc] = { maxIndex: index };
  }

  var headerLen = _rtpHeaderLength(rtpPacket);
  if (headerLen > rtpPacket.length) return null;
  var payload = rtpPacket.subarray(headerLen);

  if (this._gcm) {
    // ── RFC 7714 §8: AES-GCM ──
    _buildGcmRtpIv(this._ivScratch, this._encRtpSalt, ssrc, roc, seq);
    var iv = this._ivScratch.subarray(0, 12);
    var cipher = crypto.createCipheriv('aes-128-gcm', this._encRtpKey, iv, { authTagLength: GCM_TAG_LEN });
    cipher.setAAD(rtpPacket.subarray(0, headerLen));
    var ct = cipher.update(payload);
    cipher.final();
    var tag = cipher.getAuthTag();

    var outG = Buffer.allocUnsafe(rtpPacket.length + GCM_TAG_LEN);
    rtpPacket.copy(outG, 0, 0, headerLen);
    ct.copy(outG, headerLen);
    tag.copy(outG, headerLen + ct.length);
    return outG;
  }

  // ── RFC 3711: AES-128-CM + HMAC-SHA1-80 ──
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
 * Returns null if authentication fails or the packet is a replay.
 * @param {Buffer} srtpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.decryptRtp = function (srtpPacket) {
  var tagLen = this._tagLen;
  if (!srtpPacket || srtpPacket.length < 12 + tagLen) return null;

  var seq  = srtpPacket.readUInt16BE(2);
  var ssrc = srtpPacket.readUInt32BE(8);

  var st = this._recvState[ssrc];

  // Index guess (libsrtp srtp_index_guess): pick the ROC that puts the
  // incoming seq closest to the highest authenticated index. This makes
  // LATE packets that straddle a wraparound decrypt with roc-1 instead
  // of failing auth, and EARLY packets just past a wrap use roc+1.
  var guessRoc;
  if (st) {
    var roc = Math.floor(st.maxIndex / 0x10000);
    var lastSeq = st.maxIndex & 0xFFFF;
    if (lastSeq < 0x8000) {
      guessRoc = (seq - lastSeq > 0x8000) ? Math.max(0, roc - 1) : roc;
    } else {
      guessRoc = (lastSeq - 0x8000 > seq) ? (roc + 1) >>> 0 : roc;
    }
  } else {
    guessRoc = 0;
  }
  var index = guessRoc * 0x10000 + seq;

  var headerLen = _rtpHeaderLength(srtpPacket);
  var plaintext = null;

  if (this._gcm) {
    // ── RFC 7714 §8: AES-GCM ──
    var ctStart = headerLen;
    var tagStart = srtpPacket.length - GCM_TAG_LEN;
    if (tagStart < ctStart) return null;

    _buildGcmRtpIv(this._ivScratch, this._decRtpSalt, ssrc, guessRoc, seq);
    var iv = this._ivScratch.subarray(0, 12);
    try {
      var decipher = crypto.createDecipheriv('aes-128-gcm', this._decRtpKey, iv, { authTagLength: GCM_TAG_LEN });
      decipher.setAAD(srtpPacket.subarray(0, headerLen));
      decipher.setAuthTag(srtpPacket.subarray(tagStart));
      var pt = decipher.update(srtpPacket.subarray(ctStart, tagStart));
      decipher.final();   // throws on auth failure
      plaintext = Buffer.allocUnsafe(headerLen + pt.length);
      srtpPacket.copy(plaintext, 0, 0, headerLen);
      pt.copy(plaintext, headerLen);
    } catch (e) {
      return null;
    }
  } else {
    // ── RFC 3711: verify HMAC, then AES-CM decrypt ──
    var authTagStart = srtpPacket.length - AUTH_TAG_LEN;
    var authenticated = srtpPacket.subarray(0, authTagStart);
    var authTag = srtpPacket.subarray(authTagStart);

    this._rocScratch.writeUInt32BE(guessRoc >>> 0, 0);
    var hmac = crypto.createHmac('sha1', this._decRtpAuth);
    hmac.update(authenticated);
    hmac.update(this._rocScratch);
    var expectedTag = hmac.digest().subarray(0, AUTH_TAG_LEN);
    if (!_constantTimeEquals(authTag, expectedTag)) return null;

    var encPayload = authenticated.subarray(headerLen);
    _buildRtpIv(this._ivScratch, this._decRtpSalt, ssrc, index);
    var decPayload = _aesCmEncrypt(this._decRtpKey, this._ivScratch, encPayload);

    plaintext = Buffer.allocUnsafe(headerLen + decPayload.length);
    authenticated.copy(plaintext, 0, 0, headerLen);
    decPayload.copy(plaintext, headerLen);
  }

  // ── Auth passed. Replay check + window update (RFC 3711 §3.3.2). ──
  if (!st) {
    st = this._recvState[ssrc] = { maxIndex: -1, replay: new Uint32Array(4) };
  }
  if (this._replayEnabled) {
    if (!_replayCheckAndUpdate(st, index)) return null;
  } else if (index > st.maxIndex) {
    st.maxIndex = index;
  }

  return plaintext;
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
  var indexWord = (0x80000000 | index) >>> 0;

  if (this._gcm) {
    // ── RFC 7714 §9: layout = header(8) | ciphertext | tag(16) | E+index(4)
    //    AAD = header(8) || E+index word.
    _buildGcmRtcpIv(this._ivScratch, this._encRtcpSalt, ssrc, index);
    var iv = this._ivScratch.subarray(0, 12);
    rtcpPacket.copy(this._aadScratch, 0, 0, 8);
    this._aadScratch.writeUInt32BE(indexWord, 8);

    var cipher = crypto.createCipheriv('aes-128-gcm', this._encRtcpKey, iv, { authTagLength: GCM_TAG_LEN });
    cipher.setAAD(this._aadScratch);
    var ct = cipher.update(payload);
    cipher.final();
    var tag = cipher.getAuthTag();

    var outG = Buffer.allocUnsafe(8 + ct.length + GCM_TAG_LEN + 4);
    rtcpPacket.copy(outG, 0, 0, 8);
    ct.copy(outG, 8);
    tag.copy(outG, 8 + ct.length);
    outG.writeUInt32BE(indexWord, 8 + ct.length + GCM_TAG_LEN);
    return outG;
  }

  _buildRtcpIv(this._ivScratch, this._encRtcpSalt, ssrc, index);
  var encPayload = _aesCmEncrypt(this._encRtcpKey, this._ivScratch, payload);

  // Single allocation for the full output: header | encrypted | E+index | tag
  var outLen = rtcpPacket.length + 4 + AUTH_TAG_LEN;
  var out = Buffer.allocUnsafe(outLen);
  rtcpPacket.copy(out, 0, 0, headerLen);
  encPayload.copy(out, headerLen);
  out.writeUInt32BE(indexWord, rtcpPacket.length);

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
  if (this._gcm) return this._decryptRtcpGcm(srtcpPacket);
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

  if (!this._srtcpReplayOk(index)) return null;

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

SrtpSession.prototype._decryptRtcpGcm = function (srtcpPacket) {
  if (!srtcpPacket || srtcpPacket.length < 8 + GCM_TAG_LEN + 4) return null;

  var indexStart = srtcpPacket.length - 4;
  var tagStart = indexStart - GCM_TAG_LEN;
  var indexWord = srtcpPacket.readUInt32BE(indexStart);
  var isEncrypted = !!(indexWord & 0x80000000);
  var index = indexWord & 0x7FFFFFFF;
  var ssrc = srtcpPacket.readUInt32BE(4);

  _buildGcmRtcpIv(this._ivScratch, this._decRtcpSalt, ssrc, index);
  var iv = this._ivScratch.subarray(0, 12);
  srtcpPacket.copy(this._aadScratch, 0, 0, 8);
  this._aadScratch.writeUInt32BE(indexWord, 8);

  try {
    var decipher = crypto.createDecipheriv('aes-128-gcm', this._decRtcpKey, iv, { authTagLength: GCM_TAG_LEN });
    // For unencrypted-but-authenticated packets (E=0), the "ciphertext"
    // region is still covered by the tag as AAD-style data. We only
    // support E=1 for GCM here — WebRTC always encrypts RTCP.
    if (!isEncrypted) return null;
    decipher.setAAD(this._aadScratch);
    decipher.setAuthTag(srtcpPacket.subarray(tagStart, indexStart));
    var pt = decipher.update(srtcpPacket.subarray(8, tagStart));
    decipher.final();   // throws on auth failure
    if (!this._srtcpReplayOk(index)) return null;
    var out = Buffer.allocUnsafe(8 + pt.length);
    srtcpPacket.copy(out, 0, 0, 8);
    pt.copy(out, 8);
    return out;
  } catch (e) {
    return null;
  }
};

/** SRTCP replay: reject seen indices; bounded memory. */
SrtpSession.prototype._srtcpReplayOk = function (index) {
  if (!this._replayEnabled) return true;
  if (this._srtcpSeenIndices[index]) return false;
  this._srtcpSeenIndices[index] = true;
  if (++this._srtcpSeenCount > 1024) {
    // Evict oldest half
    var seenKeys = Object.keys(this._srtcpSeenIndices);
    seenKeys.sort(function (a, b) { return (+a) - (+b); });
    for (var i = 0; i < 512; i++) delete this._srtcpSeenIndices[seenKeys[i]];
    this._srtcpSeenCount = seenKeys.length - 512;
  }
  return true;
};


// ── libsrtp-style aliases ──
SrtpSession.prototype.protectRtp    = SrtpSession.prototype.encryptRtp;
SrtpSession.prototype.unprotectRtp  = SrtpSession.prototype.decryptRtp;
SrtpSession.prototype.protectRtcp   = SrtpSession.prototype.encryptRtcp;
SrtpSession.prototype.unprotectRtcp = SrtpSession.prototype.decryptRtcp;


// ═══════════════════════════════════════════════════════════════════
//  DTLS-SRTP integration helpers (RFC 5764 §4.2)
// ═══════════════════════════════════════════════════════════════════

/**
 * keyingMaterialLength — how many bytes to request from the DTLS
 * exporter for the given profile.
 *
 *   tls.exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp')
 *
 * Per RFC 5764 §4.2 the exporter output is
 *   2 × master_key_len + 2 × master_salt_len
 * which is 60 bytes for AES_CM_128_HMAC_SHA1_80 (2×16 + 2×14) and
 * 56 bytes for AEAD_AES_128_GCM (2×16 + 2×12).
 *
 * @param {string|number} profile — any spelling accepted by the constructor
 * @returns {number}
 */
SrtpSession.keyingMaterialLength = function (profile) {
  var p = _normalizeProfile(profile);
  var saltLen = (p === PROFILE_GCM) ? GCM_SALT_LEN : CM_SALT_LEN;
  return 2 * SESSION_KEY_LEN + 2 * saltLen;
};

/**
 * fromDtlsKeyingMaterial — build a duplex SrtpSession directly from the
 * DTLS exporter output, applying the RFC 5764 §4.2 slicing:
 *
 *   client_write_key || server_write_key || client_write_salt || server_write_salt
 *
 * (Both KEYS come before both SALTS — the classic off-by-a-field
 * mistake when hand-slicing.)
 *
 * Typical WebRTC server usage:
 *
 *   var profile = dtls.getNegotiatedSrtpProfile();     // string or number
 *   var len = SrtpSession.keyingMaterialLength(profile);
 *   var ekm = dtls.exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp');
 *   var srtp = SrtpSession.fromDtlsKeyingMaterial(profile, ekm, true);
 *
 * @param {string|number} profile  — negotiated profile (any accepted spelling)
 * @param {Buffer} keyingMaterial  — exporter output, exactly
 *                                    keyingMaterialLength(profile) bytes
 * @param {boolean} isServer       — true if WE are the DTLS server
 * @param {object} [opts]          — extra SrtpSession options
 *                                    (e.g. { replayProtection: false })
 * @returns {SrtpSession}
 */
SrtpSession.fromDtlsKeyingMaterial = function (profile, keyingMaterial, isServer, opts) {
  var p = _normalizeProfile(profile);
  var km = _asBuffer(keyingMaterial, 'keyingMaterial');
  var keyLen = SESSION_KEY_LEN;
  var saltLen = (p === PROFILE_GCM) ? GCM_SALT_LEN : CM_SALT_LEN;
  var want = 2 * keyLen + 2 * saltLen;
  if (km.length !== want) {
    throw new Error('SrtpSession.fromDtlsKeyingMaterial: expected ' + want +
      ' bytes of keying material for ' + p + ', got ' + km.length +
      ' (request keyingMaterialLength(profile) bytes from the DTLS exporter)');
  }
  var off = 0;
  var clientKey  = km.subarray(off, off + keyLen);  off += keyLen;
  var serverKey  = km.subarray(off, off + keyLen);  off += keyLen;
  var clientSalt = km.subarray(off, off + saltLen); off += saltLen;
  var serverSalt = km.subarray(off, off + saltLen);

  var merged = { clientKey: clientKey, serverKey: serverKey,
                 clientSalt: clientSalt, serverSalt: serverSalt,
                 isServer: !!isServer, profile: p };
  if (opts) {
    for (var k in opts) if (!(k in merged)) merged[k] = opts[k];
  }
  return new SrtpSession(merged);
};


// ═══════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════

function _asBuffer(b, name) {
  if (Buffer.isBuffer(b)) return b;
  if (b instanceof Uint8Array) return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  throw new Error('SrtpSession: ' + name + ' must be a Buffer');
}

/**
 * Sliding-window replay check (RFC 3711 §3.3.2 / RFC 2401 appendix C).
 *
 * st.replay is a 128-bit bitmap in a Uint32Array(4); bit d (d = 0..127)
 * means "index st.maxIndex - d has been seen". Called only after the
 * packet AUTHENTICATED — a forged packet must never advance the window.
 *
 * Returns true if the packet is new (and records it); false on replay
 * or too-old.
 */
function _replayCheckAndUpdate(st, index) {
  var bm = st.replay;
  if (st.maxIndex < 0) {
    st.maxIndex = index;
    bm[0] = 1; bm[1] = 0; bm[2] = 0; bm[3] = 0;
    return true;
  }
  if (index > st.maxIndex) {
    var shift = index - st.maxIndex;
    _bitmapShiftLeft(bm, shift);
    bm[0] |= 1;               // bit 0 = the new max itself
    st.maxIndex = index;
    return true;
  }
  var d = st.maxIndex - index;
  if (d >= REPLAY_WINDOW) return false;   // too old to track — reject
  var word = d >>> 5, bit = d & 31;
  if (bm[word] & (1 << bit)) return false; // replay
  bm[word] |= (1 << bit);
  return true;
}

/** Shift the 128-bit bitmap toward higher distances by `n` bits. */
function _bitmapShiftLeft(bm, n) {
  if (n >= 128) { bm[0] = 0; bm[1] = 0; bm[2] = 0; bm[3] = 0; return; }
  var wordShift = n >>> 5;
  var bitShift = n & 31;
  for (var i = 3; i >= 0; i--) {
    var src = i - wordShift;
    var v = (src >= 0) ? bm[src] : 0;
    if (bitShift !== 0) {
      v = (v << bitShift) | ((src - 1 >= 0) ? (bm[src - 1] >>> (32 - bitShift)) : 0);
    }
    bm[i] = v >>> 0;
  }
}

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
 * RFC 7714 §11.1: with a 96-bit (12-byte) master salt, the RFC 3711 KDF
 * is used with the salt zero-padded on the right to 112 bits (14 bytes).
 * 14-byte salts pass through unchanged.
 */
function _kdfSalt(masterSalt) {
  if (masterSalt.length === CM_SALT_LEN) return masterSalt;
  var padded = Buffer.alloc(CM_SALT_LEN);
  masterSalt.copy(padded, 0);
  return padded;
}

/**
 * Build the AES-CM RTP IV into `iv` (RFC 3711 §4.1.1):
 *   IV = (ssrc at bytes 4-7) || (packet_index as 48-bit at bytes 8-13)
 * XOR'd with the session salt.
 */
function _buildRtpIv(iv, salt, ssrc, packetIndex) {
  salt.copy(iv, 0, 0, 14);
  iv[14] = 0;
  iv[15] = 0;

  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8) & 0xFF;
  iv[7] ^= ssrc & 0xFF;

  var hi = (packetIndex / 0x10000) >>> 0;
  var lo = packetIndex & 0xFFFF;
  iv[8]  ^= (hi >>> 8) & 0xFF;
  iv[9]  ^= hi & 0xFF;
  iv[12] ^= (lo >>> 8) & 0xFF;
  iv[13] ^= lo & 0xFF;
}

function _buildRtcpIv(iv, salt, ssrc, index) {
  // See RFC 3711 §4.1.1 SRTCP IV — decomposition matches libsrtp/pion.
  salt.copy(iv, 0, 0, 14);
  iv[14] = 0;
  iv[15] = 0;

  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8)  & 0xFF;
  iv[7] ^=  ssrc         & 0xFF;

  var idx = index & 0x7FFFFFFF;
  var roc = (idx >>> 16) & 0xFFFF;
  var seq = idx & 0xFFFF;

  iv[10] ^= (roc >>> 8) & 0xFF;
  iv[11] ^=  roc        & 0xFF;
  iv[12] ^= (seq >>> 8) & 0xFF;
  iv[13] ^=  seq        & 0xFF;
}

/**
 * RFC 7714 §8.1 — 12-byte GCM RTP IV:
 *   [0,1] = 0 || [2..5] = SSRC || [6..9] = ROC || [10..11] = SEQ
 * XOR'd with the 12-byte session salt. Written into iv[0..11].
 */
function _buildGcmRtpIv(iv, salt, ssrc, roc, seq) {
  iv[0] = salt[0];
  iv[1] = salt[1];
  iv[2]  = salt[2]  ^ ((ssrc >>> 24) & 0xFF);
  iv[3]  = salt[3]  ^ ((ssrc >>> 16) & 0xFF);
  iv[4]  = salt[4]  ^ ((ssrc >>> 8)  & 0xFF);
  iv[5]  = salt[5]  ^ ( ssrc         & 0xFF);
  iv[6]  = salt[6]  ^ ((roc >>> 24) & 0xFF);
  iv[7]  = salt[7]  ^ ((roc >>> 16) & 0xFF);
  iv[8]  = salt[8]  ^ ((roc >>> 8)  & 0xFF);
  iv[9]  = salt[9]  ^ ( roc         & 0xFF);
  iv[10] = salt[10] ^ ((seq >>> 8)  & 0xFF);
  iv[11] = salt[11] ^ ( seq         & 0xFF);
}

/**
 * RFC 7714 §9.1 — 12-byte GCM SRTCP IV:
 *   [0,1] = 0 || [2..5] = SSRC || [6,7] = 0 || [8..11] = 31-bit index (E cleared)
 * XOR'd with the 12-byte session salt. Written into iv[0..11].
 */
function _buildGcmRtcpIv(iv, salt, ssrc, index) {
  var idx = index & 0x7FFFFFFF;
  iv[0] = salt[0];
  iv[1] = salt[1];
  iv[2]  = salt[2]  ^ ((ssrc >>> 24) & 0xFF);
  iv[3]  = salt[3]  ^ ((ssrc >>> 16) & 0xFF);
  iv[4]  = salt[4]  ^ ((ssrc >>> 8)  & 0xFF);
  iv[5]  = salt[5]  ^ ( ssrc         & 0xFF);
  iv[6]  = salt[6];
  iv[7]  = salt[7];
  iv[8]  = salt[8]  ^ ((idx >>> 24) & 0xFF);
  iv[9]  = salt[9]  ^ ((idx >>> 16) & 0xFF);
  iv[10] = salt[10] ^ ((idx >>> 8)  & 0xFF);
  iv[11] = salt[11] ^ ( idx         & 0xFF);
}

/**
 * AES-128-CM keystream applied to a payload (native aes-128-ctr).
 */
function _aesCmEncrypt(key, iv, payload) {
  var cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
  var out = cipher.update(payload);
  cipher.final();
  return out;
}

/**
 * SRTP session key derivation (RFC 3711 §4.3).
 */
function _deriveKey(masterKey, masterSalt, label, length) {
  var iv = Buffer.alloc(16);
  masterSalt.copy(iv, 0);   // bytes 0..13: salt (label XOR applied below)
  iv[7] ^= label;            // byte 7: salt[7] XOR label
  // bytes 14..15 stay zero — this is the counter start

  var cipher = crypto.createCipheriv('aes-128-ctr', masterKey, iv);
  var derived = cipher.update(Buffer.alloc(length <= 16 ? 16 : 32));
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


export { SrtpSession, AUTH_TAG_LEN, GCM_TAG_LEN, PROFILE_CM, PROFILE_GCM };
export default SrtpSession;
