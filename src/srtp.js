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

// Crypto from cryptographic-primitives, which picks native or pure JavaScript
import { aes_gcm_create, aes_ctr_sync } from 'cryptographic-primitives/aes.js';
import { hmac_sync } from 'cryptographic-primitives/hmac.js';
import { sha1_sync } from 'cryptographic-primitives/sha1.js';


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

var PROFILE_CM      = 'AES_CM_128_HMAC_SHA1_80';
var PROFILE_GCM     = 'AEAD_AES_128_GCM';
var PROFILE_GCM_256 = 'AEAD_AES_256_GCM';

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
    if (p === 0x0008) return PROFILE_GCM_256;
    throw new Error('SrtpSession: unsupported DTLS-SRTP profile number 0x' +
      p.toString(16).padStart(4, '0') +
      ' (supported: 0x0001 SRTP_AES128_CM_HMAC_SHA1_80, 0x0007 SRTP_AEAD_AES_128_GCM, 0x0008 SRTP_AEAD_AES_256_GCM)');
  }
  var s = String(p);
  if (s === PROFILE_CM || s === 'SRTP_AES128_CM_HMAC_SHA1_80') return PROFILE_CM;
  if (s === PROFILE_GCM || s === 'SRTP_AEAD_AES_128_GCM') return PROFILE_GCM;
  if (s === PROFILE_GCM_256 || s === 'SRTP_AEAD_AES_256_GCM') return PROFILE_GCM_256;
  throw new Error('SrtpSession: unknown profile "' + s +
    '" (supported: ' + PROFILE_CM + ', ' + PROFILE_GCM + ', ' + PROFILE_GCM_256 + ')');
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
  this._gcm = (profile === PROFILE_GCM || profile === PROFILE_GCM_256);
  // RFC 7714 §11.2: AEAD_AES_256_GCM = same construction, 32-byte keys,
  // KDF runs AES-256-CTR keyed by the 32-byte master key. Everything
  // else (12-byte salt, 16-byte tag, IV formation) is identical to 128.
  this._keyLen = (profile === PROFILE_GCM_256) ? 32 : SESSION_KEY_LEN;
  this._tagLen = this._gcm ? GCM_TAG_LEN : AUTH_TAG_LEN;
  this._replayEnabled = !(opts && opts.replayProtection === false);

  var wantSalt = this._gcm ? GCM_SALT_LEN : CM_SALT_LEN;
  if (encMasterKey.length !== this._keyLen) throw new Error('SrtpSession: masterKey must be ' + this._keyLen + ' bytes for ' + profile);
  if (decMasterKey.length !== this._keyLen) throw new Error('SrtpSession: masterKey must be ' + this._keyLen + ' bytes for ' + profile);
  if (encMasterSalt.length !== wantSalt || decMasterSalt.length !== wantSalt) {
    throw new Error('SrtpSession: masterSalt must be ' + wantSalt + ' bytes for ' + profile);
  }

  var saltLen = wantSalt;

  // Derive session keys. RFC 7714 §11.1: with a 96-bit master salt the
  // RFC 3711 KDF is used unchanged, with the salt zero-padded on the
  // right to 112 bits (libsrtp does exactly this).
  var encKdfSalt = _kdfSalt(encMasterSalt);
  var decKdfSalt = _kdfSalt(decMasterSalt);

  this._encRtpKey   = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTP_CIPHER,  this._keyLen);
  this._encRtpSalt  = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTP_SALT,    saltLen);
  this._encRtcpKey  = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTCP_CIPHER, this._keyLen);
  this._encRtcpSalt = _deriveKey(encMasterKey, encKdfSalt, LABEL_RTCP_SALT,   saltLen);

  this._decRtpKey   = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTP_CIPHER,  this._keyLen);
  this._decRtpSalt  = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTP_SALT,    saltLen);
  this._decRtcpKey  = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTCP_CIPHER, this._keyLen);
  this._decRtcpSalt = _deriveKey(decMasterKey, decKdfSalt, LABEL_RTCP_SALT,   saltLen);

  if (this._gcm) {
    // One keyed AES-GCM context per session key, made once
    this._encRtpGcm  = aes_gcm_create(this._encRtpKey);
    this._decRtpGcm  = aes_gcm_create(this._decRtpKey);
    this._encRtcpGcm = aes_gcm_create(this._encRtcpKey);
    this._decRtcpGcm = aes_gcm_create(this._decRtcpKey);
  } else {
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
  this._srtcpRecvState = {};    // ssrc → { maxIndex, replay } — SRTCP replay window per SSRC

  // Scratch buffers reused across every encrypt/decrypt call — avoids
  // allocating them on every packet. Safe because
  // we're single-threaded and each method finishes with the scratch
  // before returning.
  //
  // ⚠ WHAT GOES TO cryptographic-primitives IS A PLAIN Uint8Array, made
  //   once: the library turns every Buffer argument into a new Uint8Array
  //   over the same bytes, and each Buffer subarray() is an object of its
  //   own. Per packet those views were most of the garbage the young-generation
  //   GC collected (measured: ~1.2 KB a packet, about 0.6 µs of GC).
  this._ivScratch = new Uint8Array(16);         // CM uses 16; GCM uses first 12
  this._iv12 = this._ivScratch.subarray(0, 12);
  this._macScratch = null;                      // CM receive: authenticated || ROC, grown as needed
  this._aadScratch = Buffer.allocUnsafe(12);   // SRTCP GCM AAD: header(8) + index(4)
  this._aadView = _view(this._aadScratch, 0, 12);
}


// ═══════════════════════════════════════════════════════════════════
//  RTP protection
// ═══════════════════════════════════════════════════════════════════

/**
 * RFC 3711 §3.3.1 / libsrtp srtp_index_guess: the ROC that puts `seq`
 * closest to `maxIndex` (the highest index seen on this SSRC). Used by
 * both directions so sender and receiver agree on reordered packets.
 */
function _guessRoc(maxIndex, seq) {
  var roc = Math.floor(maxIndex / 0x10000);
  var lastSeq = maxIndex & 0xFFFF;
  if (lastSeq < 0x8000) {
    return (seq - lastSeq > 0x8000) ? Math.max(0, roc - 1) : roc;
  }
  return (lastSeq - 0x8000 > seq) ? (roc + 1) >>> 0 : roc;
}

/**
 * Encrypt an RTP packet → SRTP packet.
 * @param {Buffer} rtpPacket
 * @returns {Buffer|null}
 */
SrtpSession.prototype.encryptRtp = function (rtpPacket) {
  if (!rtpPacket || rtpPacket.length < 12) return null;
  // Before the index is taken: a packet whose header runs past its end was
  // refused after its SSRC's send state had moved to its sequence number.
  var headerLen = _rtpHeaderLength(rtpPacket);
  if (headerLen > rtpPacket.length) return null;

  var seq  = rtpPacket.readUInt16BE(2);
  var ssrc = rtpPacket.readUInt32BE(8);

  // Sender index: guessed exactly like the receiver does (the ROC that puts
  // seq nearest the highest index sent so far), and maxIndex only moves
  // forward. Before, the ROC came from maxIndex's low bits with a one-way
  // "wrap" test and maxIndex was then raised to whatever index that gave:
  // one packet forwarded out of order across the wrap (65535 after 1) got
  // ROC+1, became the new maximum, and every later packet got ROC+2 — the
  // receiver could never decrypt the stream again.
  var st = this._sendState[ssrc];
  var roc, index;
  if (st) {
    roc = _guessRoc(st.maxIndex, seq);
    index = roc * 0x10000 + seq;
    if (index > st.maxIndex) st.maxIndex = index;
  } else {
    roc = 0;
    index = seq;
    this._sendState[ssrc] = { maxIndex: index };
  }

  var len = rtpPacket.length;

  if (this._gcm) {
    // ── RFC 7714 §8: AES-GCM ── the packet sealed into its output, which
    // holds the header (the AAD) first
    _buildGcmRtpIv(this._ivScratch, this._encRtpSalt, ssrc, roc, seq);
    var outG = Buffer.allocUnsafe(len + GCM_TAG_LEN);
    rtpPacket.copy(outG, 0, 0, len);
    this._encRtpGcm.encrypt_into_sync(outG, headerLen, this._iv12, _view(outG, headerLen, len), _view(outG, 0, headerLen));
    return outG;
  }

  // ── RFC 3711: AES-128-CM + HMAC-SHA1-80 ──
  _buildRtpIv(this._ivScratch, this._encRtpSalt, ssrc, index);
  var encPayload = _aesCmEncrypt(this._encRtpKey, this._ivScratch, _view(rtpPacket, headerLen, len));

  // Assemble output: header (clear) | encrypted payload | auth tag
  var out = Buffer.allocUnsafe(len + AUTH_TAG_LEN);
  rtpPacket.copy(out, 0, 0, headerLen);
  out.set(encPayload, headerLen);

  // HMAC-SHA1 over (header + encrypted || ROC): the ROC goes where the tag
  // will be, and the tag overwrites it
  out.writeUInt32BE(roc >>> 0, len);
  _copyTag(hmac_sync(sha1_sync, this._encRtpAuth, _view(out, 0, len + 4)), out, len);

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
  var guessRoc = st ? _guessRoc(st.maxIndex, seq) : 0;
  var index = guessRoc * 0x10000 + seq;

  var headerLen = _rtpHeaderLength(srtpPacket);
  var plaintext = null;

  if (this._gcm) {
    // ── RFC 7714 §8: AES-GCM ──
    var ctStart = headerLen;
    var tagStart = srtpPacket.length - GCM_TAG_LEN;
    if (tagStart < ctStart) return null;

    _buildGcmRtpIv(this._ivScratch, this._decRtpSalt, ssrc, guessRoc, seq);
    plaintext = Buffer.allocUnsafe(tagStart);
    // null when the tag does not verify
    if (this._decRtpGcm.decrypt_into_sync(plaintext, headerLen, this._iv12, _view(srtpPacket, ctStart, srtpPacket.length),
                                          _view(srtpPacket, 0, headerLen)) === null) return null;
    srtpPacket.copy(plaintext, 0, 0, headerLen);
  } else {
    // ── RFC 3711: verify HMAC, then AES-CM decrypt ──
    var authTagStart = srtpPacket.length - AUTH_TAG_LEN;
    // A header (CC / extension length) that runs into the tag: the GCM branch
    // above already refused it, this one went on to _view() with a negative
    // length and threw a RangeError — out of handleIncomingRtp, from one
    // packet of an authenticated peer.
    if (headerLen > authTagStart) return null;

    // HMAC-SHA1 over (authenticated || ROC), assembled in a reused buffer
    var macIn = this._macScratch;
    if (!macIn || macIn.length < authTagStart + 4) {
      macIn = this._macScratch = Buffer.allocUnsafe(Math.max(authTagStart + 4, 1500));
      this._macView = _view(macIn, 0, macIn.length);
    }
    srtpPacket.copy(macIn, 0, 0, authTagStart);
    macIn.writeUInt32BE(guessRoc >>> 0, authTagStart);
    var mac = hmac_sync(sha1_sync, this._decRtpAuth, this._macView.subarray(0, authTagStart + 4));
    if (!_tagMatches(mac, srtpPacket, authTagStart)) return null;

    _buildRtpIv(this._ivScratch, this._decRtpSalt, ssrc, index);
    var decPayload = _aesCmEncrypt(this._decRtpKey, this._ivScratch, _view(srtpPacket, headerLen, authTagStart));

    plaintext = Buffer.allocUnsafe(headerLen + decPayload.length);
    srtpPacket.copy(plaintext, 0, 0, headerLen);
    plaintext.set(decPayload, headerLen);
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
  var payload = _view(rtcpPacket, headerLen, rtcpPacket.length);
  var indexWord = (0x80000000 | index) >>> 0;

  if (this._gcm) {
    // ── RFC 7714 §9: layout = header(8) | ciphertext | tag(16) | E+index(4)
    //    AAD = header(8) || E+index word.
    _buildGcmRtcpIv(this._ivScratch, this._encRtcpSalt, ssrc, index);
    rtcpPacket.copy(this._aadScratch, 0, 0, 8);
    this._aadScratch.writeUInt32BE(indexWord, 8);

    var outG = Buffer.allocUnsafe(8 + payload.length + GCM_TAG_LEN + 4);
    rtcpPacket.copy(outG, 0, 0, 8);
    this._encRtcpGcm.encrypt_into_sync(outG, 8, this._iv12, payload, this._aadView);
    outG.writeUInt32BE(indexWord, 8 + payload.length + GCM_TAG_LEN);
    return outG;
  }

  _buildRtcpIv(this._ivScratch, this._encRtcpSalt, ssrc, index);
  var encPayload = _aesCmEncrypt(this._encRtcpKey, this._ivScratch, payload);

  // Single allocation for the full output: header | encrypted | E+index | tag
  var outLen = rtcpPacket.length + 4 + AUTH_TAG_LEN;
  var out = Buffer.allocUnsafe(outLen);
  rtcpPacket.copy(out, 0, 0, headerLen);
  out.set(encPayload, headerLen);
  out.writeUInt32BE(indexWord, rtcpPacket.length);

  // HMAC covers encrypted packet + index (everything before the tag)
  _copyTag(hmac_sync(sha1_sync, this._encRtcpAuth, _view(out, 0, rtcpPacket.length + 4)), out, rtcpPacket.length + 4);

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

  var indexWord = srtcpPacket.readUInt32BE(indexStart);
  var isEncrypted = !!(indexWord & 0x80000000);
  var index = indexWord & 0x7FFFFFFF;

  // Verify auth
  var mac = hmac_sync(sha1_sync, this._decRtcpAuth, _view(srtcpPacket, 0, authTagStart));
  if (!_tagMatches(mac, srtcpPacket, authTagStart)) return null;

  var ssrc = srtcpPacket.readUInt32BE(4);
  if (!this._srtcpReplayOk(ssrc, index)) return null;

  if (!isEncrypted) {
    // E flag clear — packet was authenticated only, not encrypted
    return Buffer.from(srtcpPacket.subarray(0, indexStart));
  }

  var headerLen = 8;
  _buildRtcpIv(this._ivScratch, this._decRtcpSalt, ssrc, index);
  var decPayload = _aesCmEncrypt(this._decRtcpKey, this._ivScratch, _view(srtcpPacket, headerLen, indexStart));

  var out = Buffer.allocUnsafe(headerLen + decPayload.length);
  srtcpPacket.copy(out, 0, 0, headerLen);
  out.set(decPayload, headerLen);
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
  srtcpPacket.copy(this._aadScratch, 0, 0, 8);
  this._aadScratch.writeUInt32BE(indexWord, 8);

  if (!isEncrypted) {
    // E=0, tagged but not encrypted (RFC 7714 §9.3, the §17.3 vector): the
    // whole RTCP packet and the ESRTCP word are the AAD, the plaintext is
    // empty — packet | tag | ESRTCP. (Every such packet was refused, "WebRTC
    // always encrypts RTCP"; a sender may choose not to, RFC 3711 §3.4.)
    var aad0 = Buffer.allocUnsafe(tagStart + 4);
    srtcpPacket.copy(aad0, 0, 0, tagStart);
    aad0.writeUInt32BE(indexWord, tagStart);
    if (this._decRtcpGcm.decrypt_sync(this._iv12, _view(srtcpPacket, tagStart, indexStart), _view(aad0, 0, aad0.length)) === null) return null;
    if (!this._srtcpReplayOk(ssrc, index)) return null;
    return Buffer.from(srtcpPacket.subarray(0, tagStart));
  }
  var out = Buffer.allocUnsafe(tagStart);
  // null when the tag does not verify
  if (this._decRtcpGcm.decrypt_into_sync(out, 8, this._iv12, _view(srtcpPacket, 8, indexStart), this._aadView) === null) return null;
  if (!this._srtcpReplayOk(ssrc, index)) return null;
  srtcpPacket.copy(out, 0, 0, 8);
  return out;
};

/**
 * SRTCP replay (RFC 3711 §3.3.2): the SRTCP index is counted per sending
 * SSRC, so the window is too — the same 128-entry bitmap as SRTP.
 *
 * It used to be one set of indices for the whole session. A peer sending
 * RTCP from more than one SSRC (a browser: one per audio and video sender,
 * each counting from its own start) collided on every index, and all but the
 * first SSRC's RTCP — reports, NACKs, PLIs, transport-cc feedback — was
 * dropped as "replayed". And its evict-half-when-full step forgot indices,
 * which then passed as new: replays of older packets were accepted.
 */
SrtpSession.prototype._srtcpReplayOk = function (ssrc, index) {
  if (!this._replayEnabled) return true;
  var st = this._srtcpRecvState[ssrc];
  if (!st) st = this._srtcpRecvState[ssrc] = { maxIndex: -1, replay: new Uint32Array(4) };
  return _replayCheckAndUpdate(st, index);
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
  var saltLen = (p === PROFILE_GCM || p === PROFILE_GCM_256) ? GCM_SALT_LEN : CM_SALT_LEN;
  var keyLen  = (p === PROFILE_GCM_256) ? 32 : SESSION_KEY_LEN;
  return 2 * keyLen + 2 * saltLen;   // CM: 60, GCM-128: 56, GCM-256: 88
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
  var keyLen = (p === PROFILE_GCM_256) ? 32 : SESSION_KEY_LEN;
  var saltLen = (p === PROFILE_GCM || p === PROFILE_GCM_256) ? GCM_SALT_LEN : CM_SALT_LEN;
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
  for (var i = 0; i < 14; i++) iv[i] = salt[i];
  iv[14] = 0;
  iv[15] = 0;

  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8) & 0xFF;
  iv[7] ^= ssrc & 0xFF;

  // The 48-bit index is ROC (32 bits) || SEQ (16 bits), times 2^16: the
  // ROC takes bytes 8-11, the SEQ bytes 12-13. (The ROC was written to
  // bytes 8-9, 16 bits up: every packet after the first seq wrap was
  // encrypted with a keystream libsrtp and browsers do not use.)
  var hi = (packetIndex / 0x10000) >>> 0;
  var lo = packetIndex & 0xFFFF;
  iv[8]  ^= (hi >>> 24) & 0xFF;
  iv[9]  ^= (hi >>> 16) & 0xFF;
  iv[10] ^= (hi >>> 8) & 0xFF;
  iv[11] ^= hi & 0xFF;
  iv[12] ^= (lo >>> 8) & 0xFF;
  iv[13] ^= lo & 0xFF;
}

function _buildRtcpIv(iv, salt, ssrc, index) {
  // See RFC 3711 §4.1.1 SRTCP IV — decomposition matches libsrtp/pion.
  for (var i = 0; i < 14; i++) iv[i] = salt[i];
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
 * AES-128-CM keystream applied to a payload (AES-CTR).
 */
function _aesCmEncrypt(key, iv, payload) {
  return aes_ctr_sync(key, iv, payload);
}

/** A plain Uint8Array over buf[start..end) (see _ivScratch for why not a Buffer view). */
function _view(buf, start, end) {
  return new Uint8Array(buf.buffer, buf.byteOffset + start, end - start);
}

/** The 80-bit tag: the first AUTH_TAG_LEN bytes of `mac`, written at out[at..]. */
function _copyTag(mac, out, at) {
  for (var i = 0; i < AUTH_TAG_LEN; i++) out[at + i] = mac[i];
}

/**
 * Does the packet's tag at pkt[at..] match the first AUTH_TAG_LEN bytes of
 * `mac`? In constant time, compared where the bytes are - no view of either.
 */
function _tagMatches(mac, pkt, at) {
  if (pkt.length - at !== AUTH_TAG_LEN) return false;
  var diff = 0;
  for (var i = 0; i < AUTH_TAG_LEN; i++) diff |= mac[i] ^ pkt[at + i];
  return diff === 0;
}

/**
 * SRTP session key derivation (RFC 3711 §4.3).
 */
function _deriveKey(masterKey, masterSalt, label, length) {
  var iv = Buffer.alloc(16);
  masterSalt.copy(iv, 0);   // bytes 0..13: salt (label XOR applied below)
  iv[7] ^= label;            // byte 7: salt[7] XOR label
  // bytes 14..15 stay zero — this is the counter start

  // AES-128-CTR or AES-256-CTR, by the master key's length
  var derived = aes_ctr_sync(_view(masterKey, 0, masterKey.length), new Uint8Array(iv), new Uint8Array(length <= 16 ? 16 : 32));
  return derived.slice(0, length);   // a plain Uint8Array: see _ivScratch
}

export { SrtpSession, AUTH_TAG_LEN, GCM_TAG_LEN, PROFILE_CM, PROFILE_GCM, PROFILE_GCM_256 };
export default SrtpSession;
