/**
 * flexfec — Flexible Forward Error Correction for RTP.
 *
 * Implements draft-ietf-payload-flexible-fec-scheme-03 ("flexfec-03") —
 * deliberately the DRAFT, not RFC 8627: libwebrtc/Chrome ship flexfec-03
 * (`a=rtpmap:N flexfec-03/90000`) and the final RFC changed the header
 * layout, so -03 is what actually interoperates with browsers today.
 *
 * Model: every FEC packet is the XOR of a group of media packets. If
 * exactly ONE packet of the group is lost, it is rebuilt from the FEC
 * packet + the surviving members — no round trip, unlike NACK/RTX.
 * Overhead is 1/groupSize (e.g. 25% at groupSize 4) vs RED's 100%,
 * which is why FEC is the video-side tool and RED the audio-side one.
 *
 * Flexible-mask variant (R=0, F=0), single protected SSRC — the exact
 * shape libwebrtc sends. FEC rides on its OWN SSRC, negotiated in SDP.
 *
 *   FlexFecEncoder.protect(rtpBuffer)  → Buffer[] (FEC packets, usually 0-1)
 *   FlexFecDecoder.addMediaPacket(buf) → Buffer[] (recovered media packets)
 *   FlexFecDecoder.addFecPacket(buf)   → Buffer[] (recovered media packets)
 *
 * Mutable header extensions (`opts.extensions`, both sides): the XOR runs
 * over everything after the 12-byte fixed header, header extensions
 * included — but some extensions are written at SEND time, after the FEC
 * was computed: transport-cc, abs-send-time, toffset, and video-timing from
 * its pacer field on. libwebrtc's sender protects them while they are still
 * zero, and its FlexfecReceiver zeroes them in its copy of every media
 * packet before the XOR (RtpPacket::ZeroMutableExtensions; webrtc:7859).
 * Both sides here do the same given the negotiated ids — { id: uri }, as in
 * a=extmap. Without it, a packet recovered from Chrome's FEC had wrong bytes
 * wherever the extension layout differed within the group (video-timing is
 * on some packets only): its PAYLOAD came out corrupt (7 of 42 recoveries in
 * a capture from Chrome). The recovered packet carries those extensions as
 * zeros, as libwebrtc's does.
 */

var FIXED_HDR = 12;

// The extensions written after FEC is computed (see the top of the file),
// each with the offset in its value from which it is zeroed — libwebrtc's
// RtpPacket::ZeroMutableExtensions.
var MUTABLE_EXTENSIONS = {
  'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01': 0,
  'http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02': 0,
  'urn:ietf:params:rtp-hdrext:toffset': 0,
  'http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time': 0,
  'http://www.webrtc.org/experiments/rtp-hdrext/video-timing': 7,   // kPacerExitDeltaOffset
};

/** { id: uri } → { id: zero-from offset } for the mutable ones, or null. */
function _mutableIds(extensions) {
  if (!extensions) return null;
  var out = null;
  for (var id in extensions) {
    var from = MUTABLE_EXTENSIONS[extensions[id]];
    if (from == null) continue;
    (out = out || {})[+id] = from;
  }
  return out;
}

/** Length of an RTP packet's header: fixed part, CSRCs, extension block. -1 if it overruns. */
function _rtpHeaderLen(buf) {
  if (buf.length < FIXED_HDR) return -1;
  var len = FIXED_HDR + 4 * (buf[0] & 0x0F);
  if (buf[0] & 0x10) {
    if (len + 4 > buf.length) return -1;
    len += 4 + 4 * buf.readUInt16BE(len + 2);
  }
  return len <= buf.length ? len : -1;
}

/** A copy of buf with the mutable extensions zeroed (buf itself when there are none). */
function _zeroMutable(buf, mutable) {
  if (!mutable || !(buf[0] & 0x10)) return buf;
  var start = FIXED_HDR + 4 * (buf[0] & 0x0F);
  if (start + 4 > buf.length) return buf;
  var profile = buf.readUInt16BE(start);
  var end = start + 4 + 4 * buf.readUInt16BE(start + 2);
  if (end > buf.length) return buf;
  var twoByte = (profile & 0xFFF0) === 0x1000;      // RFC 8285 §4.3
  if (profile !== 0xBEDE && !twoByte) return buf;
  var out = null;
  var o = start + 4;
  while (o < end) {
    var id, len;
    if (twoByte) {
      id = buf[o];
      if (id === 0) { o++; continue; }               // padding
      if (o + 2 > end) break;
      len = buf[o + 1]; o += 2;
    } else {
      id = buf[o] >> 4;
      if (id === 0) { o++; continue; }               // padding
      if (id === 15) break;                          // reserved: stop
      len = (buf[o] & 0x0F) + 1; o += 1;
    }
    if (o + len > end) break;
    var from = mutable[id];
    if (from != null && from < len) {
      if (!out) out = Buffer.from(buf);
      out.fill(0, o + from, o + len);
    }
    o += len;
  }
  return out || buf;
}

function _u16(a, b) { return ((a << 8) | b) >>> 0; }
function _seqDiff(a, b) { return ((a - b) & 0xFFFF); }   // forward distance b→a

// ═══════════════════════════════════════════════════════════════════
//  Encoder
// ═══════════════════════════════════════════════════════════════════

/**
 * @param {object} opts
 * @param {number} opts.ssrc                     FEC stream SSRC (its own, from SDP)
 * @param {number} opts.payloadType              flexfec-03 payload type from SDP
 * @param {number} opts.protectedSsrc            the media SSRC being protected
 * @param {number} [opts.groupSize]              media packets per FEC packet — default 4, max 109
 * @param {number} [opts.initialSequenceNumber]  default random
 * @param {object} [opts.extensions]             negotiated header extensions, { id: uri }:
 *                                               the mutable ones are protected as zeros
 */
function FlexFecEncoder(opts) {
  if (!opts || typeof opts.ssrc !== 'number' || typeof opts.payloadType !== 'number' ||
      typeof opts.protectedSsrc !== 'number') {
    throw new Error('FlexFecEncoder: ssrc, payloadType, protectedSsrc required');
  }
  this._ssrc = opts.ssrc >>> 0;
  this._pt = opts.payloadType & 0x7F;
  this._protectedSsrc = opts.protectedSsrc >>> 0;
  this._groupSize = Math.min(109, Math.max(1, opts.groupSize || 4));
  this._seq = (opts.initialSequenceNumber != null)
    ? (opts.initialSequenceNumber & 0xFFFF)
    : (Math.random() * 0x10000) | 0;
  this._group = [];   // [{seq, buf}]
  this._mutable = _mutableIds(opts.extensions);
}

/** Set protection rate at runtime (e.g. from BWE loss estimates). */
FlexFecEncoder.prototype.setGroupSize = function (n) {
  this._groupSize = Math.min(109, Math.max(1, n | 0));
};

/**
 * Feed one outgoing media RTP packet (serialized, pre-SRTP). Returns an
 * array with a FEC packet when the group completes, else [] — two when the
 * packet does not fit the open group's mask (that group's FEC, then this
 * one's when groupSize is 1).
 */
FlexFecEncoder.prototype.protect = function (rtpBuffer) {
  var buf = Buffer.isBuffer(rtpBuffer) ? rtpBuffer : Buffer.from(rtpBuffer);
  if (buf.length < FIXED_HDR) return [];
  var ssrc = buf.readUInt32BE(8);
  if (ssrc !== this._protectedSsrc) return [];
  var seq = _u16(buf[2], buf[3]);
  var out = [];
  // The mask names the group's packets by their distance from the first
  // one, 0..108. A packet it cannot name — before the first, 109 or more
  // after it (a loss gap kept by an SFU forwarder), or a seq already in the
  // group — closes the group, and starts the next. It used to join anyway:
  // XORed into the FEC with no mask bit (bits[] past 108 is dropped), or
  // XORed twice, so every packet recovered from that FEC was wrong.
  if (this._group.length) {
    var d = _seqDiff(seq, this._group[0].seq);
    var fits = d >= 1 && d <= 108;
    for (var i = 1; fits && i < this._group.length; i++) if (this._group[i].seq === seq) fits = false;
    if (!fits) out.push(this._buildFec());
  }
  this._group.push({ seq: seq, buf: _zeroMutable(buf, this._mutable) });
  if (this._group.length >= this._groupSize) out.push(this._buildFec());
  return out;
};

/** Emit a FEC packet for a partial group (e.g. at end of frame burst). */
FlexFecEncoder.prototype.flush = function () {
  if (this._group.length === 0) return [];
  return [this._buildFec()];
};

FlexFecEncoder.prototype._buildFec = function () {
  var group = this._group;
  this._group = [];

  var snBase = group[0].seq;
  var maskBits = 0;
  for (var i = 0; i < group.length; i++) {
    var d = _seqDiff(group[i].seq, snBase);
    if (d + 1 > maskBits) maskBits = d + 1;
  }

  // Mask chunk sizing per draft-03 §4.2.2.1: 15, 46, or 109 bits.
  var maskBytes = (maskBits <= 15) ? 2 : (maskBits <= 46) ? 6 : 14;

  // XOR recovery fields + repair payload
  var maxLen = 0;
  for (var j = 0; j < group.length; j++) {
    if (group[j].buf.length - FIXED_HDR > maxLen) maxLen = group[j].buf.length - FIXED_HDR;
  }
  var xb0 = 0, xb1 = 0, xlen = 0, xts = 0;
  var repair = Buffer.alloc(maxLen);
  for (var k = 0; k < group.length; k++) {
    var b = group[k].buf;
    xb0 ^= (b[0] & 0x3F);                          // P|X|CC
    xb1 ^= b[1];                                   // M|PT
    xlen ^= (b.length - FIXED_HDR);
    xts = (xts ^ b.readUInt32BE(4)) >>> 0;
    for (var p = FIXED_HDR; p < b.length; p++) repair[p - FIXED_HDR] ^= b[p];
  }

  // ── FEC header (R=0, F=0, flexible mask, 1 SSRC) ──
  var hdrLen = 18 + maskBytes;                     // 8 recovery + 1 count + 3 resv + 4 ssrc + 2 snBase + mask
  var fecPayload = Buffer.alloc(hdrLen + maxLen);
  fecPayload[0] = xb0 & 0x3F;                      // R=0 F=0 | P X CC recovery
  fecPayload[1] = xb1;
  fecPayload.writeUInt16BE(xlen & 0xFFFF, 2);
  fecPayload.writeUInt32BE(xts >>> 0, 4);
  fecPayload[8] = 1;                               // SSRCCount
  fecPayload.writeUInt32BE(this._protectedSsrc, 12);
  fecPayload.writeUInt16BE(snBase, 16);

  // Mask: bit j (MSB-first, after the k bit(s)) ⇔ snBase + j protected.
  // Each chunk opens with its K bit, and K=1 marks the LAST chunk (as
  // libwebrtc's FlexfecHeaderReader and pion read it): 2 bytes = K | bits
  // 0-14, 6 = K | 15-45 after them, 14 = K | 46-108 after those. (The K bits
  // were written the other way round, 1 for "another chunk follows", and
  // the 14-byte mask's last chunk had none: no browser could read our FEC,
  // nor we theirs.)
  var bits = new Uint8Array(109);
  for (var m = 0; m < group.length; m++) bits[_seqDiff(group[m].seq, snBase)] = 1;
  var o = 18;
  var v = (maskBytes === 2) ? 0x8000 : 0;          // k=1 here only if this is the last chunk
  for (var i1 = 0; i1 < 15; i1++) v |= bits[i1] << (14 - i1);
  fecPayload.writeUInt16BE(v, o);
  if (maskBytes > 2) {
    var v1 = (maskBytes === 6) ? 0x80000000 : 0;   // k | 31 bits
    for (var i2 = 0; i2 < 31; i2++) v1 |= bits[15 + i2] << (30 - i2);
    fecPayload.writeUInt32BE(v1 >>> 0, o + 2);
    if (maskBytes === 14) {
      var hi = 0x80000000, lo = 0;                 // k=1 | 63 bits: 31 here, 32 in lo
      for (var i3 = 0; i3 < 31; i3++) hi |= bits[46 + i3] << (30 - i3);
      for (var i4 = 0; i4 < 32; i4++) lo |= bits[77 + i4] << (31 - i4);
      fecPayload.writeUInt32BE(hi >>> 0, o + 6);
      fecPayload.writeUInt32BE(lo >>> 0, o + 10);
    }
  }
  repair.copy(fecPayload, hdrLen);

  // ── RTP header for the FEC packet ──
  var pkt = Buffer.alloc(FIXED_HDR + fecPayload.length);
  pkt[0] = 0x80;
  pkt[1] = this._pt & 0x7F;
  pkt.writeUInt16BE(this._seq, 2);
  this._seq = (this._seq + 1) & 0xFFFF;
  // Timestamp: media clock at FEC send time; latest protected ts is the
  // conventional (and libwebrtc-compatible) choice.
  pkt.writeUInt32BE(group[group.length - 1].buf.readUInt32BE(4), 4);
  pkt.writeUInt32BE(this._ssrc, 8);
  fecPayload.copy(pkt, FIXED_HDR);
  return pkt;
};

FlexFecEncoder.prototype.close = function () { this._group = []; };


// ═══════════════════════════════════════════════════════════════════
//  Decoder
// ═══════════════════════════════════════════════════════════════════

/**
 * @param {object}   [opts]
 * @param {function} [opts.output]      called with each recovered media RTP Buffer
 * @param {number}   [opts.windowSize]  media packets kept for recovery — default 256
 * @param {object}   [opts.extensions]  the SENDER's negotiated header extensions, { id: uri }:
 *                                      the mutable ones are zeroed before the XOR
 */
function FlexFecDecoder(opts) {
  opts = opts || {};
  this._mutable = _mutableIds(opts.extensions);
  this.output = opts.output || null;
  this._win = opts.windowSize || 256;
  this._media = new Map();   // seq → Buffer (insertion-ordered)
  this._fec = [];            // [{snBase, seqs[], xb0, xb1, xlen, xts, repair, ssrc}]
  this._maxFec = 64;
}

/** Feed a received media packet (serialized RTP). Returns recovered packets. */
FlexFecDecoder.prototype.addMediaPacket = function (rtpBuffer) {
  var buf = Buffer.isBuffer(rtpBuffer) ? rtpBuffer : Buffer.from(rtpBuffer);
  if (buf.length < FIXED_HDR) return [];
  var seq = _u16(buf[2], buf[3]);
  this._media.set(seq, _zeroMutable(buf, this._mutable));
  while (this._media.size > this._win) {
    this._media.delete(this._media.keys().next().value);
  }
  return this._tryRecoverAll();
};

/** Feed a received FEC packet (serialized RTP, PT=flexfec). Returns recovered packets. */
FlexFecDecoder.prototype.addFecPacket = function (rtpBuffer) {
  var buf = Buffer.isBuffer(rtpBuffer) ? rtpBuffer : Buffer.from(rtpBuffer);
  var f = _parseFec(buf);
  if (!f) return [];
  this._fec.push(f);
  while (this._fec.length > this._maxFec) this._fec.shift();
  return this._tryRecoverAll();
};

FlexFecDecoder.prototype._tryRecoverAll = function () {
  var out = [];
  for (var i = this._fec.length - 1; i >= 0; i--) {
    var rec = this._tryRecover(this._fec[i]);
    if (rec === true) {                    // fully satisfied — retire
      this._fec.splice(i, 1);
    } else if (rec) {
      out.push(rec);
      this._media.set(_u16(rec[2], rec[3]), rec);
      this._fec.splice(i, 1);
      if (this.output) { try { this.output(rec); } catch (e) {} }
      i = this._fec.length;                // recovered packet may unlock other FECs
    }
  }
  return out;
};

/** → Buffer (recovered) | true (nothing missing) | null (can't recover yet) */
FlexFecDecoder.prototype._tryRecover = function (f) {
  var missing = null;
  var have = [];
  for (var i = 0; i < f.seqs.length; i++) {
    var m = this._media.get(f.seqs[i]);
    if (m) { have.push(m); continue; }
    if (missing !== null) return null;     // ≥2 missing — not recoverable (yet)
    missing = f.seqs[i];
  }
  if (missing === null) return true;

  var xb0 = f.xb0, xb1 = f.xb1, xlen = f.xlen, xts = f.xts;
  var repair = Buffer.from(f.repair);
  for (var j = 0; j < have.length; j++) {
    var b = have[j];
    xb0 ^= (b[0] & 0x3F);
    xb1 ^= b[1];
    xlen ^= (b.length - FIXED_HDR);
    xts = (xts ^ b.readUInt32BE(4)) >>> 0;
    for (var p = FIXED_HDR; p < b.length && p - FIXED_HDR < repair.length; p++) {
      repair[p - FIXED_HDR] ^= b[p];
    }
  }
  var recLen = xlen & 0xFFFF;
  if (recLen > repair.length) return null; // corrupt

  var pkt = Buffer.alloc(FIXED_HDR + recLen);
  pkt[0] = 0x80 | (xb0 & 0x3F);            // version 2 | recovered P X CC
  pkt[1] = xb1;
  pkt.writeUInt16BE(missing, 2);
  pkt.writeUInt32BE(xts >>> 0, 4);
  pkt.writeUInt32BE(f.ssrc, 8);
  repair.copy(pkt, FIXED_HDR, 0, recLen);
  return pkt;
};

function _parseFec(buf) {
  // The FEC header follows the FEC packet's WHOLE RTP header. It was read
  // at byte 12, which holds only for a packet with no CSRC and no header
  // extension — ours; every FEC packet Chrome sends carries extensions
  // (abs-send-time, transport-cc, mid), so not one of them parsed.
  var h = _rtpHeaderLen(buf);
  if (h < 0 || buf.length < h + 20) return null;
  var p = buf.subarray(h);
  if ((p[0] & 0xC0) !== 0) return null;    // R/F variants not supported
  if (p[8] !== 1) return null;             // single protected SSRC only
  var ssrc = p.readUInt32BE(12);
  var snBase = p.readUInt16BE(16);

  var seqs = [];
  var o = 18;
  if (o + 2 > p.length) return null;
  var c1 = p.readUInt16BE(o); o += 2;
  var k1 = (c1 & 0x8000) !== 0;                    // k=1: the mask ends with this chunk
  for (var i = 0; i < 15; i++) if (c1 & (1 << (14 - i))) seqs.push((snBase + i) & 0xFFFF);
  if (!k1) {
    if (o + 4 > p.length) return null;
    var c2 = p.readUInt32BE(o); o += 4;
    var k2 = (c2 & 0x80000000) !== 0;
    for (var i2 = 0; i2 < 31; i2++) if (c2 & (1 << (30 - i2))) seqs.push((snBase + 15 + i2) & 0xFFFF);
    if (!k2) {
      if (o + 8 > p.length) return null;
      var hi = p.readUInt32BE(o), lo = p.readUInt32BE(o + 4); o += 8;
      // The last chunk's k must be 1: a mask cannot go on past 109 bits
      // (libwebrtc drops such a packet as malformed).
      if ((hi & 0x80000000) === 0) return null;
      for (var i3 = 0; i3 < 31; i3++) if (hi & (1 << (30 - i3))) seqs.push((snBase + 46 + i3) & 0xFFFF);
      for (var i4 = 0; i4 < 32; i4++) if (lo & (1 << (31 - i4))) seqs.push((snBase + 77 + i4) & 0xFFFF);
    }
  }
  if (seqs.length === 0) return null;

  return {
    ssrc: ssrc, snBase: snBase, seqs: seqs,
    xb0: p[0] & 0x3F, xb1: p[1],
    xlen: p.readUInt16BE(2), xts: p.readUInt32BE(4),
    repair: p.subarray(o),
  };
}

FlexFecDecoder.prototype.reset = function () { this._media.clear(); this._fec = []; };
FlexFecDecoder.prototype.close = function () { this.reset(); };

/**
 * The media SSRC a FlexFEC packet protects (its FEC header's SSRC_i), or
 * null if it is not one this module reads. For a caller that routes FEC
 * packets to a decoder per protected stream.
 */
function flexfecProtectedSsrc(buf) {
  var f = _parseFec(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
  return f ? f.ssrc : null;
}

export { FlexFecEncoder, FlexFecDecoder, flexfecProtectedSsrc };
