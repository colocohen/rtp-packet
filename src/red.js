/**
 * red — RED redundant audio coding (RFC 2198).
 *
 * Each RTP packet carries the current frame (primary) plus copies of the
 * previous frame(s) (redundant). A lost packet is repaired from the copy
 * inside the NEXT packet — zero round trips, unlike NACK/RTX. This is the
 * standard loss-hardening for WebRTC audio (Chrome offers `red/48000`
 * paired with Opus by default).
 *
 * Wire format (RFC 2198 §3):
 *
 *   redundant block header (4 bytes, one per redundant block):
 *     F=1(1) | block PT(7) | timestamp offset(14) | block length(10)
 *   primary block header (1 byte, always last header):
 *     F=0(1) | block PT(7)
 *   ...followed by the block payloads in the same order.
 *
 *   chunk {data, timestamp}  →  REDPacketizer    →  Buffer[] (RTP, PT=red)
 *   RTP packet               →  REDDepacketizer  →  pseudo-packets via output()
 *
 * The depacketizer emits parse()-shaped pseudo-packets (primary + any
 * recovered redundant frames, deduped, in timestamp order) so it chains
 * directly into an inner depacketizer:
 *
 *   const opusD = new OpusDepacketizer({ output: chunk => decoder.decode(chunk) });
 *   const redD  = new REDDepacketizer({ output: p => opusD.depacketize(p) });
 *   redD.depacketize(parsedRtpPacket);
 */

import {
  initPacketizer, makePacket, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

var MAX_TS_OFFSET = 0x3FFF;   // 14-bit
var MAX_BLOCK_LEN = 0x3FF;    // 10-bit

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * REDPacketizer — wraps encoded audio frames in RED, one RTP packet per
 * primary frame with up to `redundancy` previous frames attached.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required — the RED payload type from SDP
 * @param {number}  opts.innerPayloadType         required — the wrapped codec's PT (e.g. Opus)
 * @param {number} [opts.redundancy]              previous frames per packet — default 1 (Chrome's default)
 * @param {number} [opts.clockRate]               default 48000 (Opus)
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function REDPacketizer(opts) {
  initPacketizer(this, opts);
  if (opts == null || typeof opts.innerPayloadType !== 'number') {
    throw new Error('REDPacketizer: opts.innerPayloadType required (the wrapped codec\u0027s payload type)');
  }
  this._innerPt = opts.innerPayloadType & 0x7F;
  this._redundancy = (opts.redundancy != null) ? Math.max(0, opts.redundancy | 0) : 1;
  this._clockRate = opts.clockRate || 48000;
  this._history = [];        // [{rtpTs, data}] oldest→newest
  this._sentFirst = false;
}

REDPacketizer.prototype.packetize = function (chunk) { return [this._do(chunk, false)]; };
/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
REDPacketizer.prototype.packetizeWithMeta = function (chunk) { return [this._do(chunk, true)]; };

REDPacketizer.prototype._do = function (chunk, withMeta) {
  var self = this;
  validateChunk(this, chunk);
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, this._clockRate) >>> 0;

  // Select usable redundant blocks: newest `redundancy` frames whose
  // timestamp offset and length fit the RFC 2198 field widths. A frame
  // that doesn't fit is silently skipped (the packet still carries the
  // primary — degraded protection, never a corrupt packet).
  var blocks = [];
  for (var i = Math.max(0, this._history.length - this._redundancy); i < this._history.length; i++) {
    var h = this._history[i];
    var off = (rtpTs - h.rtpTs) >>> 0;
    if (off > MAX_TS_OFFSET) continue;
    if (h.data.length > MAX_BLOCK_LEN) continue;
    blocks.push({ off: off, data: h.data });
  }

  // Assemble: N×4-byte redundant headers + 1-byte primary header + payloads
  var headerLen = blocks.length * 4 + 1;
  var total = headerLen;
  for (var b = 0; b < blocks.length; b++) total += blocks[b].data.length;
  total += data.length;

  var payload = Buffer.allocUnsafe(total);
  var o = 0;
  for (var b2 = 0; b2 < blocks.length; b2++) {
    var blk = blocks[b2];
    payload[o]     = 0x80 | this._innerPt;                       // F=1 | PT
    payload[o + 1] = (blk.off >> 6) & 0xFF;                      // ts offset high 8
    payload[o + 2] = ((blk.off & 0x3F) << 2) | ((blk.data.length >> 8) & 0x03);
    payload[o + 3] = blk.data.length & 0xFF;
    o += 4;
  }
  payload[o++] = this._innerPt & 0x7F;                           // F=0 | PT (primary)
  for (var b3 = 0; b3 < blocks.length; b3++) {
    blocks[b3].data.copy(payload, o); o += blocks[b3].data.length;
  }
  data.copy(payload, o);

  // History for future packets
  this._history.push({ rtpTs: rtpTs, data: data });
  var keep = Math.max(1, this._redundancy);
  while (this._history.length > keep) this._history.shift();

  var marker = !this._sentFirst;
  this._sentFirst = true;
  return makePacket(self, payload, rtpTs, marker, withMeta);
};

REDPacketizer.prototype.close = function () { this._history = []; };


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * REDDepacketizer — unwraps RED packets, emitting the primary frame and
 * recovering redundant copies of frames that were never delivered.
 *
 * output() receives parse()-shaped pseudo-packets ({payloadType,
 * sequenceNumber, timestamp, ssrc, marker, payload}) — primary and
 * recovered blocks alike — deduped by RTP timestamp and delivered in
 * ascending timestamp order, ready to chain into an inner depacketizer.
 *
 * @param {object}   opts
 * @param {function} opts.output    required
 * @param {function} [opts.error]
 * @param {number}   [opts.historySize]  dedupe window in frames — default 64
 */
function REDDepacketizer(opts) {
  initDepacketizer(this, opts);
  this._seen = new Map();    // rtpTs → true (insertion-ordered ring)
  this._seenMax = (opts && opts.historySize) || 64;
}

REDDepacketizer.prototype.depacketize = function (pkt) {
  if (!pkt || !pkt.payload) return;
  var p = _toBuffer(pkt.payload);
  var blocks = _parseRed(p);
  if (!blocks) { emitError(this, new Error('RED: malformed payload')); return; }

  // Redundant blocks carry ts = primaryTs − offset; emit any block whose
  // timestamp we haven't delivered, oldest first (offset descending).
  var out = [];
  for (var i = 0; i < blocks.length; i++) {
    var blk = blocks[i];
    var ts = (pkt.timestamp - blk.tsOffset) >>> 0;
    if (this._seen.has(ts)) continue;
    out.push({ ts: ts, blk: blk });
  }
  out.sort(function (a, b) { return (a.ts - b.ts) | 0; });   // wrap-safe for small windows

  for (var j = 0; j < out.length; j++) {
    var e = out[j];
    this._seen.set(e.ts, true);
    while (this._seen.size > this._seenMax) {
      this._seen.delete(this._seen.keys().next().value);
    }
    this._output({
      payloadType:    e.blk.pt,
      sequenceNumber: pkt.sequenceNumber,     // informational — inner audio depacketizers key on timestamp
      timestamp:      e.ts,
      ssrc:           pkt.ssrc,
      marker:         e.blk.isPrimary ? !!pkt.marker : false,
      payload:        e.blk.data,
      _redRecovered:  !e.blk.isPrimary,
    });
  }
};

/** Parse a RED payload → [{pt, tsOffset, data, isPrimary}] in wire order, or null. */
function _parseRed(p) {
  var headers = [];
  var o = 0;
  for (;;) {
    if (o >= p.length) return null;
    var b0 = p[o];
    if ((b0 & 0x80) === 0) {                       // primary header — 1 byte, ends header list
      headers.push({ pt: b0 & 0x7F, tsOffset: 0, len: -1, isPrimary: true });
      o += 1;
      break;
    }
    if (o + 4 > p.length) return null;             // redundant header — 4 bytes
    headers.push({
      pt: b0 & 0x7F,
      tsOffset: (p[o + 1] << 6) | (p[o + 2] >> 2),
      len: ((p[o + 2] & 0x03) << 8) | p[o + 3],
      isPrimary: false,
    });
    o += 4;
  }
  // Payloads follow in header order; primary takes the remainder.
  var blocks = [];
  for (var i = 0; i < headers.length; i++) {
    var h = headers[i];
    var len = h.isPrimary ? (p.length - o) : h.len;
    if (len < 0 || o + len > p.length) return null;
    blocks.push({ pt: h.pt, tsOffset: h.tsOffset, data: p.subarray(o, o + len), isPrimary: h.isPrimary });
    o += len;
  }
  if (o !== p.length) return null;
  return blocks;
}

REDDepacketizer.prototype.reset = function () { this._seen.clear(); };
REDDepacketizer.prototype.close = function () { this._seen.clear(); };

/** Keyframe peek — audio has no keyframes; kept for interface parity. */
REDDepacketizer.peekKeyframe = function () { return false; };

export { REDPacketizer, REDDepacketizer };
