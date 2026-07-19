/**
 * av1 — AV1 RTP packetizer + depacketizer (RFC 9798).
 *
 *   chunk {data, timestamp, type}  →  AV1Packetizer   →  Buffer[]
 *   RTP packet                      →  AV1Depacketizer →  chunk via output()
 */

import {
  initPacketizer, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AV1Packetizer — fragments an AV1 encoded frame into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function AV1Packetizer(opts) {
  initPacketizer(this, opts);
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       AV1 OBUs
 * @param {number} chunk.timestamp  microseconds
 * @param {string} [chunk.type]     'key' | 'delta' — used to set N flag on keyframes
 * @returns {Buffer[]}
 */
AV1Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
AV1Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

AV1Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var isKey = (chunk.type === 'key');
  var maxPayload = self.mtu - 1;   // -1 for the 1-byte AV1 aggregation header

  // Aggregation header (AV1 RTP spec §4.4):
  //   Z (0x80) — first OBU element continues a previous fragment
  //   Y (0x40) — last OBU element continues in the next packet
  //   W (0x30) — 2-bit OBU element count; W=1 means "exactly one OBU
  //              element, occupying the rest of the payload, with NO
  //              leb128 length prefix"
  //   N (0x08) — start of a new coded video sequence (keyframe)
  //
  // We always emit exactly one OBU element per packet, so W MUST be 1.
  // W=0 would tell the receiver that every element carries a leb128
  // length prefix — which we don't write — so libwebrtc/Chrome would
  // misparse the first payload byte as a length. (Our own depacketizer
  // ignores W and concatenates, which is why round-trip tests passed
  // while real-world interop would have failed.)
  var W1 = 0x10;   // W=1 in bits 4-5

  // Fast path — single packet (no fragmentation needed).
  if (data.length <= maxPayload) {
    return [makePacketWithPrefix(
      self, W1 | (isKey ? 0x08 : 0x00), 0, 0, 0, 1,   // W=1 + N on keyframes
      data, 0, data.length,
      rtpTs, true, withMeta
    )];
  }

  // Fragmented: Z (continuation) on all but first, Y (continues) on all but last,
  // N (new coded video sequence) only on first-and-keyframe. W=1 on every
  // fragment — each packet still carries exactly one OBU element.
  var out = [];
  var offset = 0;
  var fragCount = Math.ceil(data.length / maxPayload);
  for (var i = 0; i < fragCount; i++) {
    var isFirst = (i === 0);
    var isLast = (i === fragCount - 1);
    var size = Math.min(maxPayload, data.length - offset);

    var header = W1;
    if (!isFirst) header |= 0x80;            // Z
    if (!isLast)  header |= 0x40;            // Y
    if (isFirst && isKey) header |= 0x08;    // N

    out.push(makePacketWithPrefix(
      self, header, 0, 0, 0, 1,
      data, offset, size,
      rtpTs, isLast, withMeta
    ));
    offset += size;
  }
  return out;
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AV1Depacketizer — reassembles AV1 frames from RTP packets.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error]
 */
function AV1Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._fragments = [];
  this._isKey = false;
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start an
 * AV1 keyframe? Static method (no Depacketizer state needed).
 *
 * RFC 9798 §4.3: the descriptor byte's N bit (0x08) signals "new
 * coded video sequence". A new coded video sequence starts with a
 * key frame, so N=1 means this packet contains the start of a
 * keyframe.
 *
 * The N bit is only meaningful at the START of a coded video
 * sequence — i.e., when Z=0 (this packet is NOT a continuation of a
 * previous OBU). The packetizer only sets N together with isFirst
 * (Z=0), so checking N alone would catch all our own output, but
 * being explicit about Z=0 makes peekKeyframe robust against
 * conforming-but-unusual senders too.
 *
 * Returns:
 *   true  — Z=0 (start of OBU sequence) AND N=1 (keyframe begins)
 *   false — continuation fragment, mid-stream OBU, or short payload
 *
 * @param {Buffer} payload
 * @returns {boolean}
 */
AV1Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 1) return false;
  var hdr = payload[0];
  var Z = !!(hdr & 0x80);   // continuation of previous OBU
  var N = !!(hdr & 0x08);   // new coded video sequence
  return !Z && N;
};

AV1Depacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 1) {
    emitError(this, new Error('AV1Depacketizer: empty or missing payload'));
    return;
  }

  var payload = packet.payload;
  var hdr = payload[0];
  var Z = !!(hdr & 0x80);  // continuation of previous OBU
  var Y = !!(hdr & 0x40);  // OBU continues in next packet
  var N = !!(hdr & 0x08);  // new coded video sequence
  var data = payload.subarray(1);

  if (!Z) {
    // New frame starts — reset buffer
    this._fragments = [data];
    this._isKey = N;
  } else {
    this._fragments.push(data);
  }

  // Frame complete when we're not continuing to next packet, OR on marker
  if (!Y || packet.marker) {
    if (this._fragments.length === 0) return;
    var frame = this._fragments.length === 1
      ? this._fragments[0]
      : Buffer.concat(this._fragments);
    var isKey = this._isKey;
    this._fragments = [];
    this._isKey = false;

    this._output({
      data: frame,
      timestamp: packet.timestamp,
      type: isKey ? 'key' : 'delta',
    });
  }
};

AV1Depacketizer.prototype.reset = function () {
  this._fragments = [];
  this._isKey = false;
};

AV1Depacketizer.prototype.close = function () {
  this._fragments = [];
  this._output = null;
  this._error = null;
};


export { AV1Packetizer, AV1Depacketizer };
