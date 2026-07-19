/**
 * vp9 — VP9 RTP packetizer + depacketizer (draft-ietf-payload-vp9).
 *
 *   chunk {data, timestamp, type}  →  VP9Packetizer   →  Buffer[]
 *   RTP packet                      →  VP9Depacketizer →  chunk via output()
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
 * VP9Packetizer — fragments a VP9 encoded frame into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 * @param {boolean|number} [opts.pictureId]       emit a 15-bit PictureID in the
 *                          payload descriptor (draft-ietf-payload-vp9 §4.2,
 *                          I bit). `true` for a random initial value, or a
 *                          number for a specific one. Increments once per
 *                          FRAME, wraps at 2^15. Off by default; turn on for
 *                          WebRTC/SFU use (frame continuity + layer switching).
 */
function VP9Packetizer(opts) {
  initPacketizer(this, opts);
  if (opts && opts.pictureId !== undefined && opts.pictureId !== false) {
    this._hasPid = true;
    this._pid = (typeof opts.pictureId === 'number')
      ? (opts.pictureId & 0x7FFF)
      : Math.floor(Math.random() * 0x8000);
  } else {
    this._hasPid = false;
    this._pid = 0;
  }
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       VP9 bitstream
 * @param {number} chunk.timestamp  microseconds
 * @param {string} [chunk.type]     'key' | 'delta' — informational; VP9 encodes keyframe flag in the bitstream itself
 * @returns {Buffer[]}
 */
VP9Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
VP9Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

VP9Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var maxPayload = self.mtu - 1;   // -1 for the 1-byte VP9 descriptor

  // P bit (Inter-picture predicted) — draft-ietf-payload-vp9 §4.2.
  // Per spec: P=0 indicates the frame does NOT depend on previous
  // frames (keyframes, intra-coded frames). P=1 indicates the frame
  // depends on previous frames (delta).
  //
  // This must be set per-frame, not hardcoded. Hardcoding P=0 trips
  // up downstream consumers that use the descriptor for keyframe
  // detection — including our own peekKeyframe (returns true for
  // every B=1 packet when P is always 0) and Chrome's NACK keyframe-
  // eviction logic. Same family as the Opus marker-bit bug: a
  // protocol field with frame-type semantics that was being emitted
  // as a constant.
  //
  // We derive the bit from chunk.type — the WebCodecs convention is
  // 'key' for self-sufficient frames and 'delta' for predicted ones.
  // Callers that don't set chunk.type get P=0 (safe default — at
  // worst, a delta frame is mis-flagged as keyframe and triggers an
  // unnecessary NACK reset; never the other direction, which would
  // miss real keyframes and stall recovery).
  var P = (chunk.type === 'delta') ? 0x40 : 0;

  // With PictureID: descriptor gets I=0x80 and is followed by 2 bytes
  // of M(1)+PictureID(15). All fragments of a frame share the PID.
  var hasPid = self._hasPid;
  var prefixLen = hasPid ? 3 : 1;
  var I = hasPid ? 0x80 : 0;
  var pidHi = 0, pidLo = 0;
  if (hasPid) {
    var pid = self._pid;
    self._pid = (pid + 1) & 0x7FFF;
    pidHi = 0x80 | ((pid >> 8) & 0x7F);   // M=1 → 15-bit
    pidLo = pid & 0xFF;
  }
  // Recompute max payload for the actual prefix size.
  maxPayload = self.mtu - prefixLen;

  // Fast path — single-packet (B=1, E=1, no fragmentation).
  if (data.length <= maxPayload) {
    return [makePacketWithPrefix(
      self, I | P | 0x08 | 0x04, pidHi, pidLo, 0, prefixLen,   // (I+)P+B+E
      data, 0, data.length,
      rtpTs, true, withMeta
    )];
  }

  // Fragmented path
  var out = [];
  var offset = 0;
  var fragCount = Math.ceil(data.length / maxPayload);
  for (var i = 0; i < fragCount; i++) {
    var isFirst = (i === 0);
    var isLast = (i === fragCount - 1);
    var size = Math.min(maxPayload, data.length - offset);

    // VP9 descriptor: I (PictureID present), P (frame-type, same on
    // every fragment), B (0x08) on start of frame, E (0x04) on end.
    var descriptor = I | P;
    if (isFirst) descriptor |= 0x08;
    if (isLast)  descriptor |= 0x04;

    out.push(makePacketWithPrefix(
      self, descriptor, pidHi, pidLo, 0, prefixLen,
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
 * VP9Depacketizer — reassembles VP9 frames from RTP packets.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error]
 */
function VP9Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._fragments = [];
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start a
 * VP9 keyframe? Static method (no Depacketizer state needed).
 *
 * Per the VP9 RTP payload format (draft-ietf-payload-vp9 §4.2), the
 * payload descriptor's first byte carries:
 *   B (0x08) — start of a frame
 *   P (0x40) — inter-picture predicted (1 = predicted, 0 = not)
 *
 * A packet starts a keyframe iff B=1 (we're seeing a frame's first
 * byte, not a continuation) AND P=0 (no inter-prediction).
 *
 * We deliberately do NOT also peek into the uncompressed VP9 header
 * for frame_marker like the post-reassembly code in depacketize()
 * does. The descriptor flags are sufficient for NACK use-cases —
 * a false positive (rare; only on intra-only frames in scalable mode
 * with anomalous P bit) costs an extra NACK skip, not correctness.
 *
 * Returns:
 *   true  — B=1 AND P=0
 *   false — continuation fragment, predicted frame, or short payload
 *
 * @param {Buffer} payload
 * @returns {boolean}
 */
VP9Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 1) return false;
  var desc = payload[0];
  var B = !!(desc & 0x08);   // start of a frame
  var P = !!(desc & 0x40);   // inter-picture predicted
  return B && !P;
};

VP9Depacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 1) {
    emitError(this, new Error('VP9Depacketizer: empty or missing payload'));
    return;
  }

  var payload = packet.payload;
  var desc = payload[0];
  var I = !!(desc & 0x80);   // Picture ID present
  var P = !!(desc & 0x40);   // Inter-picture predicted
  var L = !!(desc & 0x20);   // Layer indices present
  var F = !!(desc & 0x10);   // Flexible mode
  var B = !!(desc & 0x08);   // Start of a frame
  var E = !!(desc & 0x04);   // End of a frame

  // Compute payload descriptor length (RFC draft §4.2)
  var hdrLen = 1;
  if (I) {
    hdrLen += (hdrLen < payload.length && (payload[hdrLen] & 0x80)) ? 2 : 1;
  }
  if (L) hdrLen++;
  if (F && P) {
    while (hdrLen < payload.length && !(payload[hdrLen] & 0x01)) hdrLen++;
    hdrLen++;
  }
  if (hdrLen >= payload.length) {
    emitError(this, new Error('VP9Depacketizer: header larger than payload'));
    return;
  }

  var data = payload.subarray(hdrLen);
  if (B) this._fragments = [data];
  else this._fragments.push(data);

  if (E || packet.marker) {
    if (this._fragments.length === 0) return;
    var frame = this._fragments.length === 1
      ? this._fragments[0]
      : Buffer.concat(this._fragments);
    this._fragments = [];

    // Detect keyframe from uncompressed header (§4.2 frame_marker)
    var isKey = false;
    if (frame.length > 0) {
      var fm = (frame[0] >> 6) & 3;
      if (fm === 2) {
        var bitOff = ((frame[0] >> 4) & 3) === 3 ? 5 : 4;
        var showExisting = (frame[0] >> (7 - bitOff)) & 1;
        if (!showExisting) {
          isKey = (((frame[0] >> (6 - bitOff)) & 1) === 0);
        }
      }
    }

    this._output({
      data: frame,
      timestamp: packet.timestamp,
      type: isKey ? 'key' : 'delta',
    });
  }
};

VP9Depacketizer.prototype.reset = function () {
  this._fragments = [];
};

VP9Depacketizer.prototype.close = function () {
  this._fragments = [];
  this._output = null;
  this._error = null;
};


export { VP9Packetizer, VP9Depacketizer };
