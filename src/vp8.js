/**
 * vp8 — VP8 RTP packetizer + depacketizer (RFC 7741).
 *
 *   chunk {data, timestamp, type}  →  VP8Packetizer   →  Buffer[]
 *   RTP packet                      →  VP8Depacketizer →  chunk via output()
 */

import {
  initPacketizer, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError, checkDepacketizePayload, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * VP8Packetizer — fragments a VP8 encoded frame into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 * @param {boolean|number} [opts.pictureId]       emit a 15-bit PictureID in the
 *                          payload descriptor (RFC 7741 §4.2). Pass `true` for
 *                          a random initial value or a number for a specific
 *                          one. The PictureID increments once per FRAME (all
 *                          fragments of a frame share it) and wraps at 2^15.
 *
 *                          Off by default for wire-compat with the minimal
 *                          descriptor. Turn it ON for WebRTC/SFU use: without
 *                          a PictureID, receivers can't do frame-level
 *                          continuity tracking and simulcast layer switching
 *                          (libwebrtc's packet buffer keys frames on it).
 */
function VP8Packetizer(opts) {
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
 * @param {object} chunk            encoded frame
 * @param {Buffer} chunk.data       VP8 bitstream
 * @param {number} chunk.timestamp  microseconds (monotonic)
 * @param {string} [chunk.type]     'key' | 'delta' — informational; VP8 encodes keyframe flag in the bitstream itself
 * @returns {Buffer[]} RTP packets ready for the wire (or SRTP)
 */
VP8Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/**
 * Same as packetize(), but returns an array of descriptor objects
 * including sequenceNumber/timestamp/marker — useful for an RTX cache.
 *
 * @returns {Array<{buffer, sequenceNumber, timestamp, marker}>}
 */
VP8Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

/** No-op close() for symmetry with depacketizer / WebCodecs style. */
VP8Packetizer.prototype.close = function () {};


// Inline hot-path. Kept separate from VP9/AV1 equivalents (despite visual
// similarity) because V8 optimizes monomorphic functions best — each codec
// gets its own compiled version with the codec's descriptor inlined.
//
// The packet buffer is built in a single Buffer.allocUnsafe — the codec's
// 1-byte descriptor and the bitstream slice are written directly into the
// final RTP packet, avoiding the historical "alloc payload → copy data →
// makePacket allocs again → copy again" double-pass.
function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);

  // Descriptor layout (RFC 7741 §4.2):
  //   minimal: [X=0|...|S|PID=0]                              → 1 byte
  //   with PictureID: [X=1|...|S|0] [I=1|...] [M=1|pid15 hi] [pid lo] → 4 bytes
  var hasPid = self._hasPid;
  var prefixLen = hasPid ? 4 : 1;
  var maxPayload = self.mtu - prefixLen;

  // PictureID increments once per FRAME; every fragment of this frame
  // carries the same value (RFC 7741: "incremented by 1 for each
  // subsequent frame").
  var pidHi = 0, pidLo = 0;
  if (hasPid) {
    var pid = self._pid;
    self._pid = (pid + 1) & 0x7FFF;
    pidHi = 0x80 | ((pid >> 8) & 0x7F);   // M=1 → 15-bit PictureID
    pidLo = pid & 0xFF;
  }
  var descFirst = hasPid ? 0x90 : 0x10;   // X (0x80 when extended) + S
  var descCont  = hasPid ? 0x80 : 0x00;   // X only on continuation
  var extByte   = 0x80;                   // I=1 (PictureID present)

  // Fast path — single-packet (no fragmentation). Marker = true (frame end).
  if (data.length <= maxPayload) {
    return [makePacketWithPrefix(
      self, descFirst, extByte, pidHi, pidLo, prefixLen,
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
    out.push(makePacketWithPrefix(
      self, isFirst ? descFirst : descCont, extByte, pidHi, pidLo, prefixLen,
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
 * VP8Depacketizer — reassembles VP8 frames from RTP packets.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first. Out-of-order delivery will
 * cause fragment loss (the S bit of a later packet resets the buffer).
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error] called with Error on malformed input
 */
function VP8Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._fragments = [];
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start a
 * VP8 keyframe? Static method (no Depacketizer state needed).
 *
 * Used by NACK generators on the receive side: knowing that a newly-
 * arrived packet is a keyframe lets the gap detector skip retransmits
 * for packets below it (the decoder will start fresh from the keyframe,
 * so the lost frames are useless).
 *
 * Returns:
 *   true  — payload's S=1 fragment AND the first byte of the VP8
 *           bitstream past the descriptor has the P-bit (frame_type)
 *           cleared. Per RFC 6386 §9.1: P=0 means keyframe.
 *   false — anything else: continuation fragment (S=0 — no info from
 *           this packet alone), inter-coded frame (P=1), or malformed
 *           input. False is safe — the worst case is an extra NACK
 *           that wouldn't have been needed.
 *
 * @param {Buffer} payload — RTP payload (no RTP header)
 * @returns {boolean}
 */
VP8Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 1) return false;

  // S bit (RFC 7741 §4.2 figure 1) — start of a partition. Only the
  // first packet of a frame can declare keyframe-ness; continuation
  // packets carry no frame_type info on their own.
  if ((payload[0] & 0x10) === 0) return false;

  // Skip the VP8 payload descriptor to reach the first byte of the
  // VP8 bitstream. Length depends on the X bit + extension bits.
  // Walk it the same way depacketize() does, but defensively — bail
  // out (return false) on any short read rather than throwing.
  var hdrLen = 1;
  if (payload[0] & 0x80) {
    if (payload.length < 2) return false;
    var ext = payload[1];
    hdrLen = 2;
    if (ext & 0x80) hdrLen++;       // PictureID byte 1
    if (ext & 0x40) hdrLen++;       // TL0PICIDX
    // TID/Y/KEYIDX share one byte. Per RFC 7741 §4.2, the byte is
    // present if EITHER T (0x20) or K (0x10) is set — checking only
    // T misses encoders that emit KEYIDX without TID (rare but valid).
    if (ext & 0x30) hdrLen++;       // TID/Y/KEYIDX (T or K bit)
    // 16-bit PictureID — present when (ext & 0x80) AND (PID byte's
    // top bit set). Mirrors the depacketize() walk; bounds-check first.
    if ((ext & 0x80) && payload.length > 2 && (payload[2] & 0x80)) hdrLen++;
  }
  if (hdrLen >= payload.length) return false;

  // Bit 0 of the VP8 frame tag byte: 0 = key frame, 1 = inter frame.
  // (RFC 6386 §9.1 "frame tag" — first byte of the VP8 frame.)
  return (payload[hdrLen] & 0x01) === 0;
};

/**
 * Feed a parsed RTP packet (from rtp.parse()).
 * When a full frame is assembled, output() is invoked with the chunk.
 *
 * @param {object} packet — { payload, marker, timestamp, ... }
 */
VP8Depacketizer.prototype.depacketize = function (packet) {
  if (!checkDepacketizePayload(this, packet, 1)) return;

  var payload = packet.payload;
  var S = !!(payload[0] & 0x10);
  var X = !!(payload[0] & 0x80);

  // VP8 payload descriptor header length (RFC 7741 §4.2)
  var hdrLen = 1;
  if (X && payload.length > 1) {
    var ext = payload[1]; hdrLen = 2;
    if (ext & 0x80) hdrLen++;  // PictureID
    if (ext & 0x40) hdrLen++;  // TL0PICIDX
    // TID/Y/KEYIDX share one byte; present if T (0x20) OR K (0x10) is set.
    if (ext & 0x30) hdrLen++;  // TID/Y/KEYIDX
    // 16-bit PictureID: the first PID byte sits at index 2 (right after
    // the extension byte); its top bit (M) signals a second PID byte.
    // Previous check compared hdrLen against payload.length, which is
    // unrelated to whether index 2 is readable.
    if ((ext & 0x80) && payload.length > 2 && (payload[2] & 0x80)) hdrLen++;
  }
  if (hdrLen >= payload.length) {
    emitError(this, new Error('VP8Depacketizer: header larger than payload'));
    return;
  }

  var data = payload.subarray(hdrLen);
  if (S) this._fragments = [data];
  else this._fragments.push(data);

  if (packet.marker && this._fragments.length > 0) {
    var frame = this._fragments.length === 1
      ? this._fragments[0]
      : Buffer.concat(this._fragments);
    this._fragments = [];

    var isKey = (frame.length > 0 && (frame[0] & 0x01) === 0);

    this._output({
      data: frame,
      timestamp: packet.timestamp,
      type: isKey ? 'key' : 'delta',
    });
  }
};

/** Reset internal fragment buffer (e.g. on SSRC change or detected loss). */
VP8Depacketizer.prototype.reset = function () {
  this._fragments = [];
};

/** Release resources. Safe to call multiple times. */
VP8Depacketizer.prototype.close = function () {
  this._fragments = [];
  this._output = null;
  this._error = null;
};


export { VP8Packetizer, VP8Depacketizer };
