/**
 * g711 — G.711 RTP packetizer + depacketizer (RFC 3551 §4.5).
 *
 *   chunk {data, timestamp}  →  G711Packetizer   →  Buffer[]
 *   RTP packet                →  G711Depacketizer →  chunk via output()
 *
 * G.711 (μ-law and A-law) is "bytes are samples" — one 8-bit sample per
 * byte, 8 kHz, mono. There's no codec frame structure, no key/delta
 * distinction, no fragmentation considerations beyond MTU.
 *
 * The same packetizer handles both encodings:
 *   - μ-law (PCMU) — RTP payload type 0  (RFC 3551 §6)
 *   - A-law (PCMA) — RTP payload type 8
 *
 * They differ only in how the 8-bit sample is interpreted (companding
 * curve), which is an encoder/decoder concern, not an RTP one. From
 * RTP's perspective both are identical: 8000 Hz clock, 1 byte per
 * sample, marker bit set on the first packet of a talkspurt.
 *
 * Typical packetization is 20 ms per packet = 160 samples = 160 bytes
 * of payload (well under any reasonable MTU). The caller is expected to
 * feed pre-packetized 20 ms (or 10/30 ms) blocks; this packetizer does
 * not buffer or split samples by duration — it just wraps whatever
 * bytes it receives in an RTP packet.
 */

import {
  initPacketizer, makePacket, validateChunk, usToRtp,
  initDepacketizer, emitError, checkDepacketizePayload, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 8000;  // RFC 3551 §4.5 — fixed for both PCMU and PCMA

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * G711Packetizer — wraps a G.711 sample block in an RTP packet.
 *
 * Same packetizer for μ-law and A-law — choose by setting
 * `payloadType: 0` (PCMU) or `payloadType: 8` (PCMA). The payload
 * bytes pass through unchanged; the encoding lives in the bytes
 * themselves and is the caller's responsibility.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 *                                                (0 for PCMU, 8 for PCMA per RFC 3551,
 *                                                 or any dynamic value 96-127 if negotiated)
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function G711Packetizer(opts) {
  initPacketizer(this, opts);
  // Marker bit: RFC 3551 §4.1 — set on the first packet of a talkspurt
  // (i.e. the first packet after silence). The caller signals this
  // via chunk.marker; default false (mid-talkspurt).
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       G.711 samples (1 byte each, μ-law or A-law)
 * @param {number} chunk.timestamp  microseconds (monotonic)
 * @param {boolean} [chunk.marker]  true on first packet of a talkspurt (default false)
 * @returns {Buffer[]} RTP packets ready for the wire (or SRTP)
 */
G711Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/**
 * Same as packetize(), but returns descriptors with seq/ts/marker for
 * RTX caching.
 *
 * @returns {Array<{buffer, sequenceNumber, timestamp, marker}>}
 */
G711Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

/** No-op close() for symmetry with depacketizer / WebCodecs style. */
G711Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var marker = !!chunk.marker;

  // Common case — block fits in one packet (20 ms @ 8 kHz = 160 bytes,
  // well under any sane MTU). Single allocation, no fragmentation.
  if (data.length <= self.mtu) {
    return [makePacket(self, data, rtpTs, marker, withMeta)];
  }

  // Pathological case — caller passed a block larger than MTU. Unlike
  // Opus (where a frame is a single decodable unit), G.711 has no
  // codec-level framing: every byte is an independent sample, so any
  // split point is legal. We warn (matching the Opus convention —
  // crossing MTU usually means the caller misconfigured packetization
  // duration), then split along byte boundaries. Each fragment
  // advances the timestamp by its sample count.
  if (typeof process !== 'undefined' && process.emitWarning) {
    process.emitWarning(
      'G711Packetizer: block size ' + data.length + ' exceeds MTU ' + self.mtu +
        ' — splitting (consider smaller packetization duration)',
      'RtpPacketWarning'
    );
  }

  // Marker bit goes on the FIRST fragment only — it indicates start
  // of talkspurt, not start of packet. Subsequent fragments are
  // mid-talkspurt by construction.
  var out = [];
  var offset = 0;
  var fragIndex = 0;
  while (offset < data.length) {
    var size = Math.min(self.mtu, data.length - offset);
    var slice = data.subarray(offset, offset + size);
    var fragTs = (rtpTs + offset) >>> 0;   // 1 sample = 1 RTP tick at 8 kHz
    out.push(makePacket(self, slice, fragTs, fragIndex === 0 && marker, withMeta));
    offset += size;
    fragIndex++;
  }
  return out;
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * G711Depacketizer — passes through G.711 sample blocks from RTP packets.
 *
 * G.711 has no frame structure to reassemble — every packet's payload
 * IS a self-contained block of samples. The depacketizer is a thin
 * adapter that emits each packet's payload via output().
 *
 * Same depacketizer for μ-law and A-law — the bytes pass through
 * unchanged, and the encoding interpretation is the decoder's
 * concern.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type: 'key', marker }
 * @param {function} [opts.error] called with Error on malformed input
 */
function G711Depacketizer(opts) {
  initDepacketizer(this, opts);
}

/**
 * peekKeyframe — G.711 has no concept of keyframe vs delta. Every
 * G.711 packet is independently decodable. Returns false to match the
 * uniform NackGenerator interface (no "skip retransmit because keyframe
 * is coming" optimization applies to audio).
 *
 * Same rationale as OpusDepacketizer.peekKeyframe.
 *
 * @returns {false}
 */
G711Depacketizer.peekKeyframe = function () { return false; };

/**
 * Feed a parsed RTP packet (from rtp.parse()).
 *
 * @param {object} packet — { payload, marker, timestamp, ... }
 */
G711Depacketizer.prototype.depacketize = function (packet) {
  if (!checkDepacketizePayload(this, packet, 1)) return;

  // Audio: every block is independently decodable — always 'key'.
  // Surface the marker bit so consumers can detect talkspurt starts
  // (useful for VAD-driven UI, comfort-noise insertion, etc.).
  this._output({
    data: packet.payload,
    timestamp: packet.timestamp,
    type: 'key',
    marker: !!packet.marker,
  });
};

G711Depacketizer.prototype.reset = function () {};

G711Depacketizer.prototype.close = function () {
  this._output = null;
  this._error = null;
};


export { G711Packetizer, G711Depacketizer };
