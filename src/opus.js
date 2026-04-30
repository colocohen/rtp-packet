/**
 * opus — Opus RTP packetizer + depacketizer (RFC 7587).
 * One Opus frame per RTP packet (Opus is self-delimiting).
 *
 *   chunk {data, timestamp}  →  OpusPacketizer   →  Buffer[]
 *   RTP packet                →  OpusDepacketizer →  chunk via output()
 */

import {
  initPacketizer, makePacket, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 48000;  // Opus always uses 48 kHz RTP clock regardless of sample rate

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * OpusPacketizer — wraps an Opus frame in an RTP packet.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400 (Opus frames rarely exceed this)
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function OpusPacketizer(opts) {
  initPacketizer(this, opts);
  // ── RFC 7587 §4.2 marker-bit state ──
  //
  // The M bit MUST be set on the first packet of a talkspurt — i.e.,
  // the first packet ever, or the first packet after a silence
  // interval (DTX gap, network pause, or speaker pause). On
  // continuation packets within a talkspurt M MUST be 0.
  //
  // Setting M=1 on every packet (the previous behavior) violates the
  // spec and triggers NetEq state changes in libwebrtc-based receivers
  // every 20 ms — Chrome's audio pipeline interprets each M=1 as a
  // potential resync point and may flush parts of the jitter buffer.
  // The audible result is metallic / "alien" speech: the decoder is
  // never allowed to settle into a steady state.
  //
  // Talkspurt-resume is detected by comparing RTP timestamps. Anything
  // beyond _SILENCE_GAP_RTP units (500 ms at 48 kHz = 24000) is treated
  // as a silence break. The first packet ever always gets M=1.
  this._sentFirst = false;
  this._lastRtpTs = 0;
}

// 500 ms in 48 kHz RTP units. Long enough that normal jitter (typically
// <100 ms) never crosses it; short enough that a real pause is detected
// promptly. Outside this window we consider the talkspurt continuous.
var _SILENCE_GAP_RTP = 24000;

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       Opus frame
 * @param {number} chunk.timestamp  microseconds
 * @returns {Buffer[]} array with a single RTP packet
 */
OpusPacketizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return [_packetize(this, chunk, false)];
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
OpusPacketizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return [_packetize(this, chunk, true)];
};

OpusPacketizer.prototype.close = function () {};


// Single internal helper — keeps the MTU warning behavior uniform between
// packetize() and packetizeWithMeta().
function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  if (data.length > self.mtu) {
    // Opus frames shouldn't exceed network MTU — UDP fragmentation hurts
    // quality more than the bandwidth saved by larger packets. We still
    // emit the packet; the warning surfaces a likely misconfiguration.
    if (typeof process !== 'undefined' && process.emitWarning) {
      process.emitWarning(
        'OpusPacketizer: frame size ' + data.length + ' exceeds MTU ' + self.mtu,
        'RtpPacketWarning'
      );
    }
  }
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);

  // ── Marker bit (RFC 7587 §4.2) ──
  // M=1 on first packet ever, or first packet after a silence gap.
  // M=0 on continuation packets within a talkspurt. Unsigned 32-bit
  // subtraction (>>> 0) handles RTP timestamp wraparound correctly:
  // for a stream that's been running long enough to wrap (~24 hours
  // at 48 kHz), the difference modulo 2^32 still gives the right gap.
  var marker;
  if (!self._sentFirst) {
    marker = true;
    self._sentFirst = true;
  } else {
    var diff = (rtpTs - self._lastRtpTs) >>> 0;
    marker = (diff > _SILENCE_GAP_RTP);
  }
  self._lastRtpTs = rtpTs;

  return makePacket(self, data, rtpTs, marker, withMeta);
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * OpusDepacketizer — passes through Opus frames from RTP packets.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type: 'key' }
 * @param {function} [opts.error]
 */
function OpusDepacketizer(opts) {
  initDepacketizer(this, opts);
}

/**
 * peekKeyframe — Opus has no concept of keyframe vs delta. Every Opus
 * packet is independently decodable (no inter-frame prediction across
 * RTP packet boundaries). Returns false unconditionally — this matches
 * how the NACK keyframe-eviction logic should behave for audio: never
 * skip retransmits "because a keyframe is coming", because there's no
 * such thing.
 *
 * Provided so callers (NackGenerator) can dispatch through a uniform
 * `Depacketizer.peekKeyframe(payload)` interface across all kinds.
 *
 * @returns {false}
 */
OpusDepacketizer.peekKeyframe = function () { return false; };

OpusDepacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 1) {
    emitError(this, new Error('OpusDepacketizer: empty or missing payload'));
    return;
  }

  // Audio: every frame is independently decodable — always 'key'
  this._output({
    data: packet.payload,
    timestamp: packet.timestamp,
    type: 'key',
  });
};

OpusDepacketizer.prototype.reset = function () {};

OpusDepacketizer.prototype.close = function () {
  this._output = null;
  this._error = null;
};


export { OpusPacketizer, OpusDepacketizer };
