/**
 * g722 — G.722 RTP packetizer + depacketizer (RFC 3551 §4.5.2).
 *
 *   chunk {data, timestamp}  →  G722Packetizer   →  Buffer[]
 *   RTP packet                →  G722Depacketizer →  chunk via output()
 *
 * G.722 is "7 kHz audio-coding within 64 kbit/s" (ITU-T G.722). At the
 * RTP layer it's "bytes are samples" — like G.711, the encoder produces
 * a stream of octets that are octet-aligned in the RTP packet. There's
 * no codec frame structure, no key/delta distinction, and no
 * fragmentation considerations beyond MTU.
 *
 * ── The RTP clock rate quirk ───────────────────────────────────────
 *
 * G.722's actual audio sampling rate is 16,000 Hz. But the RTP clock
 * rate for the G.722 payload format is 8,000 Hz, because RFC 1890
 * incorrectly specified that and RFC 3551 kept it for backward
 * compatibility (§4.5.2). EVERY G.722 implementation has to deal with
 * this: timestamps are advanced by the octet count, not the sample
 * count. Specifically:
 *
 *   - 1 octet of payload = 1 G.722 octet = 1 unit of RTP timestamp
 *   - octet rate = 8,000 Hz (matches RTP clock)
 *   - therefore 20 ms of audio = 160 octets = 160 RTP ticks
 *
 * From this packetizer's perspective this is identical to G.711 — we
 * just bump the timestamp by data.length.
 *
 * ── Payload type ───────────────────────────────────────────────────
 *
 * G.722 has the static payload type 9 (RFC 3551 §6). Dynamic types
 * (96-127) are also legal if negotiated via SDP/SIP.
 *
 * ── Typical packetization ──────────────────────────────────────────
 *
 * 20 ms per packet = 160 octets (same as G.711, since the octet rate
 * is also 8 kHz). The caller is expected to feed pre-packetized
 * blocks; this packetizer does not buffer or split samples by
 * duration — it just wraps whatever bytes it receives in an RTP
 * packet.
 */

import {
  initPacketizer, makePacket, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

// RFC 3551 §4.5.2 — RTP clock for G.722 is 8 kHz, NOT the 16 kHz
// audio sampling rate. This is the famous RFC 1890 historical bug.
var CLOCK_RATE = 8000;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * G722Packetizer — wraps a G.722 octet block in an RTP packet.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 *                                                (9 for static G.722 per RFC 3551 §6,
 *                                                 or any dynamic value 96-127 if negotiated)
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function G722Packetizer(opts) {
  initPacketizer(this, opts);
  // Marker bit: per the same convention as other audio codecs in this
  // library — true on the first packet of a talkspurt (i.e. after
  // silence). Caller signals via chunk.marker; default false.
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       G.722 octets (each contains 2 sub-band samples,
 *                                  but at the RTP layer they're opaque bytes)
 * @param {number} chunk.timestamp  microseconds (monotonic)
 * @param {boolean} [chunk.marker]  true on first packet of a talkspurt (default false)
 * @returns {Buffer[]} RTP packets ready for the wire (or SRTP)
 */
G722Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/**
 * Same as packetize(), but returns descriptors with seq/ts/marker for
 * RTX caching.
 *
 * @returns {Array<{buffer, sequenceNumber, timestamp, marker}>}
 */
G722Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

/** No-op close() for symmetry with depacketizer / WebCodecs style. */
G722Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var marker = !!chunk.marker;

  // Common case — block fits in one packet (20 ms = 160 octets, well
  // under any sane MTU). Single allocation, no fragmentation.
  if (data.length <= self.mtu) {
    return [makePacket(self, data, rtpTs, marker, withMeta)];
  }

  // Pathological case — caller passed a block larger than MTU. G.722
  // octets are independent units (each is a pair of 4-bit sub-band
  // codewords representing two 16 kHz samples), so any byte boundary
  // is a legal split point. We warn (matching G.711/Opus convention)
  // then split. Each fragment advances the timestamp by its octet
  // count — same rule as G.711 because the RTP clock for G.722 is also
  // 8 kHz.
  if (typeof process !== 'undefined' && process.emitWarning) {
    process.emitWarning(
      'G722Packetizer: block size ' + data.length + ' exceeds MTU ' + self.mtu +
        ' — splitting (consider smaller packetization duration)',
      'RtpPacketWarning'
    );
  }

  // Marker bit goes on the FIRST fragment only — talkspurt-start
  // semantics, not packet-start. Subsequent fragments are
  // mid-talkspurt by construction.
  var out = [];
  var offset = 0;
  var fragIndex = 0;
  while (offset < data.length) {
    var size = Math.min(self.mtu, data.length - offset);
    var slice = data.subarray(offset, offset + size);
    var fragTs = (rtpTs + offset) >>> 0;   // 1 octet = 1 RTP tick at 8 kHz clock
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
 * G722Depacketizer — passes through G.722 octet blocks from RTP packets.
 *
 * Like G.711, G.722 has no frame structure to reassemble — every
 * packet's payload IS a self-contained block of octets. The
 * depacketizer is a thin adapter that emits each packet's payload
 * via output().
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type: 'key', marker }
 * @param {function} [opts.error] called with Error on malformed input
 */
function G722Depacketizer(opts) {
  initDepacketizer(this, opts);
}

/**
 * peekKeyframe — G.722 has no keyframe vs delta concept. Every G.722
 * packet is independently decodable. Returns false to match the
 * uniform NackGenerator interface across all audio codecs.
 *
 * Same rationale as Opus/G.711 depacketizers.
 *
 * @returns {false}
 */
G722Depacketizer.peekKeyframe = function () { return false; };

/**
 * Feed a parsed RTP packet (from rtp.parse()).
 *
 * @param {object} packet — { payload, marker, timestamp, ... }
 */
G722Depacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 1) {
    emitError(this, new Error('G722Depacketizer: empty or missing payload'));
    return;
  }

  // Audio: every block is independently decodable — always 'key'.
  // Surface the marker bit so consumers can detect talkspurt starts.
  this._output({
    data: packet.payload,
    timestamp: packet.timestamp,
    type: 'key',
    marker: !!packet.marker,
  });
};

G722Depacketizer.prototype.reset = function () {};

G722Depacketizer.prototype.close = function () {
  this._output = null;
  this._error = null;
};


export { G722Packetizer, G722Depacketizer };
