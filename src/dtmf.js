/**
 * dtmf — DTMF and named telephony events over RTP (RFC 4733).
 *
 *   chunk { event, durationSamples, timestamp, end }
 *      → DTMFPacketizer  → Buffer[]
 *   RTP packet
 *      → DTMFDepacketizer → chunk via output()
 *
 * What this is for
 * ----------------
 * DTMF (Dual-Tone Multi-Frequency) is "press 1 for English". In a SIP
 * call you can't just play the tone in-band over the audio codec —
 * Opus/G.711 don't preserve the precise frequencies, and tones can get
 * corrupted by codec compression or Voice Activity Detection. RFC 4733
 * solves this by carrying the DTMF event itself out-of-band as a
 * dedicated RTP payload type.
 *
 * The wire format is tiny — 4 bytes per packet:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     event     |E|R| volume    |          duration             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   event     — 0..15 = "0".."9", "*", "#", "A".."D"; 16+ = other named events
 *   E         — End-of-event flag (set on the LAST packets of an event)
 *   R         — Reserved, MUST be 0
 *   volume    — 0..63 (negative dBm0; 0 is loudest, RFC 4733 §2.3.4)
 *   duration  — total event duration so far, in RTP timestamp units
 *
 * State machine (caller's responsibility — this module is RTP only)
 * -----------------------------------------------------------------
 * A single DTMF press of "5" looks roughly like this on the wire:
 *
 *   seq=N+0,  ts=T,  marker=1, event=5, duration= 160, end=0    (start)
 *   seq=N+1,  ts=T,            event=5, duration= 320, end=0
 *   seq=N+2,  ts=T,            event=5, duration= 480, end=0    (every 50 ms)
 *   seq=N+3,  ts=T,            event=5, duration= 640, end=1    (final, 3×)
 *   seq=N+4,  ts=T,            event=5, duration= 640, end=1
 *   seq=N+5,  ts=T,            event=5, duration= 640, end=1
 *
 * Notes:
 *   - All packets share the same RTP timestamp T (the start of the event).
 *   - Sequence numbers advance normally.
 *   - Duration grows by the packetization interval (typically 50 ms).
 *   - The marker bit on the FIRST packet signals "start of new event"
 *     (RFC 4733 §2.5.1.2).
 *   - The final packet (E=1) is sent THREE times for redundancy — losing
 *     the end-of-event packet is much more harmful than losing a mid
 *     packet. The caller drives this; the packetizer doesn't decide.
 *
 * The packetizer is intentionally low-level: it builds one RTP packet
 * per call, given the event/duration/end fields. A higher-level
 * "sendDigit('5', 200ms)" helper belongs in a SIP softphone library
 * built on top of rtp-packet, not in rtp-packet itself.
 */

import {
  initPacketizer, makePacket, usToRtp,
  initDepacketizer, emitError,
} from './rtp.js';

// RTP payload type clock rate. Per RFC 4733 §2.1, the named-event
// payload format inherits the sample rate of the audio stream it's
// multiplexed with. Telephony audio (G.711, G.722, AMR) is 8 kHz, and
// telephone-event/8000 is what every SIP softphone advertises. We
// default to 8000 but allow override for 48 kHz Opus deployments
// (telephone-event/48000 is also legal — Chrome/Firefox use it).
var DEFAULT_CLOCK_RATE = 8000;

// Event name → numeric code (RFC 4733 §3.2 + §3.3).
// The packetizer accepts either the numeric code or these strings.
var EVENT_NAMES = {
  '0': 0,  '1': 1,  '2': 2,  '3': 3,  '4': 4,
  '5': 5,  '6': 6,  '7': 7,  '8': 8,  '9': 9,
  '*': 10, '#': 11,
  'A': 12, 'B': 13, 'C': 14, 'D': 15,
};


// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * DTMFPacketizer — builds a single named-event RTP packet (RFC 4733).
 *
 * Stateless beyond the inherited sequence counter — does NOT manage
 * the event state machine (start / mid / end / 3× redundancy). That
 * belongs to the caller.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 *                                                 (dynamic; whatever was
 *                                                  negotiated for telephone-event)
 * @param {number} [opts.clockRate]               default 8000
 *                                                 (matches telephone-event/8000)
 * @param {number} [opts.mtu]                     default 1400 (irrelevant — DTMF is 4 bytes)
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function DTMFPacketizer(opts) {
  initPacketizer(this, opts);
  this.clockRate = (opts && typeof opts.clockRate === 'number')
    ? opts.clockRate : DEFAULT_CLOCK_RATE;
}

/**
 * Build one RTP packet carrying a DTMF named-event payload.
 *
 * @param {object} chunk
 * @param {number|string} chunk.event       0-15 numeric, or '0'-'9', '*', '#', 'A'-'D'
 * @param {number} chunk.timestamp          microseconds — start time of the event
 *                                          (SAME for every packet of one event)
 * @param {number} chunk.durationSamples    cumulative duration so far, in RTP clock ticks
 * @param {boolean} [chunk.end]             true on the final 3 packets of the event
 * @param {boolean} [chunk.marker]          true on the FIRST packet of a new event
 *                                          (RFC 4733 §2.5.1.2). Default false.
 * @param {number} [chunk.volume]           0-63 (negative dBm0). Default 10.
 * @returns {Buffer[]} array with one RTP packet
 */
DTMFPacketizer.prototype.packetize = function (chunk) {
  return [_packetize(this, chunk, false)];
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
DTMFPacketizer.prototype.packetizeWithMeta = function (chunk) {
  return [_packetize(this, chunk, true)];
};

DTMFPacketizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  if (!chunk || typeof chunk !== 'object') {
    throw new TypeError('DTMFPacketizer.packetize: chunk object is required');
  }
  if (typeof chunk.timestamp !== 'number' || !Number.isFinite(chunk.timestamp)) {
    throw new TypeError('DTMFPacketizer.packetize: chunk.timestamp must be a finite number (microseconds)');
  }
  if (typeof chunk.durationSamples !== 'number' || chunk.durationSamples < 0 || chunk.durationSamples > 0xFFFF) {
    throw new TypeError('DTMFPacketizer.packetize: chunk.durationSamples must be 0..65535 (RTP clock ticks)');
  }

  // Resolve event: accept numeric (0..255 per §2.3.2; we stay 0..15 for
  // DTMF but allow up to 255 for non-DTMF named events e.g. fax tones)
  // or symbolic ('5', '*', 'A').
  var ev;
  if (typeof chunk.event === 'number') {
    if (!Number.isInteger(chunk.event) || chunk.event < 0 || chunk.event > 255) {
      throw new RangeError('DTMFPacketizer.packetize: chunk.event must be 0..255');
    }
    ev = chunk.event;
  } else if (typeof chunk.event === 'string') {
    var key = chunk.event.toUpperCase();
    if (!(key in EVENT_NAMES)) {
      throw new RangeError("DTMFPacketizer.packetize: unknown event name '" + chunk.event + "'");
    }
    ev = EVENT_NAMES[key];
  } else {
    throw new TypeError('DTMFPacketizer.packetize: chunk.event must be a number or DTMF symbol string');
  }

  var volume = (chunk.volume == null) ? 10 : (chunk.volume & 0x3F);
  var endBit = chunk.end ? 0x80 : 0x00;

  // 4-byte RFC 4733 payload — built directly, no intermediate Buffer.
  var payload = Buffer.allocUnsafe(4);
  payload[0] = ev & 0xFF;
  payload[1] = endBit | (volume & 0x3F);   // R bit (0x40) MUST be 0
  payload[2] = (chunk.durationSamples >>> 8) & 0xFF;
  payload[3] = chunk.durationSamples & 0xFF;

  var rtpTs = usToRtp(chunk.timestamp, self.clockRate);
  var marker = !!chunk.marker;
  return makePacket(self, payload, rtpTs, marker, withMeta);
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * DTMFDepacketizer — parses a named-event RTP packet (RFC 4733) and
 * surfaces the event fields to the caller.
 *
 * Like the packetizer, this is stateless — it does NOT collapse the
 * 3× end-of-event redundancy or detect mid-press losses. Callers that
 * want a "press completed" event should consume the chunks here and
 * apply de-duplication on (event, ssrc, RTP timestamp) themselves;
 * that policy belongs in a SIP layer above.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with chunk (see below)
 * @param {function} [opts.error] called with Error on malformed input
 *
 * Output chunk shape:
 *   {
 *     event:           number,          // 0..255
 *     end:             boolean,
 *     volume:          number,          // 0..63
 *     durationSamples: number,          // 0..65535
 *     timestamp:       number,          // RTP timestamp from packet (ticks, not µs)
 *     marker:          boolean,
 *     // Convenience: event name when applicable, else null
 *     symbol:          string|null,     // '5', '*', 'A', etc.
 *   }
 */
function DTMFDepacketizer(opts) {
  initDepacketizer(this, opts);
}

/**
 * peekKeyframe — DTMF carries no media frames; there is no keyframe
 * concept. Returns false to match the uniform NackGenerator interface.
 */
DTMFDepacketizer.peekKeyframe = function () { return false; };

/**
 * Reverse lookup table — built once at module load. EVENT_NAMES is small
 * enough that an inverse table is the cleanest implementation.
 */
var _EVENT_SYMBOLS = (function () {
  var t = new Array(16);
  for (var name in EVENT_NAMES) {
    t[EVENT_NAMES[name]] = name;
  }
  return t;
})();

DTMFDepacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 4) {
    emitError(this, new Error('DTMFDepacketizer: payload must be at least 4 bytes'));
    return;
  }

  var p = packet.payload;
  var event = p[0];
  var b1 = p[1];
  var endBit = !!(b1 & 0x80);
  // Bit 6 (0x40) is reserved per RFC 4733 §2.3.1; we ignore it on input.
  var volume = b1 & 0x3F;
  var durationSamples = (p[2] << 8) | p[3];

  this._output({
    event: event,
    end: endBit,
    volume: volume,
    durationSamples: durationSamples,
    timestamp: packet.timestamp,
    marker: !!packet.marker,
    symbol: (event < 16) ? (_EVENT_SYMBOLS[event] || null) : null,
  });
};

DTMFDepacketizer.prototype.reset = function () {};

DTMFDepacketizer.prototype.close = function () {
  this._output = null;
  this._error = null;
};


export { DTMFPacketizer, DTMFDepacketizer };
