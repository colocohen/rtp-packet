/**
 * dtmf.js — RFC 4733 telephone-event RTP payload (DTMF).
 *
 * Wire format (§2.3), 4 bytes per event packet:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     event     |E|R| volume    |          duration             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Event semantics (§2.5.1.2):
 *   - RTP timestamp is FIXED for the whole event (= start instant);
 *     the growing `duration` field carries elapsed time instead.
 *   - marker=1 on the FIRST packet of an event only.
 *   - The final packet sets E=1 and is retransmitted twice (3 total end
 *     packets) for loss robustness — receivers dedupe by timestamp.
 *
 * Division of labor: this class owns byte layout + per-event RTP field
 * discipline (ts/marker/E/duration). The CALLER owns real-time pacing
 * and the tone queue (webrtc-server's RTCDTMFSender), and — critically —
 * the sequence-number space: DTMF rides the SAME SSRC as the audio
 * stream, so seq numbers must come from the audio packetizer's counter.
 * Pass a `nextSequenceNumber` callback for that; standalone use can
 * omit it and get an internal counter.
 */

import { serialize } from './rtp.js';

var EVENT_CODES = {
  '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7,
  '8': 8, '9': 9, '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15,
};

function DtmfPacketizer(opts) {
  if (!(this instanceof DtmfPacketizer)) return new DtmfPacketizer(opts);
  if (!opts || opts.ssrc == null || opts.payloadType == null) {
    throw new Error('DtmfPacketizer: ssrc and payloadType are required');
  }
  this.ssrc = opts.ssrc >>> 0;
  this.payloadType = opts.payloadType & 0x7F;
  this.clockRate = opts.clockRate || 48000;   // matches the paired audio codec
  this._nextSeq = (typeof opts.nextSequenceNumber === 'function')
    ? opts.nextSequenceNumber
    : null;
  this._seq = (opts.initialSequenceNumber != null)
    ? (opts.initialSequenceNumber & 0xFFFF)
    : (Math.random() * 0x10000) & 0xFFFF;

  // Active-event state
  this._eventCode = null;
  this._eventTs = 0;          // fixed RTP ts for the event
  this._elapsedTicks = 0;
  this._first = false;
}

DtmfPacketizer.codeForTone = function (ch) {
  var c = EVENT_CODES[String(ch).toUpperCase()];
  return (c === undefined) ? null : c;
};

DtmfPacketizer.prototype._takeSeq = function () {
  if (this._nextSeq) return this._nextSeq() & 0xFFFF;
  var s = this._seq;
  this._seq = (this._seq + 1) & 0xFFFF;
  return s;
};

/**
 * Begin a new event. `timestamp` is the RTP timestamp of the start
 * instant (caller derives it from the audio clock).
 */
DtmfPacketizer.prototype.startEvent = function (toneChar, timestamp) {
  var code = DtmfPacketizer.codeForTone(toneChar);
  if (code === null) throw new Error('DtmfPacketizer: invalid tone "' + toneChar + '"');
  this._eventCode = code;
  this._eventTs = timestamp >>> 0;
  this._elapsedTicks = 0;
  this._first = true;
};

DtmfPacketizer.prototype._buildPayload = function (end, volume) {
  var p = Buffer.allocUnsafe(4);
  p[0] = this._eventCode & 0xFF;
  p[1] = (end ? 0x80 : 0x00) | (volume & 0x3F);   // E | R=0 | volume (dBm0, 0..63)
  p.writeUInt16BE(Math.min(this._elapsedTicks, 0xFFFF), 2);
  return p;
};

/**
 * Emit one update packet, advancing elapsed time by deltaMs.
 * Returns a single serialized RTP packet (Buffer).
 */
DtmfPacketizer.prototype.update = function (deltaMs, opts) {
  if (this._eventCode === null) throw new Error('DtmfPacketizer: no active event');
  this._elapsedTicks += Math.round(deltaMs * this.clockRate / 1000);
  var pkt = serialize({
    payloadType: this.payloadType,
    sequenceNumber: this._takeSeq(),
    timestamp: this._eventTs,
    ssrc: this.ssrc,
    marker: this._first,
    payload: this._buildPayload(false, (opts && opts.volume) != null ? opts.volume : 10),
  });
  this._first = false;
  return pkt;
};

/**
 * Finish the event: emits the E=1 packet plus 2 retransmits (§2.5.1.2
 * — 3 identical end packets except for their sequence numbers).
 * Returns an array of 3 serialized RTP packets and clears event state.
 */
DtmfPacketizer.prototype.endEvent = function (finalDeltaMs, opts) {
  if (this._eventCode === null) throw new Error('DtmfPacketizer: no active event');
  if (finalDeltaMs) this._elapsedTicks += Math.round(finalDeltaMs * this.clockRate / 1000);
  var out = [];
  var payload = this._buildPayload(true, (opts && opts.volume) != null ? opts.volume : 10);
  for (var i = 0; i < 3; i++) {
    out.push(serialize({
      payloadType: this.payloadType,
      sequenceNumber: this._takeSeq(),
      timestamp: this._eventTs,
      ssrc: this.ssrc,
      marker: this._first,     // only true if the event had zero updates
      payload: payload,
    }));
    this._first = false;
  }
  this._eventCode = null;
  return out;
};

/**
 * parseDtmf — inverse: read a telephone-event payload.
 * @returns {{event, end, volume, duration, tone}|null}
 */
function parseDtmf(payload) {
  if (!payload || payload.length < 4) return null;
  var event = payload[0];
  if (event > 15) return null;   // tones only (events 16+ are other signals)
  var TONES = '0123456789*#ABCD';
  return {
    event: event,
    tone: TONES[event],
    end: !!(payload[1] & 0x80),
    volume: payload[1] & 0x3F,
    duration: payload.readUInt16BE(2),
  };
}

/**
 * DTMFDepacketizer — library-convention counterpart ({output} callback,
 * depacketize(parsedPacket)). Emits one event per E=1 packet (deduped
 * by event timestamp, since the end packet is sent 3x).
 */
function DTMFDepacketizer(opts) {
  if (!(this instanceof DTMFDepacketizer)) return new DTMFDepacketizer(opts);
  this._output = (opts && opts.output) || function () {};
  this._lastEndTs = null;
}
DTMFDepacketizer.prototype.depacketize = function (pkt) {
  var payload = pkt.payload || pkt;
  var ev = parseDtmf(payload);
  if (!ev) return;
  if (ev.end) {
    var ts = pkt.timestamp >>> 0;
    if (this._lastEndTs === ts) return;      // end-packet retransmit
    this._lastEndTs = ts;
    this._output({ tone: ev.tone, event: ev.event, volume: ev.volume,
                   duration: ev.duration, timestamp: ts });
  }
};

// Registry-facing aliases (index.js maps 'dtmf'/'telephone-event' to these)
var DTMFPacketizer = DtmfPacketizer;

export { DtmfPacketizer, DTMFPacketizer, DTMFDepacketizer, parseDtmf };
