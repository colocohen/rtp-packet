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
 *   - Long events (§2.5.1.3): the duration field is 16 bits — 1.36 s at
 *     48 kHz. An event that outlasts it goes on in a new SEGMENT: the
 *     segment that filled up is reported once with duration 0xFFFF, the
 *     next one starts at its timestamp + 0xFFFF with the duration counted
 *     from 0 again, marker 0 (it is the same event). libwebrtc splits the
 *     same way (rtp_sender_audio.cc).
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
  this._eventTs = 0;          // fixed RTP ts for the event (of its current segment)
  this._elapsedTicks = 0;     // since the start of the current segment
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

// Move the event on to its next segment (§2.5.1.3, see the top of the file)
// for as long as the elapsed time does not fit in 16 bits. Previously the
// duration stayed at 0xFFFF: a 3 s tone (the W3C API allows up to 6 s)
// reached the peer as 1.36 s.
DtmfPacketizer.prototype._nextSegment = function () {
  while (this._elapsedTicks > 0xFFFF) {
    this._eventTs = (this._eventTs + 0xFFFF) >>> 0;
    this._elapsedTicks -= 0xFFFF;
  }
};

// The time an update adds: a finite number, not negative. (A negative one
// made writeUInt16BE throw Node's generic range error; NaN made the elapsed
// time NaN for the rest of the event, every duration written as 0.)
function _checkDelta(fn, ms) {
  if (typeof ms !== 'number' || !(ms >= 0) || ms === Infinity) {
    throw new RangeError('DtmfPacketizer.' + fn + ': the time must be a finite number of ms, not negative');
  }
}

/**
 * Emit one update packet, advancing elapsed time by deltaMs.
 * Returns a single serialized RTP packet (Buffer).
 */
DtmfPacketizer.prototype.update = function (deltaMs, opts) {
  if (this._eventCode === null) throw new Error('DtmfPacketizer: no active event');
  _checkDelta('update', deltaMs);
  // A segment that already went out full (0xFFFF) is over: this packet
  // belongs to the next one.
  if (this._elapsedTicks >= 0xFFFF) this._nextSegment();
  this._elapsedTicks += Math.round(deltaMs * this.clockRate / 1000);
  // Crossing 0xFFFF now: this packet closes the segment with 0xFFFF (from
  // _buildPayload's clamp), and the next call carries on in a new one.
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
 * Returns an array of 3 serialized RTP packets (4 when the end crosses into
 * a new segment: the full segment's last report comes first) and clears
 * event state.
 */
DtmfPacketizer.prototype.endEvent = function (finalDeltaMs, opts) {
  if (this._eventCode === null) throw new Error('DtmfPacketizer: no active event');
  if (this._elapsedTicks >= 0xFFFF) this._nextSegment();
  if (finalDeltaMs) {
    _checkDelta('endEvent', finalDeltaMs);
    this._elapsedTicks += Math.round(finalDeltaMs * this.clockRate / 1000);
  }
  var out = [];
  // Ending past the segment's limit: report it full first, then end in the next.
  if (this._elapsedTicks > 0xFFFF) {
    out.push(serialize({
      payloadType: this.payloadType,
      sequenceNumber: this._takeSeq(),
      timestamp: this._eventTs,
      ssrc: this.ssrc,
      marker: this._first,
      payload: this._buildPayload(false, (opts && opts.volume) != null ? opts.volume : 10),
    }));
    this._first = false;
    this._nextSegment();
  }
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
 * by event timestamp, since the end packet is sent 3x). The duration it
 * reports is the whole event's, segments of a long event (§2.5.1.3) added up.
 */
function DTMFDepacketizer(opts) {
  if (!(this instanceof DTMFDepacketizer)) return new DTMFDepacketizer(opts);
  this._output = (opts && opts.output) || function () {};
  this._lastEndTs = null;
  this._lastEndRaw = null;    // dedupe key for raw payloads (no timestamp)
  this._segTs = null;         // timestamp of the segment being received
  this._segEvent = -1;
  this._segDur = 0;           // last duration seen in that segment
  this._carry = 0;            // ticks of the event's earlier segments
}
DTMFDepacketizer.prototype.depacketize = function (pkt) {
  if (!this._output) return;                 // closed — ignore (parity with other codecs)
  var payload = pkt && (pkt.payload || pkt);
  var ev = parseDtmf(payload);
  if (!ev) return;

  // A raw payload (accepted above) carries no timestamp. It used to be read
  // as 0 for every packet, so every tone after the first was dropped as a
  // "retransmit". Without a timestamp the 3 end packets are recognised as
  // identical end packets in a row; any non-end packet in between (every
  // tone that lasts past its first report has some) opens a new tone.
  if (pkt === payload || pkt.timestamp == null) {
    if (!ev.end) { this._lastEndRaw = null; return; }
    var key = ev.event + ':' + ev.duration + ':' + ev.volume;
    if (this._lastEndRaw === key) return;
    this._lastEndRaw = key;
    this._output({ tone: ev.tone, event: ev.event, volume: ev.volume,
                   duration: ev.duration, timestamp: null });
    return;
  }

  var ts = pkt.timestamp >>> 0;
  // A new timestamp for the same event right after a full segment (0xFFFF)
  // is the event's next segment: keep the time already elapsed. Anything
  // else is a new event. (The gap between the two timestamps is what passed,
  // whether the sender put the new segment at +0xFFFF, as the RFC does, or
  // at the current time, as libwebrtc does.)
  if (ts !== this._segTs) {
    var gap = (ts - this._segTs) >>> 0;
    if (this._segTs !== null && ev.event === this._segEvent &&
        this._segDur === 0xFFFF && gap >= 0xFFFF && gap < 0x20000) {
      this._carry += gap;
    } else {
      this._carry = 0;
    }
    this._segTs = ts;
    this._segEvent = ev.event;
  }
  this._segDur = ev.duration;

  if (ev.end) {
    if (this._lastEndTs === ts) return;      // end-packet retransmit
    this._lastEndTs = ts;
    this._output({ tone: ev.tone, event: ev.event, volume: ev.volume,
                   duration: this._carry + ev.duration,
                   timestamp: (ts - this._carry) >>> 0 });   // the event's start
  }
};

/** Clear duplicate-suppression state (e.g. on SSRC change). Interface
 *  parity with every other codec's depacketizer. */
DTMFDepacketizer.prototype.reset = function () {
  this._lastEndTs = null;
  this._lastEndRaw = null;
  this._segTs = null;
  this._segEvent = -1;
  this._segDur = 0;
  this._carry = 0;
};

/** Release resources. Safe to call multiple times; depacketize() after
 *  close() is silently ignored. Interface parity with the other codecs. */
DTMFDepacketizer.prototype.close = function () {
  this.reset();
  this._output = null;
};

// Registry-facing aliases (index.js maps 'dtmf'/'telephone-event' to these)
var DTMFPacketizer = DtmfPacketizer;

export { DtmfPacketizer, DTMFPacketizer, DTMFDepacketizer, parseDtmf };
