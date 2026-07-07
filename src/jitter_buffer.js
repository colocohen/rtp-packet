/**
 * jitter_buffer — Reorders RTP packets and handles loss.
 *
 * Packets arrive out of order over the network. The jitter buffer:
 *   1. Sorts by sequence number
 *   2. Waits a configurable delay for late packets
 *   3. Emits packets in order (or emits gap events for lost packets)
 *
 * Usage:
 *   var jb = new JitterBuffer({ latency: 50 });  // 50ms buffer
 *   jb.on('packet', function (pkt) { depacketizer.feed(pkt.payload, pkt.marker, pkt.timestamp); });
 *   jb.on('loss', function (seq) { sendNACK(seq); });
 *   jb.push(parsedRtpPacket);
 */

import { EventEmitter } from 'node:events';

function JitterBuffer(opts) {
  if (!opts) opts = {};
  this._ee = new EventEmitter();
  this._latency = opts.latency || 50;  // ms — base latency floor (used when RTT unknown)
  this._maxSize = opts.maxSize || 256;
  this._buffer = {};  // seq → { pkt, insertTime }
  this._nextSeq = -1;  // next expected sequence number
  this._timer = null;
  this._clockRate = opts.clockRate || 90000;

  // Direct callback API (mirrors the rest of rtp-packet — depacketizers
  // also take output/error callbacks at construction). Documented in
  // README. Both this and the .on() EventEmitter API are supported;
  // callbacks fire FIRST so they integrate with code that doesn't
  // bother subscribing.
  this._output = (typeof opts.output === 'function') ? opts.output : null;
  this._onLoss = (typeof opts.onLoss === 'function') ? opts.onLoss : null;

  // RTT-aware loss declaration. NACK→RTX requires roughly one round
  // trip to recover a missing packet; declaring loss too early causes
  // the recovered packet to arrive after we've already given up on it.
  // Late RTX arrivals can't be salvaged downstream — the depacketizer
  // builds frames in arrival order, so an out-of-order packet would
  // corrupt the next frame's assembly. The fix: don't declare loss
  // until we've waited long enough for a possible RTX to come back.
  //
  // Effective latency = max(_latency, 2*RTT + safety). The 2× factor
  // covers: gap detection → NACK send (up to one feedback interval) →
  // round trip to peer and back → one flush tick to pick it up. The
  // safety margin handles RTT variance.
  //
  // When RTT is unknown (no RTCP exchanged yet), we fall back to
  // _latency — preserving original behavior for fresh connections.
  this._rttMs       = (typeof opts.rttMs === 'number')       ? opts.rttMs       : 0;
  this._rttSafetyMs = (typeof opts.rttSafetyMs === 'number') ? opts.rttSafetyMs : 50;

  var self = this;
  this._timer = setInterval(function () { self._flush(); }, Math.max(5, self._latency >> 1));
}

JitterBuffer.prototype.on = function (ev, fn) { this._ee.on(ev, fn); };
JitterBuffer.prototype.off = function (ev, fn) { this._ee.off(ev, fn); };

/**
 * Update the jitter buffer's base latency floor (ms). Useful for adapting
 * to playout-delay hints from the application or transport feedback.
 *
 * @param {number} ms — new latency floor in milliseconds
 */
JitterBuffer.prototype.setLatency = function (ms) {
  if (typeof ms !== 'number' || ms < 0 || !Number.isFinite(ms)) return;
  this._latency = ms;
  // Re-tune the flush interval; cap min at 5 ms (matches constructor).
  if (this._timer) {
    clearInterval(this._timer);
    var self = this;
    this._timer = setInterval(function () { self._flush(); }, Math.max(5, ms >> 1));
  }
};

/**
 * Update the round-trip time used for adaptive loss declaration.
 *
 * Call this whenever a fresh RTT measurement arrives (typically from
 * RTCP RR/SR exchange). The new value affects only future loss
 * decisions — packets currently in the buffer keep waiting against
 * their stored insertTime.
 *
 * Pass 0 to revert to the fixed _latency floor (e.g. on connection
 * reset, before fresh RTT is measured).
 *
 * @param {number} rttMs — measured RTT in milliseconds
 */
JitterBuffer.prototype.setRtt = function (rttMs) {
  if (typeof rttMs !== 'number' || rttMs < 0) return;
  this._rttMs = rttMs;
};

/**
 * Effective latency for loss declaration. See constructor comment for
 * the design rationale. Exposed as a method (not a field) because RTT
 * may change between flushes.
 *
 * @returns {number} milliseconds to wait before declaring a packet lost
 */
JitterBuffer.prototype._effectiveLatency = function () {
  if (this._rttMs > 0) {
    return Math.max(this._latency, 2 * this._rttMs + this._rttSafetyMs);
  }
  return this._latency;
};

/**
 * Push a parsed RTP packet into the buffer.
 * @param {object} pkt — from parse(): { sequenceNumber, timestamp, payload, marker, ... }
 */
JitterBuffer.prototype.push = function (pkt) {
  if (!pkt) return;
  var seq = pkt.sequenceNumber;

  // Initialize on first packet
  if (this._nextSeq === -1) this._nextSeq = seq;

  // Reject if too old (already played out)
  var behind = _seqDiff(this._nextSeq, seq);
  if (behind > 128) return;  // way too old, discard

  // Store
  this._buffer[seq] = { pkt: pkt, insertTime: Date.now() };

  // Limit buffer size
  var keys = Object.keys(this._buffer);
  if (keys.length > this._maxSize) {
    // Force flush oldest
    this._flush();
  }
};

/**
 * Flush packets that are ready (waited long enough or in-order).
 */
JitterBuffer.prototype._flush = function () {
  var now = Date.now();
  var emitted = 0;
  var maxEmit = 30;  // prevent infinite loop

  while (emitted < maxEmit) {
    var entry = this._buffer[this._nextSeq & 0xFFFF];

    if (entry) {
      // Packet available — emit it
      delete this._buffer[this._nextSeq & 0xFFFF];
      if (this._output) this._output(entry.pkt);
      this._ee.emit('packet', entry.pkt);
      this._nextSeq = (this._nextSeq + 1) & 0xFFFF;
      emitted++;
    } else {
      // Packet missing — check if we've waited long enough
      var nextEntry = this._findNextAvailable();
      if (!nextEntry) break;  // nothing in buffer

      var waited = now - nextEntry.insertTime;
      if (waited >= this._effectiveLatency()) {
        // Waited long enough — declare loss and skip ahead
        var gapStart = this._nextSeq;
        var gapEnd = nextEntry.seq;
        for (var s = gapStart; s !== gapEnd; s = (s + 1) & 0xFFFF) {
          var lostSeq = s & 0xFFFF;
          if (this._onLoss) this._onLoss(lostSeq);
          this._ee.emit('loss', lostSeq);
        }
        this._nextSeq = gapEnd;
        // Don't break — continue flushing from new position
      } else {
        break;  // still waiting
      }
    }
  }
};

/**
 * Find the next available packet after _nextSeq.
 */
JitterBuffer.prototype._findNextAvailable = function () {
  // Check next 64 sequence numbers for anything available
  for (var i = 1; i < 64; i++) {
    var seq = (this._nextSeq + i) & 0xFFFF;
    if (this._buffer[seq]) {
      return { seq: seq, insertTime: this._buffer[seq].insertTime };
    }
  }
  return null;
};

/**
 * Stop the jitter buffer timer.
 */
JitterBuffer.prototype.close = function () {
  if (this._timer) {
    clearInterval(this._timer);
    this._timer = null;
  }
  this._buffer = {};
};

/**
 * Reset state (e.g., on SSRC change).
 */
JitterBuffer.prototype.reset = function () {
  this._buffer = {};
  this._nextSeq = -1;
};

/**
 * Signed 16-bit sequence number difference.
 */
function _seqDiff(a, b) {
  var d = ((a - b) + 0x10000) & 0xFFFF;
  return d > 0x8000 ? d - 0x10000 : d;
}

export default JitterBuffer;
export { JitterBuffer };
