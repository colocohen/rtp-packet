/**
 * jitter_buffer — Reorders RTP packets and handles loss.
 *
 * Packets arrive out of order over the network. The jitter buffer:
 *   1. Sorts by sequence number
 *   2. Waits a configurable delay for late packets
 *   3. Emits packets in order (or emits loss events for lost packets)
 *   4. Auto-resyncs when the stream jumps (camera restart, SSRC reuse,
 *      long network outage) instead of dying silently
 *
 * Usage:
 *   var jb = new JitterBuffer({
 *     latency: 50,                           // ms
 *     output: (pkt) => depacketizer.depacketize(pkt),
 *     onLoss: (seq) => nackGenerator.markLost(seq),
 *   });
 *   jb.push(parsedRtpPacket);
 *
 * EventEmitter API also supported: jb.on('packet', fn), jb.on('loss', fn).
 */

import { EventEmitter } from 'node:events';

// How many consecutive "too old" packets trigger an automatic resync.
// A genuine late straggler produces 1-2 rejects; a stream restart (or a
// forward jump > 32768 that LOOKS like "old" under signed 16-bit math)
// produces an unbroken run of them. libwebrtc uses a similar heuristic.
var RESYNC_THRESHOLD = 8;

// Hard cap on how many per-seq loss callbacks a single gap can emit.
// Beyond this the gap is treated as a stream discontinuity: we jump to
// the next available packet without flooding the caller with (up to
// 65k) events. NACKing thousands of packets is pointless anyway — the
// caller should be requesting a keyframe at that point.
var MAX_LOSS_EVENTS_PER_GAP = 512;

function JitterBuffer(opts) {
  if (!opts) opts = {};
  this._ee = new EventEmitter();
  this._latency = opts.latency || 50;  // ms — base latency floor (used when RTT unknown)
  this._maxSize = opts.maxSize || 256;
  this._buffer = Object.create(null);  // seq → { pkt, insertTime }
  this._count = 0;                     // live entry count (no Object.keys on hot path)
  this._nextSeq = -1;                  // next expected sequence number
  this._timer = null;
  this._oldStreak = 0;                 // consecutive too-old rejects (resync detector)
  this._emittedAny = false;            // becomes true on first emitted packet

  // Direct callback API (mirrors the rest of rtp-packet). Both this and
  // the .on() EventEmitter API are supported; callbacks fire FIRST.
  this._output = (typeof opts.output === 'function') ? opts.output : null;
  this._onLoss = (typeof opts.onLoss === 'function') ? opts.onLoss : null;

  // RTT-aware loss declaration: don't declare loss until a NACK→RTX
  // round trip had a chance to recover the packet. Effective latency =
  // max(_latency, 2*RTT + safety). When RTT is unknown, fall back to
  // _latency.
  this._rttMs       = (typeof opts.rttMs === 'number')       ? opts.rttMs       : 0;
  this._rttSafetyMs = (typeof opts.rttSafetyMs === 'number') ? opts.rttSafetyMs : 50;

  var self = this;
  this._timer = setInterval(function () { self._flush(); }, Math.max(5, self._latency >> 1));
  // Don't keep the process alive just for the flush timer.
  if (this._timer.unref) this._timer.unref();
}

JitterBuffer.prototype.on = function (ev, fn) { this._ee.on(ev, fn); };
JitterBuffer.prototype.off = function (ev, fn) { this._ee.off(ev, fn); };

/**
 * Update the base latency floor (ms) and re-tune the flush interval.
 */
JitterBuffer.prototype.setLatency = function (ms) {
  if (typeof ms !== 'number' || ms < 0 || !Number.isFinite(ms)) return;
  this._latency = ms;
  if (this._timer) {
    clearInterval(this._timer);
    var self = this;
    this._timer = setInterval(function () { self._flush(); }, Math.max(5, ms >> 1));
    if (this._timer.unref) this._timer.unref();
  }
};

/**
 * Update the round-trip time used for adaptive loss declaration.
 * Pass 0 to revert to the fixed _latency floor.
 */
JitterBuffer.prototype.setRtt = function (rttMs) {
  if (typeof rttMs !== 'number' || rttMs < 0) return;
  this._rttMs = rttMs;
};

/** Effective latency for loss declaration (see constructor). */
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
  var seq = pkt.sequenceNumber & 0xFFFF;

  // Initialize on first packet
  if (this._nextSeq === -1) this._nextSeq = seq;

  // Reject if too old (already played out). NOTE: a forward jump of
  // more than 32768 is indistinguishable from "very old" under signed
  // 16-bit arithmetic — that's exactly what the resync streak below
  // catches. Without it, a camera restart / SSRC reuse / long outage
  // would silently discard every packet forever.
  var behind = _seqDiff(this._nextSeq, seq);
  if (behind > 128) {
    this._oldStreak++;
    if (this._oldStreak >= RESYNC_THRESHOLD) {
      // Sustained run of "old" packets — this is a stream jump, not
      // stragglers. Resync to the new position.
      this._resyncTo(seq);
      this._store(seq, pkt);
    }
    return;
  }
  this._oldStreak = 0;

  if (behind > 0) {
    // Packet is (mildly) behind the playout position.
    if (!this._emittedAny) {
      // Nothing has been emitted yet — the stream simply STARTED on an
      // out-of-order packet (the first arrival wasn't the lowest seq).
      // Rewind the baseline so the earlier packets aren't stranded
      // behind an already-advanced position.
      this._nextSeq = seq;
      this._store(seq, pkt);
    }
    // Otherwise: a late duplicate of a position we already played or
    // declared lost — dropping it is the correct behavior. Storing it
    // would just leak an unreachable entry.
    return;
  }

  this._store(seq, pkt);
};

JitterBuffer.prototype._store = function (seq, pkt) {
  if (this._buffer[seq] === undefined) this._count++;
  this._buffer[seq] = { pkt: pkt, insertTime: Date.now() };

  // Enforce maxSize: if the buffer is over capacity, the head of the
  // stream is stuck (gap the flusher hasn't timed out yet, or a gap
  // larger than the search window). Force-advance past the gap now —
  // memory stays bounded no matter what the network does.
  if (this._count > this._maxSize) {
    this._forceAdvance();
  }
};

/** Reset ordering state and continue from `seq` (stream discontinuity). */
JitterBuffer.prototype._resyncTo = function (seq) {
  this._buffer = Object.create(null);
  this._count = 0;
  this._nextSeq = seq;
  this._oldStreak = 0;
  this._emittedAny = false;   // allow rewind again at the new position
  this._ee.emit('resync', seq);
};

/**
 * Flush packets that are ready (waited long enough or in-order).
 */
JitterBuffer.prototype._flush = function () {
  var now = Date.now();
  var emitted = 0;
  // Emit budget per tick. High enough that even 4K video (≈2000 pps)
  // drains within one tick at the default 25ms flush interval; low
  // enough to bound worst-case work per tick.
  var maxEmit = Math.max(64, this._maxSize);

  while (emitted < maxEmit) {
    var entry = this._buffer[this._nextSeq];

    if (entry) {
      // Packet available — emit it
      delete this._buffer[this._nextSeq];
      this._count--;
      this._emittedAny = true;
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
        this._declareGapAndSkip(nextEntry.seq);
        // Don't break — continue flushing from new position
      } else {
        break;  // still waiting
      }
    }
  }
};

/**
 * Declare every seq in [_nextSeq, gapEnd) lost (bounded) and jump.
 */
JitterBuffer.prototype._declareGapAndSkip = function (gapEnd) {
  var gapLen = _seqDiff(gapEnd, this._nextSeq);
  if (gapLen < 0) { this._nextSeq = gapEnd; return; }   // shouldn't happen

  var toReport = Math.min(gapLen, MAX_LOSS_EVENTS_PER_GAP);
  var s = this._nextSeq;
  for (var i = 0; i < toReport; i++) {
    var lostSeq = s & 0xFFFF;
    if (this._onLoss) this._onLoss(lostSeq);
    this._ee.emit('loss', lostSeq);
    s = (s + 1) & 0xFFFF;
  }
  if (gapLen > toReport) {
    // Discontinuity too large to enumerate — surface as one event so
    // the caller can request a keyframe instead of NACKing thousands.
    this._ee.emit('gap', { from: this._nextSeq, to: gapEnd, length: gapLen });
  }
  this._nextSeq = gapEnd;
};

/**
 * Buffer over capacity — the flusher can't advance (gap not timed out,
 * or gap beyond the search window). Skip to the earliest buffered seq
 * unconditionally so memory stays bounded.
 */
JitterBuffer.prototype._forceAdvance = function () {
  var earliest = this._findEarliest();
  if (earliest === null) return;
  this._declareGapAndSkip(earliest);
  // Emit what's now in-order (synchronously, so count drops immediately).
  this._flush();
};

/**
 * Find the next available packet after _nextSeq.
 *
 * Fast path: linear scan of the next 256 seqs (covers normal gaps).
 * Slow path (rare — only when the fast window is empty but the buffer
 * isn't): full key scan picking the wrap-aware closest seq. This is
 * what makes gaps larger than the linear window recoverable at all.
 */
JitterBuffer.prototype._findNextAvailable = function () {
  var limit = Math.min(256, this._maxSize + 1);
  for (var i = 1; i <= limit; i++) {
    var seq = (this._nextSeq + i) & 0xFFFF;
    var e = this._buffer[seq];
    if (e !== undefined) return { seq: seq, insertTime: e.insertTime };
  }
  if (this._count === 0) return null;
  var earliest = this._findEarliest();
  if (earliest === null) return null;
  return { seq: earliest, insertTime: this._buffer[earliest].insertTime };
};

/** Wrap-aware earliest buffered seq relative to _nextSeq (full scan). */
JitterBuffer.prototype._findEarliest = function () {
  var best = null, bestDist = 0x10000;
  for (var key in this._buffer) {
    var seq = +key;
    var dist = (seq - this._nextSeq + 0x10000) & 0xFFFF;   // forward distance
    if (dist < bestDist) { bestDist = dist; best = seq; }
  }
  return best;
};

/** Number of packets currently buffered. */
JitterBuffer.prototype.size = function () { return this._count; };

/**
 * Stop the jitter buffer timer.
 */
JitterBuffer.prototype.close = function () {
  if (this._timer) {
    clearInterval(this._timer);
    this._timer = null;
  }
  this._buffer = Object.create(null);
  this._count = 0;
};

/**
 * Reset state (e.g., on SSRC change).
 */
JitterBuffer.prototype.reset = function () {
  this._buffer = Object.create(null);
  this._count = 0;
  this._nextSeq = -1;
  this._oldStreak = 0;
  this._emittedAny = false;
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
