// src/retransmit.js
//
// RTP retransmission support — both sides of the wire.
//
//   SEND side (we sent a packet, peer asks for it back):
//     - SenderBuffer    — ring buffer of plaintext RTP we sent
//     - RtxStream       — RFC 4588 encapsulation of stored packets
//     - NackThrottle    — dedup re-NACKs of the same seq within RTT
//     - buildRtxPacket  — pure function used by RtxStream
//
//   RECV side (we received a stream, peer's packets are missing):
//     - NackGenerator   — detect gaps in incoming seq numbers, emit
//                         NACK feedback respecting RTT + maxRetries +
//                         keyframe-aware list eviction
//     - parseRtxPacket  — inverse of buildRtxPacket: extract original
//                         RTP from an arriving RTX packet
//
// This module is transport-agnostic: it doesn't know about DTLS, SRTP,
// ICE, or any of WebRTC's wiring. The send-side classes track plaintext
// packets and produce RTX bytes on demand. The receive-side class tracks
// received seq numbers and produces lists of seqs to NACK. Wiring (when
// to call into them, where to send the bytes) is the caller's problem.
//
//
// Usage (sender side):
//
//   var buf = new SenderBuffer();
//   var rtx = new RtxStream({ rtxSsrc: 12345, rtxPt: 97 });
//
//   // Every outgoing packet:
//   buf.store(rtpPacket);
//   transport.send(encrypt(rtpPacket));
//
//   // On NACK arrival for mediaSsrc:
//   for (var seq of lostSequenceNumbers) {
//     var orig = buf.get(mediaSsrc, seq);
//     if (!orig) continue;                // evicted or never sent
//     if (!throttle.shouldSend(mediaSsrc, seq)) continue;
//     var rtxPkt = rtx.wrap(orig);
//     transport.send(encrypt(rtxPkt));
//   }
//
//
// RFC references:
//   - RFC 3550 §5.1    — RTP header format
//   - RFC 4585 §6.2.1  — Generic NACK (FCI: PID + BLP bitmask)
//   - RFC 4588 §4      — RTX payload format (OSN prepended, separate SSRC)
//

import { randomBytes } from 'node:crypto';

/**
 * Default size of the per-SSRC retransmission ring buffer, in packets.
 *
 * At a typical 30 fps single-packet-per-frame stream this covers ~17s of
 * history. At 10 packets per frame (highly-fragmented I-frames) it drops
 * to ~1.7s — still well past any realistic NACK RTT. Memory cost is
 * 512 slots * ~1300 bytes/packet = ~650KB per stream.
 */
var DEFAULT_BUFFER_SIZE = 512;

/**
 * Default NACK dedup window (milliseconds). If the same PID is requested
 * again within this window, we don't resend. Prevents a NACK storm from
 * multiplying our upstream. Chrome re-requests typically every 50-100ms,
 * so 100ms is a reasonable floor.
 */
var DEFAULT_THROTTLE_MS = 100;


/**
 * SenderBuffer — per-SSRC ring buffer of plaintext RTP packets.
 *
 * Packets are stored by (ssrc, seq). The buffer is per-SSRC so primary
 * and RTX streams (or multiple senders sharing this buffer) never collide.
 * Each SSRC has its own ring of `size` slots indexed by (seq % size).
 * When seq wraps around after 65536, old slots are overwritten naturally.
 *
 * The entry stores the actual seq number alongside the packet so stale
 * slots (from wrap-around or eviction) can be distinguished from fresh
 * ones — get(ssrc, seq) returns null unless the slot's seq matches.
 *
 * store() keeps a *copy* of the packet bytes (Buffer.from), so callers
 * are free to reuse or mutate their buffer after the call.
 */
function SenderBuffer(opts) {
  opts = opts || {};
  this._size = opts.size || DEFAULT_BUFFER_SIZE;
  this._rings = Object.create(null);   // ssrc → Array<{seq, packet}>
}

SenderBuffer.prototype.store = function (rtpPacket) {
  if (!rtpPacket || rtpPacket.length < 12) return;
  var ssrc = rtpPacket.readUInt32BE(8);
  var seq  = rtpPacket.readUInt16BE(2);
  var ring = this._rings[ssrc];
  if (!ring) ring = this._rings[ssrc] = new Array(this._size);
  ring[seq % this._size] = {
    seq:    seq,
    packet: Buffer.from(rtpPacket),   // snapshot; caller can reuse their buffer
  };
};

SenderBuffer.prototype.get = function (ssrc, seq) {
  var ring = this._rings[ssrc];
  if (!ring) return null;
  var slot = ring[seq % this._size];
  if (!slot || slot.seq !== seq) return null;  // evicted or never stored
  return slot.packet;
};

SenderBuffer.prototype.clear = function (ssrc) {
  if (ssrc == null) {
    this._rings = Object.create(null);
  } else {
    delete this._rings[ssrc];
  }
};


/**
 * buildRtxPacket — pure function. Converts an original RTP packet into
 * its RFC 4588 retransmission form.
 *
 * Transformation:
 *   - PT byte:  [M|PT] → [M|rtxPt]             (marker bit preserved)
 *   - Seq:      overwritten with rtxSeq        (independent counter)
 *   - SSRC:     overwritten with rtxSsrc
 *   - Payload:  prepend 2-byte OSN (original sequence number)
 *
 * CSRC list + header extensions are preserved as-is.
 *
 * Returns a fresh Buffer; the input is not mutated.
 */
function buildRtxPacket(origPkt, opts) {
  if (!origPkt || origPkt.length < 12) return null;
  if (!opts || opts.rtxSsrc == null || opts.rtxPt == null || opts.rtxSeq == null) {
    return null;
  }

  // Compute original header length (fixed 12 + CSRC list + ext).
  var cc = origPkt[0] & 0x0F;
  var hasExt = !!(origPkt[0] & 0x10);
  var headerLen = 12 + cc * 4;
  if (hasExt && origPkt.length >= headerLen + 4) {
    var extLen = origPkt.readUInt16BE(headerLen + 2);   // in 32-bit words
    headerLen += 4 + extLen * 4;
  }
  if (origPkt.length < headerLen) return null;

  var origSeq    = origPkt.readUInt16BE(2);
  var payloadLen = origPkt.length - headerLen;

  // [copy of original header] || [OSN (2 bytes)] || [original payload]
  var out = Buffer.allocUnsafe(headerLen + 2 + payloadLen);
  origPkt.copy(out, 0, 0, headerLen);

  // Patch PT (preserve marker bit): byte 1 = M (1 bit) | PT (7 bits).
  out[1] = (origPkt[1] & 0x80) | (opts.rtxPt & 0x7F);

  // Patch sequence number.
  out.writeUInt16BE(opts.rtxSeq & 0xFFFF, 2);

  // Patch SSRC (byte 8).
  out.writeUInt32BE(opts.rtxSsrc >>> 0, 8);

  // OSN at start of payload.
  out.writeUInt16BE(origSeq, headerLen);

  // Original payload after OSN.
  origPkt.copy(out, headerLen + 2, headerLen);

  return out;
}


/**
 * parseRtxPacket — pure function. Inverse of buildRtxPacket.
 * Reconstructs the original RTP packet from an RFC 4588 retransmission
 * packet, restoring:
 *   - PT byte:  [M|rtxPt] → [M|primaryPt]      (marker bit preserved)
 *   - Seq:      overwritten with OSN read from payload
 *   - SSRC:     overwritten with primarySsrc
 *   - Payload:  drop the leading 2-byte OSN
 *
 * CSRC list + header extensions are preserved (the sender copied them
 * from the original; we keep them).
 *
 * Returns a fresh Buffer; the input is not mutated. Returns null if the
 * packet is too short to contain a valid RTP header + OSN, or if opts
 * is missing required fields.
 *
 * Note: the caller (typically a connection manager that already knows
 * which SSRCs are RTX and what their primary mapping is) supplies
 * primarySsrc and primaryPt. This function does not look them up — it
 * just performs the byte-level transformation.
 */
function parseRtxPacket(rtxPkt, opts) {
  if (!rtxPkt || rtxPkt.length < 12) return null;
  if (!opts || opts.primarySsrc == null || opts.primaryPt == null) {
    return null;
  }

  // Compute header length (same algorithm as buildRtxPacket).
  var cc = rtxPkt[0] & 0x0F;
  var hasExt = !!(rtxPkt[0] & 0x10);
  var headerLen = 12 + cc * 4;
  if (hasExt && rtxPkt.length >= headerLen + 4) {
    var extLen = rtxPkt.readUInt16BE(headerLen + 2);   // in 32-bit words
    headerLen += 4 + extLen * 4;
  }

  // RFC 3550 padding must be excluded BEFORE locating the OSN. Chrome's
  // bandwidth probes arrive on the RTX SSRC as padding-only packets:
  // P bit set, padding bytes only, no OSN, no wrapped media. Reading the
  // padding bytes as if they were an OSN fabricated a "recovered" primary
  // packet with seq=0 (padding is zeros) and garbage payload — observed
  // live as runs of seq=0 packets injected into the media pipeline,
  // poisoning the NackGenerator window and the jitter buffer's resync
  // heuristic. Same RFC 3550 §5.1 validation as parse(): a pad count of
  // 0 or one that exceeds the packet is ignored, not honored.
  var payloadEnd = rtxPkt.length;
  if (rtxPkt[0] & 0x20) {
    var padLen = rtxPkt[rtxPkt.length - 1];
    if (padLen >= 1 && headerLen + padLen <= rtxPkt.length) payloadEnd -= padLen;
  }

  // Need at least a 2-byte OSN of real (non-padding) payload. A padding-
  // only probe has none — it repairs nothing and stops here; it already
  // served its purpose by being received and counted for BWE.
  if (payloadEnd < headerLen + 2) return null;

  var osn        = rtxPkt.readUInt16BE(headerLen);
  var payloadLen = payloadEnd - headerLen - 2;

  // [copy of header] || [original payload (skipping OSN)]
  var out = Buffer.allocUnsafe(headerLen + payloadLen);
  rtxPkt.copy(out, 0, 0, headerLen);

  // Clear the P bit — the padding bytes were not copied into the
  // reconstructed packet, so advertising padding would corrupt parse().
  out[0] = out[0] & ~0x20;

  // Patch PT (preserve marker bit): byte 1 = M (1 bit) | PT (7 bits).
  out[1] = (rtxPkt[1] & 0x80) | (opts.primaryPt & 0x7F);

  // Patch sequence number to OSN.
  out.writeUInt16BE(osn, 2);

  // Patch SSRC to primary's.
  out.writeUInt32BE(opts.primarySsrc >>> 0, 8);

  // Copy payload after the OSN, stopping at payloadEnd — trailing padding
  // (if any) stays behind, matching the cleared P bit above.
  rtxPkt.copy(out, headerLen, headerLen + 2, payloadEnd);

  return out;
}


/**
 * RtxStream — stateful wrapper around buildRtxPacket() that auto-advances
 * the RTX stream's sequence number. One per (primary, RTX) pair.
 *
 * RFC 3550 §5.1: the initial sequence number SHOULD be unpredictable to
 * prevent plaintext attack against the (hypothetical) stream cipher.
 * Under SRTP the cipher keying is independent so the requirement is
 * relaxed in practice, but using crypto.randomBytes (CSPRNG) instead of
 * Math.random (PRNG with predictable output given a few samples) costs
 * nothing and is what the spec asks for.
 *
 * Math.random in Node uses xoroshiro128+ which is NOT cryptographically
 * secure — given ~5 sequential outputs an attacker can recover internal
 * state and predict future outputs. We don't currently expose multiple
 * RtxStream initial seqs from the same process to anyone who might care,
 * but the cost of doing it correctly is one syscall (randomBytes(2)),
 * called once per RtxStream constructor — negligible overhead, full
 * spec alignment.
 */
function RtxStream(opts) {
  opts = opts || {};
  if (opts.rtxSsrc == null || opts.rtxPt == null) {
    throw new Error('RtxStream: rtxSsrc and rtxPt required');
  }
  this._rtxSsrc = opts.rtxSsrc >>> 0;
  this._rtxPt   = opts.rtxPt & 0x7F;
  this._seq     = (opts.initialSeq != null)
    ? (opts.initialSeq & 0xFFFF)
    : randomBytes(2).readUInt16BE(0);
}

RtxStream.prototype.wrap = function (origPkt) {
  this._seq = (this._seq + 1) & 0xFFFF;
  return buildRtxPacket(origPkt, {
    rtxSsrc: this._rtxSsrc,
    rtxPt:   this._rtxPt,
    rtxSeq:  this._seq,
  });
};

RtxStream.prototype.ssrc = function () { return this._rtxSsrc; };
RtxStream.prototype.pt   = function () { return this._rtxPt; };
RtxStream.prototype.seq  = function () { return this._seq; };


/**
 * NackThrottle — dedup recently-requested (ssrc, seq) pairs, so a NACK
 * storm doesn't cause us to retransmit the same packet over and over in
 * quick succession.
 *
 * shouldSend() returns true iff the pair hasn't been sent in the last
 * `windowMs` milliseconds. Entries auto-expire via a probabilistic sweep
 * (≈1% of calls) so the internal map doesn't grow unboundedly on long
 * sessions.
 */
function NackThrottle(opts) {
  opts = opts || {};
  this._windowMs = opts.windowMs || DEFAULT_THROTTLE_MS;
  this._lastSent = Object.create(null);   // "ssrc:seq" → timestamp
}

NackThrottle.prototype.shouldSend = function (ssrc, seq) {
  var key = ssrc + ':' + seq;
  var now = Date.now();
  var last = this._lastSent[key];
  if (last && (now - last) < this._windowMs) return false;
  this._lastSent[key] = now;

  // Occasional sweep — keep the map size bounded in long sessions.
  if (Math.random() < 0.01) this._evictExpired(now);

  return true;
};

NackThrottle.prototype._evictExpired = function (now) {
  var cutoff = now - this._windowMs * 20;   // keep ~2s of history max
  var keys = Object.keys(this._lastSent);
  for (var i = 0; i < keys.length; i++) {
    if (this._lastSent[keys[i]] < cutoff) delete this._lastSent[keys[i]];
  }
};

NackThrottle.prototype.clear = function () {
  this._lastSent = Object.create(null);
};


/* ────────────────────────────────────────────────────────────────────
 * RECEIVE SIDE
 * ──────────────────────────────────────────────────────────────────── */

import flatRanges from 'flat-ranges';

/**
 * Receive-side defaults. These mirror libwebrtc's nack_module.cc and
 * mediasoup's NackGenerator.cpp, both of which converged on the same
 * numbers after years of production tuning. We deliberately match them
 * — deviating would mean we're either over- or under-NACKing relative
 * to what senders are calibrated against.
 */
var DEFAULT_MAX_PACKET_AGE   = 10000;  // extSeqs (≈100s @30fps single-pkt frames; ≈10s @1000pps)
var DEFAULT_MAX_NACK_ENTRIES = 1000;   // hard cap on _missing.size before eviction
var DEFAULT_MAX_NACK_RETRIES = 10;     // libwebrtc kMaxNackRetries
var DEFAULT_RTT_MS           = 100;    // libwebrtc kDefaultRttMs
var DEFAULT_SEND_NACK_DELAY  = 0;      // 0 = NACK immediately on gap; 5-20ms recommended for reordered networks
var DEFAULT_REORDER_BUCKETS  = 10;     // libwebrtc kNumReorderingBuckets
var DEFAULT_REORDER_VALUES   = 128;    // libwebrtc kMaxReorderedPackets


/**
 * Histogram — discrete histogram with circular buffer of recent values.
 *
 * This is a faithful port of libwebrtc's video_coding::Histogram
 * (modules/video_coding/histogram.cc). It tracks the last `maxNumValues`
 * samples in a circular buffer and maintains per-bucket counts for fast
 * InverseCdf queries.
 *
 * Buckets are 0..numBuckets-1. Values >= numBuckets are clamped to the
 * last bucket. This makes it safe to feed unbounded values; outliers
 * just stack up in the tail.
 *
 * Used by NackGenerator to track reordering distances — how many packets
 * a late packet typically arrives behind. The 50th-percentile distance
 * is then used as a delay before NACKing a missing seq, so we don't
 * NACK packets that would have arrived on their own anyway.
 */
function Histogram(numBuckets, maxNumValues) {
  if (!(numBuckets > 0) || !(maxNumValues > 0)) {
    throw new Error('Histogram: numBuckets and maxNumValues must be > 0');
  }
  this._buckets      = new Array(numBuckets);
  for (var i = 0; i < numBuckets; i++) this._buckets[i] = 0;
  this._values       = [];                 // grows to maxNumValues, then circular
  this._maxNumValues = maxNumValues;
  this._index        = 0;                  // next slot to overwrite (0..maxNumValues-1)
}

/**
 * Add — insert a sample. If the buffer is at capacity, the oldest sample
 * is overwritten and its bucket count decremented before the new one
 * takes its place.
 */
Histogram.prototype.add = function (value) {
  // Clamp to last bucket — protects against unbounded inputs.
  if (value < 0) value = 0;
  if (value > this._buckets.length - 1) value = this._buckets.length - 1;

  if (this._index < this._values.length) {
    // Overwriting an existing slot — first remove its contribution.
    --this._buckets[this._values[this._index]];
    this._values[this._index] = value;
  } else {
    // Still filling up — append.
    this._values.push(value);
  }

  ++this._buckets[value];
  this._index = (this._index + 1) % this._maxNumValues;
};

/**
 * inverseCdf — return the smallest bucket index B such that the cumulative
 * probability over buckets [0..B) is >= `probability`. Used to query
 * "what's the threshold above which we accept the next P fraction of
 * samples?"
 *
 * For NACK: inverseCdf(0.5) gives the median reordering distance —
 * we'll wait that many packets before NACKing a gap, since 50% of late
 * packets historically arrived within that window on their own.
 *
 * Returns 0 if no samples (caller should check NumValues first).
 */
Histogram.prototype.inverseCdf = function (probability) {
  if (probability < 0) probability = 0;
  if (probability > 1) probability = 1;
  var n = this._values.length;
  if (n === 0) return 0;

  var bucket = 0;
  var accumulated = 0;
  while (accumulated < probability && bucket < this._buckets.length) {
    accumulated += this._buckets[bucket] / n;
    ++bucket;
  }
  return bucket;
};

Histogram.prototype.numValues = function () {
  return this._values.length;
};

Histogram.prototype.reset = function () {
  for (var i = 0; i < this._buckets.length; i++) this._buckets[i] = 0;
  this._values.length = 0;
  this._index = 0;
};


/**
 * NackGenerator — receive-side NACK detection and feedback assembly.
 *
 * Design (after comparing libwebrtc nack_module.cc + mediasoup
 * NackGenerator.cpp):
 *
 *   - `_received` is a flat-ranges array. Membership only — no per-seq
 *     metadata needed to answer "did this arrive?". Compact representation
 *     (typically a handful of integers even for 10s of seq numbers).
 *
 *   - `_missing` is a Map<extSeq → NackInfo>. Per-seq state (createdAt,
 *     sentAt, retries, sendAtSeq) makes a Map the right structure here;
 *     a flat-range can't express "this seq has been NACKed 3 times,
 *     last at t=12345". libwebrtc + mediasoup both use ordered maps for
 *     the same reason — we follow the proven shape.
 *
 *   - `_keyframes` is a sorted array of extSeqs marking keyframes. When
 *     `_missing` overflows MaxNackEntries, we evict everything below the
 *     latest keyframe (those packets are useless to the decoder anyway —
 *     it'll start fresh from the next keyframe). If still full, signal
 *     `needKeyframe` to the caller (typically translated to PLI). This
 *     escalation policy matches mediasoup.
 *
 *   - All seq numbers passed in/out are EXTENDED seq (cycles*65536+seq),
 *     monotonically increasing. This generator does not deal with 16-bit
 *     wraparound — the caller (handleIncomingRtp in our case) already
 *     has cycle tracking and converts before calling. This makes flat-ranges
 *     usable directly (it operates on monotonic integers).
 *
 * Wiring:
 *
 *     var gen = new NackGenerator({ rttMs: 100 });
 *
 *     // On every incoming RTP packet for the SSRC we're protecting:
 *     gen.observePacket(extSeq, isKeyframe, isRecovered);
 *
 *     // Whenever a fresher RTT estimate becomes available (e.g. from RR DLSR):
 *     gen.updateRtt(rttMs);
 *
 *     // From an RTCP timer (typically 20-100ms):
 *     var seqs = gen.buildFeedback(now);
 *     if (seqs.length) {
 *       var pkt = rtcp.buildNACK(ourSsrc, mediaSsrc,
 *                                seqs.map(extToShort));
 *       transport.send(encrypt(pkt));
 *     }
 *
 *     // If gen.needKeyframe() returns true at any point, the current
 *     // _missing list is unrecoverable — send a PLI to ask for a fresh
 *     // start. Then call gen.acknowledgeKeyframeRequested() to clear.
 *
 * Output of buildFeedback() is an array of EXTENDED seq numbers. The
 * caller is responsible for masking back to 16-bit before passing to
 * rtcp.buildNACK (which expects 16-bit PIDs).
 */
function NackGenerator(opts) {
  opts = opts || {};
  this._maxPacketAge    = opts.maxPacketAge    != null ? opts.maxPacketAge    : DEFAULT_MAX_PACKET_AGE;
  this._maxNackEntries  = opts.maxNackEntries  != null ? opts.maxNackEntries  : DEFAULT_MAX_NACK_ENTRIES;
  this._maxNackRetries  = opts.maxNackRetries  != null ? opts.maxNackRetries  : DEFAULT_MAX_NACK_RETRIES;
  this._rttMs           = opts.rttMs           != null ? opts.rttMs           : DEFAULT_RTT_MS;
  this._sendNackDelayMs = opts.sendNackDelayMs != null ? opts.sendNackDelayMs : DEFAULT_SEND_NACK_DELAY;

  this._received     = [];                    // flat-ranges of arrived extSeqs
  this._missing      = new Map();             // extSeq → {createdAt, sentAt, retries, sendAtSeq}
  this._keyframes    = [];                    // sorted array of extSeqs that were keyframes

  // Reordering histogram — tracks how far behind out-of-order packets
  // typically arrive (in extSeq distance). Used to delay first NACK on
  // gaps so we don't NACK packets that would have shown up on their own.
  // libwebrtc uses 10 buckets × 128 max values; we follow.
  this._reorderHistogram = new Histogram(
    opts.reorderBuckets != null ? opts.reorderBuckets : DEFAULT_REORDER_BUCKETS,
    opts.reorderValues  != null ? opts.reorderValues  : DEFAULT_REORDER_VALUES
  );

  this._highestExtSeq = -1;                   // max extSeq seen
  this._started       = false;
  this._needKeyframe  = false;                // set when _missing overflows beyond recovery
}

/**
 * _waitNumberOfPackets — return the extSeq distance to wait before
 * NACKing a newly-detected missing seq. Returns 0 if the histogram has
 * no samples yet (cold start — no reordering data, NACK immediately).
 *
 * libwebrtc calls this with probability=0.5 so the wait equals the
 * median historical reordering distance: half of all late packets in
 * the past arrived within this many packets, so waiting that long
 * before NACKing avoids redundant NACKs for typical out-of-order.
 */
NackGenerator.prototype._waitNumberOfPackets = function (probability) {
  if (this._reorderHistogram.numValues() === 0) return 0;
  return this._reorderHistogram.inverseCdf(probability);
};

/**
 * observePacket — process one incoming RTP packet.
 *
 * @param {number}  extSeq      — extended seq number (caller maintains cycles)
 * @param {boolean} isKeyframe  — true if this is the first packet of a keyframe
 * @param {boolean} isRecovered — true if this came via RTX (don't gap-detect off it)
 */
NackGenerator.prototype.observePacket = function (extSeq, isKeyframe, isRecovered) {
  // Record arrival in _received unconditionally. Even RTX-recovered
  // packets count as "we have this one" for future NACK suppression.
  flatRanges.add(this._received, [extSeq, extSeq + 1]);

  // If this seq was sitting in _missing, it's no longer missing.
  this._missing.delete(extSeq);

  // First-ever packet: just initialize, no gaps to detect.
  if (!this._started) {
    this._started = true;
    this._highestExtSeq = extSeq;
    if (isKeyframe) this._addKeyframe(extSeq);
    return;
  }

  // Recovered packets MUST NOT advance _highestExtSeq even if they happen
  // to be newer than what we'd seen on the primary stream. RTX is "out of
  // band history" — using it as the gap-detection anchor would tell us
  // there's no gap when there really is one (we just got the recovery
  // for it before the original loss was detected). libwebrtc and
  // mediasoup both enforce this.
  if (isRecovered) {
    if (isKeyframe) this._addKeyframe(extSeq);
    return;
  }

  // Out-of-order arrival: extSeq is older than highest. Nothing to add
  // to _missing (already accounted for when the gap was created), and
  // we already removed it from _missing above.
  //
  // libwebrtc nack_module.cc: only NON-retransmitted out-of-order packets
  // count toward the reordering distribution. RTX packets are by
  // definition late (we asked for them), so including them would skew
  // the histogram toward over-waiting.
  if (extSeq <= this._highestExtSeq) {
    if (!isRecovered && extSeq < this._highestExtSeq) {
      var diff = this._highestExtSeq - extSeq;
      this._reorderHistogram.add(diff);
    }
    if (isKeyframe) this._addKeyframe(extSeq);
    return;
  }

  // New high-water mark. Everything between (highest+1) and (extSeq-1)
  // is missing — but if THIS packet is a keyframe, packets below it are
  // useless to the decoder (it'll start fresh from this keyframe). In
  // that case we skip adding the gap and also evict any existing missing
  // entries below the keyframe. This matches mediasoup's behavior and
  // avoids requesting RTX for packets the decoder will never use.
  if (extSeq > this._highestExtSeq + 1) {
    if (isKeyframe) {
      // Drop any existing missing entries that are below this keyframe;
      // they're now superseded.
      this._evictMissingBelow(extSeq);
      // Don't add the new gap — those packets are useless.
    } else {
      this._addMissingRange(this._highestExtSeq + 1, extSeq);
    }
  }

  this._highestExtSeq = extSeq;
  if (isKeyframe) this._addKeyframe(extSeq);

  // Opportunistic age-out — cheap when called per-packet. The bulk
  // eviction work happens in buildFeedback (where we also evict
  // exhausted-retry entries). Here we just trim what's clearly out
  // of window so memory stays bounded between drains.
  this._evictOld();
};

/**
 * _addMissingRange — insert [start, end) into _missing with overflow
 * protection. Each new entry gets fresh NackInfo. If the resulting
 * size would exceed _maxNackEntries, run smart eviction (mediasoup-style):
 *
 *   1. Drop entries below the latest keyframe (those are useless —
 *      the decoder will start from the next keyframe regardless).
 *   2. If still over, drop everything and signal needKeyframe.
 *
 * Both paths bound memory in the face of catastrophic loss.
 */
NackGenerator.prototype._addMissingRange = function (start, end) {
  // Pre-count actual additions: scan [start, end) and skip seqs already
  // in _received. The latter case happens when an RTX retransmit delivers
  // a packet BEFORE the natural-order arrival fires the gap detection —
  // observePacket's RTX path stamps _received with the recovered seq,
  // then a few packets later a forward-jump in the natural seq triggers
  // _addMissingRange over a range that includes the recovered seq.
  //
  // The loop at line ~660 below already skips these (defensive `if
  // contains(_received, seq) continue`), so the actual insert count
  // equals newCount-skipped. The willBe projection MUST mirror this,
  // otherwise a range with many already-recovered seqs spuriously
  // triggers eviction on still-tight memory pressure (`willBe >
  // _maxNackEntries` fires; eviction starts dropping below-keyframe
  // entries; sometimes also fires the "still over" branch and clears
  // _missing entirely + sets _needKeyframe — a real cost when the
  // actual addition would have fit comfortably).
  //
  // Cost: O(end-start) extra contains() checks, all cheap (flat-ranges
  // is binary-searched). For typical small gaps (1-5 seqs) the cost
  // is sub-microsecond; for large catastrophic-loss gaps the precise
  // count is exactly when it matters most.
  var newCount = 0;
  for (var preScanSeq = start; preScanSeq < end; preScanSeq++) {
    if (!flatRanges.contains(this._received, preScanSeq)) newCount++;
  }
  var willBe = this._missing.size + newCount;

  if (willBe > this._maxNackEntries) {
    // Step 1: evict below latest keyframe
    if (this._keyframes.length > 0) {
      var latestKf = this._keyframes[this._keyframes.length - 1];
      this._evictMissingBelow(latestKf);
      willBe = this._missing.size + newCount;
    }

    // Step 2: still over? clear all + ask for keyframe.
    if (willBe > this._maxNackEntries) {
      this._missing.clear();
      this._needKeyframe = true;
      // We deliberately DON'T add the new range either — we're asking
      // for a fresh keyframe, so requesting retransmission of these
      // packets would only waste bandwidth.
      return;
    }
  }

  // Compute the wait threshold once for the whole batch: every newly
  // missing extSeq gets `sendAtSeq = extSeq + medianReorder`. The first
  // NACK isn't sent until _highestExtSeq exceeds sendAtSeq — i.e., until
  // we've seen enough new packets that this seq is unlikely to be just
  // reordered. With no histogram data yet, wait=0 → NACK immediately.
  var wait = this._waitNumberOfPackets(0.5);

  // Stamp createdAt at gap-detection time (wall clock), NOT at first
  // buildFeedback. The wait clock for sendNackDelayMs measures "how
  // long since the gap was observed", and observePacket runs every
  // arriving packet — far more granular than the buildFeedback poll
  // (typically every 20-100ms). Without this, sendDelay would be
  // measured from poll time and the effective minimum delay would be
  // bounded below by the buildFeedback period (50-100ms instead of
  // the configured 20ms). Default sendDelay=0 hid this for normal
  // sessions; production tunings with sendDelay=5-20ms (recommended
  // for reordered networks) need the precise timing here.
  var now = Date.now();

  for (var seq = start; seq < end; seq++) {
    // Don't add if we've already received it (defensive — a recovered
    // packet might have arrived while we were processing).
    if (flatRanges.contains(this._received, seq)) continue;

    this._missing.set(seq, {
      createdAt:  now,           // gap-detection wall time (see comment above)
      sentAt:     0,             // 0 = never sent yet
      retries:    0,
      sendAtSeq:  seq + wait,    // libwebrtc-style: NACK once highest > this
    });
  }
};

NackGenerator.prototype._addKeyframe = function (extSeq) {
  // Append (sorted) — keyframes arrive in order in practice, but we
  // tolerate out-of-order via binary insert.
  var arr = this._keyframes;
  if (arr.length === 0 || arr[arr.length - 1] < extSeq) {
    arr.push(extSeq);
    return;
  }
  // Binary insert to keep sorted.
  var lo = 0, hi = arr.length;
  while (lo < hi) {
    var mid = (lo + hi) >>> 1;
    if (arr[mid] < extSeq) lo = mid + 1;
    else hi = mid;
  }
  if (arr[lo] !== extSeq) arr.splice(lo, 0, extSeq);
};

/**
 * _evictMissingBelow — remove entries from _missing whose extSeq is
 * strictly less than `cutoff`. Used both for normal age-out and for
 * keyframe-based emergency eviction.
 */
NackGenerator.prototype._evictMissingBelow = function (cutoff) {
  // Map iteration order is insertion order, which is roughly seq order
  // for normal traffic. We do a full scan rather than a sorted index
  // because the eviction work is bounded (only happens at drain).
  var toDelete = [];
  this._missing.forEach(function (info, seq) {
    if (seq < cutoff) toDelete.push(seq);
  });
  for (var i = 0; i < toDelete.length; i++) {
    this._missing.delete(toDelete[i]);
  }
};

/**
 * _evictOld — age-based cleanup. Trims _received, _keyframes, and
 * _missing entries that fall outside the maxPacketAge window relative
 * to _highestExtSeq.
 */
NackGenerator.prototype._evictOld = function () {
  if (this._highestExtSeq < 0) return;
  var cutoff = this._highestExtSeq - this._maxPacketAge;
  if (cutoff <= 0) return;

  // _received: drop everything below cutoff.
  flatRanges.remove(this._received, [-Infinity, cutoff]);

  // _keyframes: drop everything below cutoff.
  var arr = this._keyframes;
  var dropTo = 0;
  while (dropTo < arr.length && arr[dropTo] < cutoff) dropTo++;
  if (dropTo > 0) arr.splice(0, dropTo);

  // _missing: drop everything below cutoff (along with their meta).
  this._evictMissingBelow(cutoff);
};

/**
 * updateRtt — update the RTT estimate used to gate NACK retransmission.
 *
 * Following libwebrtc, we do NOT smooth here — the caller is expected to
 * pass an already-smoothed RTT (e.g. from RR DLSR processing). We just
 * latch the value with a small floor so a degenerate 0ms RTT can't cause
 * NACK storms.
 */
NackGenerator.prototype.updateRtt = function (rttMs) {
  if (typeof rttMs !== 'number' || !isFinite(rttMs)) return;
  this._rttMs = Math.max(20, rttMs);   // floor at 20ms — anything lower invites storms
};

/**
 * buildFeedback — drain the NACK list, returning extSeqs ready for
 * retransmission. Must be called periodically (typically 20-100ms).
 *
 * Decision per-entry follows libwebrtc nack_module.cc semantics:
 *   - never sent + age >= sendNackDelayMs + highest >= sendAtSeq → send
 *   - sent + age since last send >= rttMs                        → send
 *   - retries >= maxNacks                                        → drop
 *
 * The `sendAtSeq` check is the reordering-aware threshold: a freshly
 * missing seq waits until the receiver has seen enough subsequent
 * packets that the missing one is unlikely to be just out-of-order.
 * That threshold is `seq + median(historicalReorderingDistance)`.
 *
 * @param {number} now — current time in ms (Date.now() or equivalent)
 * @returns {number[]} 16-bit seq numbers to NACK now (possibly empty).
 *                     The caller hands these straight to rtcp.buildNACK
 *                     with no further conversion. Internal state uses
 *                     extended seq numbers for wrap-safe comparisons,
 *                     but the output is always native 16-bit (matching
 *                     libwebrtc's NackModule and mediasoup's NackGenerator).
 */
NackGenerator.prototype.buildFeedback = function (now) {
  if (typeof now !== 'number') now = Date.now();
  this._evictOld();

  var out = [];
  var toDelete = [];
  var rtt = this._rttMs;
  var maxRetries = this._maxNackRetries;
  var sendDelay = this._sendNackDelayMs;
  var highest = this._highestExtSeq;

  this._missing.forEach(function (info, seq) {
    if (info.sentAt === 0) {
      // First-time send. Two gates must clear:
      //   (1) sendNackDelayMs elapsed since gap detected (time-based)
      //   (2) highest >= sendAtSeq                       (seq-based, reordering)
      // Both are needed: the time gate handles micro-bursts of
      // reorder (~ms); the seq gate handles structural reordering
      // (some packets always arrive N behind).
      // createdAt is stamped at gap-detection time in _addMissingRange,
      // so the time-since-detection measurement is accurate to the
      // arrival of the gap-revealing packet, not the next buildFeedback poll.
      if (now - info.createdAt < sendDelay) return;
      if (highest < info.sendAtSeq) return;

      // Emit as 16-bit wire seq. The internal extSeq space is monotonic
      // for wrap-safe comparisons; output mirrors RTP's native 16-bit
      // form so the caller hands the array straight to buildNACK with
      // no further conversion. (Both libwebrtc's NackModule and
      // mediasoup's NackGenerator work in 16-bit natively.)
      out.push(seq & 0xFFFF);
      info.sentAt = now;
      info.retries = 1;
      return;
    }

    // Retry: wait at least one RTT.
    if (now - info.sentAt < rtt) return;

    if (info.retries >= maxRetries) {
      toDelete.push(seq);
      return;
    }

    out.push(seq & 0xFFFF);
    info.sentAt = now;
    info.retries += 1;
  });

  for (var i = 0; i < toDelete.length; i++) {
    this._missing.delete(toDelete[i]);
  }

  return out;
};

/**
 * needKeyframe — has the NACK list overflowed beyond what retransmission
 * can recover? When true, the caller should send a PLI/FIR rather than
 * (or in addition to) NACKs and then call acknowledgeKeyframeRequested().
 */
NackGenerator.prototype.needKeyframe = function () {
  return this._needKeyframe;
};

NackGenerator.prototype.acknowledgeKeyframeRequested = function () {
  this._needKeyframe = false;
};

/**
 * stats — debugging snapshot. Cheap; safe to call from a logger.
 */
NackGenerator.prototype.stats = function () {
  return {
    highestExtSeq:    this._highestExtSeq,
    receivedRanges:   this._received.length / 2,    // pairs of from/to
    missing:          this._missing.size,
    keyframes:        this._keyframes.length,
    needKeyframe:     this._needKeyframe,
    rttMs:            this._rttMs,
    reorderSamples:   this._reorderHistogram.numValues(),
    reorderMedian:    this._waitNumberOfPackets(0.5),
  };
};

NackGenerator.prototype.reset = function () {
  this._received.length  = 0;
  this._missing.clear();
  this._keyframes.length = 0;
  this._reorderHistogram.reset();
  this._highestExtSeq    = -1;
  this._started          = false;
  this._needKeyframe     = false;
};


export {
  SenderBuffer, RtxStream, NackThrottle,
  NackGenerator, Histogram,
  buildRtxPacket, parseRtxPacket
};
