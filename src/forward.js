/**
 * forward.js — RTP stream forwarding rewriter (the SFU primitive).
 *
 * An SFU takes packets received from a producer and re-emits them to each
 * consumer as if they originated from the SFU itself: the consumer sees
 * ONE continuous RTP stream (its own SSRC, its own sequence space, its
 * own timestamp timeline) regardless of what happens upstream — including
 * simulcast layer switches, producer restarts, and pauses.
 *
 * Model (the mediasoup SeqManager approach, independently implemented):
 * DELTA-PRESERVING offset mapping. Output seq/ts are input seq/ts minus a
 * per-stream offset. Upstream LOSS gaps are preserved (the consumer must
 * see the gap to NACK it — and the SFU's sender buffer serves the
 * retransmission if the packet arrives late). Source SWITCHES re-base the
 * offsets so the output stays contiguous in seq (+1 from the last
 * forwarded packet) and monotonic in ts (advanced by an estimated jump).
 *
 * The rewrite itself is surgical: the packet is copied and exactly ten
 * header bytes are patched (PT in byte 1 preserving the marker, seq in
 * bytes 2-3, ts in 4-7, SSRC in 8-11). CSRCs, header extensions, payload
 * and padding pass through untouched — whatever the stamper needs to do
 * downstream (mid/TCC rewriting) happens in the sender's own path.
 */

var U16 = 0x10000;

// Wrap-safe signed deltas.
function seqDelta(a, b) {           // a - b in 16-bit space, [-32768, 32767]
  var d = (a - b) & 0xFFFF;
  return d >= 0x8000 ? d - U16 : d;
}
function tsDelta(a, b) {            // a - b in 32-bit space
  var d = (a - b) >>> 0;
  return d >= 0x80000000 ? d - 0x100000000 : d;
}

/**
 * @param {object} opts
 *   ssrc         REQUIRED — the outgoing SSRC this consumer sees.
 *   payloadType  REQUIRED — the outgoing PT (consumer-side negotiation).
 *   startSeq     optional — first output sequence number (default random).
 *   startTs      optional — first output timestamp (default random).
 */
function RtpForwarder(opts) {
  if (!opts || opts.ssrc == null || opts.payloadType == null) {
    throw new Error('RtpForwarder: ssrc and payloadType are required');
  }
  this._ssrc = opts.ssrc >>> 0;
  this._pt   = opts.payloadType & 0x7F;

  this._seqOffset = null;      // in - offset = out  (established on first packet / re-based on switch)
  this._tsOffset  = null;

  this._startSeq = (opts.startSeq != null) ? (opts.startSeq & 0xFFFF)
                                           : Math.floor(Math.random() * U16);
  this._startTs  = (opts.startTs != null) ? (opts.startTs >>> 0)
                                          : (Math.floor(Math.random() * 0xFFFFFFFF) >>> 0);

  this._lastOutSeq = null;     // last EMITTED output seq (for switch re-basing)
  this._lastOutTs  = null;
  this._pendingSwitch = false;
  this._pendingTsJump = 0;

  this._forwarded = 0;

  // Packets this consumer deliberately did not get (a layer above its
  // ceiling), by input seq, since the last re-base. Output numbering
  // closes up over them: a gap the viewer sees is a loss it NACKs and
  // then waits on, and a packet the SFU chose to drop will never come.
  this._drops = [];
  this._highestIn = null;      // newest input seq seen (forwarded or dropped)
  this._dropped = 0;
}

// Drops further back than this are folded into the offset: a packet that
// late is past any reordering, and the list stays short.
var DROP_WINDOW = 512;

RtpForwarder.prototype._foldOldDrops = function () {
  while (this._drops.length && seqDelta(this._highestIn, this._drops[0]) > DROP_WINDOW) {
    this._drops.shift();
    this._seqOffset = (this._seqOffset + 1) | 0;
  }
};

// How many dropped packets come before input seq `inSeq` — the amount
// its output number moves down by.
RtpForwarder.prototype._shiftFor = function (inSeq) {
  var n = this._drops.length;
  if (!n) return 0;
  // In order (the normal case): newer than every drop.
  if (seqDelta(inSeq, this._drops[n - 1]) > 0) return n;
  var k = 0;
  for (var i = 0; i < n; i++) if (seqDelta(inSeq, this._drops[i]) > 0) k++;
  return k;
};

/**
 * The SFU is not forwarding this packet to this consumer (spatial or
 * temporal layer above its ceiling). Later output sequence numbers close
 * up over it, so the viewer sees a contiguous stream instead of a loss.
 * (mediasoup's SeqManager does the same with its dropped set.)
 *
 * A drop before anything was forwarded, or while a re-base is pending,
 * needs no bookkeeping: the next forwarded packet anchors the numbering.
 * A drop of a packet OLDER than one already seen (reordered) is not
 * tracked: it would renumber packets already sent.
 */
RtpForwarder.prototype.drop = function (pkt) {
  if (!pkt || pkt.length < 12) return;
  this._dropped++;
  if (this._seqOffset === null || this._pendingSwitch) return;
  var inSeq = (pkt[2] << 8) | pkt[3];
  if (this._highestIn !== null && seqDelta(inSeq, this._highestIn) <= 0) return;
  this._highestIn = inSeq;
  this._drops.push(inSeq);
  this._foldOldDrops();
};

/**
 * Announce that the NEXT packet comes from a different source timeline
 * (simulcast layer switch, producer replacement, resumed-after-pause).
 * The next forward() re-bases: output seq continues at last+1, output ts
 * advances by `tsJump` (estimate the elapsed media time in RTP units —
 * e.g. one frame duration for a seamless layer switch; larger after a
 * pause). Before anything was forwarded, this is a no-op.
 *
 * @param {number} tsJump  RTP-clock units to advance the output timeline.
 */
RtpForwarder.prototype.switchSource = function (tsJump) {
  if (this._lastOutSeq === null) return;   // nothing emitted yet — first anchor will handle it
  this._pendingSwitch = true;
  this._pendingTsJump = (tsJump == null) ? 0 : (tsJump >>> 0);
};

/**
 * Rewrite one packet for this consumer.
 *
 * @param {Buffer|Uint8Array} pkt  A complete RTP packet (post-SRTP-decrypt).
 * @returns {Buffer|null}  A NEW buffer with patched header, or null if the
 *                         input is not a plausible RTP packet.
 */
RtpForwarder.prototype.forward = function (pkt) {
  if (!pkt || pkt.length < 12) return null;
  if (((pkt[0] >> 6) & 0x03) !== 2) return null;   // RTP version 2 only

  var inSeq = (pkt[2] << 8) | pkt[3];
  var inTs  = ((pkt[4] << 24) | (pkt[5] << 16) | (pkt[6] << 8) | pkt[7]) >>> 0;

  if (this._seqOffset === null) {
    // First packet ever: anchor so that out = startSeq / startTs.
    this._seqOffset = seqDelta(inSeq, this._startSeq);
    this._tsOffset  = tsDelta(inTs, this._startTs) | 0;
    this._drops = [];
  } else if (this._pendingSwitch) {
    // Re-base: the new source's arbitrary seq/ts must land exactly at
    // (lastOut+1, lastOutTs+jump). Deltas WITHIN the new source are
    // preserved from here on.
    this._pendingSwitch = false;
    var wantSeq = (this._lastOutSeq + 1) & 0xFFFF;
    var wantTs  = (this._lastOutTs + this._pendingTsJump) >>> 0;
    this._seqOffset = seqDelta(inSeq, wantSeq);
    this._tsOffset  = tsDelta(inTs, wantTs) | 0;
    this._drops = [];
    this._highestIn = null;
  }

  if (this._highestIn === null || seqDelta(inSeq, this._highestIn) > 0) {
    this._highestIn = inSeq;
    this._foldOldDrops();
  }
  var outSeq = (inSeq - this._seqOffset - this._shiftFor(inSeq)) & 0xFFFF;
  var outTs  = ((inTs - this._tsOffset) >>> 0);

  var out = Buffer.from(pkt);                        // copy — never mutate the shared receive buffer
  out[1] = (out[1] & 0x80) | this._pt;               // preserve marker
  out[2] = (outSeq >> 8) & 0xFF;
  out[3] = outSeq & 0xFF;
  out[4] = (outTs >>> 24) & 0xFF;
  out[5] = (outTs >>> 16) & 0xFF;
  out[6] = (outTs >>> 8) & 0xFF;
  out[7] = outTs & 0xFF;
  out[8] = (this._ssrc >>> 24) & 0xFF;
  out[9] = (this._ssrc >>> 16) & 0xFF;
  out[10] = (this._ssrc >>> 8) & 0xFF;
  out[11] = this._ssrc & 0xFF;

  // Track the furthest emitted point (wrap-safe) — switches continue
  // from the LATEST packet, not from a late reordered one.
  if (this._lastOutSeq === null || seqDelta(outSeq, this._lastOutSeq) > 0) {
    this._lastOutSeq = outSeq;
    this._lastOutTs  = outTs;
  }
  this._forwarded++;
  return out;
};

/** Introspection for stats / debugging. */
RtpForwarder.prototype.getState = function () {
  return {
    ssrc: this._ssrc,
    payloadType: this._pt,
    forwarded: this._forwarded,
    dropped: this._dropped,
    lastOutputSeq: this._lastOutSeq,
    lastOutputTimestamp: this._lastOutTs,
  };
};

export { RtpForwarder };
