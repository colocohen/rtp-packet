// src/bandwidth.js
//
// Bandwidth estimation support for RTP senders.
//
// Parses two RTCP feedback messages that remote peers send to inform us
// about downlink quality:
//
//   - transport-cc  (draft-holmer-rmcat-transport-wide-cc-extensions-01)
//     PT=205, FMT=15. Per-packet arrival times keyed by a transport-wide
//     sequence number (carried in an RTP header extension). Gives us
//     fine-grained delay-variation information for congestion control.
//
//   - REMB          (draft-alvestrand-rmcat-remb)
//     PT=206, FMT=15. A single bitrate value in bps, the remote's estimate
//     of how much we can send. Older and coarser than transport-cc but still
//     emitted by Chrome when `a=rtcp-fb:N goog-remb` is negotiated.
//
// And provides a small sender-side estimator that combines these into a
// single `availableOutgoingBitrate` value usable for rate control. The
// estimator is intentionally conservative and simple: it's not GCC, it's
// "trust the remote unless delay-variation says otherwise."
//
// Transport-agnostic — knows nothing about DTLS/SRTP/ICE. Feed it parsed
// feedback events, ask it for the current estimate.
//


/**
 * parseTransportCC — decodes the FCI portion of an RTCP transport-cc
 * feedback packet (RTPFB PT=205 FMT=15).
 *
 * Wire format (from draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1):
 *
 *    0               1               2               3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      base sequence number     |      packet status count      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 reference time                | fb pkt. count |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          packet chunk         |         packet chunk          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   .                                                               .
 *   |         packet chunk          |  recv delta   |  recv delta   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   .                                                               .
 *   |           recv delta          |  recv delta   | zero padding  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Reference time is 24-bit signed in units of 64ms.
 * Packet chunks are 16-bit, two forms:
 *   - Run length:       [0][S (2 bits)][run length (13 bits)]
 *     S = 00 not received, 01 received (small delta), 10 received (large delta)
 *   - Status vector:    [1][symbol size][14 or 7 symbols]
 *     symbol size = 0 → 14 one-bit symbols (0 = lost, 1 = received small)
 *     symbol size = 1 → 7 two-bit symbols (same codes as run length)
 * Recv deltas are in 250µs units, unsigned 8-bit for "small" (0..63.75ms)
 * and signed 16-bit for "large" (-8192..+8191.75ms).
 *
 * @param {Buffer} fci — FCI bytes (starts at offset 12 of the RTCP packet,
 *                       after the common 4-byte header, sender SSRC,
 *                       and media SSRC fields)
 * @returns {object|null} {
 *     baseSeq,          // uint16 — first transport-wide seq in this report
 *     packetCount,      // uint16 — number of packets described
 *     referenceTimeMs,  // ms (abs, wraps every ~4.6 hours at 24-bit / 64ms)
 *     fbPktCount,       // uint8 — increments per feedback sent for this peer
 *     packets,          // [{seq, received, deltaUs}, …]
 *                       //   received: boolean
 *                       //   deltaUs: present iff received, integer µs offset
 *                       //            from previous recv time (or refTime for
 *                       //            the first received packet)
 *   }  or null if the buffer is malformed.
 */
function parseTransportCC(fci) {
  if (!fci || fci.length < 8) return null;

  var baseSeq     = fci.readUInt16BE(0);
  var packetCount = fci.readUInt16BE(2);
  // Reference time is 24-bit signed, big-endian, in 64ms units.
  var refRaw = (fci[4] << 16) | (fci[5] << 8) | fci[6];
  if (refRaw & 0x800000) refRaw |= 0xFF000000;   // sign-extend
  refRaw = refRaw | 0;   // force signed 32-bit
  var referenceTimeMs = refRaw * 64;
  var fbPktCount = fci[7];

  // Pass 1: decode packet chunks into a per-packet symbol array.
  //   0 = not received
  //   1 = received small delta (1 byte)
  //   2 = received large delta (2 bytes)
  //   3 = reserved (draft §3.1.3): the feedback is malformed
  var symbols = [];
  var off = 8;
  while (symbols.length < packetCount) {
    if (off + 2 > fci.length) return null;
    var chunk = fci.readUInt16BE(off);
    off += 2;

    if ((chunk & 0x8000) === 0) {
      // Run-length chunk: T=0 | S(2) | runLen(13)
      var s       = (chunk >> 13) & 0x3;
      var runLen  = chunk & 0x1FFF;
      for (var i = 0; i < runLen && symbols.length < packetCount; i++) {
        symbols.push(s);
      }
    } else {
      // Status vector: T=1 | symbolSize(1) | bits(14)
      var symbolSize = (chunk >> 14) & 0x1;
      if (symbolSize === 0) {
        // 14 single-bit symbols (0 = not received, 1 = received small delta)
        for (var i = 13; i >= 0 && symbols.length < packetCount; i--) {
          symbols.push(((chunk >> i) & 0x1) ? 1 : 0);
        }
      } else {
        // 7 two-bit symbols
        for (var i = 6; i >= 0 && symbols.length < packetCount; i--) {
          symbols.push((chunk >> (i * 2)) & 0x3);
        }
      }
    }
  }

  // Pass 2: decode recv deltas — one per received packet.
  var packets = [];
  for (var i = 0; i < packetCount; i++) {
    var seq = (baseSeq + i) & 0xFFFF;
    var sym = symbols[i];

    if (sym === 3) {
      // The two-bit symbol 11 is reserved (draft §3.1.3). It used to be read
      // as "received, no delta", a meaning the draft does not give it; the
      // feedback is rejected instead, as libwebrtc does.
      return null;
    }
    if (sym === 0) {
      packets.push({ seq: seq, received: false, deltaUs: null });
      continue;
    }

    if (sym === 1) {
      // Small delta (1 byte unsigned, 250µs units)
      if (off + 1 > fci.length) return null;
      var d8 = fci[off]; off += 1;
      packets.push({ seq: seq, received: true, deltaUs: d8 * 250 });
    } else if (sym === 2) {
      // Large delta (2 bytes signed, 250µs units)
      if (off + 2 > fci.length) return null;
      var d16 = fci.readInt16BE(off); off += 2;
      packets.push({ seq: seq, received: true, deltaUs: d16 * 250 });
    }
  }

  return {
    baseSeq:          baseSeq,
    packetCount:      packetCount,
    referenceTimeMs:  referenceTimeMs,
    fbPktCount:       fbPktCount,
    packets:          packets,
  };
}


/**
 * parseREMB — decodes the FCI portion of a REMB feedback message
 * (PSFB PT=206 FMT=15).
 *
 * Wire format (draft-alvestrand-rmcat-remb):
 *
 *    0               1               2               3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Unique identifier 'R' 'E' 'M' 'B'                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Num SSRC    | BR Exp |   BR Mantissa                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   SSRC feedback (first)                                       |
 *   ...                                                             ...
 *
 * Bitrate = mantissa << exp  (in bps)
 *
 * @param {Buffer} fci — FCI bytes
 * @returns {object|null} { bitrate, ssrcs: [...] } or null if malformed
 */
function parseREMB(fci) {
  if (!fci || fci.length < 8) return null;
  if (fci[0] !== 0x52 /*R*/ || fci[1] !== 0x45 /*E*/ ||
      fci[2] !== 0x4D /*M*/ || fci[3] !== 0x42 /*B*/) {
    return null;   // not a REMB FCI
  }

  var numSsrc  = fci[4];
  var brExp    = (fci[5] >> 2) & 0x3F;
  var mantissa = ((fci[5] & 0x03) << 16) | (fci[6] << 8) | fci[7];
  var bitrate  = mantissa * Math.pow(2, brExp);   // bps

  var ssrcs = [];
  for (var i = 0; i < numSsrc; i++) {
    var off = 8 + i * 4;
    if (off + 4 > fci.length) break;
    ssrcs.push(fci.readUInt32BE(off));
  }

  return { bitrate: bitrate, ssrcs: ssrcs };
}


/**
 * BandwidthEstimator — tracks incoming bandwidth signals and produces a
 * single current estimate in bps.
 *
 * Inputs:
 *   - observeRemb(bitrate)
 *       Called when a REMB message arrives. Uses the remote's estimate
 *       directly (subject to floor/ceiling), since REMB already contains
 *       an integrated estimate.
 *   - observeTransportCC(report)
 *       Called with the parsed transport-cc FCI. We measure delay
 *       variation across the reported packets; sustained growth indicates
 *       buffer filling → congestion → reduce estimate. Stable or shrinking
 *       delay → bandwidth is headroom → ramp up slowly.
 *
 * Output:
 *   - getEstimate() → number (bps)
 *
 * This is intentionally simple. It is NOT Google's full congestion
 * controller (GCC). It is a safe, conservative estimator suitable for
 * sender-side adaptive bitrate when no dedicated CC is available.
 * For high-quality congestion control a full GCC or BBR-for-RTP
 * implementation would be needed, but that is out of scope here.
 *
 * Algorithm (simplified delay-based):
 *   - Track last N transport-cc reports.
 *   - For each report, compute delta-delay = Σ recv_deltas − Σ send_deltas
 *     (we approximate send_deltas as (seq_count−1) × expected_pacing_ms;
 *      in practice sender-side needs to track the actual send time per
 *      transport-wide seq to be accurate — the consumer can feed us those
 *      via recordSend() if they want better accuracy).
 *   - If delta-delay trends upward → congestion, reduce 5%.
 *   - If delta-delay trends stable/down → allow 5% growth, capped at the
 *     most recent REMB value if any.
 */
function BandwidthEstimator(opts) {
  opts = opts || {};

  this._minBps        = opts.minBps        || 50 * 1000;       // 50 kbps floor
  this._maxBps        = opts.maxBps        || 100 * 1000 * 1000; // 100 Mbps ceiling
  this._startBps      = opts.startBps      || 500 * 1000;      // 500 kbps initial
  this._remoteRembBps = 0;                                      // last REMB seen

  // Current estimate (bps). Initially optimistic; will converge as
  // feedback arrives.
  this._estimate = this._startBps;

  // Send-time history: transportSeq → { sendTimeMs, sizeBytes }.
  // Populated by recordSend() on the sender side. Bounded ring.
  this._sendHistory = Object.create(null);
  this._sendHistoryOrder = [];   // for FIFO eviction
  this._sendHistoryMax = 2048;   // ~20s at 100pkt/s

  // Delay-variation smoothing: exponential moving average of the trend.
  this._delayTrendMs = 0;

  // Whether usable transport-cc feedback has arrived (a report with at least
  // one pair of packets we know the send times of). With it, the estimate is
  // ours (send-side, delay and loss based) and a REMB is only a ceiling on it
  // (libwebrtc: SendSideBandwidthEstimation caps its estimate with the
  // receiver's). Without it, REMB is the only rate signal there is.
  this._tccActive = false;

  // Loss-based control (draft-ietf-rmcat-gcc-02 §6), over windows of at least
  // LOSS_WINDOW_PACKETS reported packets: the lost and the reported counts
  // of the open window, and whether the last closed one held the estimate
  // (loss between 2% and 10%: no increase until a window says otherwise).
  this._lossLost = 0;
  this._lossTotal = 0;
  this._lossHold = false;
}

// Loss-based control (draft-ietf-rmcat-gcc-02 §6): a window of reported
// packets whose loss fraction p is above LOSS_HIGH cuts the estimate to
// estimate * (1 - 0.5 p); between LOSS_LOW and LOSS_HIGH it holds it (no
// increase); below LOSS_LOW it lets it grow. RFC 8836 §4 asks a WebRTC
// congestion controller to react to loss as well as to delay; the estimator
// used to look at delay only, and a link losing half the packets with no
// queue growth saw its estimate climb.
var LOSS_WINDOW_PACKETS = 50;
var LOSS_LOW  = 0.02;
var LOSS_HIGH = 0.10;
// Growth when an RR-only peer (no transport-cc) reports loss under LOSS_LOW:
// GCC's loss-based controller grows by 8% per report; 5% here, the same
// order, as the RR arrives about once a second.
var LOSS_RR_GROWTH = 1.05;

/** Record that we sent a packet with the given transport-wide sequence
 *  number. Call before or at the moment of send. The estimator uses
 *  the recorded send time together with incoming transport-cc arrival
 *  times to compute per-packet delay. */
BandwidthEstimator.prototype.recordSend = function (transportSeq, sendTimeMs, sizeBytes) {
  if (transportSeq == null) return;
  // Feedback carries 16-bit seqs: a wider number would never be looked up.
  transportSeq = transportSeq & 0xFFFF;
  // A seq recorded again (a resend under the same seq) updates its entry in
  // place. Pushing it on the order list a second time let the older copy's
  // eviction delete the fresh entry early.
  var known = transportSeq in this._sendHistory;
  this._sendHistory[transportSeq] = {
    sendTimeMs: sendTimeMs != null ? sendTimeMs : Date.now(),
    sizeBytes:  sizeBytes  || 0,
  };
  if (known) return;
  this._sendHistoryOrder.push(transportSeq);
  if (this._sendHistoryOrder.length > this._sendHistoryMax) {
    var evict = this._sendHistoryOrder.shift();
    delete this._sendHistory[evict];
  }
};

/** Called on REMB arrival. Use it as a ceiling hint. */
BandwidthEstimator.prototype.observeRemb = function (bitrateBps) {
  // `!(x > 0)` also turns away NaN, which `x <= 0` let through to make the
  // estimate NaN for good.
  if (typeof bitrateBps !== 'number' || !(bitrateBps > 0)) return;
  // Sanity floor: REMB values below 10 kbps are almost certainly
  // a bug in the remote or a parsing error — a real WebRTC stream
  // needs ≥30 kbps even for lowest-quality audio. Ignore them so
  // the estimator doesn't get dragged to its floor by noise.
  if (bitrateBps < 10 * 1000) return;
  this._remoteRembBps = bitrateBps;
  var target = Math.min(bitrateBps, this._maxBps);
  target = Math.max(target, this._minBps);
  if (this._tccActive) {
    // A CEILING, not an estimate: with transport-cc the send-side estimate
    // is the evidence, and REMB only caps it. Converging toward it (below)
    // pulled the estimate up to whatever the peer advertised — 10 Mbps from
    // a receiver that runs no REMB estimator of its own (this library's
    // default) — in two REMBs, whatever the delay and loss said.
    if (this._estimate > target) this._estimate = Math.round(target);
    return;
  }
  // No transport-cc: REMB is the only rate signal. Converge toward it but
  // only by half each time — avoids thrash if REMB oscillates.
  this._estimate = Math.round((this._estimate + target) / 2);
};

/**
 * Loss reported by an RTCP receiver report block (RFC 3550 §6.4.1: the
 * fraction lost, an 8-bit fixed point number, over the receiver's last
 * reporting interval). Used only while no transport-cc feedback has come:
 * transport-cc reports each loss already, and counting both would count
 * every loss twice. The loss-based rule of draft-ietf-rmcat-gcc-02 §6 on
 * the interval's fraction p: above 10% the estimate is cut to
 * estimate * (1 - 0.5 p), below 2% it grows (LOSS_RR_GROWTH), between it
 * holds. Bounded by a REMB seen and by the estimator's bounds.
 *
 * @param {number} fractionLost — the report block's field, 0..255
 */
BandwidthEstimator.prototype.observeReceiverReportLoss = function (fractionLost) {
  if (this._tccActive) return;
  if (typeof fractionLost !== 'number' || !(fractionLost >= 0)) return;
  var p = Math.min(fractionLost, 255) / 256;
  var next = this._estimate;
  if (p > LOSS_HIGH) next = this._estimate * (1 - 0.5 * p);
  else if (p < LOSS_LOW) next = this._estimate * LOSS_RR_GROWTH;
  if (this._remoteRembBps > 0) next = Math.min(next, this._remoteRembBps);
  next = Math.max(next, this._minBps);
  next = Math.min(next, this._maxBps);
  this._estimate = Math.round(next);
};

/** Called on transport-cc arrival. Observes delay variation. */
BandwidthEstimator.prototype.observeTransportCC = function (report) {
  if (!report || !report.packets || report.packets.length < 2) return;

  // Compute average delay-gradient across this feedback window.
  // For each pair of consecutive received packets (i, i-1):
  //   arrivalDelta = packets[i].deltaUs   (already relative to previous)
  //   sendDelta    = sendTime[seq_i] - sendTime[seq_(i-1)]
  //   gradient     = arrivalDelta - sendDelta
  // Positive gradient means the network queue is growing.
  var totalGradientUs = 0;
  var pairCount = 0;
  var prevSeq = -1;
  var prevSendMs = 0;
  var cumulativeArrivalUs = 0;

  for (var i = 0; i < report.packets.length; i++) {
    var p = report.packets[i];
    if (!p.received || p.deltaUs == null) continue;
    cumulativeArrivalUs += p.deltaUs;

    var rec = this._sendHistory[p.seq];
    if (!rec) { prevSeq = p.seq; continue; }

    if (prevSeq >= 0 && this._sendHistory[prevSeq]) {
      var arrivalDeltaUs = p.deltaUs;   // relative to previous received
      var sendDeltaMs    = rec.sendTimeMs - prevSendMs;
      var gradientUs     = arrivalDeltaUs - (sendDeltaMs * 1000);
      totalGradientUs   += gradientUs;
      pairCount++;
    }
    prevSeq    = p.seq;
    prevSendMs = rec.sendTimeMs;
  }

  if (pairCount === 0) return;   // no usable data this cycle
  this._tccActive = true;

  // Loss: every packet the report describes counts, received or not
  // (transport-cc names each one). A window closes once it holds
  // LOSS_WINDOW_PACKETS; its fraction decides the loss-based limit below.
  for (var il = 0; il < report.packets.length; il++) {
    this._lossTotal++;
    if (!report.packets[il].received) this._lossLost++;
  }
  var lossCut = null;
  if (this._lossTotal >= LOSS_WINDOW_PACKETS) {
    var pLoss = this._lossLost / this._lossTotal;
    this._lossLost = 0;
    this._lossTotal = 0;
    this._lossHold = pLoss >= LOSS_LOW;
    if (pLoss > LOSS_HIGH) lossCut = this._estimate * (1 - 0.5 * pLoss);
  }

  var avgGradientUs = totalGradientUs / pairCount;
  // EMA the trend so we don't react to single noisy reports.
  // Alpha=0.4 gives reasonable responsiveness without being too jittery
  // on isolated noisy reports.
  var alpha = 0.4;
  this._delayTrendMs = (1 - alpha) * this._delayTrendMs + alpha * (avgGradientUs / 1000);

  // Measure actual throughput over the reporting window. This is the
  // total bytes we sent for the reported packets (from sendHistory).
  // Used as an upper bound on how high we probe — there's no evidence
  // the link supports more than (say) 2× what we actually sent.
  var bytesInWindow = 0;
  var firstSendMs = Infinity, lastSendMs = 0;
  for (var i2 = 0; i2 < report.packets.length; i2++) {
    var rec2 = this._sendHistory[report.packets[i2].seq];
    if (!rec2) continue;
    bytesInWindow += rec2.sizeBytes || 0;
    if (rec2.sendTimeMs < firstSendMs) firstSendMs = rec2.sendTimeMs;
    if (rec2.sendTimeMs > lastSendMs)  lastSendMs  = rec2.sendTimeMs;
  }
  var windowMs = (lastSendMs > firstSendMs) ? (lastSendMs - firstSendMs) : 0;
  // If window is too short to be meaningful, skip the probe-cap.
  var actualBps = (windowMs > 10) ? (bytesInWindow * 8 * 1000 / windowMs) : 0;

  // Decision thresholds in milliseconds of delay-gradient EMA:
  //   > 5ms  → growing queue → back off by 5%
  //   < -3ms → queue draining → probe up by 2% (bounded by REMB hint)
  //   else   → hold ~steady (slow 1% creep up)
  //
  // These numbers are empirical: small enough to notice real congestion,
  // large enough to ignore jitter on a healthy link.
  var next;
  if (this._delayTrendMs > 5) {
    next = this._estimate * 0.95;
  } else if (this._delayTrendMs < -3) {
    next = this._estimate * 1.02;
  } else {
    next = this._estimate * 1.01;
  }

  // Probe cap: don't push the estimate more than 2× what we actually
  // transmitted in this window. There's no evidence the link supports
  // more than what passed through cleanly. Without this, on an idle
  // link (no congestion, no packet loss) the estimate grows unbounded
  // at +1% per feedback until it hits maxBps. This keeps it tethered
  // to reality. Only applied when we have a meaningful throughput
  // measurement (>= 10ms of send-history window).
  var probeCap = actualBps > 0 ? (actualBps * 2) : Infinity;
  next = Math.min(next, Math.max(this._estimate, probeCap));

  // Loss-based limit: the delay-based rate, capped by the loss rule (the
  // smaller of the two, as GCC combines them). Held: no increase.
  if (this._lossHold) next = Math.min(next, this._estimate);
  if (lossCut !== null) next = Math.min(next, lossCut);

  // Respect REMB ceiling (if we have one) and absolute bounds.
  if (this._remoteRembBps > 0) next = Math.min(next, this._remoteRembBps);
  next = Math.max(next, this._minBps);
  next = Math.min(next, this._maxBps);

  this._estimate = Math.round(next);
};

BandwidthEstimator.prototype.getEstimate = function () {
  return this._estimate;
};

BandwidthEstimator.prototype.getRemoteRembEstimate = function () {
  return this._remoteRembBps;
};

/** Reset the estimator (e.g. on renegotiation). */
BandwidthEstimator.prototype.reset = function () {
  this._estimate      = this._startBps;
  this._remoteRembBps = 0;
  this._delayTrendMs  = 0;
  this._sendHistory   = Object.create(null);
  this._sendHistoryOrder = [];
  this._tccActive     = false;
  this._lossLost      = 0;
  this._lossTotal     = 0;
  this._lossHold      = false;
};


// ═══════════════════════════════════════════════════════════════════
//  TMMBR bounding set (RFC 5104 §3.5.4.2)
// ═══════════════════════════════════════════════════════════════════

/**
 * tmmbrBoundingSet — the TMMBR tuples that bound a media sender: RFC 5104
 * §3.5.4.2's "Initial Algorithm", the one a media sender runs on the tuples
 * it holds (the previous bounding set and the TMMBRs received since).
 *
 * Each tuple (maximum total media bit rate BR, per-packet overhead OH)
 * limits the net media bit rate at packet rate PR to BR - PR * OH * 8; the
 * bounding set is the lower envelope of those lines. The result is ordered
 * by increasing overhead; each member carries `intersection` (the packet
 * rate where it takes over from the previous member, 0 for the first) and
 * `maxPacketRate` (where its line meets the X axis, or SMAXPR if lower).
 *
 * Edge cases the RFC leaves open: an overhead of 0 never meets the X axis
 * (maxPacketRate Infinity, or SMAXPR); a bit rate of 0 meets it at 0.
 *
 * @param {Array<{ssrc, bitrate, overhead}>} tuples
 * @param {number} [smaxpr]  session maximum packet rate (a=rtcp-fb ccm tmmbr
 *                           smaxpr=, RFC 5104 §7.1), if any
 * @returns {Array<{ssrc, bitrate, overhead, intersection, maxPacketRate}>}
 */
function tmmbrBoundingSet(tuples, smaxpr) {
  if (!tuples || tuples.length === 0) return [];
  var hasMax = typeof smaxpr === 'number' && smaxpr > 0;
  function maxPr(t) {
    // Equation (4): Max PR = BR / (8 * OH).
    var pr = t.bitrate <= 0 ? 0 : (t.overhead <= 0 ? Infinity : t.bitrate / (8 * t.overhead));
    return hasMax ? Math.min(smaxpr, pr) : pr;
  }
  // 1. Sort by increasing overhead (stable: ties keep their order).
  var x = tuples.map(function (t, i) { return { t: t, i: i }; });
  x.sort(function (a, b) { return (a.t.overhead - b.t.overhead) || (a.i - b.i); });
  // 2. Equal overheads: keep only the lowest bit rate (the first of those).
  var cand = [];
  for (var k = 0; k < x.length; k++) {
    var last = cand.length ? cand[cand.length - 1] : null;
    if (last && last.overhead === x[k].t.overhead) {
      if (x[k].t.bitrate < last.bitrate) cand[cand.length - 1] = x[k].t;
      continue;
    }
    cand.push(x[k].t);
  }
  // 3. The lowest bit rate starts the selected list (ties: the highest
  // overhead, which is the last of them in overhead order).
  var first = 0;
  for (var j = 1; j < cand.length; j++) {
    if (cand[j].bitrate <= cand[first].bitrate) first = j;
  }
  function member(t, intersection) {
    return { ssrc: t.ssrc, bitrate: t.bitrate, overhead: t.overhead,
             intersection: intersection, maxPacketRate: maxPr(t) };
  }
  var y = [member(cand[first], 0)];
  // 4. Discard the candidates with a lower overhead than the selected one.
  cand = cand.slice(first + 1);
  // 5-9.
  for (var c = 0; c < cand.length; c++) {
    var cur = cand[c];
    var pr;
    for (;;) {
      var tail = y[y.length - 1];
      // Equation (3), between the current candidate and the last selected
      // tuple (the candidate's overhead is the higher one).
      pr = (cur.bitrate - tail.bitrate) / (8 * (cur.overhead - tail.overhead));
      // 7. At or before the last member's own intersection: that member is
      // not on the envelope. The first is never dropped (step 3 makes its
      // bit rate the lowest, so pr > 0 against it).
      if (pr <= tail.intersection && y.length > 1) { y.pop(); continue; }
      break;
    }
    // 8. Added only while the envelope is still above the X axis there.
    if (pr > y[y.length - 1].intersection && pr < y[y.length - 1].maxPacketRate) {
      y.push(member(cur, pr));
    }
  }
  return y;
}

/**
 * The net media bit rate a bounding set allows at packet rate `packetRate`
 * (RFC 5104 §3.5.4.2, equations (1)/(2)): the lowest of BR - PR * OH * 8
 * over its tuples, never below 0. An empty set: Infinity (no limit).
 *
 * @param {Array<{bitrate, overhead}>} boundingSet
 * @param {number} packetRate  packets per second
 * @returns {number} bps
 */
function tmmbrNetBitrate(boundingSet, packetRate) {
  if (!boundingSet || boundingSet.length === 0) return Infinity;
  var pr = packetRate > 0 ? packetRate : 0;
  var best = Infinity;
  for (var i = 0; i < boundingSet.length; i++) {
    var v = boundingSet[i].bitrate - pr * boundingSet[i].overhead * 8;
    if (v < best) best = v;
  }
  return best > 0 ? best : 0;
}


// ═══════════════════════════════════════════════════════════════════
//  TransportCCFeedbackGenerator
// ═══════════════════════════════════════════════════════════════════

/**
 * TransportCCFeedbackGenerator — accumulates arrival times of incoming
 * RTP packets keyed by their transport-wide sequence number (carried in
 * the RTP header extension) and emits RTCP transport-cc feedback packets
 * summarizing those arrivals.
 *
 * This is the counterpart of `BandwidthEstimator` on the receiver side:
 * where BandwidthEstimator consumes incoming feedback to adjust our
 * sending rate, this one produces outgoing feedback so the *remote* can
 * adjust its sending rate toward us.
 *
 * Usage:
 *     var gen = new TransportCCFeedbackGenerator({
 *       senderSsrc: myLocalSsrc,
 *       mediaSsrc:  theirMediaSsrc,
 *     });
 *
 *     // On each received RTP packet, extract transport-cc seq from the
 *     // RTP header extension (id determined by SDP) and call:
 *     gen.recordArrival(tccSeq, Date.now());
 *
 *     // Every ~100ms (or after accumulating enough packets), call:
 *     var feedbackPacket = gen.buildFeedback();   // Buffer or null
 *     if (feedbackPacket) sendRtcp(feedbackPacket);
 *
 * After buildFeedback(), all accumulated arrivals are cleared — the next
 * feedback starts fresh with whatever packets arrive next.
 *
 * The generator is independent of SRTP, ICE, and other transport
 * concerns — callers are responsible for actually encrypting and sending
 * the returned Buffer.
 *
 * @param {object}  opts
 * @param {number} [opts.senderSsrc=1]  — SSRC to put in the sender field
 *                                         of outgoing feedback packets
 * @param {number} [opts.mediaSsrc=0]   — SSRC of the media stream being
 *                                         reported on (identifies which
 *                                         peer/stream the remote should
 *                                         apply this feedback to)
 */
function TransportCCFeedbackGenerator(opts) {
  opts = opts || {};
  this._senderSsrc = (opts.senderSsrc != null) ? (opts.senderSsrc >>> 0) : 1;
  this._mediaSsrc  = (opts.mediaSsrc  != null) ? (opts.mediaSsrc  >>> 0) : 0;
  this._fbPktCount = 0;

  // Accumulated arrivals since the last buildFeedback() call, keyed by
  // seq for O(1) dedup — the previous linear scan was O(n) per packet
  // (O(n²) per feedback window), which shows up at high packet rates.
  // Sequence numbers may wrap; we handle that at build time with a
  // wrap-aware sort.
  this._arrivalMap = new Map();   // seq → timeMs (first arrival wins)
}

/**
 * Record that an RTP packet with transport-wide sequence number `seq`
 * arrived at local time `timeMs` (default: now). Duplicates on the same
 * seq are ignored (keeps the first arrival time — matches libwebrtc).
 */
TransportCCFeedbackGenerator.prototype.recordArrival = function (seq, timeMs) {
  if (timeMs == null) timeMs = Date.now();
  var s = seq & 0xFFFF;
  if (this._arrivalMap.has(s)) return;
  this._arrivalMap.set(s, timeMs);
};

/**
 * Build an RTCP transport-cc feedback packet describing all arrivals
 * since the last call, then clear the arrival buffer.
 *
 * @returns {Buffer|null}  Ready-to-send RTCP packet, or null if no
 *                         packets have been recorded.
 */
TransportCCFeedbackGenerator.prototype.buildFeedback = function () {
  if (this._arrivalMap.size === 0) return null;

  // Wrap-aware sort: treat a 16-bit seq space and find a linear ordering.
  // Strategy: pick the minimum "wrap-distance" ordering by sorting around
  // a pivot. In practice, arrivals within a ~100ms window span a handful
  // of sequence numbers with no wrap; we handle the rare wrap case by
  // detecting when the max-min gap exceeds 32768 and shifting.
  var arrs = [];
  this._arrivalMap.forEach(function (timeMs, seq) {
    arrs.push({ seq: seq, timeMs: timeMs });
  });
  arrs.sort(function (a, b) { return a.seq - b.seq; });
  // Detect wrap: if there's a big gap between adjacent sorted entries,
  // the run actually crosses 0. Shift all entries below the gap by 65536.
  if (arrs.length >= 2) {
    var maxGap = 0;
    var gapAt = -1;
    for (var i = 1; i < arrs.length; i++) {
      var g = arrs[i].seq - arrs[i - 1].seq;
      if (g > maxGap) { maxGap = g; gapAt = i; }
    }
    if (maxGap > 32768) {
      // Seq wrapped. After sorting by raw seq, the maximum gap sits at
      // the wrap boundary: entries *before* the gap are the post-wrap
      // "low" seqs (0, 1, …), entries *from* the gap onward are the
      // pre-wrap "high" seqs (65534, 65535, …). Shift the low half up
      // by 65536 so the full run becomes monotonically increasing.
      var low  = arrs.slice(0, gapAt).map(function (a) {
        return { seq: a.seq + 65536, timeMs: a.timeMs };
      });
      var high = arrs.slice(gapAt);
      arrs = high.concat(low);
      arrs.sort(function (a, b) { return a.seq - b.seq; });
    }
  }

  var baseSeq     = arrs[0].seq & 0xFFFF;
  var highestSeq  = arrs[arrs.length - 1].seq;
  var packetCount = highestSeq - arrs[0].seq + 1;
  // Safety clamp — transport-cc packetCount is u16
  if (packetCount > 0xFFFF) packetCount = 0xFFFF;

  // Reference time: round down the first arrival to a 64ms boundary so
  // the first received packet has a non-negative delta from it.
  var firstArrivalMs = arrs[0].timeMs;
  var refTimeMs = Math.floor(firstArrivalMs / 64) * 64;

  // Build the full packets[] array. For each seq in [baseSeq, baseSeq+packetCount),
  // look up arrival. If not present → not received.
  var packets = new Array(packetCount);
  var ai = 0;                      // index into sorted arrivals
  // Deltas are taken between arrival times rounded to µs from refTime, so
  // their sum is each arrival's own rounded time (rounding each difference
  // on its own let up to 0.5µs per packet add up).
  var prevUs = 0;

  for (var i = 0; i < packetCount; i++) {
    var seqI = arrs[0].seq + i;
    if (ai < arrs.length && arrs[ai].seq === seqI) {
      var atUs = Math.round((arrs[ai].timeMs - refTimeMs) * 1000);
      packets[i] = { received: true, deltaUs: atUs - prevUs };   // µs
      prevUs = atUs;
      ai++;
    } else {
      packets[i] = { received: false, deltaUs: null };
    }
  }

  // buildTransportCC lives in rtcp.js; we import it lazily to avoid a
  // circular import at module load (rtcp.js is free of bandwidth state).
  // Callers get the ready-to-send RTCP packet.
  var pkt = _buildTransportCC({
    senderSsrc:       this._senderSsrc,
    mediaSsrc:        this._mediaSsrc,
    baseSeq:          baseSeq,
    packetCount:      packetCount,
    referenceTimeMs:  refTimeMs,
    fbPktCount:       this._fbPktCount,
    packets:          packets,
  });

  this._fbPktCount = (this._fbPktCount + 1) & 0xFF;
  this._arrivalMap.clear();
  return pkt;
};

/** How many arrivals are buffered waiting for the next buildFeedback(). */
TransportCCFeedbackGenerator.prototype.pending = function () {
  return this._arrivalMap.size;
};

/** Update the media SSRC — used after SDP renegotiation. */
TransportCCFeedbackGenerator.prototype.setMediaSsrc = function (ssrc) {
  this._mediaSsrc = ssrc >>> 0;
};

/** Clear all pending arrivals without building feedback. */
TransportCCFeedbackGenerator.prototype.reset = function () {
  this._arrivalMap.clear();
  this._fbPktCount = 0;
};


// Late-bind buildTransportCC to avoid a circular import. rtcp.js doesn't
// depend on bandwidth.js, so importing it at the top of this file is
// safe, but keeping the reference resolvable per-call makes the module
// layout robust to future changes.
import { buildTransportCC as _buildTransportCC } from './rtcp.js';


export {
  parseTransportCC,
  parseREMB,
  BandwidthEstimator,
  TransportCCFeedbackGenerator,
  tmmbrBoundingSet,
  tmmbrNetBitrate,
};
