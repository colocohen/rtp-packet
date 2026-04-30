// src/rtp_header_stamper.js
//
// RtpHeaderStamper — apply outgoing RTP header extensions per RFC 5285
// with per-session state (counters, timestamps) managed internally.
//
// Motivation
// ----------
// Every outgoing RTP packet from a WebRTC sender typically needs one or
// more header extensions stamped on it:
//
//   - transport-cc (a=extmap:N …rmcat-transport-wide-cc-extensions…)
//       A monotonically-increasing 16-bit sequence number that is
//       *independent* of the RTP sequence number, used by the remote
//       to produce transport-cc feedback.
//
//   - abs-send-time (a=extmap:N …webrtc-experiments/abs-send-time)
//       24-bit fixed-point NTP-style timestamp marking when the packet
//       was actually sent on the wire.
//
//   - mid (a=extmap:N urn:ietf:params:rtp-hdrext:sdes:mid)
//       Constant per-transceiver string (the SDP media-id).
//
// Without this module, each of these would live as ad-hoc code in the
// connection manager — the counter for transport-cc, the clock-read for
// abs-send-time, the per-transceiver string for mid. That works, but it
// scatters RTP-protocol knowledge across the orchestration layer.
//
// The stamper co-locates all "apply extensions to outgoing packets"
// concerns in one place, matches the design of libwebrtc's
// RTPSenderEgress (which applies extensions as a final step before the
// network) and pion's HeaderExtensionInterceptor (which chains
// extension application through a pipeline).
//
// Usage
// -----
//
//   import { RtpHeaderStamper } from 'rtp-packet';
//
//   var stamper = new RtpHeaderStamper({
//     extMap: {                 // from SDP: a=extmap:N <URI>
//       'transport-cc':  2,
//       'abs-send-time': 1,
//       'mid':           3,
//     },
//     mid: '1',                 // optional, only needed if 'mid' is in extMap
//   });
//
//   // For each outgoing packet, right before SRTP encryption:
//   rtpPacket = stamper.stamp(rtpPacket);
//
//   // If you also run congestion control, pair the transport-cc seq with
//   // the send time so incoming feedback lines up:
//   var seq = stamper.lastTransportCcSeq();
//   bandwidthEstimator.recordSend(seq, Date.now(), rtpPacket.length);
//
//
// Known extensions
// ----------------
// Keys recognized in `extMap`:
//
//   'transport-cc'         → draft-holmer-rmcat-transport-wide-cc-extensions-01
//   'abs-send-time'        → webrtc-experiments/abs-send-time
//   'mid'                  → urn:ietf:params:rtp-hdrext:sdes:mid
//   'rtp-stream-id'        → urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id (RFC 8852)
//   'repaired-rtp-stream-id' → urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
//                            (RFC 8852 — for RTX packets, paired with rtp-stream-id
//                             that identifies the source layer being repaired)
//
// Other URIs in extMap are ignored (no stamping action registered for them).
// Callers can mix and match — if only 'transport-cc' is mapped, only the
// transport-cc extension is stamped.
//

import { setHeaderExtension, transportCC, absSendTime } from './rtp.js';


/**
 * @param {object} opts
 *   extMap: {name: id, ...}   — map of known extension names → RFC-5285 IDs
 *                                (values come from SDP a=extmap: lines)
 *   mid:    string            — value to stamp for 'mid' extension (if mapped)
 *   rid:    string            — value to stamp for 'rtp-stream-id' extension
 *                                (RFC 8852, simulcast layer identifier)
 *   repairedRid: string       — value to stamp for 'repaired-rtp-stream-id'
 *                                (RFC 8852, RTX packets — identifies which
 *                                 source layer this retransmission repairs)
 *   initialTransportCcSeq: number  — starting counter (default: 0; wraps 16-bit)
 */
function RtpHeaderStamper(opts) {
  opts = opts || {};
  this._extMap      = opts.extMap || {};
  this._mid         = opts.mid != null ? String(opts.mid) : null;
  this._twccSeq     = (opts.initialTransportCcSeq | 0) & 0xFFFF;

  // Per-SSRC RID / repaired-RID mappings. Simulcast ships multiple SSRCs
  // through the same stamper (so the transport-cc counter stays session-
  // global, matching Chrome). At stamp time we peek the outgoing packet's
  // SSRC and pick the right RID. Non-simulcast senders never populate
  // these maps and pay zero cost.
  //
  //   _ridBySsrc[ssrc]         — primary RID for this SSRC (simulcast layer)
  //   _repairedRidBySsrc[ssrc] — repaired-RID for RTX SSRCs
  //   _ridPayloadCache         — ssrc → Buffer (pre-encoded, avoids per-pkt alloc)
  this._ridBySsrc          = {};
  this._repairedRidBySsrc  = {};
  this._ridPayloadCache    = {};
  this._repairedRidPayloadCache = {};

  // Pre-encode mid — constant for transceiver life.
  if (this._mid != null && this._extMap['mid'] != null) {
    this._midPayload = Buffer.from(this._mid, 'ascii');
  }
}

/**
 * Stamp all configured extensions onto the given RTP packet. Returns a
 * new Buffer; the input is not mutated.
 *
 * Order matters only for reproducibility — the actual extension block
 * is a dictionary (ID → value), not an ordered list, so readers don't
 * care about the order the IDs appear in the block.
 *
 * If the extMap has no known keys, the packet is returned unchanged.
 */
RtpHeaderStamper.prototype.stamp = function (rtpPacket) {
  var pkt = rtpPacket;

  // Transport-wide congestion control sequence number. Increment
  // *first*, so the counter starts at 1, not 0 (matching Chrome's
  // observed behavior — their first-seen seq is 1).
  var twccId = this._extMap['transport-cc'];
  if (twccId != null) {
    this._twccSeq = (this._twccSeq + 1) & 0xFFFF;
    pkt = setHeaderExtension(pkt, twccId, transportCC(this._twccSeq));
  }

  // Absolute send time — freshly computed at stamp time, so it reflects
  // the moment the packet is about to go on the wire (after any queuing).
  var absId = this._extMap['abs-send-time'];
  if (absId != null) {
    pkt = setHeaderExtension(pkt, absId, absSendTime());
  }

  // MID — constant per transceiver (see a=mid: in SDP).
  var midId = this._extMap['mid'];
  if (midId != null && this._midPayload) {
    pkt = setHeaderExtension(pkt, midId, this._midPayload);
  }

  // RID + repaired-RID (RFC 8852). Both are per-SSRC — simulcast ships
  // multiple layers through the same stamper and we pick the right RID
  // by peeking the outgoing packet's SSRC (bytes 8-11 of the RTP header).
  var ridId  = this._extMap['rtp-stream-id'];
  var rridId = this._extMap['repaired-rtp-stream-id'];
  if (ridId != null || rridId != null) {
    // Parse SSRC inline — avoid full rtp.parse() on the hot path.
    var ssrc = (pkt[8] << 24 | pkt[9] << 16 | pkt[10] << 8 | pkt[11]) >>> 0;
    if (ridId != null) {
      var ridPayload = this._ridPayloadCache[ssrc];
      if (ridPayload) pkt = setHeaderExtension(pkt, ridId, ridPayload);
    }
    if (rridId != null) {
      var rridPayload = this._repairedRidPayloadCache[ssrc];
      if (rridPayload) pkt = setHeaderExtension(pkt, rridId, rridPayload);
    }
  }

  return pkt;
};

/** The last transport-wide seq actually stamped. Use for pairing with
 *  bandwidth estimator recordSend(). Returns 0 if transport-cc is not
 *  configured. */
RtpHeaderStamper.prototype.lastTransportCcSeq = function () {
  return this._twccSeq;
};

/** Update the mid string — called on renegotiation if the media's mid
 *  changed (rare). */
RtpHeaderStamper.prototype.setMid = function (mid) {
  this._mid = mid != null ? String(mid) : null;
  this._midPayload = (this._mid != null && this._extMap['mid'] != null)
    ? Buffer.from(this._mid, 'ascii') : null;
};

/**
 * Register a simulcast layer: tell the stamper that packets carrying the
 * given SSRC belong to the given RID. The RID is stamped as the
 * rtp-stream-id extension on every outgoing packet with this SSRC (as
 * long as 'rtp-stream-id' is present in extMap).
 *
 * For non-simulcast senders this is never called — the maps stay empty
 * and stamp() skips the RID path.
 *
 * @param {number} ssrc — the layer's primary SSRC
 * @param {string} rid  — the RID identifier (matches a=rid: in SDP)
 */
RtpHeaderStamper.prototype.setRidForSsrc = function (ssrc, rid) {
  if (ssrc == null) return;
  var key = ssrc >>> 0;
  if (rid == null) {
    delete this._ridBySsrc[key];
    delete this._ridPayloadCache[key];
  } else {
    this._ridBySsrc[key] = String(rid);
    this._ridPayloadCache[key] = Buffer.from(String(rid), 'ascii');
  }
};

/**
 * Fully clear all per-SSRC state for this SSRC (both rid and
 * repaired-rid maps). Called by transceiver.stop() to prevent
 * SSRC→RID entries from accumulating across transceiver lifecycles.
 */
RtpHeaderStamper.prototype.clearSsrc = function (ssrc) {
  if (ssrc == null) return;
  var key = ssrc >>> 0;
  delete this._ridBySsrc[key];
  delete this._ridPayloadCache[key];
  delete this._repairedRidBySsrc[key];
  delete this._repairedRidPayloadCache[key];
};

/**
 * Register an RTX SSRC's repaired-RID: packets with this SSRC carry
 * rtp-stream-id = rid (the RTX layer's own id, usually mirrors the
 * source layer) plus repaired-rtp-stream-id = repairedRid (the source
 * layer being repaired).
 *
 * @param {number} rtxSsrc     — the RTX stream's SSRC
 * @param {string} rid         — the RTX stream's own RID
 * @param {string} repairedRid — the source layer's RID (the one the RTX repairs)
 */
RtpHeaderStamper.prototype.setRtxRids = function (rtxSsrc, rid, repairedRid) {
  if (rtxSsrc == null) return;
  var key = rtxSsrc >>> 0;
  if (rid != null) {
    this._ridBySsrc[key] = String(rid);
    this._ridPayloadCache[key] = Buffer.from(String(rid), 'ascii');
  }
  if (repairedRid != null) {
    this._repairedRidBySsrc[key] = String(repairedRid);
    this._repairedRidPayloadCache[key] = Buffer.from(String(repairedRid), 'ascii');
  }
};

/** Reconfigure the extMap (e.g. after renegotiation re-numbered IDs). */
RtpHeaderStamper.prototype.setExtMap = function (extMap) {
  this._extMap = extMap || {};
  // Re-encode mid if still configured. RID payload caches are keyed by
  // SSRC and their Buffers are already encoded — they stay valid as long
  // as the RID strings don't change. extMap changes only affect which
  // extensions are stamped, not the cached values.
  this._midPayload = (this._mid != null && this._extMap['mid'] != null)
    ? Buffer.from(this._mid, 'ascii') : null;
};


export { RtpHeaderStamper };
