/**
 * h264 — H.264 RTP packetizer + depacketizer (RFC 6184).
 *
 *   chunk {data, timestamp, type}  →  H264Packetizer   →  Buffer[]
 *   RTP packet                      →  H264Depacketizer →  chunk via output()
 *
 * Input `data` is Annex-B (with start codes 00 00 00 01 or 00 00 01).
 * Output `data` is also Annex-B — the depacketizer reassembles a full
 * Access Unit and emits it with start codes between NALUs.
 *
 * Packetizer handles:
 *   - Single NAL  (NAL fits in one packet)
 *   - FU-A        (NAL larger than MTU, fragmented)
 *   - STAP-A      (explicit via packetizeStapA for SPS+PPS bundling)
 *
 * Depacketizer handles:
 *   - Single NAL  (pass through)
 *   - STAP-A      (split into NALUs)
 *   - FU-A        (reassemble fragments)
 *   Frame output on marker bit.
 */

import {
  initPacketizer, makePacket, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;
var START_CODE_4 = Buffer.from([0, 0, 0, 1]);

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * H264Packetizer — fragments an H.264 access unit into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function H264Packetizer(opts) {
  initPacketizer(this, opts);
}

/**
 * @param {object}   chunk
 * @param {Buffer}   [chunk.data]       Annex-B access unit (split automatically into NALUs)
 * @param {Buffer[]} [chunk.nalus]      pre-split NALUs (alternative to data, avoids re-splitting)
 * @param {number}   chunk.timestamp    microseconds
 * @param {string}   [chunk.type]       'key' | 'delta' — informational; H.264 keyframes are detected by the presence of IDR NALUs (type 5)
 * @returns {Buffer[]}
 */
H264Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
H264Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

/**
 * Create a STAP-A packet aggregating multiple small NALUs (typically SPS + PPS).
 * Sent as a single RTP packet.
 *
 * @param {Buffer[]} nalus        raw NALUs (without start codes)
 * @param {number}   timestampUs  microseconds
 * @param {boolean}  [marker]     marker bit. Default true — STAP-A is most
 *                                commonly used for a standalone SPS+PPS
 *                                packet that ends its access unit. Pass
 *                                false when the STAP-A is followed by
 *                                more packets within the same AU (e.g.
 *                                SPS+PPS bundled before an IDR that's
 *                                sent as separate FU-A fragments).
 * @returns {Buffer}
 */
H264Packetizer.prototype.packetizeStapA = function (nalus, timestampUs, marker) {
  if (!nalus || !nalus.length) {
    throw new TypeError('H264Packetizer.packetizeStapA: nalus array required');
  }
  // Normalize each NALU to Buffer locally without mutating the caller's array.
  var localNalus = new Array(nalus.length);
  for (var i = 0; i < nalus.length; i++) localNalus[i] = _toBuffer(nalus[i]);

  var nri = (localNalus[0][0] >> 5) & 0x03;
  var totalSize = 1;
  for (var ii = 0; ii < localNalus.length; ii++) totalSize += 2 + localNalus[ii].length;

  var payload = Buffer.allocUnsafe(totalSize);
  payload[0] = (nri << 5) | 24;  // STAP-A type = 24
  var off = 1;
  for (var j = 0; j < localNalus.length; j++) {
    payload.writeUInt16BE(localNalus[j].length, off); off += 2;
    localNalus[j].copy(payload, off); off += localNalus[j].length;
  }
  var m = (marker === undefined) ? true : !!marker;
  return makePacket(this, payload, usToRtp(timestampUs, CLOCK_RATE), m, false);
};

H264Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  // Accept either pre-split NALUs or Annex-B data that we split
  // internally. Normalize Uint8Array → Buffer locally — never mutate
  // the chunk (WebCodecs chunks are frozen / read-only per spec).
  var nalus;
  if (chunk.nalus) {
    nalus = new Array(chunk.nalus.length);
    for (var k = 0; k < chunk.nalus.length; k++) {
      nalus[k] = _toBuffer(chunk.nalus[k]);
    }
  } else {
    nalus = _splitNALUs(_toBuffer(chunk.data));
  }
  if (!nalus.length) return [];

  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var out = [];
  var lastIdx = nalus.length - 1;

  for (var i = 0; i < nalus.length; i++) {
    var nalu = nalus[i];
    var isLastNalu = (i === lastIdx);
    if (nalu.length <= self.mtu) {
      out.push(makePacket(self, nalu, rtpTs, isLastNalu, withMeta));
    } else {
      _fragmentFUA(self, nalu, rtpTs, isLastNalu, withMeta, out);
    }
  }
  return out;
}

function _fragmentFUA(self, nalu, rtpTs, isLastNalu, withMeta, out) {
  var naluHeader = nalu[0];
  var nri = (naluHeader >> 5) & 0x03;
  var naluType = naluHeader & 0x1F;
  var fuIndicator = (nri << 5) | 28;  // FU-A type = 28
  var maxPayload = self.mtu - 2;       // -2 for the FU indicator + FU header
  var dataStart = 1;                   // skip the original NAL header byte
  var dataEnd = nalu.length;
  var dataLen = dataEnd - dataStart;
  var offset = 0;
  var fragCount = Math.ceil(dataLen / maxPayload);

  for (var i = 0; i < fragCount; i++) {
    var start = (i === 0);
    var end = (i === fragCount - 1);
    var size = Math.min(maxPayload, dataLen - offset);
    var fuHeader = (start ? 0x80 : 0) | (end ? 0x40 : 0) | naluType;

    out.push(makePacketWithPrefix(
      self, fuIndicator, fuHeader, 0, 0, 2,
      nalu, dataStart + offset, size,
      rtpTs, end && isLastNalu, withMeta
    ));
    offset += size;
  }
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * H264Depacketizer — reassembles H.264 access units from RTP packets.
 * Collects NALUs until marker bit, then emits a full Annex-B access unit.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first. Out-of-order arrival of FU-A
 * fragments will cause the NALU to be discarded (start-packet loss is
 * reported via the error callback).
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error]
 */
function H264Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._nalus = [];        // collected NALUs for current access unit (raw, no start code)
  this._fuFragments = [];  // in-flight FU-A fragments
  this._fuHeader = 0;      // reconstructed NAL header byte for FU-A
  this._sawIDR = false;    // tracks if any NALU in this AU was IDR (type 5)
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start an
 * H.264 keyframe (IDR)? Static method (no Depacketizer state needed).
 *
 * H.264 over RTP (RFC 6184) has three packet shapes; each needs its
 * own check:
 *
 *   Single NAL (types 1-23):
 *     The NAL header byte IS the first byte of the payload. Look at
 *     the bottom 5 bits — if it's 5, this packet IS a complete IDR
 *     NALU and the access unit it belongs to is keyframe-flagged.
 *
 *   STAP-A (type 24):
 *     An aggregator carrying multiple NALUs back-to-back, each with
 *     a 16-bit length prefix. We have a keyframe if ANY of those
 *     aggregated NALUs is type 5. Walking the structure mirrors what
 *     depacketize() does, but defensively (return false on truncation).
 *
 *   FU-A (type 28):
 *     A fragment of a larger NALU. The NALU's original type is in
 *     the FU header byte (payload[1]) bottom 5 bits. We can only
 *     detect IDR on the START fragment (payload[1] & 0x80 set);
 *     mid/end fragments carry no NALU-type info beyond the FU header
 *     they share with the start, but they're useless for NACK
 *     keyframe-tracking purposes anyway — the start fragment
 *     already triggered the eviction.
 *
 * Returns:
 *   true  — packet contains the start of an IDR NALU
 *   false — anything else (delta, mid-fragment, malformed, or
 *           unsupported NAL type)
 *
 * @param {Buffer} payload
 * @returns {boolean}
 */
H264Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 1) return false;
  var naluType = payload[0] & 0x1F;

  // Single NAL — NAL header IS the first byte
  if (naluType >= 1 && naluType <= 23) {
    return naluType === 5;
  }

  // STAP-A — walk aggregated NALUs, check each one's type
  if (naluType === 24) {
    var off = 1;
    while (off + 2 <= payload.length) {
      var size = payload.readUInt16BE(off);
      off += 2;
      if (size === 0) continue;
      if (off + size > payload.length) return false;  // truncated
      // First byte of the aggregated NALU is its NAL header.
      if ((payload[off] & 0x1F) === 5) return true;
      off += size;
    }
    return false;
  }

  // FU-A — only the START fragment carries useful info. The FU
  // header (payload[1]) has Start bit at 0x80 and the NALU's
  // original type in the bottom 5 bits.
  if (naluType === 28) {
    if (payload.length < 2) return false;
    var fuHeader = payload[1];
    var startBit = !!(fuHeader & 0x80);
    if (!startBit) return false;
    return (fuHeader & 0x1F) === 5;
  }

  // STAP-B (25), MTAP (26-27), FU-B (29) — not in our packetizer's
  // output, and rarely seen on the wire. Treat as "no info".
  return false;
};

H264Depacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 1) {
    emitError(this, new Error('H264Depacketizer: empty or missing payload'));
    return;
  }

  var payload = packet.payload;
  var naluType = payload[0] & 0x1F;

  if (naluType >= 1 && naluType <= 23) {
    // Single NAL unit
    this._nalus.push(payload);
    if (naluType === 5) this._sawIDR = true;

  } else if (naluType === 24) {
    // STAP-A — split into individual NALUs
    var off = 1;
    while (off + 2 <= payload.length) {
      var size = payload.readUInt16BE(off); off += 2;
      if (size === 0) continue;                       // skip malformed zero-length NALU
      if (off + size > payload.length) {
        emitError(this, new Error('H264Depacketizer: STAP-A truncated NALU'));
        break;
      }
      var nalu = payload.subarray(off, off + size);
      this._nalus.push(nalu);
      if ((nalu[0] & 0x1F) === 5) this._sawIDR = true;
      off += size;
    }

  } else if (naluType === 28) {
    // FU-A — fragmented NAL unit
    if (payload.length < 2) {
      emitError(this, new Error('H264Depacketizer: FU-A header truncated'));
      return;
    }
    var fuHeader = payload[1];
    var startBit = !!(fuHeader & 0x80);
    var endBit = !!(fuHeader & 0x40);
    var type = fuHeader & 0x1F;

    if (startBit) {
      this._fuHeader = (payload[0] & 0x60) | type;        // reconstruct NAL header (F+NRI from indicator, type from FU header)
      var hdrBuf = Buffer.allocUnsafe(1);                 // cheaper than Buffer.from([...])
      hdrBuf[0] = this._fuHeader;
      this._fuFragments = [hdrBuf];
    } else if (this._fuFragments.length === 0) {
      // Mid/end fragment arrived but we never saw a start — previous start must
      // have been lost. Drop this fragment rather than accumulate garbage that
      // would later be emitted as a headerless NALU.
      emitError(this, new Error('H264Depacketizer: FU-A fragment without start (start packet lost)'));
      return;
    }
    this._fuFragments.push(payload.subarray(2));

    if (endBit) {
      var fullNalu = Buffer.concat(this._fuFragments);
      this._fuFragments = [];
      this._nalus.push(fullNalu);
      if ((fullNalu[0] & 0x1F) === 5) this._sawIDR = true;
    }

  } else {
    emitError(this, new Error('H264Depacketizer: unsupported NAL type ' + naluType));
    return;
  }

  // Emit complete access unit on marker bit
  if (packet.marker && this._nalus.length > 0) {
    var accessUnit = _joinAnnexB(this._nalus);
    var isKey = this._sawIDR;
    this._nalus = [];
    this._sawIDR = false;

    this._output({
      data: accessUnit,
      timestamp: packet.timestamp,
      type: isKey ? 'key' : 'delta',
    });
  }
};

H264Depacketizer.prototype.reset = function () {
  this._nalus = [];
  this._fuFragments = [];
  this._fuHeader = 0;
  this._sawIDR = false;
};

H264Depacketizer.prototype.close = function () {
  this.reset();
  this._output = null;
  this._error = null;
};


// ═══════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════

/**
 * Split an encoded H.264 buffer into NALUs, auto-detecting the framing:
 *
 *   Annex-B — NALUs separated by start codes (00 00 01 / 00 00 00 01).
 *             What ffmpeg's raw h264 output and most encoders emit.
 *   AVCC    — NALUs prefixed by 4-byte big-endian lengths. What MP4
 *             containers and WebCodecs (avc format) hand out.
 *
 * Detection: a leading start code means Annex-B. Otherwise we attempt a
 * strict AVCC walk — 4-byte lengths that exactly tile the buffer, each
 * NALU non-empty with a plausible NAL header. If the walk fails, we
 * fall back to the Annex-B splitter (which degrades to "whole buffer is
 * one NALU" for unframed input, preserving the old behavior).
 */
function _splitNALUs(buf) {
  if (_startsWithStartCode(buf)) return _splitAnnexB(buf);
  var avcc = _trydSplitAVCC(buf);
  if (avcc) return avcc;
  return _splitAnnexB(buf);
}

function _startsWithStartCode(buf) {
  if (buf.length >= 3 && buf[0] === 0 && buf[1] === 0 && buf[2] === 1) return true;
  if (buf.length >= 4 && buf[0] === 0 && buf[1] === 0 && buf[2] === 0 && buf[3] === 1) return true;
  return false;
}

/**
 * Strict AVCC parse: 4-byte BE length prefixes that exactly tile the
 * buffer. Returns the NALU array, or null if the buffer isn't valid
 * AVCC (so the caller can fall back to Annex-B).
 */
function _trydSplitAVCC(buf) {
  if (buf.length < 5) return null;
  var nalus = [];
  var off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) return null;
    var len = buf.readUInt32BE(off);
    off += 4;
    if (len === 0 || off + len > buf.length) return null;
    // Sanity: forbidden_zero_bit must be 0 in a real NAL header.
    if (buf[off] & 0x80) return null;
    nalus.push(buf.subarray(off, off + len));
    off += len;
  }
  return nalus.length > 0 ? nalus : null;
}

/**
 * Split an Annex-B buffer into NALUs (no start codes in output).
 * Start codes: 00 00 01 or 00 00 00 01.
 */
function _splitAnnexB(buf) {
  var nalus = [];
  var i = 0, len = buf.length;

  // Find first start code
  while (i < len - 3) {
    if (buf[i] === 0 && buf[i + 1] === 0) {
      if (buf[i + 2] === 1) { i += 3; break; }
      if (i < len - 3 && buf[i + 2] === 0 && buf[i + 3] === 1) { i += 4; break; }
    }
    i++;
  }
  var naluStart = i;

  while (i < len - 3) {
    if (buf[i] === 0 && buf[i + 1] === 0) {
      var scLen = 0;
      if (buf[i + 2] === 1) scLen = 3;
      else if (i < len - 3 && buf[i + 2] === 0 && buf[i + 3] === 1) scLen = 4;
      if (scLen > 0) {
        if (i > naluStart) nalus.push(buf.subarray(naluStart, i));
        i += scLen;
        naluStart = i;
        continue;
      }
    }
    i++;
  }
  if (naluStart < len) nalus.push(buf.subarray(naluStart, len));
  return nalus;
}

/**
 * Join NALUs into an Annex-B access unit (4-byte start code before each NALU).
 */
function _joinAnnexB(nalus) {
  var totalSize = 0;
  for (var i = 0; i < nalus.length; i++) totalSize += 4 + nalus[i].length;

  var out = Buffer.allocUnsafe(totalSize);
  var off = 0;
  for (var j = 0; j < nalus.length; j++) {
    START_CODE_4.copy(out, off); off += 4;
    nalus[j].copy(out, off); off += nalus[j].length;
  }
  return out;
}


export { H264Packetizer, H264Depacketizer };
