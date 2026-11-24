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
  initDepacketizer, emitError, checkDepacketizePayload, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;
var START_CODE_4 = Buffer.from([0, 0, 0, 1]);
var bufferCopy = Buffer.prototype.copy;

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
 * @param {string} [opts.format]                  the chunks' framing, as WebCodecs' avc.format:
 *                                                'annexb' (start codes) or 'avc' (4-byte
 *                                                lengths). Unset: told from the data.
 */
function H264Packetizer(opts) {
  initPacketizer(this, opts);
  this._format = _checkFormat(this, opts.format, 'avc');
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
  // Normalize each NALU to Buffer locally without mutating the caller's
  // array. An empty one is no NAL unit (it has no header) and is left out:
  // it went out as a zero size, which a receiver reads as malformed.
  var localNalus = [];
  if (nalus) {
    for (var i = 0; i < nalus.length; i++) {
      var nb = _toBuffer(nalus[i]);
      if (nb && nb.length > 0) localNalus.push(nb);
    }
  }
  if (!localNalus.length) {
    throw new TypeError('H264Packetizer.packetizeStapA: nalus array required');
  }

  // RFC 6184 §5.7: the STAP's NRI MUST be the maximum of the aggregated
  // NALUs' NRIs, and its F bit set when any of theirs is. (It took the
  // first NALU's NRI and dropped F: an SPS+PPS bundle led by a lower-NRI
  // unit was marked less important than what it carries.)
  var nri = 0, fBit = 0;
  var totalSize = 1;
  for (var ii = 0; ii < localNalus.length; ii++) {
    var h = localNalus[ii][0];
    // The size field is 16 bits; a longer NALU made writeUInt16BE throw
    // Node's generic out-of-range error.
    if (localNalus[ii].length > 0xFFFF) {
      throw new RangeError('H264Packetizer.packetizeStapA: a NALU of ' + localNalus[ii].length + ' bytes does not fit in a STAP-A (65535 at most)');
    }
    fBit |= h & 0x80;
    if (((h >> 5) & 0x03) > nri) nri = (h >> 5) & 0x03;
    totalSize += 2 + localNalus[ii].length;
  }

  var payload = Buffer.allocUnsafe(totalSize);
  payload[0] = fBit | (nri << 5) | 24;  // STAP-A type = 24
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
    // An empty NALU is left out: it went out as an RTP packet with no
    // payload, which no receiver can read as a NAL unit (and the marker
    // was lost with it when it was the last one).
    nalus = [];
    for (var k = 0; k < chunk.nalus.length; k++) {
      var nk = _toBuffer(chunk.nalus[k]);
      if (nk.length > 0) nalus.push(nk);
    }
  } else {
    nalus = _splitNALUs(_toBuffer(chunk.data), self._format);
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
  var naluType = naluHeader & 0x1F;
  // F and NRI of the NAL unit go in the FU indicator (RFC 6184 §5.8: they
  // carry its header octet; only NRI was copied, so an F=1 unit lost F).
  var fuIndicator = (naluHeader & 0xE0) | 28;  // FU-A type = 28
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
  this._ts = null;         // RTP timestamp of the access unit being built
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
  if (!checkDepacketizePayload(this, packet, 1)) return;

  // A new RTP timestamp is a new access unit (RFC 6184 §5.1 / RFC 7798
  // §4.1: all packets of one AU share it). When the previous AU's marker
  // packet was lost, its NALUs used to stay in _nalus and went out at the
  // head of THIS AU: a slice of the old picture glued into the new one (and
  // the whole AU typed 'key' when the lost one was an IDR). The incomplete
  // AU is dropped instead, as libwebrtc's packet buffer drops a frame it
  // cannot complete; a half-built FU from it goes with it.
  if (this._ts !== null && packet.timestamp !== this._ts) {
    this._nalus = [];
    this._fuFragments = [];
    this._sawIDR = false;
  }
  this._ts = packet.timestamp;

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
      // Reconstruct the NAL header: F+NRI from the indicator, type from the
      // FU header (RFC 6184 §5.8). The mask was 0x60, NRI only, so a NAL
      // unit marked F=1 (errors) came out clean.
      this._fuHeader = (payload[0] & 0xE0) | type;
      // A reassembled NALU is kept as [headerByte, payload, payload, ...]
      // — the whole FU-A payloads, their 2-byte FU prefix skipped when
      // _joinAnnexB copies them into the access unit. Concatenating here
      // first copied every fragment twice (once into the NALU, once into
      // the access unit) and allocated a view per fragment plus the
      // NALU's buffer, all garbage once the access unit was built.
      this._fuFragments = [this._fuHeader];
    } else if (this._fuFragments.length === 0) {
      // Mid/end fragment arrived but we never saw a start — previous start must
      // have been lost. Drop this fragment rather than accumulate garbage that
      // would later be emitted as a headerless NALU.
      emitError(this, new Error('H264Depacketizer: FU-A fragment without start (start packet lost)'));
      return;
    }
    this._fuFragments.push(payload);

    if (endBit) {
      this._nalus.push(this._fuFragments);
      if ((this._fuHeader & 0x1F) === 5) this._sawIDR = true;
      this._fuFragments = [];
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
    // A FU still open at the marker belongs to this access unit, which is
    // done: it was kept, and with _ts cleared the next AU's fragments
    // (their start lost) were appended to it and went out as one NALU.
    this._fuFragments = [];
    this._sawIDR = false;
    this._ts = null;

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
  this._ts = null;
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
 * The packetizer's `format` says which ('annexb' / 'avc'). Without it the
 * data tells: a strict AVCC walk first — 4-byte lengths that exactly tile
 * the buffer, each NALU non-empty with a plausible NAL header — and the
 * Annex-B splitter when it fails (which degrades to "whole buffer is one
 * NALU" for unframed input, preserving the old behavior).
 *
 * The walk goes first because a leading 00 00 01 is not proof of Annex-B:
 * it is also the length of an AVCC NALU of 256-511 bytes (00 00 01 xx).
 * A leading start code used to settle it, and 13 of 105 access units of
 * a WebCodecs H.264 encoder (avc format) went out split at the wrong
 * places. Annex-B data almost never tiles as lengths by chance; when the
 * framing is known, `format` takes the guess away.
 */
function _splitNALUs(buf, format) {
  if (format === 'annexb') return _splitAnnexB(buf);
  var avcc = _trydSplitAVCC(buf);
  if (avcc) return avcc;
  return _splitAnnexB(buf);
}

/** opts.format: 'annexb', or the length-prefixed name (`lp`), or unset. */
function _checkFormat(self, format, lp) {
  if (format == null) return null;
  if (format !== 'annexb' && format !== lp) {
    throw new TypeError(self.constructor.name + ': opts.format must be "annexb" or "' + lp + '"');
  }
  return format;
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
  var found = false;

  // Find first start code
  while (i < len - 3) {
    if (buf[i] === 0 && buf[i + 1] === 0) {
      if (buf[i + 2] === 1) { i += 3; found = true; break; }
      if (i < len - 3 && buf[i + 2] === 0 && buf[i + 3] === 1) { i += 4; found = true; break; }
    }
    i++;
  }
  // No start code: unframed input, the whole buffer is one NALU. (The
  // scan above leaves i at the end, and only the last 3 bytes went out.)
  if (!found) return len > 0 ? [buf] : [];
  var naluStart = i;
  // trailing_zero_8bits (H.264 B.1) between a NALU and the next start code
  // are not part of it — a NAL unit's last byte is never 0x00 (7.4.1). They
  // went out at the end of the NALU.
  var end;

  while (i < len - 3) {
    if (buf[i] === 0 && buf[i + 1] === 0) {
      var scLen = 0;
      if (buf[i + 2] === 1) scLen = 3;
      else if (i < len - 3 && buf[i + 2] === 0 && buf[i + 3] === 1) scLen = 4;
      if (scLen > 0) {
        end = i;
        while (end > naluStart && buf[end - 1] === 0) end--;
        if (end > naluStart) nalus.push(buf.subarray(naluStart, end));
        i += scLen;
        naluStart = i;
        continue;
      }
    }
    i++;
  }
  end = len;
  while (end > naluStart && buf[end - 1] === 0) end--;
  if (end > naluStart) nalus.push(buf.subarray(naluStart, end));
  return nalus;
}

/**
 * Join NALUs into an Annex-B access unit (4-byte start code before each NALU).
 * An entry is either a NALU Buffer or a reassembled FU-A NALU in the
 * depacketizer's [headerByte, payload, ...] form (FU prefix not yet
 * stripped). Copies go through Buffer.prototype.copy so a Uint8Array
 * payload works as it did with Buffer.concat.
 */
function _joinAnnexB(nalus) {
  var totalSize = 0;
  for (var i = 0; i < nalus.length; i++) {
    var n = nalus[i];
    if (Array.isArray(n)) {
      totalSize += 4 + 1;
      for (var f = 1; f < n.length; f++) totalSize += n[f].length - 2;
    } else {
      totalSize += 4 + n.length;
    }
  }

  var out = Buffer.allocUnsafe(totalSize);
  var off = 0;
  for (var j = 0; j < nalus.length; j++) {
    var nj = nalus[j];
    START_CODE_4.copy(out, off); off += 4;
    if (Array.isArray(nj)) {
      out[off++] = nj[0];
      for (var g = 1; g < nj.length; g++) off += bufferCopy.call(nj[g], out, off, 2);
    } else {
      nalus[j].copy(out, off); off += nj.length;
    }
  }
  return out;
}


export { H264Packetizer, H264Depacketizer };
