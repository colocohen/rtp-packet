/**
 * h265 — H.265/HEVC RTP packetizer + depacketizer (RFC 7798).
 *
 *   chunk {data, timestamp, type}  →  H265Packetizer   →  Buffer[]
 *   RTP packet                      →  H265Depacketizer →  chunk via output()
 *
 * Input `data` is Annex-B (with start codes 00 00 00 01 or 00 00 01).
 * Output `data` is also Annex-B — the depacketizer reassembles a full
 * Access Unit and emits it with start codes between NALUs.
 *
 * H.265 vs H.264 — what changed at the RTP layer
 * ----------------------------------------------
 * The RTP payload format for H.265 is structurally similar to H.264's
 * (RFC 6184), with three notable differences. If you've read h264.js,
 * the deltas are:
 *
 *   1. NAL HEADER IS 2 BYTES (was 1).
 *      H.264:  [F:1 | NRI:2 | Type:5]                              (8 bits)
 *      H.265:  [F:1 | Type:6 | LayerId:6 | TID:3]                  (16 bits)
 *
 *      H.265 type field is 6 bits → 0..63. Important values:
 *        19 = IDR_W_RADL    } both are IDR frames (keyframes);
 *        20 = IDR_N_LP      } either constitutes a new RAP point
 *        32 = VPS           Video Parameter Set
 *        33 = SPS           Sequence Parameter Set
 *        34 = PPS           Picture Parameter Set
 *        35 = AUD           Access Unit Delimiter
 *        48 = AP            Aggregation Packet (analog of H.264 STAP-A)
 *        49 = FU            Fragmentation Unit (analog of H.264 FU-A)
 *        50 = PACI          PACI packet (rare — DONL/DONB extensions)
 *
 *   2. Aggregation Packet (AP, type 48) replaces STAP-A.
 *      Same wire shape: 2-byte aggregation NAL header + repeated
 *      [16-bit length | NALU]. Used to bundle VPS+SPS+PPS together.
 *
 *   3. Fragmentation Unit (FU, type 49) replaces FU-A.
 *      Layout:  [PayloadHdr (2 bytes)] [FU header (1 byte)] [data]
 *
 *      The PayloadHdr looks like a NAL header with type=49. The FU
 *      header carries S/E/Type bits — same convention as H.264 FU-A
 *      but the "type" field here is 6 bits (the original NALU type).
 *
 *        FU header:
 *          0 1 2 3 4 5 6 7
 *         +-+-+-+-+-+-+-+-+
 *         |S|E|  FuType   |       S=start, E=end, FuType=original type
 *         +-+-+-+-+-+-+-+-+
 *
 * Everything else (NALU splitting from Annex-B, marker bit on AU
 * boundary, frame reassembly across packets) carries over from H.264.
 *
 * Packetizer handles:
 *   - Single NAL  (NAL fits in one packet)
 *   - FU          (NAL larger than MTU, fragmented)
 *   - AP          (explicit via packetizeAP for VPS+SPS+PPS bundling)
 *
 * Depacketizer handles:
 *   - Single NAL  (pass through)
 *   - AP          (split into NALUs)
 *   - FU          (reassemble fragments)
 *   - Frame output on marker bit.
 */

import {
  initPacketizer, makePacket, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;
var START_CODE_4 = Buffer.from([0, 0, 0, 1]);

// NAL types we care about (RFC 7798 §1.1.4 + Table 7-1 in HEVC spec).
var NAL_IDR_W_RADL = 19;
var NAL_IDR_N_LP   = 20;
var NAL_AP         = 48;
var NAL_FU         = 49;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * H265Packetizer — fragments an H.265 access unit into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function H265Packetizer(opts) {
  initPacketizer(this, opts);
}

/**
 * @param {object}   chunk
 * @param {Buffer}   [chunk.data]       Annex-B access unit (split automatically into NALUs)
 * @param {Buffer[]} [chunk.nalus]      pre-split NALUs (alternative to data, avoids re-splitting)
 * @param {number}   chunk.timestamp    microseconds
 * @param {string}   [chunk.type]       'key' | 'delta' — informational; H.265 keyframes are
 *                                       detected by NAL types 19/20 (IDR_W_RADL/IDR_N_LP)
 * @returns {Buffer[]}
 */
H265Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
H265Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

/**
 * Create an Aggregation Packet (AP, type 48) bundling multiple small
 * NALUs into one RTP packet — typically VPS + SPS + PPS sent together
 * before a keyframe (analog of H.264 packetizeStapA).
 *
 * @param {Buffer[]} nalus        raw NALUs (without start codes)
 * @param {number}   timestampUs  microseconds
 * @param {boolean}  [marker]     marker bit; default true (standalone AP that
 *                                ends its access unit). Pass false when the
 *                                AP precedes more packets of the same AU —
 *                                e.g. VPS+SPS+PPS bundled before an IDR sent
 *                                as separate FU fragments. Parity with
 *                                H264Packetizer.packetizeStapA.
 * @returns {Buffer}
 */
H265Packetizer.prototype.packetizeAP = function (nalus, timestampUs, marker) {
  if (!nalus || !nalus.length) {
    throw new TypeError('H265Packetizer.packetizeAP: nalus array required');
  }
  // Normalize each NALU to Buffer locally without mutating the caller's array.
  var localNalus = new Array(nalus.length);
  for (var ll = 0; ll < nalus.length; ll++) localNalus[ll] = _toBuffer(nalus[ll]);

  // Compute totals. Aggregation NAL header is 2 bytes; each aggregated
  // NALU is preceded by its own 2-byte length field.
  var totalSize = 2;
  for (var i = 0; i < localNalus.length; i++) totalSize += 2 + localNalus[i].length;

  // The aggregation NAL header takes its layer/TID from the FIRST NALU
  // (RFC 7798 §4.4.2). We zero F (forbidden_zero_bit) per spec, set
  // Type=48 (AP), and copy LayerId/TID from the first aggregated NALU.
  var firstHdrHi = localNalus[0][0];
  var firstHdrLo = localNalus[0].length > 1 ? localNalus[0][1] : 0;
  // Original layout: [F:1 | Type:6 | LayerId(hi):1] [LayerId(lo):5 | TID:3]
  // Replace Type field (bits 1..6 of high byte) with 48 (AP).
  // High byte becomes: (F=0, Type=48, LayerId hi bit from firstHdrLo top)
  var apHdrHi = (NAL_AP << 1) | (firstHdrHi & 0x01);
  var apHdrLo = firstHdrLo;

  var payload = Buffer.allocUnsafe(totalSize);
  payload[0] = apHdrHi;
  payload[1] = apHdrLo;
  var off = 2;
  for (var j = 0; j < localNalus.length; j++) {
    payload.writeUInt16BE(localNalus[j].length, off); off += 2;
    localNalus[j].copy(payload, off); off += localNalus[j].length;
  }
  var m = (marker === undefined) ? true : !!marker;
  return makePacket(this, payload, usToRtp(timestampUs, CLOCK_RATE), m, false);
};

H265Packetizer.prototype.close = function () {};


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
      // Single NAL — payload IS the NALU. makePacket already builds the
      // final buffer in one allocation/copy.
      out.push(makePacket(self, nalu, rtpTs, isLastNalu, withMeta));
    } else {
      _fragmentFU(self, nalu, rtpTs, isLastNalu, withMeta, out);
    }
  }
  return out;
}

function _fragmentFU(self, nalu, rtpTs, isLastNalu, withMeta, out) {
  // Original NAL header: 2 bytes.
  //   byte0:  [F:1 | Type:6 | LayerId(hi):1]
  //   byte1:  [LayerId(lo):5 | TID:3]
  if (nalu.length < 2) {
    // Malformed — too short to even read the original NAL header. We
    // emit nothing rather than producing a corrupt FU. The packetize()
    // caller never sees this for normal input (validateChunk checks
    // chunk.data, and _splitNALUs filters zero-length slices).
    return;
  }
  var origHi = nalu[0];
  var origLo = nalu[1];
  var origType = (origHi >> 1) & 0x3F;

  // FU PayloadHdr: same as original NAL header, but with Type field
  // replaced by 49 (FU). Bit 0 (F) stays; bottom bit of high byte
  // (top of LayerId) stays; LayerId(lo)+TID byte is unchanged.
  var fuHdrHi = (origHi & 0x81) | (NAL_FU << 1);
  var fuHdrLo = origLo;

  // 3-byte prefix per packet: [PayloadHdr(2)] [FU header(1)]
  var maxPayload = self.mtu - 3;
  var dataStart = 2;                   // skip the original 2-byte NAL header
  var dataLen = nalu.length - 2;
  var offset = 0;
  var fragCount = Math.ceil(dataLen / maxPayload);

  for (var i = 0; i < fragCount; i++) {
    var start = (i === 0);
    var end = (i === fragCount - 1);
    var size = Math.min(maxPayload, dataLen - offset);
    // FU header byte: [S | E | FuType(6)]  — FuType is the original NAL type
    var fuByte = (start ? 0x80 : 0) | (end ? 0x40 : 0) | (origType & 0x3F);

    out.push(makePacketWithPrefix(
      self, fuHdrHi, fuHdrLo, fuByte, 0, 3,
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
 * H265Depacketizer — reassembles H.265 access units from RTP packets.
 * Collects NALUs until marker bit, then emits a full Annex-B access unit.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first. Out-of-order arrival of FU
 * fragments will cause the NALU to be discarded (start-packet loss is
 * reported via the error callback).
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error]
 */
function H265Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._nalus = [];        // collected NALUs for current AU (raw, no start code)
  this._fuFragments = [];  // in-flight FU fragments
  this._fuHdrHi = 0;       // reconstructed NAL header byte 0 for in-progress FU
  this._fuHdrLo = 0;       // reconstructed NAL header byte 1
  this._sawIDR = false;    // true if any NALU in this AU was IDR (type 19/20)
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start an
 * H.265 keyframe (IDR_W_RADL or IDR_N_LP)?  Static, no state.
 *
 * H.265 over RTP (RFC 7798) has three packet shapes; the check mirrors
 * H264Depacketizer.peekKeyframe with two adaptations:
 *
 *   - NAL header is 2 bytes; type field is bits 1..6 of byte 0.
 *   - Keyframes are NAL types 19 (IDR_W_RADL) or 20 (IDR_N_LP).
 *
 *   Single NAL (types 0..47, except 48/49/50/63):
 *     The NAL header IS the first 2 bytes of the payload. Type = 19 or 20.
 *
 *   AP (type 48):
 *     2-byte aggregation header, then repeated [16-bit length | NALU].
 *     Walk the NALUs and check each one's type.
 *
 *   FU (type 49):
 *     The original NAL type lives in the bottom 6 bits of payload[2]
 *     (the FU header byte). Only the Start fragment (S=0x80 in payload[2])
 *     carries information we can act on for keyframe-tracking purposes.
 *
 * @param {Buffer} payload
 * @returns {boolean}
 */
H265Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 2) return false;
  var naluType = (payload[0] >> 1) & 0x3F;

  // Single NAL — type 0..47 (excluding the special types). For the
  // common case, just check the type byte directly.
  if (naluType < NAL_AP) {
    return naluType === NAL_IDR_W_RADL || naluType === NAL_IDR_N_LP;
  }

  if (naluType === NAL_AP) {
    // Aggregation Packet — walk aggregated NALUs.
    // Layout: 2-byte AP header, then [length:2 | NALU:length] entries.
    // Each aggregated NALU has its own 2-byte NAL header at position 0
    // of the aggregated NALU bytes.
    var off = 2;
    while (off + 2 <= payload.length) {
      var size = payload.readUInt16BE(off);
      off += 2;
      if (size === 0) continue;
      if (off + size > payload.length) return false;   // truncated
      if (size >= 2) {
        var aggType = (payload[off] >> 1) & 0x3F;
        if (aggType === NAL_IDR_W_RADL || aggType === NAL_IDR_N_LP) return true;
      }
      off += size;
    }
    return false;
  }

  if (naluType === NAL_FU) {
    // Fragmentation Unit — payload layout:
    //   payload[0..1] = PayloadHdr (FU type)
    //   payload[2]    = FU header [S | E | FuType]
    if (payload.length < 3) return false;
    var fuByte = payload[2];
    var startBit = !!(fuByte & 0x80);
    if (!startBit) return false;       // mid/end fragment carries no useful info
    var origType = fuByte & 0x3F;
    return origType === NAL_IDR_W_RADL || origType === NAL_IDR_N_LP;
  }

  // PACI (50) and reserved/extension types — treat as no-info.
  return false;
};

H265Depacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < 2) {
    emitError(this, new Error('H265Depacketizer: payload must be at least 2 bytes (NAL header)'));
    return;
  }

  var payload = packet.payload;
  var naluType = (payload[0] >> 1) & 0x3F;

  if (naluType === NAL_AP) {
    // Aggregation Packet — split into individual NALUs (skip the 2-byte
    // AP header at the start).
    var off = 2;
    while (off + 2 <= payload.length) {
      var size = payload.readUInt16BE(off); off += 2;
      if (size === 0) continue;
      if (off + size > payload.length) {
        emitError(this, new Error('H265Depacketizer: AP truncated NALU'));
        break;
      }
      var nalu = payload.subarray(off, off + size);
      this._nalus.push(nalu);
      if (size >= 2) {
        var t = (nalu[0] >> 1) & 0x3F;
        if (t === NAL_IDR_W_RADL || t === NAL_IDR_N_LP) this._sawIDR = true;
      }
      off += size;
    }

  } else if (naluType === NAL_FU) {
    // Fragmentation Unit
    if (payload.length < 3) {
      emitError(this, new Error('H265Depacketizer: FU header truncated'));
      return;
    }
    var fuByte = payload[2];
    var startBit = !!(fuByte & 0x80);
    var endBit = !!(fuByte & 0x40);
    var origType = fuByte & 0x3F;

    if (startBit) {
      // Reconstruct the original 2-byte NAL header:
      //   - F bit and LayerId(hi) come from the FU PayloadHdr (high byte
      //     of payload[0]). We replace the Type field with origType.
      //   - LayerId(lo) + TID come from payload[1] unchanged.
      this._fuHdrHi = (payload[0] & 0x81) | ((origType & 0x3F) << 1);
      this._fuHdrLo = payload[1];
      var hdrBuf = Buffer.allocUnsafe(2);
      hdrBuf[0] = this._fuHdrHi;
      hdrBuf[1] = this._fuHdrLo;
      this._fuFragments = [hdrBuf];
    } else if (this._fuFragments.length === 0) {
      emitError(this, new Error('H265Depacketizer: FU fragment without start (start packet lost)'));
      return;
    }
    this._fuFragments.push(payload.subarray(3));

    if (endBit) {
      var fullNalu = Buffer.concat(this._fuFragments);
      this._fuFragments = [];
      this._nalus.push(fullNalu);
      var t2 = (fullNalu[0] >> 1) & 0x3F;
      if (t2 === NAL_IDR_W_RADL || t2 === NAL_IDR_N_LP) this._sawIDR = true;
    }

  } else if (naluType < NAL_AP) {
    // Single NAL unit (regular video/parameter-set NALU).
    this._nalus.push(payload);
    if (naluType === NAL_IDR_W_RADL || naluType === NAL_IDR_N_LP) this._sawIDR = true;

  } else {
    // PACI (50) and other extension types not handled. We skip rather
    // than fail the AU — emitting an error lets the caller decide.
    emitError(this, new Error('H265Depacketizer: unsupported NAL type ' + naluType));
    return;
  }

  // Emit complete access unit on marker bit.
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

H265Depacketizer.prototype.reset = function () {
  this._nalus = [];
  this._fuFragments = [];
  this._fuHdrHi = 0;
  this._fuHdrLo = 0;
  this._sawIDR = false;
};

H265Depacketizer.prototype.close = function () {
  this.reset();
  this._output = null;
  this._error = null;
};


// ═══════════════════════════════════════════════════════════════════
//  Internal helpers — Annex-B splitting / joining
//  (Identical to h264.js — H.265 uses the same Annex-B framing)
// ═══════════════════════════════════════════════════════════════════

function _splitNALUs(buf) {
  // Auto-detect framing, mirroring h264.js: Annex-B start codes vs.
  // length-prefixed (hvcC / MP4 / WebCodecs "hevc" format — 4-byte
  // big-endian lengths). Fall back to the Annex-B splitter, which
  // treats unframed input as a single NALU (previous behavior).
  if (!_startsWithStartCode(buf)) {
    var lp = _trySplitLengthPrefixed(buf);
    if (lp) return lp;
  }
  return _splitAnnexB(buf);
}

function _startsWithStartCode(buf) {
  if (buf.length >= 3 && buf[0] === 0 && buf[1] === 0 && buf[2] === 1) return true;
  if (buf.length >= 4 && buf[0] === 0 && buf[1] === 0 && buf[2] === 0 && buf[3] === 1) return true;
  return false;
}

function _trySplitLengthPrefixed(buf) {
  if (buf.length < 6) return null;
  var nalus = [];
  var off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) return null;
    var len = buf.readUInt32BE(off);
    off += 4;
    if (len === 0 || off + len > buf.length) return null;
    // H.265 NAL header: forbidden_zero_bit (top bit of byte 0) must be 0.
    if (buf[off] & 0x80) return null;
    nalus.push(buf.subarray(off, off + len));
    off += len;
  }
  return nalus.length > 0 ? nalus : null;
}

function _splitAnnexB(buf) {
  var nalus = [];
  var i = 0, len = buf.length;

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


export { H265Packetizer, H265Depacketizer };
