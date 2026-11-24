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
 *        16..18 = BLA     }
 *        19, 20 = IDR     } IRAP pictures (keyframes): each one is a
 *        21     = CRA     } point a decoder can start from
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
  initDepacketizer, emitError, checkDepacketizePayload, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;
var START_CODE_4 = Buffer.from([0, 0, 0, 1]);

// A keyframe is any IRAP picture, NAL types 16..23 (H.265 §7.4.2.2): BLA
// (16-18), IDR (19, 20), CRA (21) and the reserved IRAP types 22-23. Only
// 19/20 used to count, so x265's default open GOP (IDR first, CRA for every
// keyframe after it) was all 'delta' after the first frame: a decoder that
// lost its place waited for a key that never came. libwebrtc's H265
// depacketizer marks the same set (video_rtp_depacketizer_h265.cc).
function _isIrap(type) {
  return type >= 16 && type <= 23;
}
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
 * @param {string} [opts.format]                  the chunks' framing, as WebCodecs' hevc.format:
 *                                                'annexb' (start codes) or 'hevc' (4-byte
 *                                                lengths). Unset: told from the data.
 */
function H265Packetizer(opts) {
  initPacketizer(this, opts);
  this._format = _checkFormat(this, opts.format, 'hevc');
}

/**
 * @param {object}   chunk
 * @param {Buffer}   [chunk.data]       Annex-B access unit (split automatically into NALUs)
 * @param {Buffer[]} [chunk.nalus]      pre-split NALUs (alternative to data, avoids re-splitting)
 * @param {number}   chunk.timestamp    microseconds
 * @param {string}   [chunk.type]       'key' | 'delta' — informational; H.265 keyframes are
 *                                       detected by IRAP NAL types 16-23 (BLA/IDR/CRA)
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
  // Normalize each NALU to Buffer locally without mutating the caller's
  // array. One shorter than its 2-byte header is no NAL unit and is left
  // out (it went out as such, a zero size among them).
  var localNalus = [];
  if (nalus) {
    for (var ll = 0; ll < nalus.length; ll++) {
      var nb = _toBuffer(nalus[ll]);
      if (nb && nb.length >= 2) localNalus.push(nb);
    }
  }
  if (!localNalus.length) {
    throw new TypeError('H265Packetizer.packetizeAP: nalus array required');
  }

  // The AP's payload header (RFC 7798 §4.4.2): F set when any aggregated
  // NALU's F is, Type 48, LayerId and TID the LOWEST of the aggregated
  // NALUs'. (It took LayerId/TID from the first NALU and always wrote F=0.)
  // NAL header: [F:1 | Type:6 | LayerId(hi):1] [LayerId(lo):5 | TID:3]
  var fBit = 0, layerId = 63, tid = 7;
  var totalSize = 2;
  for (var i = 0; i < localNalus.length; i++) {
    var n = localNalus[i];
    // The size field is 16 bits; a longer NALU made writeUInt16BE throw
    // Node's generic out-of-range error.
    if (n.length > 0xFFFF) {
      throw new RangeError('H265Packetizer.packetizeAP: a NALU of ' + n.length + ' bytes does not fit in an AP (65535 at most)');
    }
    fBit |= n[0] & 0x80;
    var lid = ((n[0] & 0x01) << 5) | (n[1] >> 3);
    if (lid < layerId) layerId = lid;
    if ((n[1] & 0x07) < tid) tid = n[1] & 0x07;
    totalSize += 2 + n.length;
  }
  var apHdrHi = fBit | (NAL_AP << 1) | (layerId >> 5);
  var apHdrLo = ((layerId & 0x1F) << 3) | tid;

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
    nalus = _splitNALUs(_toBuffer(chunk.data), self._format);
  }
  // A NALU shorter than its 2-byte header is no NAL unit: it went out as a
  // packet every receiver drops (ours too: minLen 2), and took the marker
  // with it when it was the last one. It is left out.
  nalus = nalus.filter(function (n) { return n.length >= 2; });
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
  this._sawIDR = false;    // true if any NALU in this AU was IRAP (types 16-23)
  this._ts = null;         // RTP timestamp of the access unit being built
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start an
 * H.265 keyframe (IDR_W_RADL or IDR_N_LP)?  Static, no state.
 *
 * H.265 over RTP (RFC 7798) has three packet shapes; the check mirrors
 * H264Depacketizer.peekKeyframe with two adaptations:
 *
 *   - NAL header is 2 bytes; type field is bits 1..6 of byte 0.
 *   - Keyframes are IRAP NAL types 16-23 (BLA, IDR, CRA; see _isIrap).
 *
 *   Single NAL (types 0..47, except 48/49/50/63):
 *     The NAL header IS the first 2 bytes of the payload. Type = 16..23.
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
    return _isIrap(naluType);
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
        if (_isIrap(aggType)) return true;
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
    return _isIrap(origType);
  }

  // PACI (50) and reserved/extension types — treat as no-info.
  return false;
};

H265Depacketizer.prototype.depacketize = function (packet) {
  // minLen 2: the H265 NAL header itself is two bytes — anything shorter
  // (including zero-length padding probes) carries nothing parseable.
  if (!checkDepacketizePayload(this, packet, 2)) return;

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
        if (_isIrap(t)) this._sawIDR = true;
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
      if (_isIrap(t2)) this._sawIDR = true;
    }

  } else if (naluType < NAL_AP) {
    // Single NAL unit (regular video/parameter-set NALU).
    this._nalus.push(payload);
    if (_isIrap(naluType)) this._sawIDR = true;

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

H265Depacketizer.prototype.reset = function () {
  this._nalus = [];
  this._fuFragments = [];
  this._fuHdrHi = 0;
  this._fuHdrLo = 0;
  this._sawIDR = false;
  this._ts = null;
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

function _splitNALUs(buf, format) {
  // The packetizer's `format` ('annexb' / 'hevc'), or auto-detect the
  // framing, mirroring h264.js: Annex-B start codes vs. length-prefixed
  // (hvcC / MP4 / WebCodecs "hevc" format — 4-byte big-endian lengths).
  // The strict length walk goes first: a leading 00 00 01 is also the
  // length of a NALU of 256-511 bytes, which went to the Annex-B splitter
  // (see h264.js). Fall back to the Annex-B splitter, which treats
  // unframed input as a single NALU (previous behavior).
  if (format === 'annexb') return _splitAnnexB(buf);
  var lp = _trySplitLengthPrefixed(buf);
  if (lp) return lp;
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
  var found = false;

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
  // trailing_zero_8bits (H.265 B.2) between a NALU and the next start code
  // are not part of it — a NAL unit's last byte is never 0x00 (7.4.2.1).
  // They went out at the end of the NALU.
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
