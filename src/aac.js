/**
 * aac — AAC RTP packetizer + depacketizer (RFC 3640, AAC-hbr mode).
 *
 *   chunk {data, timestamp}  →  AacPacketizer   →  Buffer[]
 *   RTP packet                →  AacDepacketizer →  chunk via output()
 *
 * RFC 3640 defines the RTP payload format for MPEG-4 elementary
 * streams. It supports several modes; this implementation targets
 * **AAC-hbr** ("high bit-rate AAC"), which is the mode used by
 * essentially every real-world deployment — RTSP cameras, streaming
 * servers, VoIP wideband audio, etc. AAC-lbr (low bit-rate, 6+2 bit
 * AU-headers) is not supported; if you need it, the fundamental
 * structure is the same with different sizeLength/indexLength values.
 *
 * ── Payload structure (RFC 3640 §3.3.6) ────────────────────────────
 *
 *   +---------+-----------+-----------+---------------+
 *   | RTP     | AU Header | Auxiliary | Access Unit   |
 *   | Header  | Section   | Section   | Data Section  |
 *   +---------+-----------+-----------+---------------+
 *
 * In AAC-hbr the Auxiliary Section MUST be empty, so the layout is:
 *
 *   AU Header Section  : 2-byte length-in-bits prefix, then N × 2-byte AU-headers
 *   Access Unit Data   : N AAC frames concatenated (or one fragment)
 *
 * Each AU-header is 16 bits:
 *
 *      0                   1
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |       AU-size (13 bits)       |  AU-Index/Delta (3 bits) |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   AU-size           — size of the corresponding AAC frame in octets.
 *                       Max 8191 (13 bits). For fragmented AUs, this is
 *                       the size of the WHOLE AU, not the fragment.
 *   AU-Index          — index of the first AU (0). De-interleave hint.
 *   AU-Index-delta    — for subsequent AUs in the same packet:
 *                       (this AU's index) − (previous AU's index) − 1.
 *                       For non-interleaved transmission this is 0.
 *
 * The AU-headers-length field is 16 bits and counts BITS, not octets,
 * across all AU-headers. With 2-byte AU-headers this is always
 * 16 × N bits; we still write it as bits per spec.
 *
 * ── Packetization scenarios (the three legal cases) ────────────────
 *
 *   1. Single AU per packet — one AAC frame, one AU-header (the common
 *      case for low-latency delivery).
 *   2. Multiple AUs per packet — several small AAC frames concatenated
 *      to amortize the RTP overhead. All AUs MUST be complete; you
 *      cannot mix fragments and complete AUs in one packet.
 *   3. Fragmented AU — a single large AAC frame split across multiple
 *      RTP packets, each carrying one AU-header (with the WHOLE AU's
 *      size) and one fragment of the data. The marker bit on the
 *      RTP header marks the LAST fragment.
 *
 * The packetizer auto-selects between (1) and (3) based on size.
 * Mode (2) is not used by this packetizer — it requires lookahead and
 * a batching policy that's an application concern. Senders generally
 * call packetize() once per encoded AAC frame.
 *
 * ── Timestamp handling ─────────────────────────────────────────────
 *
 * AAC RTP timestamps tick at the audio sampling rate, not 90 kHz like
 * video. The caller specifies the rate at packetizer construction
 * (via opts.clockRate). Common values: 44100, 48000, 22050, 32000,
 * 16000.
 *
 * Each AAC frame represents 1024 samples (or 960 in some profiles, or
 * 2048 with SBR/HE-AAC v1). The RTP timestamp advances by 1024 (or
 * whatever the AU duration is) between frames; this module does not
 * enforce a duration — the caller passes microsecond timestamps and
 * the packetizer converts to RTP ticks at clockRate.
 *
 * ── Marker bit ─────────────────────────────────────────────────────
 *
 * RFC 3640 §3.4: marker bit = 1 means this packet contains the LAST
 * fragment of an Access Unit (or a complete AU; or the last of a
 * concatenated batch). For a single-packet AU the marker is always
 * set. For a fragmented AU only the final fragment has marker=1.
 */

import {
  initPacketizer, makePacket, validateChunk, usToRtp,
  initDepacketizer, emitError, _toBuffer,
} from './rtp.js';


// AAC-hbr fixed parameters (RFC 3640 §3.3.6)
var AU_HEADER_BITS   = 16;   // 13 bits AU-size + 3 bits AU-Index/Delta
var AU_HEADER_BYTES  = 2;
var AU_HEADERS_LENGTH_PREFIX_BYTES = 2;   // 16-bit AU-headers-length field
var MAX_AU_SIZE = (1 << 13) - 1;   // 13-bit field — max 8191 octets
var MAX_AU_INDEX_DELTA = (1 << 3) - 1;   // 3 bits

// Default audio clock rate. AAC has many possible values (44.1, 48, 22.05,
// 32, 16, ...) and there's no universal default. We pick 48000 as a
// reasonable fallback; callers SHOULD set explicitly.
var DEFAULT_CLOCK_RATE = 48000;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AacPacketizer — wraps an AAC frame in RTP packet(s) per RFC 3640
 * AAC-hbr mode.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127 (typically 96-127 dynamic)
 * @param {number} [opts.clockRate]               default 48000; should match the
 *                                                audio sampling rate negotiated in SDP
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function AacPacketizer(opts) {
  initPacketizer(this, opts);
  this.clockRate = (opts && opts.clockRate) || DEFAULT_CLOCK_RATE;
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       a single AAC raw access unit (no ADTS header)
 * @param {number} chunk.timestamp  microseconds (monotonic)
 * @returns {Buffer[]} one or more RTP packets (one if AU fits, several if fragmented)
 */
AacPacketizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/**
 * Same as packetize(), but returns descriptors with seq/ts/marker for
 * RTX caching.
 *
 * @returns {Array<{buffer, sequenceNumber, timestamp, marker}>}
 */
AacPacketizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

AacPacketizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);

  if (data.length === 0) {
    // Defensive — emitting an empty AU is a caller bug. We treat it
    // as a no-op rather than producing a malformed packet (no AAC
    // implementation can decode a zero-length AU anyway).
    return [];
  }

  if (data.length > MAX_AU_SIZE) {
    // The 13-bit AU-size field cannot represent this. AAC-hbr's hard
    // limit is 8191 octets; AAC-ldr (low-delay reduced) goes higher
    // but we don't implement it. Surface as a warning rather than
    // throwing — the caller may have a misconfigured encoder.
    if (typeof process !== 'undefined' && process.emitWarning) {
      process.emitWarning(
        'AacPacketizer: AU size ' + data.length +
          ' exceeds AAC-hbr maximum ' + MAX_AU_SIZE + ' octets',
        'RtpPacketWarning'
      );
    }
    // We still produce the packets, but the size field will be
    // truncated to 13 bits. This will fail to decode; that's the
    // caller's problem, but at least the bytes go on the wire.
  }

  var rtpTs = usToRtp(chunk.timestamp, self.clockRate);

  // Header overhead per packet: 2-byte AU-headers-length prefix + one
  // 2-byte AU-header. (We always emit exactly one AU-header per
  // packet, whether the AU fits in one packet or is fragmented across
  // many — fragments share the AU's size in their header.)
  var headerOverhead = AU_HEADERS_LENGTH_PREFIX_BYTES + AU_HEADER_BYTES;
  var maxFragSize = self.mtu - headerOverhead;

  if (maxFragSize <= 0) {
    // MTU is so small there's no room for even one byte of payload.
    // Almost certainly a misconfigured MTU. Emit one packet with no
    // data anyway so the stream doesn't silently drop.
    if (typeof process !== 'undefined' && process.emitWarning) {
      process.emitWarning(
        'AacPacketizer: MTU ' + self.mtu + ' too small for AAC-hbr headers',
        'RtpPacketWarning'
      );
    }
    return [_buildSinglePacket(self, data, rtpTs, true, withMeta)];
  }

  // Common case — AU fits in one packet. Marker = 1 (last/only
  // fragment of this AU).
  if (data.length <= maxFragSize) {
    return [_buildSinglePacket(self, data, rtpTs, true, withMeta)];
  }

  // Fragmentation case — split across multiple packets. All fragments
  // carry the SAME AU-header (with the whole AU's size) and the SAME
  // RTP timestamp. Marker = 1 only on the final fragment.
  var out = [];
  var offset = 0;
  var totalSize = data.length;
  while (offset < totalSize) {
    var fragSize = Math.min(maxFragSize, totalSize - offset);
    var fragData = data.subarray(offset, offset + fragSize);
    var isLast = (offset + fragSize === totalSize);
    out.push(_buildFragmentPacket(self, fragData, totalSize, rtpTs, isLast, withMeta));
    offset += fragSize;
  }
  return out;
}


/**
 * Build a single-packet AU: AU-headers-length (16) + AU-header (16) +
 * AU data. Marker = 1.
 */
function _buildSinglePacket(self, auData, rtpTs, marker, withMeta) {
  var auSize = auData.length & MAX_AU_SIZE;   // truncate to 13 bits if oversized
  var payload = Buffer.allocUnsafe(AU_HEADERS_LENGTH_PREFIX_BYTES + AU_HEADER_BYTES + auData.length);
  // AU-headers-length in BITS — exactly one 16-bit AU-header.
  payload.writeUInt16BE(AU_HEADER_BITS, 0);
  // AU-header: 13 bits size + 3 bits Index/Delta. Index for the first
  // (and only) AU in this packet is 0.
  payload.writeUInt16BE((auSize << 3) & 0xFFFF, 2);
  auData.copy(payload, 4);
  return makePacket(self, payload, rtpTs, marker, withMeta);
}

/**
 * Build a fragment packet: AU-headers-length (16) + AU-header (16, with
 * WHOLE AU size, not fragment size) + fragment data.
 *
 * Per RFC 3640 §3.3.6, fragments carry the size of the entire AU in
 * their AU-header so the receiver can pre-allocate the reassembly
 * buffer.
 */
function _buildFragmentPacket(self, fragData, totalAuSize, rtpTs, isLast, withMeta) {
  var auSize = totalAuSize & MAX_AU_SIZE;
  var payload = Buffer.allocUnsafe(AU_HEADERS_LENGTH_PREFIX_BYTES + AU_HEADER_BYTES + fragData.length);
  payload.writeUInt16BE(AU_HEADER_BITS, 0);
  payload.writeUInt16BE((auSize << 3) & 0xFFFF, 2);
  fragData.copy(payload, 4);
  return makePacket(self, payload, rtpTs, isLast, withMeta);
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AacDepacketizer — reassembles AAC AUs from RTP packets per RFC 3640
 * AAC-hbr mode.
 *
 * Output behavior mirrors the video depacketizers: a chunk is emitted
 * once a complete AU is reassembled. For single-packet AUs that
 * happens immediately on receipt; for fragmented AUs it happens when
 * the marker-bit packet arrives.
 *
 * Multiple AUs in one packet (concatenated, mode 2) are also
 * supported — each is emitted as a separate chunk. Their timestamps
 * are derived from the RTP timestamp using the clock rate; the spec
 * requires constant AU duration for in-band concatenation, signaled
 * via the SDP `constantDuration` parameter. The caller specifies this
 * via opts.constantDuration (in RTP ticks); default 1024 (typical AAC
 * frame size in samples).
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type: 'key' }
 * @param {function} [opts.error] called with Error on malformed input
 * @param {number}   [opts.constantDuration] RTP ticks per AU when multiple
 *                                            AUs share a packet (default 1024)
 */
function AacDepacketizer(opts) {
  initDepacketizer(this, opts);
  this._constantDuration = (opts && opts.constantDuration) || 1024;
  // Reassembly state for fragmented AUs:
  this._fragments = null;        // Array of Buffers waiting to be joined
  this._expectedSize = 0;         // total AU size announced in fragment headers
  this._fragmentTimestamp = 0;    // RTP ts of the first fragment
  this._receivedSize = 0;         // bytes accumulated so far
}

/**
 * peekKeyframe — AAC has no keyframe vs delta concept. Every AAC AU
 * is independently decodable. Returns false to match the uniform
 * NackGenerator interface across all audio codecs.
 *
 * @returns {false}
 */
AacDepacketizer.peekKeyframe = function () { return false; };

/**
 * Feed a parsed RTP packet (from rtp.parse()).
 *
 * @param {object} packet — { payload, marker, timestamp, ... }
 */
AacDepacketizer.prototype.depacketize = function (packet) {
  if (!packet || !packet.payload || packet.payload.length < AU_HEADERS_LENGTH_PREFIX_BYTES) {
    emitError(this, new Error('AacDepacketizer: payload too short for AU-headers-length prefix'));
    return;
  }

  var payload = packet.payload;
  var auHeadersLengthBits = payload.readUInt16BE(0);

  // AU-headers section is octet-aligned (round up bits→bytes).
  var auHeadersBytes = (auHeadersLengthBits + 7) >> 3;
  var auHeadersStart = AU_HEADERS_LENGTH_PREFIX_BYTES;
  var auHeadersEnd   = auHeadersStart + auHeadersBytes;

  if (auHeadersEnd > payload.length) {
    emitError(this, new Error('AacDepacketizer: AU-headers extend past payload end'));
    return;
  }

  // In AAC-hbr each AU-header is exactly 16 bits, so the count is
  // auHeadersLengthBits / 16. If this doesn't divide evenly the
  // sender is using a different mode (lbr, generic, etc.) and we
  // can't decode it.
  if (auHeadersLengthBits % AU_HEADER_BITS !== 0) {
    emitError(this, new Error(
      'AacDepacketizer: AU-headers-length ' + auHeadersLengthBits +
        ' bits is not a multiple of ' + AU_HEADER_BITS +
        ' (this depacketizer only supports AAC-hbr mode)'
    ));
    return;
  }
  var numAUs = auHeadersLengthBits / AU_HEADER_BITS;

  // Auxiliary section MUST be empty in AAC-hbr (RFC 3640 §3.3.6), so
  // AU data starts immediately after AU-headers.
  var auDataStart = auHeadersEnd;

  // Parse all AU-headers up front. We need their sizes before we can
  // slice the data section.
  var headers = new Array(numAUs);
  for (var i = 0; i < numAUs; i++) {
    var hdrOffset = auHeadersStart + i * AU_HEADER_BYTES;
    var hdrWord = payload.readUInt16BE(hdrOffset);
    var auSize = (hdrWord >> 3) & MAX_AU_SIZE;       // top 13 bits
    var auIndexDelta = hdrWord & MAX_AU_INDEX_DELTA;  // bottom 3 bits
    headers[i] = { size: auSize, indexDelta: auIndexDelta };
  }

  // ── Case A: single AU header → either one complete AU or a fragment.
  //
  // Distinguishing fragments from complete AUs requires comparing the
  // AU-header's announced size to the bytes available in this packet's
  // data section. If the announced size > available, it's a fragment.
  // If equal, it's a complete AU. (If less, the packet is malformed
  // or there are multiple AUs concatenated, which we handle in case B.)
  if (numAUs === 1) {
    var announcedSize = headers[0].size;
    var availableSize = payload.length - auDataStart;

    if (availableSize < announcedSize) {
      // Fragment.
      this._handleFragment(payload, auDataStart, availableSize,
                           announcedSize, packet.timestamp, packet.marker);
      return;
    }

    if (availableSize > announcedSize) {
      // The data section is bigger than the single AU-header claims.
      // This happens if a sender batched multiple AUs but only emitted
      // one header — that's malformed. We surface and stop.
      emitError(this, new Error(
        'AacDepacketizer: data section (' + availableSize +
          ' bytes) larger than single AU size (' + announcedSize + ')'
      ));
      return;
    }

    // Complete AU in one packet.
    this._resetFragmentState();   // clear any half-finished prior fragmentation
    this._output({
      data: payload.subarray(auDataStart, auDataStart + announcedSize),
      timestamp: packet.timestamp,
      type: 'key',
    });
    return;
  }

  // ── Case B: multiple AU headers → concatenated complete AUs.
  //
  // Per RFC 3640 §3.2.3.2, when multiple AUs are present in one packet,
  // each MUST be complete (no mixing fragments with complete AUs).
  // We slice the data section by the sizes given in the headers. The
  // timestamps for AUs after the first are computed by adding
  // constantDuration RTP ticks per AU (this is what the SDP
  // `constantDuration` parameter is for; we accept it as an opt).
  this._resetFragmentState();
  var dataOffset = auDataStart;
  var ts = packet.timestamp >>> 0;
  for (var j = 0; j < numAUs; j++) {
    var sz = headers[j].size;
    if (dataOffset + sz > payload.length) {
      emitError(this, new Error(
        'AacDepacketizer: AU ' + j + ' size ' + sz +
          ' extends past payload end'
      ));
      return;
    }
    this._output({
      data: payload.subarray(dataOffset, dataOffset + sz),
      timestamp: ts,
      type: 'key',
    });
    dataOffset += sz;
    ts = (ts + this._constantDuration) >>> 0;
  }
};


/**
 * Append a fragment of an AU to the reassembly buffer; emit the
 * complete AU when the marker bit arrives.
 */
AacDepacketizer.prototype._handleFragment = function (payload, dataStart, fragSize,
                                                       announcedSize, packetTs, markerBit) {
  // Start a new reassembly if there isn't one in progress, or if this
  // fragment's announced AU size differs from the in-progress one
  // (which means we missed the end of the previous AU and a new one
  // started).
  if (!this._fragments || this._expectedSize !== announcedSize) {
    if (this._fragments) {
      // We were mid-AU and got a fragment of a different AU. The
      // previous AU is lost; surface as an error and start fresh.
      emitError(this, new Error(
        'AacDepacketizer: dropped incomplete AU (' + this._receivedSize +
          '/' + this._expectedSize + ' bytes)'
      ));
    }
    this._fragments = [];
    this._expectedSize = announcedSize;
    this._fragmentTimestamp = packetTs;
    this._receivedSize = 0;
  }

  this._fragments.push(payload.subarray(dataStart, dataStart + fragSize));
  this._receivedSize += fragSize;

  // Marker = end of AU. Reassemble and emit.
  if (markerBit) {
    if (this._receivedSize !== this._expectedSize) {
      // Common cause: lost middle fragment, only the final one made
      // it (with marker=1). Surface and reset.
      emitError(this, new Error(
        'AacDepacketizer: AU reassembly size mismatch (got ' +
          this._receivedSize + ', expected ' + this._expectedSize + ')'
      ));
      this._resetFragmentState();
      return;
    }
    var au = Buffer.concat(this._fragments, this._receivedSize);
    var ts = this._fragmentTimestamp;
    this._resetFragmentState();
    this._output({
      data: au,
      timestamp: ts,
      type: 'key',
    });
  }
};

AacDepacketizer.prototype._resetFragmentState = function () {
  this._fragments = null;
  this._expectedSize = 0;
  this._fragmentTimestamp = 0;
  this._receivedSize = 0;
};

AacDepacketizer.prototype.reset = function () {
  this._resetFragmentState();
};

AacDepacketizer.prototype.close = function () {
  this._resetFragmentState();
  this._output = null;
  this._error = null;
};


export { AacPacketizer, AacDepacketizer };
