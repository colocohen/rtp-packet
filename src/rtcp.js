/**
 * rtcp — RTCP packet types (RFC 3550, RFC 4585).
 *
 * Implements:
 *   - SR  (Sender Report)     — type 200
 *   - RR  (Receiver Report)   — type 201
 *   - NACK (Generic NACK)     — type 205, fmt=1
 *   - PLI  (Picture Loss)     — type 206, fmt=1
 *   - FIR  (Full Intra Req)   — type 206, fmt=4
 */

/**
 * Build Sender Report.
 * @param {object} opts
 * @param {number} opts.ssrc         — sender SSRC
 * @param {number} opts.ntpTimestamp — NTP timestamp (64-bit as [hi, lo])
 * @param {number} opts.rtpTimestamp — RTP timestamp
 * @param {number} opts.packetCount  — total RTP packets sent
 * @param {number} opts.octetCount   — total payload bytes sent
 * @returns {Buffer}
 */
function buildSR(opts) {
  var buf = Buffer.allocUnsafe(28);
  // Header: V=2, P=0, RC=0, PT=200, length=6 (words)
  buf[0] = 0x80;
  buf[1] = 200;
  buf.writeUInt16BE(6, 2);         // length in 32-bit words minus 1
  buf.writeUInt32BE(opts.ssrc >>> 0, 4);

  // NTP timestamp (64 bits)
  var ntp = opts.ntpTimestamp || _getNtpTimestamp();
  buf.writeUInt32BE(ntp[0] >>> 0, 8);
  buf.writeUInt32BE(ntp[1] >>> 0, 12);

  buf.writeUInt32BE(opts.rtpTimestamp >>> 0, 16);
  buf.writeUInt32BE(opts.packetCount >>> 0, 20);
  buf.writeUInt32BE(opts.octetCount >>> 0, 24);

  return buf;
}

/**
 * Build PLI (Picture Loss Indication) — request keyframe.
 * @param {number} senderSsrc — our SSRC
 * @param {number} mediaSsrc  — SSRC of the media stream
 * @returns {Buffer}
 */
function buildPLI(senderSsrc, mediaSsrc) {
  var buf = Buffer.allocUnsafe(12);
  buf[0] = 0x81;  // V=2, P=0, FMT=1
  buf[1] = 206;   // PSFB
  buf.writeUInt16BE(2, 2);  // length = 2
  buf.writeUInt32BE(senderSsrc >>> 0, 4);
  buf.writeUInt32BE(mediaSsrc >>> 0, 8);
  return buf;
}

/**
 * Build NACK — request retransmission of specific packets.
 * @param {number} senderSsrc — our SSRC
 * @param {number} mediaSsrc  — SSRC of the media stream
 * @param {number[]} seqNums  — lost sequence numbers
 * @returns {Buffer}
 */
function buildNACK(senderSsrc, mediaSsrc, seqNums) {
  if (!seqNums || !seqNums.length) return null;

  // Group into NACK FCI entries (PID + BLP)
  var entries = _buildNackEntries(seqNums);
  var buf = Buffer.allocUnsafe(12 + entries.length * 4);
  buf[0] = 0x81;  // V=2, P=0, FMT=1
  buf[1] = 205;   // RTPFB
  buf.writeUInt16BE(2 + entries.length, 2);  // length
  buf.writeUInt32BE(senderSsrc >>> 0, 4);
  buf.writeUInt32BE(mediaSsrc >>> 0, 8);

  for (var i = 0; i < entries.length; i++) {
    buf.writeUInt16BE(entries[i].pid, 12 + i * 4);
    buf.writeUInt16BE(entries[i].blp, 14 + i * 4);
  }

  return buf;
}

/**
 * Build FIR (Full Intra Request).
 * @param {number} senderSsrc — our SSRC
 * @param {number} mediaSsrc  — SSRC of the media stream
 * @param {number} seqNr      — FIR sequence number (increment each time)
 * @returns {Buffer}
 */
function buildFIR(senderSsrc, mediaSsrc, seqNr) {
  var buf = Buffer.allocUnsafe(20);
  buf[0] = 0x84;  // V=2, P=0, FMT=4
  buf[1] = 206;   // PSFB
  buf.writeUInt16BE(4, 2);  // length = 4
  buf.writeUInt32BE(senderSsrc >>> 0, 4);
  buf.writeUInt32BE(0, 8);  // media SSRC = 0 per RFC 5104
  buf.writeUInt32BE(mediaSsrc >>> 0, 12);
  buf[16] = seqNr & 0xFF;
  buf[17] = 0; buf[18] = 0; buf[19] = 0;  // reserved
  return buf;
}

/**
 * Build Receiver Report (RR).
 * @param {object} opts
 * @param {number} opts.ssrc           — our SSRC
 * @param {number} opts.mediaSsrc      — source SSRC
 * @param {number} opts.fractionLost   — 0-255
 * @param {number} opts.totalLost      — cumulative packets lost (24-bit)
 * @param {number} opts.highestSeq     — highest seq received (full 32-bit: cycles + seq)
 * @param {number} opts.jitter         — interarrival jitter (RTP timestamp units)
 * @param {number} opts.lastSR         — middle 32 bits of last SR NTP timestamp
 * @param {number} opts.delaySinceLastSR — delay since last SR in 1/65536 seconds
 * @returns {Buffer}
 */
function buildRR(opts) {
  var buf = Buffer.allocUnsafe(32);
  buf[0] = 0x81;  // V=2, P=0, RC=1
  buf[1] = 201;   // RR
  buf.writeUInt16BE(7, 2);  // length = 7 (words)
  buf.writeUInt32BE(opts.ssrc >>> 0, 4);

  // Report block
  buf.writeUInt32BE(opts.mediaSsrc >>> 0, 8);
  buf[12] = opts.fractionLost & 0xFF;
  var lost = opts.totalLost & 0x00FFFFFF;
  buf[13] = (lost >> 16) & 0xFF;
  buf[14] = (lost >> 8) & 0xFF;
  buf[15] = lost & 0xFF;
  buf.writeUInt32BE(opts.highestSeq >>> 0, 16);
  buf.writeUInt32BE(opts.jitter >>> 0, 20);
  buf.writeUInt32BE(opts.lastSR >>> 0, 24);
  buf.writeUInt32BE(opts.delaySinceLastSR >>> 0, 28);

  return buf;
}

/**
 * Build REMB (Receiver Estimated Maximum Bitrate).
 * @param {number} senderSsrc — our SSRC
 * @param {number[]} mediaSsrcs — SSRCs this applies to
 * @param {number} bitrate — estimated max bitrate in bps
 * @returns {Buffer}
 */
function buildREMB(senderSsrc, mediaSsrcs, bitrate) {
  var numSsrcs = mediaSsrcs.length;
  var buf = Buffer.allocUnsafe(20 + numSsrcs * 4);
  buf[0] = 0x8F;  // V=2, P=0, FMT=15
  buf[1] = 206;   // PSFB
  buf.writeUInt16BE((2 + 1 + numSsrcs), 2);  // length
  buf.writeUInt32BE(senderSsrc >>> 0, 4);
  buf.writeUInt32BE(0, 8);  // media SSRC = 0

  // REMB identifier
  buf.write('REMB', 12, 4, 'ascii');

  // BR mantissa and exponent: bitrate = mantissa × 2^exp
  var exp = 0;
  var mantissa = Math.floor(bitrate);
  while (mantissa > 0x3FFFF) { mantissa >>= 1; exp++; }
  buf[16] = (numSsrcs & 0xFF);
  buf[17] = ((exp & 0x3F) << 2) | ((mantissa >> 16) & 0x03);
  buf[18] = (mantissa >> 8) & 0xFF;
  buf[19] = mantissa & 0xFF;

  for (var i = 0; i < numSsrcs; i++) {
    buf.writeUInt32BE(mediaSsrcs[i] >>> 0, 20 + i * 4);
  }

  return buf;
}


/**
 * buildTransportCC — encode a transport-wide congestion control feedback
 * message (RTPFB PT=205 FMT=15, draft-holmer-rmcat-transport-wide-cc-extensions-01).
 *
 * This is the counterpart of parseTransportCC in bandwidth.js.  The two
 * together allow round-trip testing of the format without involving the
 * network.
 *
 * Inputs describe which packets were received (and when), for a contiguous
 * range of transport-wide sequence numbers [baseSeq, baseSeq + packetCount).
 *
 * @param {object} opts
 * @param {number} opts.senderSsrc       — our SSRC (included in the header)
 * @param {number} opts.mediaSsrc        — SSRC of the media stream being reported on
 * @param {number} opts.baseSeq          — first transport-wide seq covered (u16)
 * @param {number} opts.packetCount      — number of packet status entries (u16)
 * @param {number} opts.referenceTimeMs  — abs time for the first *received* packet's
 *                                         delta base; will be truncated to 64ms units
 *                                         (24-bit signed wraps every ~4.6 hours)
 * @param {number} opts.fbPktCount       — feedback packet counter, 0..255, wraps
 * @param {Array}  opts.packets          — packetCount entries, each:
 *                                             { received: bool, deltaUs: int|null }
 *                                         deltaUs is the offset from the previous
 *                                         received packet's arrival (or from refTime
 *                                         for the first received packet), in µs.
 * @returns {Buffer} complete RTCP packet ready to send.
 *
 * Layout (from draft §3.1):
 *
 *    +V-P-FMT+   PT=205   +----- length -----+
 *    +------+ sender SSRC +------+ media SSRC +
 *    | baseSeq (16)      | packetCount (16)   |
 *    | referenceTime (24)        | fbPktCnt(8)|
 *    | chunk 1 (16) | chunk 2 (16)            |
 *    | ...                                    |
 *    | recv delta 1 (8/16) | recv delta 2 ... |
 *    | ...                                    |
 *    | zero padding to 4-byte boundary        |
 */
function buildTransportCC(opts) {
  var senderSsrc      = opts.senderSsrc >>> 0;
  var mediaSsrc       = opts.mediaSsrc >>> 0;
  var baseSeq         = opts.baseSeq & 0xFFFF;
  var packetCount     = opts.packetCount & 0xFFFF;
  var fbPktCount      = opts.fbPktCount & 0xFF;
  var packets         = opts.packets || [];

  // Reference time is 24-bit signed, in 64ms units. Truncate input ms to
  // the nearest 64ms boundary so the first packet's delta is always ≥0.
  var refUnits = Math.floor(opts.referenceTimeMs / 64);
  // Clamp to 24-bit signed range (-0x800000 .. 0x7FFFFF).
  if (refUnits > 0x7FFFFF)  refUnits = 0x7FFFFF;
  if (refUnits < -0x800000) refUnits = -0x800000;
  var refTime24 = refUnits & 0xFFFFFF;

  // Pass 1: build per-packet symbol array and collect deltas
  //   symbol 0 = not received
  //   symbol 1 = received, small delta (1 byte, 0..63750µs)
  //   symbol 2 = received, large delta (2 bytes, -8192000..+8191750µs)
  //   symbol 3 = received without delta  — we never emit this from here,
  //              since we always compute deltas from timestamps
  var symbols = new Array(packetCount);
  var deltas  = [];   // byte-level encoded recv deltas, appended in order

  for (var i = 0; i < packetCount; i++) {
    var p = packets[i];
    if (!p || !p.received) {
      symbols[i] = 0;
      continue;
    }
    var deltaUs = p.deltaUs | 0;
    // Quantize to 250µs units per draft §3.1.5
    var deltaQ = Math.round(deltaUs / 250);

    if (deltaQ >= 0 && deltaQ <= 0xFF) {
      // Small delta: 1 unsigned byte
      symbols[i] = 1;
      deltas.push({ size: 1, value: deltaQ });
    } else if (deltaQ >= -0x8000 && deltaQ <= 0x7FFF) {
      // Large delta: 2 bytes signed
      symbols[i] = 2;
      deltas.push({ size: 2, value: deltaQ });
    } else {
      // Out of representable range (> ~8s gap). Report as not received —
      // the remote will treat this packet as lost. In practice this
      // only happens if the caller delays building feedback past ~8s,
      // which is already far beyond useful for congestion control.
      symbols[i] = 0;
    }
  }

  // Pass 2: encode symbol array into chunks.
  //
  // Greedy strategy (matches libwebrtc behavior):
  //
  //   1. If the next ≥14 symbols are all identical AND ≤2 (can go in run-length),
  //      emit a run-length chunk covering them all.
  //   2. Else, if the next ≤14 symbols are all ∈ {0, 1} (no large deltas),
  //      emit a 1-bit status-vector chunk (14 packets in 2 bytes).
  //   3. Else, emit a 2-bit status-vector chunk (7 packets in 2 bytes).
  //
  // Each chunk is 2 bytes regardless of how many packets it covers.
  var chunks = [];
  var i2 = 0;
  while (i2 < packetCount) {
    var s = symbols[i2];

    // How many consecutive symbols match s?
    var runEnd = i2 + 1;
    while (runEnd < packetCount && symbols[runEnd] === s) runEnd++;
    var runLen = runEnd - i2;
    if (runLen > 8191) runLen = 8191;   // max 13-bit run length

    // Prefer run-length when worthwhile. Symbol 3 isn't a legal
    // run-length status code, so only run-length for s ≤ 2.
    if (s <= 2 && runLen >= 14) {
      // Run-length chunk: T=0 | S(2) | runLen(13)
      chunks.push(((s & 0x3) << 13) | (runLen & 0x1FFF));
      i2 += runLen;
      continue;
    }

    // Check if the next 14 all fit in a 1-bit status vector (all ∈ {0, 1})
    var look14 = Math.min(14, packetCount - i2);
    var fits1bit = true;
    for (var j = 0; j < look14; j++) {
      if (symbols[i2 + j] > 1) { fits1bit = false; break; }
    }
    if (fits1bit && look14 >= 1) {
      // Status vector T=1, symbolSize=0, 14 one-bit symbols
      var chunk1 = 0x8000;
      for (var j2 = 0; j2 < look14; j2++) {
        if (symbols[i2 + j2] === 1) {
          chunk1 |= (1 << (13 - j2));
        }
      }
      chunks.push(chunk1);
      i2 += look14;
      continue;
    }

    // 2-bit status vector (7 packets)
    var look7 = Math.min(7, packetCount - i2);
    var chunk2 = 0xC000;
    for (var j3 = 0; j3 < look7; j3++) {
      chunk2 |= ((symbols[i2 + j3] & 0x3) << ((6 - j3) * 2));
    }
    chunks.push(chunk2);
    i2 += look7;
  }

  // Compute sizes.
  //
  //   RTCP header       : 4 bytes
  //   sender SSRC       : 4 bytes
  //   media SSRC        : 4 bytes
  //   FCI header        : 8 bytes (baseSeq + packetCount + refTime + fbPktCount)
  //   chunks            : 2 bytes each
  //   recv deltas       : 1 or 2 bytes each
  //   zero padding      : 0..3 bytes to align to 4
  var headerSize  = 12;          // 4 (RTCP header) + 4 (senderSsrc) + 4 (mediaSsrc)
  var fciHeader   = 8;
  var chunksSize  = chunks.length * 2;
  var deltasSize  = 0;
  for (var k = 0; k < deltas.length; k++) deltasSize += deltas[k].size;

  var unpadded   = headerSize + fciHeader + chunksSize + deltasSize;
  var padded     = (unpadded + 3) & ~3;    // round up to 4
  var padBytes   = padded - unpadded;

  var buf = Buffer.alloc(padded);   // alloc (not allocUnsafe) zero-fills padding

  // RTCP common header
  buf[0] = 0x8F;                                       // V=2, P=0, FMT=15
  buf[1] = 205;                                        // RTPFB
  buf.writeUInt16BE((padded / 4) - 1, 2);              // length in 32-bit words, minus 1
  buf.writeUInt32BE(senderSsrc, 4);
  buf.writeUInt32BE(mediaSsrc, 8);

  // FCI header
  buf.writeUInt16BE(baseSeq, 12);
  buf.writeUInt16BE(packetCount, 14);
  buf[16] = (refTime24 >> 16) & 0xFF;
  buf[17] = (refTime24 >> 8)  & 0xFF;
  buf[18] =  refTime24        & 0xFF;
  buf[19] = fbPktCount;

  // Chunks
  var off = 20;
  for (var c = 0; c < chunks.length; c++) {
    buf.writeUInt16BE(chunks[c] & 0xFFFF, off);
    off += 2;
  }

  // Recv deltas
  for (var d = 0; d < deltas.length; d++) {
    var de = deltas[d];
    if (de.size === 1) {
      buf[off] = de.value & 0xFF;
      off += 1;
    } else {
      buf.writeInt16BE(de.value, off);
      off += 2;
    }
  }
  // (Remaining bytes are already zero from Buffer.alloc.)

  return buf;
}

/**
 * Parse an RTCP packet.
 * @param {Buffer} buf
 * @returns {object} — { version, type, length, ssrc, ... }
 */
function parseRTCP(buf) {
  if (!buf || buf.length < 4) return null;
  var b0 = buf[0];
  var version = (b0 >> 6) & 3;
  if (version !== 2) return null;
  var padding = !!((b0 >> 5) & 1);
  var count = b0 & 0x1F;
  var type = buf[1];
  var length = buf.readUInt16BE(2);

  var result = { version: version, padding: padding, type: type, length: length };

  if (type === 200 && buf.length >= 28) {
    result.name = 'SR';
    result.ssrc = buf.readUInt32BE(4);
    result.ntpTimestampMsw = buf.readUInt32BE(8);
    result.ntpTimestampLsw = buf.readUInt32BE(12);
    result.rtpTimestamp = buf.readUInt32BE(16);
    result.packetCount = buf.readUInt32BE(20);
    result.octetCount = buf.readUInt32BE(24);
    // SR may also carry 0+ report blocks, identical to RR format.
    result.reports = [];
    for (var sb = 0; sb < count && 28 + (sb + 1) * 24 <= buf.length; sb++) {
      var soff = 28 + sb * 24;
      result.reports.push({
        mediaSsrc:        buf.readUInt32BE(soff),
        fractionLost:     buf[soff + 4],
        totalLost:        (buf[soff + 5] << 16) | (buf[soff + 6] << 8) | buf[soff + 7],
        highestSeq:       buf.readUInt32BE(soff + 8),
        jitter:           buf.readUInt32BE(soff + 12),
        lastSR:           buf.readUInt32BE(soff + 16),
        delaySinceLastSR: buf.readUInt32BE(soff + 20),
      });
    }
  } else if (type === 206 && count === 1 && buf.length >= 12) {
    result.name = 'PLI';
    result.senderSsrc = buf.readUInt32BE(4);
    result.mediaSsrc = buf.readUInt32BE(8);
  } else if (type === 205 && count === 1 && buf.length >= 16) {
    result.name = 'NACK';
    result.senderSsrc = buf.readUInt32BE(4);
    result.mediaSsrc = buf.readUInt32BE(8);
    result.lostSequenceNumbers = _parseNackEntries(buf, 12);
  } else if (type === 205 && count === 15 && buf.length >= 16) {
    // RTPFB transport-cc feedback (draft-holmer-rmcat-transport-wide-cc-
    // extensions-01). We only record that it IS transport-cc here;
    // detailed parsing of the chunks/deltas lives in rtp-packet's
    // bandwidth.js so callers can opt in (parsing is non-trivial).
    result.name = 'TransportCC';
    result.senderSsrc = buf.readUInt32BE(4);
    result.mediaSsrc  = buf.readUInt32BE(8);
    // Slice out the FCI so the consumer can pass it to parseTransportCC.
    result.fci = buf.subarray(12);
  } else if (type === 206 && count === 15 && buf.length >= 20) {
    // PSFB REMB feedback (draft-alvestrand-rmcat-remb). Identified by
    // the 4-byte "REMB" ASCII tag at offset 12.
    if (buf[12] === 0x52 && buf[13] === 0x45 && buf[14] === 0x4D && buf[15] === 0x42) {
      result.name = 'REMB';
      result.senderSsrc = buf.readUInt32BE(4);
      result.mediaSsrc  = buf.readUInt32BE(8);
      result.fci = buf.subarray(12);
    }
  } else if (type === 206 && count === 4 && buf.length >= 20) {
    result.name = 'FIR';
    result.senderSsrc = buf.readUInt32BE(4);
    result.mediaSsrc = buf.readUInt32BE(12);
    result.seqNr = buf[16];
  } else if (type === 202 && buf.length >= 8) {
    result.name = 'SDES';
    result.ssrc = buf.readUInt32BE(4);
    result.items = [];
    var off = 8;
    while (off + 2 <= buf.length && buf[off] !== 0) {
      var itemType = buf[off];
      var itemLen = buf[off + 1];
      if (off + 2 + itemLen > buf.length) break;
      result.items.push({
        type: itemType,
        value: buf.subarray(off + 2, off + 2 + itemLen).toString('utf8'),
      });
      off += 2 + itemLen;
    }
    if (result.items.length > 0 && result.items[0].type === 1) {
      result.cname = result.items[0].value;
    }
  } else if (type === 203) {
    result.name = 'BYE';
    result.ssrcs = [];
    for (var s = 0; s < count && 4 + (s + 1) * 4 <= buf.length; s++) {
      result.ssrcs.push(buf.readUInt32BE(4 + s * 4));
    }
    var reasonOff = 4 + count * 4;
    if (reasonOff + 1 <= buf.length && buf[reasonOff] > 0) {
      var rLen = buf[reasonOff];
      if (reasonOff + 1 + rLen <= buf.length) {
        result.reason = buf.subarray(reasonOff + 1, reasonOff + 1 + rLen).toString('utf8');
      }
    }
  } else if (type === 201 && buf.length >= 32) {
    result.name = 'RR';
    result.ssrc = buf.readUInt32BE(4);
    result.mediaSsrc = buf.readUInt32BE(8);
    result.fractionLost = buf[12];
    result.totalLost = (buf[13] << 16) | (buf[14] << 8) | buf[15];
    result.highestSeq = buf.readUInt32BE(16);
    result.jitter = buf.readUInt32BE(20);
    result.lastSR = buf.readUInt32BE(24);
    result.delaySinceLastSR = buf.readUInt32BE(28);
    // Also surface all report blocks (spec allows up to 31). Consumers that
    // want to match a specific SSRC can iterate result.reports[]. The first
    // block is also surfaced via the flat fields above for back-compat.
    result.reports = [];
    for (var b = 0; b < count && 8 + (b + 1) * 24 <= buf.length; b++) {
      var off = 8 + b * 24;
      result.reports.push({
        mediaSsrc:        buf.readUInt32BE(off),
        fractionLost:     buf[off + 4],
        totalLost:        (buf[off + 5] << 16) | (buf[off + 6] << 8) | buf[off + 7],
        highestSeq:       buf.readUInt32BE(off + 8),
        jitter:           buf.readUInt32BE(off + 12),
        lastSR:           buf.readUInt32BE(off + 16),
        delaySinceLastSR: buf.readUInt32BE(off + 20),
      });
    }
  }

  return result;
}


/**
 * Parse a compound RTCP packet into an array of sub-packets.
 *
 * RFC 3550 §6.1 — RTCP packets are typically sent as compound packets
 * (e.g. SR+SDES, or RR+SDES+BYE). The transport carries one datagram, but
 * inside there are multiple RTCP "packets" concatenated. Each sub-packet
 * has its own 4-byte header with a `length` field (in 32-bit words, minus 1).
 *
 * Returns an array of parsed packets — call parseRTCP on each slice and
 * advance by (length + 1) * 4 bytes.
 *
 * @param {Buffer} buf — full RTCP datagram (post-decryption)
 * @returns {Array<object>} parsed sub-packets; empty if buf malformed
 */
function parseRTCPCompound(buf) {
  if (!buf || buf.length < 4) return [];
  var out = [];
  var off = 0;
  while (off + 4 <= buf.length) {
    // Each RTCP sub-packet carries a length in 32-bit words, minus 1.
    // Total sub-packet size = (length + 1) * 4 bytes.
    var subLen = (buf.readUInt16BE(off + 2) + 1) * 4;
    if (subLen <= 0 || off + subLen > buf.length) break;
    var sub = buf.subarray(off, off + subLen);
    var parsed = parseRTCP(sub);
    if (parsed) out.push(parsed);
    off += subLen;
  }
  return out;
}

// ── Helpers ──

function _buildNackEntries(seqNums) {
  seqNums = seqNums.slice().sort(function (a, b) { return a - b; });
  var entries = [];
  var i = 0;
  while (i < seqNums.length) {
    var pid = seqNums[i];
    var blp = 0;
    i++;
    while (i < seqNums.length && seqNums[i] - pid <= 16) {
      blp |= (1 << (seqNums[i] - pid - 1));
      i++;
    }
    entries.push({ pid: pid, blp: blp });
  }
  return entries;
}

function _parseNackEntries(buf, off) {
  var lost = [];
  while (off + 4 <= buf.length) {
    var pid = buf.readUInt16BE(off);
    var blp = buf.readUInt16BE(off + 2);
    lost.push(pid);
    for (var bit = 0; bit < 16; bit++) {
      if (blp & (1 << bit)) lost.push(pid + bit + 1);
    }
    off += 4;
  }
  return lost;
}

function _getNtpTimestamp() {
  var now = Date.now();
  var sec = Math.floor(now / 1000) + 2208988800;  // NTP epoch offset
  var frac = ((now % 1000) / 1000 * 0x100000000) >>> 0;
  return [sec, frac];
}


/**
 * sdp — SDP session description generator.
 *
 * Generates SDP for:
 *  - VLC receiver (simple RTP playback)
 *  - WebRTC offer/answer (future)
 */

/**
 * Generate an SDP file for receiving an RTP stream in VLC.
 *
 * @param {object} opts
 * @param {string} [opts.address]     — IP address (default: '127.0.0.1')
 * @param {number} [opts.port]        — RTP port (default: 5004)
 * @param {string} [opts.codec]       — 'h264', 'h265', 'vp8', 'vp9', 'av1',
 *                                       'opus', 'pcmu', 'pcma', 'g722', 'aac',
 *                                       'telephone-event'
 * @param {number} [opts.payloadType] — RTP payload type (default: 96)
 * @param {number} [opts.clockRate]   — clock rate (default: 90000 for video)
 * @param {string} [opts.name]        — session name
 * @param {Buffer} [opts.sps]         — H.264 SPS NAL (for sprop-parameter-sets)
 * @param {Buffer} [opts.pps]         — H.264 PPS NAL (for sprop-parameter-sets)
 * @returns {string} — SDP text
 */
function generateSDP(opts) {
  if (!opts) opts = {};
  var addr = opts.address || '127.0.0.1';
  var port = opts.port || 5004;
  var codec = (opts.codec || 'h264').toLowerCase();
  var pt = opts.payloadType || 96;
  var name = opts.name || 'media-processing RTP stream';

  var lines = [
    'v=0',
    'o=- 0 0 IN IP4 ' + addr,
    's=' + name,
    'c=IN IP4 ' + addr,
    't=0 0',
  ];

  if (codec === 'h264') {
    var clockRate = opts.clockRate || 90000;
    lines.push('m=video ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' H264/' + clockRate);

    var fmtp = 'a=fmtp:' + pt + ' packetization-mode=1';
    if (opts.sps && opts.pps) {
      var spropB64 = opts.sps.toString('base64') + ',' + opts.pps.toString('base64');
      fmtp += '; sprop-parameter-sets=' + spropB64;
    }
    lines.push(fmtp);
  } else if (codec === 'h265' || codec === 'hevc') {
    // RFC 7798 — payload format. Clock rate is 90 kHz like H.264.
    // sprop-vps/sprop-sps/sprop-pps are optional out-of-band parameter
    // set carriage (RFC 7798 §7.1).
    var hevcRate = opts.clockRate || 90000;
    lines.push('m=video ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' H265/' + hevcRate);
    var hevcFmtp = 'a=fmtp:' + pt;
    var hevcParts = [];
    if (opts.vps) hevcParts.push('sprop-vps=' + opts.vps.toString('base64'));
    if (opts.sps) hevcParts.push('sprop-sps=' + opts.sps.toString('base64'));
    if (opts.pps) hevcParts.push('sprop-pps=' + opts.pps.toString('base64'));
    if (hevcParts.length > 0) {
      lines.push(hevcFmtp + ' ' + hevcParts.join('; '));
    }
  } else if (codec === 'vp8') {
    lines.push('m=video ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' VP8/90000');
  } else if (codec === 'vp9') {
    lines.push('m=video ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' VP9/90000');
  } else if (codec === 'opus') {
    var opusRate = opts.clockRate || 48000;
    lines.push('m=audio ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' opus/' + opusRate + '/2');
  } else if (codec === 'av1') {
    lines.push('m=video ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' AV1/90000');
  } else if (codec === 'pcmu') {
    // RFC 3551 §6 — PCMU is static payload type 0, fixed 8 kHz mono.
    // If the caller didn't override payloadType, use the static value.
    var pcmuPt = (opts.payloadType != null) ? opts.payloadType : 0;
    lines.push('m=audio ' + port + ' RTP/AVP ' + pcmuPt);
    lines.push('a=rtpmap:' + pcmuPt + ' PCMU/8000');
  } else if (codec === 'pcma') {
    // RFC 3551 §6 — PCMA is static payload type 8, fixed 8 kHz mono.
    var pcmaPt = (opts.payloadType != null) ? opts.payloadType : 8;
    lines.push('m=audio ' + port + ' RTP/AVP ' + pcmaPt);
    lines.push('a=rtpmap:' + pcmaPt + ' PCMA/8000');
  } else if (codec === 'g722') {
    // RFC 3551 §6 + §4.5.2 — G.722 is static payload type 9.
    // The clock rate in SDP is 8000, NOT 16000, despite G.722 actually
    // sampling at 16 kHz. This is the famous RFC 1890 quirk that
    // RFC 3551 codified for backward compatibility.
    var g722Pt = (opts.payloadType != null) ? opts.payloadType : 9;
    lines.push('m=audio ' + port + ' RTP/AVP ' + g722Pt);
    lines.push('a=rtpmap:' + g722Pt + ' G722/8000');
  } else if (codec === 'aac' || codec === 'mpeg4-generic') {
    // RFC 3640 — AAC-hbr mode. Always uses dynamic PT.
    // The fmtp line carries the AudioSpecificConfig as a hex string in
    // the `config` parameter; the caller supplies it via opts.config.
    // sizeLength=13, indexLength=3, indexDeltaLength=3 are mandatory
    // in AAC-hbr mode (13-bit AU-size, 3-bit AU-Index/Delta).
    var aacRate = opts.clockRate || 48000;
    var aacChannels = opts.channels || 2;
    lines.push('m=audio ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' mpeg4-generic/' + aacRate + '/' + aacChannels);
    var aacFmtp = 'a=fmtp:' + pt +
      ' streamtype=5; profile-level-id=' + (opts.profileLevelId || 1) +
      '; mode=AAC-hbr; sizeLength=13; indexLength=3; indexDeltaLength=3';
    if (opts.config) {
      // AudioSpecificConfig as a hex string (typically 2-4 bytes).
      aacFmtp += '; config=' + opts.config;
    }
    if (opts.constantDuration) {
      aacFmtp += '; constantDuration=' + opts.constantDuration;
    }
    lines.push(aacFmtp);
  } else if (codec === 'telephone-event' || codec === 'dtmf') {
    // RFC 4733 — named telephony events (DTMF). Always a dynamic
    // payload type. Clock rate matches the audio stream it's
    // multiplexed with — 8 kHz for telephony, but Chrome/Firefox
    // commonly negotiate 48 kHz alongside Opus.
    var teRate = opts.clockRate || 8000;
    lines.push('m=audio ' + port + ' RTP/AVP ' + pt);
    lines.push('a=rtpmap:' + pt + ' telephone-event/' + teRate);
    // fmtp gives the supported event range. 0-15 covers DTMF (0-9, *, #, A-D).
    var teEvents = opts.events || '0-15';
    lines.push('a=fmtp:' + pt + ' ' + teEvents);
  }

  lines.push('');
  return lines.join('\r\n');
}

/**
 * Build SDES (Source Description) — carries CNAME for source identification.
 * CNAME is mandatory in every RTCP compound packet (RFC 3550 §6.5).
 * @param {number} ssrc — source SSRC
 * @param {string} cname — canonical name (e.g., 'user@host' or random UUID)
 * @returns {Buffer}
 */
function buildSDES(ssrc, cname) {
  var cnameBytes = Buffer.from(cname, 'utf8');
  // Item: type=1 (CNAME), length, value
  var itemLen = 2 + cnameBytes.length;
  // Chunk = SSRC(4) + item + null terminator, padded to 4-byte boundary
  var chunkLen = 4 + itemLen + 1;  // +1 for null terminator
  var paddedChunkLen = (chunkLen + 3) & ~3;

  var buf = Buffer.alloc(4 + paddedChunkLen);
  buf[0] = 0x81;  // V=2, P=0, SC=1
  buf[1] = 202;   // SDES
  buf.writeUInt16BE((paddedChunkLen >> 2), 2);  // length in 32-bit words
  buf.writeUInt32BE(ssrc >>> 0, 4);
  buf[8] = 1;  // CNAME type
  buf[9] = cnameBytes.length;
  cnameBytes.copy(buf, 10);
  // Remaining bytes are already 0 (null terminator + padding)
  return buf;
}

/**
 * Build BYE — notify session end.
 * @param {number[]} ssrcs — SSRCs leaving the session
 * @param {string} [reason] — optional reason string
 * @returns {Buffer}
 */
function buildBYE(ssrcs, reason) {
  var reasonBytes = reason ? Buffer.from(reason, 'utf8') : null;
  var reasonLen = reasonBytes ? 1 + reasonBytes.length : 0;  // length byte + string
  var paddedReasonLen = reasonBytes ? ((reasonLen + 3) & ~3) : 0;
  var totalLen = 4 + ssrcs.length * 4 + paddedReasonLen;

  var buf = Buffer.alloc(totalLen);
  buf[0] = 0x80 | (ssrcs.length & 0x1F);  // V=2, P=0, SC=count
  buf[1] = 203;  // BYE
  buf.writeUInt16BE((totalLen >> 2) - 1, 2);  // length in words minus 1

  for (var i = 0; i < ssrcs.length; i++) {
    buf.writeUInt32BE(ssrcs[i] >>> 0, 4 + i * 4);
  }

  if (reasonBytes) {
    var off = 4 + ssrcs.length * 4;
    buf[off] = reasonBytes.length;
    reasonBytes.copy(buf, off + 1);
  }

  return buf;
}

/**
 * Build compound RTCP packet — SR/RR + SDES bundled together.
 * RFC 3550 requires every RTCP packet to be compound: at least SR/RR + SDES.
 * @param {Buffer[]} packets — array of individual RTCP packets
 * @returns {Buffer} — concatenated compound packet
 */
function buildCompound(packets) {
  return Buffer.concat(packets);
}


// NOTE: RTX (RFC 4588) build/parse used to live here but was buggy —
// it ignored CSRC lists and header extensions, copying only the fixed
// 12-byte RTP header. WebRTC packets carry RFC 5285 extensions
// (transport-cc, abs-send-time, mid…) so that implementation produced
// corrupt RTX packets. The correct implementation, which preserves
// the full original header (CSRCs + extension block), lives in
// retransmit.js as buildRtxPacket / parseRtxPacket.

export { buildSR, buildPLI, buildNACK, buildFIR, buildRR, buildREMB, buildTransportCC, buildSDES, buildBYE, buildCompound, parseRTCP, parseRTCPCompound, generateSDP };
