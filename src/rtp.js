/**
 * rtp — RTP header parse/serialize, header extensions, packetizer base.
 *
 * RTP Header (RFC 3550):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       Sequence Number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Synchronization Source (SSRC)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

var RTP_VERSION = 2;
var RTP_HEADER_SIZE = 12;
var DEFAULT_MTU = 1400;
var PROFILE_ONE_BYTE = 0xBEDE;
var EMPTY_BUF = Buffer.alloc(0);

// ═══════════════════════════════════════════════════════════════════
//  Internal helper — Uint8Array → Buffer normalization
// ═══════════════════════════════════════════════════════════════════

/**
 * Normalize a Buffer-like input to a Buffer.
 *
 * Accepts:
 *   - Buffer        → returned as-is (no allocation)
 *   - Uint8Array    → wrapped as a Buffer view over the SAME underlying
 *                     memory (zero-copy; just a few bytes for the
 *                     Buffer object itself)
 *   - anything else → returned as-is (caller is expected to have
 *                     validated; this helper does not type-check)
 *
 * The motivation: this library is WebCodecs-shaped, and WebCodecs APIs
 * (EncodedVideoChunk.copyTo, etc.) hand back Uint8Array — not Buffer.
 * Forcing the caller to do `Buffer.from(uint8)` at every boundary is
 * unidiomatic and creates friction with crypto.subtle, fetch bodies,
 * WASM modules, and browser-style code paths.
 *
 * Buffer.from(view.buffer, view.byteOffset, view.byteLength) is the
 * documented zero-copy idiom — it shares the underlying ArrayBuffer
 * rather than copying. Verified safe with Node ≥ 4.5.
 */
function _toBuffer(b) {
  if (b == null) return b;
  if (Buffer.isBuffer(b)) return b;
  if (b instanceof Uint8Array) {
    return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  }
  return b;   // not Buffer-like; let downstream raise (e.g. .copy is undefined)
}

// ═══════════════════════════════════════════════════════════════════
//  RTP Header serialize / parse
// ═══════════════════════════════════════════════════════════════════

/**
 * Serialize an RTP packet object to a Buffer ready to send on the wire.
 *
 * Round-tripping `parse()` output: pass the parsed `extensions` map
 * back through `pkt.extensions` to preserve the extension block. The
 * legacy `pkt.extension` boolean is intentionally ignored — setting
 * X=1 in the header without actually emitting an extension block (as
 * the previous code did) produces a packet whose receiver mis-reads
 * payload bytes as the extension header. Use `pkt.extensions` to emit
 * extensions, or call setHeaderExtension() to add them post-hoc.
 *
 * @param {object} pkt
 * @param {number} pkt.payloadType     0-127
 * @param {number} pkt.sequenceNumber  0-65535 (wraps)
 * @param {number} pkt.timestamp       32-bit RTP timestamp (wraps)
 * @param {number} pkt.ssrc            32-bit source identifier
 * @param {boolean} [pkt.marker]       marker bit (codec-specific meaning)
 * @param {boolean} [pkt.padding]      padding bit
 * @param {object}  [pkt.extensions]   { id: Buffer } map (RFC 5285 one-byte)
 * @param {number[]} [pkt.csrc]        contributing sources
 * @param {Buffer}  [pkt.payload]      codec-specific payload
 * @returns {Buffer}
 */
function serialize(pkt) {
  var payload = _toBuffer(pkt.payload) || EMPTY_BUF;
  var csrcCount = (pkt.csrc && pkt.csrc.length) || 0;

  // Encode extensions block if a non-empty `extensions` map is supplied.
  // We deliberately do NOT honor a bare `pkt.extension: true` flag —
  // see the docstring above for why.
  var extBlock = null;
  if (pkt.extensions && typeof pkt.extensions === 'object') {
    var hasAny = false;
    for (var _k in pkt.extensions) {
      if (Object.prototype.hasOwnProperty.call(pkt.extensions, _k)) {
        hasAny = true; break;
      }
    }
    if (hasAny) extBlock = writeExtensions(pkt.extensions);
  }
  var extLen = extBlock ? extBlock.length : 0;

  var fixedAndCsrcLen = RTP_HEADER_SIZE + (csrcCount * 4);
  var headerLen = fixedAndCsrcLen + extLen;
  var buf = Buffer.allocUnsafe(headerLen + payload.length);

  buf[0] = (RTP_VERSION << 6) |
           ((pkt.padding ? 1 : 0) << 5) |
           (extBlock ? 0x10 : 0) |          // X bit derived from extensions presence
           (csrcCount & 0x0F);
  buf[1] = ((pkt.marker ? 1 : 0) << 7) | (pkt.payloadType & 0x7F);
  buf.writeUInt16BE(pkt.sequenceNumber & 0xFFFF, 2);
  buf.writeUInt32BE(pkt.timestamp >>> 0, 4);
  buf.writeUInt32BE(pkt.ssrc >>> 0, 8);

  for (var i = 0; i < csrcCount; i++) {
    buf.writeUInt32BE(pkt.csrc[i] >>> 0, 12 + i * 4);
  }
  if (extBlock) extBlock.copy(buf, fixedAndCsrcLen);
  payload.copy(buf, headerLen);
  return buf;
}

/**
 * Parse a received buffer into an RTP packet object. Returns null if the
 * buffer is not a valid RTP packet.
 *
 * @param {Buffer} buf
 * @returns {object|null} { version, padding, extension, csrcCount, marker,
 *   payloadType, sequenceNumber, timestamp, ssrc, csrc, payload, headerLength,
 *   extensions }
 *
 * `extensions` is a map { id: Buffer } of one-byte RFC 5285 extensions
 * parsed from the extension block, or null if no extension block is present.
 */
function parse(buf) {
  if (!buf || buf.length < RTP_HEADER_SIZE) return null;
  var b0 = buf[0], b1 = buf[1];
  var version = (b0 >> 6) & 0x03;
  if (version !== RTP_VERSION) return null;

  var padding = !!((b0 >> 5) & 1);
  var extension = !!((b0 >> 4) & 1);
  var csrcCount = b0 & 0x0F;
  var marker = !!((b1 >> 7) & 1);
  var payloadType = b1 & 0x7F;
  var sequenceNumber = buf.readUInt16BE(2);
  var timestamp = buf.readUInt32BE(4);
  var ssrc = buf.readUInt32BE(8);

  var headerLen = RTP_HEADER_SIZE + (csrcCount * 4);
  if (buf.length < headerLen) return null;

  var csrc = [];
  for (var i = 0; i < csrcCount; i++) csrc.push(buf.readUInt32BE(12 + i * 4));

  var extensions = null;
  if (extension && buf.length >= headerLen + 4) {
    // Extension header layout (RFC 3550 §5.3.1):
    //   profile (2 bytes) | length in 32-bit words (2 bytes) | data
    // Profile 0xBEDE identifies one-byte-header RFC 5285 extensions,
    // which is what WebRTC uses for abs-send-time / transport-cc / mid.
    var profile = buf.readUInt16BE(headerLen);
    var extLen  = buf.readUInt16BE(headerLen + 2) * 4;
    var extDataStart = headerLen + 4;
    var extDataEnd   = extDataStart + extLen;
    if (profile === 0xBEDE && extDataEnd <= buf.length) {
      extensions = parseExtensions(buf.subarray(extDataStart, extDataEnd));
    }
    headerLen = extDataEnd;
  }

  var payloadEnd = buf.length;
  if (padding && buf.length > headerLen) payloadEnd -= buf[buf.length - 1];

  return {
    version: version, padding: padding, extension: extension,
    csrcCount: csrcCount, marker: marker, payloadType: payloadType,
    sequenceNumber: sequenceNumber, timestamp: timestamp,
    ssrc: ssrc, csrc: csrc,
    payload: buf.subarray(headerLen, payloadEnd),
    headerLength: headerLen,
    extensions: extensions,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  Packetizer base — shared by all codec packetizers
// ═══════════════════════════════════════════════════════════════════

/**
 * Initialize shared packetizer state. Validates required options and
 * throws with a clear message if anything essential is missing.
 *
 * REQUIRED options:
 *   ssrc          — 32-bit number. Must be unique per RTP stream.
 *   payloadType   — 0-127. Must match the one in the SDP.
 *
 * OPTIONAL options:
 *   mtu                     — default 1400
 *   initialSequenceNumber   — default random 0-65535
 */
function initPacketizer(self, opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError(self.constructor.name + ': options object is required');
  }
  if (typeof opts.ssrc !== 'number' || !Number.isFinite(opts.ssrc)) {
    throw new TypeError(self.constructor.name + ': opts.ssrc is required (32-bit number)');
  }
  if (typeof opts.payloadType !== 'number' || opts.payloadType < 0 || opts.payloadType > 127) {
    throw new TypeError(self.constructor.name + ': opts.payloadType is required (0-127)');
  }

  // mtu validation — reject NaN, strings, absurd values
  if (opts.mtu !== undefined) {
    if (typeof opts.mtu !== 'number' || opts.mtu < 100 || opts.mtu > 65535) {
      throw new TypeError(self.constructor.name + ': opts.mtu must be between 100 and 65535');
    }
    self.mtu = opts.mtu | 0;
  } else {
    self.mtu = DEFAULT_MTU;
  }

  self.ssrc = opts.ssrc >>> 0;
  self.payloadType = opts.payloadType & 0x7F;
  self._seq = (typeof opts.initialSequenceNumber === 'number')
    ? (opts.initialSequenceNumber & 0xFFFF)
    : Math.floor(Math.random() * 0x10000);   // full 0-65535 range
}

/**
 * Build a single RTP packet with the next sequence number.
 * Allocates exactly ONE Buffer (the packet itself) — no intermediate objects.
 * Optional `withMeta` returns a descriptor for RTX caching.
 *
 * If you need RTP header extensions (abs-send-time, transport-cc, etc.),
 * use the public `serialize()` function directly — it supports the full
 * RTP header including CSRC, padding, and extension blocks.
 */
function makePacket(self, payload, rtpTimestamp, marker, withMeta) {
  var seq = self._seq;
  var payloadLen = payload ? payload.length : 0;
  var buf = Buffer.allocUnsafe(RTP_HEADER_SIZE + payloadLen);

  // RTP header — inline, no temp object allocation
  buf[0] = (RTP_VERSION << 6);                                  // V=2, P=0, X=0, CC=0
  buf[1] = (marker ? 0x80 : 0) | (self.payloadType & 0x7F);
  buf[2] = (seq >> 8) & 0xFF;
  buf[3] = seq & 0xFF;
  buf[4] = (rtpTimestamp >>> 24) & 0xFF;
  buf[5] = (rtpTimestamp >>> 16) & 0xFF;
  buf[6] = (rtpTimestamp >>> 8) & 0xFF;
  buf[7] = rtpTimestamp & 0xFF;
  buf[8] = (self.ssrc >>> 24) & 0xFF;
  buf[9] = (self.ssrc >>> 16) & 0xFF;
  buf[10] = (self.ssrc >>> 8) & 0xFF;
  buf[11] = self.ssrc & 0xFF;

  if (payloadLen > 0) payload.copy(buf, RTP_HEADER_SIZE);

  self._seq = (self._seq + 1) & 0xFFFF;

  if (withMeta) {
    return { buffer: buf, sequenceNumber: seq, timestamp: rtpTimestamp, marker: !!marker };
  }
  return buf;
}

/**
 * Build a single RTP packet whose payload is `prefix` followed by a
 * slice of `data`, in a single Buffer allocation.
 *
 * This is the codec-packetizer hot path. The naive shape —
 *
 *     var payload = allocUnsafe(prefixLen + dataLen);
 *     ...write prefix bytes into payload...
 *     data.copy(payload, prefixLen, dataStart, dataStart + dataLen);
 *     return makePacket(self, payload, ...);   // allocates AGAIN, copies AGAIN
 *
 * does two allocations and two copies of the bitstream data per packet.
 * For 30 fps video at high bitrate that's tens of megabytes per second
 * of avoidable allocator pressure. This helper folds the codec
 * descriptor and the bitstream slice into the final packet buffer in
 * one shot.
 *
 * The prefix is supplied as up to 4 inline bytes (covers all current
 * codecs: VP8 = 1, VP9 = 1, AV1 = 1, H.264 single-NAL = 0, H.264 FU-A
 * = 2). Larger prefixes degrade gracefully into the prefixBuf path.
 *
 * @param {object} self            packetizer (uses ssrc, payloadType, _seq)
 * @param {number} p0              prefix byte 0 (0 if prefixLen === 0)
 * @param {number} p1              prefix byte 1
 * @param {number} p2              prefix byte 2
 * @param {number} p3              prefix byte 3
 * @param {number} prefixLen       0..4 — number of inline prefix bytes
 * @param {Buffer} data            bitstream Buffer (already normalized)
 * @param {number} dataStart       start offset within data
 * @param {number} dataLen         bytes to take from data
 * @param {number} rtpTimestamp    RTP timestamp (codec ticks, not µs)
 * @param {boolean} marker         marker bit
 * @param {boolean} withMeta       if true, return descriptor object instead
 * @returns {Buffer | {buffer, sequenceNumber, timestamp, marker}}
 */
function makePacketWithPrefix(
  self, p0, p1, p2, p3, prefixLen, data, dataStart, dataLen,
  rtpTimestamp, marker, withMeta
) {
  var seq = self._seq;
  var totalLen = RTP_HEADER_SIZE + prefixLen + dataLen;
  var buf = Buffer.allocUnsafe(totalLen);

  // RTP header — same byte layout as makePacket(). Inline so V8 can
  // monomorphize / SROA without going through a helper.
  buf[0] = (RTP_VERSION << 6);                                  // V=2, P=0, X=0, CC=0
  buf[1] = (marker ? 0x80 : 0) | (self.payloadType & 0x7F);
  buf[2] = (seq >> 8) & 0xFF;
  buf[3] = seq & 0xFF;
  buf[4] = (rtpTimestamp >>> 24) & 0xFF;
  buf[5] = (rtpTimestamp >>> 16) & 0xFF;
  buf[6] = (rtpTimestamp >>> 8) & 0xFF;
  buf[7] = rtpTimestamp & 0xFF;
  buf[8] = (self.ssrc >>> 24) & 0xFF;
  buf[9] = (self.ssrc >>> 16) & 0xFF;
  buf[10] = (self.ssrc >>> 8) & 0xFF;
  buf[11] = self.ssrc & 0xFF;

  // Codec descriptor — up to 4 bytes. Branchless on the common
  // prefixLen=1 case (VP8/VP9/AV1).
  if (prefixLen > 0) {
    buf[12] = p0 & 0xFF;
    if (prefixLen > 1) {
      buf[13] = p1 & 0xFF;
      if (prefixLen > 2) {
        buf[14] = p2 & 0xFF;
        if (prefixLen > 3) buf[15] = p3 & 0xFF;
      }
    }
  }

  // Bitstream payload — single copy directly into the final buffer.
  if (dataLen > 0) {
    data.copy(buf, RTP_HEADER_SIZE + prefixLen, dataStart, dataStart + dataLen);
  }

  self._seq = (self._seq + 1) & 0xFFFF;

  if (withMeta) {
    return { buffer: buf, sequenceNumber: seq, timestamp: rtpTimestamp, marker: !!marker };
  }
  return buf;
}


/**
 * Validate a chunk object passed to packetize(). Throws if invalid.
 * Accepts both `data` (Buffer/Uint8Array) and optionally `nalus`
 * (Buffer/Uint8Array[], H.264 only).
 *
 * Pure validation — does NOT mutate the chunk. WebCodecs-style chunks
 * (EncodedVideoChunk, EncodedAudioChunk) are spec'd as immutable
 * objects, and many implementations freeze them or expose `.data` as a
 * non-writable property. Earlier versions of this function tried to
 * normalize Uint8Array → Buffer in-place via `chunk.data = ...`, which
 * threw a TypeError on frozen chunks.
 *
 * Normalization now lives in the codec packetizers — they call
 * `_toBuffer(chunk.data)` once into a local variable. This keeps the
 * Uint8Array compat without ever mutating the caller's chunk.
 */
function validateChunk(self, chunk) {
  if (!chunk || typeof chunk !== 'object') {
    throw new TypeError(self.constructor.name + '.packetize: chunk object is required');
  }
  if (typeof chunk.timestamp !== 'number' || !Number.isFinite(chunk.timestamp)) {
    throw new TypeError(self.constructor.name + '.packetize: chunk.timestamp must be a finite number (microseconds)');
  }
  if (!chunk.data && !chunk.nalus) {
    throw new TypeError(self.constructor.name + '.packetize: chunk.data (Buffer) is required');
  }
  if (chunk.data) {
    if (!Buffer.isBuffer(chunk.data) && !(chunk.data instanceof Uint8Array)) {
      throw new TypeError(self.constructor.name + '.packetize: chunk.data must be a Buffer or Uint8Array');
    }
  }
  if (chunk.nalus) {
    if (!Array.isArray(chunk.nalus)) {
      throw new TypeError(self.constructor.name + '.packetize: chunk.nalus must be an array of Buffers/Uint8Arrays');
    }
    for (var i = 0; i < chunk.nalus.length; i++) {
      var n = chunk.nalus[i];
      if (!Buffer.isBuffer(n) && !(n instanceof Uint8Array)) {
        throw new TypeError(self.constructor.name + '.packetize: chunk.nalus[' + i + '] must be a Buffer or Uint8Array');
      }
    }
  }
}

/**
 * Convert microseconds to a codec's RTP clock ticks.
 */
function usToRtp(us, clockRate) {
  return ((us * clockRate / 1000000) >>> 0);
}

// ═══════════════════════════════════════════════════════════════════
//  Depacketizer base — shared validation for constructor options
// ═══════════════════════════════════════════════════════════════════

/**
 * Validate depacketizer options. `output` is required; `error` is optional.
 */
function initDepacketizer(self, opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError(self.constructor.name + ': options object is required');
  }
  if (typeof opts.output !== 'function') {
    throw new TypeError(self.constructor.name + ': opts.output callback is required');
  }
  self._output = opts.output;
  self._error = (typeof opts.error === 'function') ? opts.error : null;
}

/**
 * Emit an error to the depacketizer's error callback (if provided).
 * If no callback is registered, the error is silently dropped — matching
 * WebCodecs behavior (errors without a handler are not crashes).
 * If the handler itself throws, we surface that to stderr so developers
 * can debug callback bugs, but we don't propagate (callers shouldn't crash).
 */
function emitError(self, err) {
  if (!self._error) return;
  try {
    self._error(err);
  } catch (callbackErr) {
    if (typeof console !== 'undefined' && console.error) {
      console.error('rtp-packet: error callback threw:', callbackErr);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
//  Header Extensions (RFC 5285)
// ═══════════════════════════════════════════════════════════════════

function parseExtensions(extData) {
  var exts = {};
  var i = 0;
  while (i < extData.length) {
    var b = extData[i];
    if (b === 0) { i++; continue; }
    var id = (b >> 4) & 0x0F;
    var len = (b & 0x0F) + 1;
    i++;
    if (id === 15) break;
    if (i + len > extData.length) break;
    exts[id] = extData.subarray(i, i + len);
    i += len;
  }
  return exts;
}

function writeExtensions(exts) {
  var keys = Object.keys(exts);
  var n = keys.length;

  // Pre-parse IDs once (Object.keys returns strings; we want numbers).
  // Also normalize Uint8Array → Buffer at this boundary so the .copy()
  // call below works regardless of which the caller passed.
  var ids = new Array(n);
  var datas = new Array(n);
  var dataSize = 0;
  for (var k = 0; k < n; k++) {
    ids[k] = parseInt(keys[k], 10);
    datas[k] = _toBuffer(exts[keys[k]]);
    // Per RFC 5285 one-byte form: data length is encoded as L (4 bits),
    // where actual_length = L + 1. Valid range is therefore 1..16 bytes.
    // Out-of-range values produce silently-malformed output: length 0
    // wraps to L=15 ("16 bytes" in the header but 0 written), and any
    // length > 16 truncates the L field, mis-claiming the extension's
    // size. setHeaderExtension validates its `data` argument, but
    // direct callers of writeExtensions don't get that protection — so
    // we throw here rather than emit corrupt bytes.
    if (!datas[k] || datas[k].length < 1 || datas[k].length > 16) {
      throw new RangeError('writeExtensions: extension id ' + ids[k] +
        ' data length ' + (datas[k] ? datas[k].length : 'null') +
        ' out of range [1, 16]');
    }
    dataSize += 1 + datas[k].length;
  }
  var paddedSize = (dataSize + 3) & ~3;

  var buf = Buffer.allocUnsafe(4 + paddedSize);
  buf.writeUInt16BE(PROFILE_ONE_BYTE, 0);
  buf.writeUInt16BE(paddedSize >> 2, 2);

  var off = 4;
  for (var j = 0; j < n; j++) {
    var data = datas[j];
    buf[off++] = ((ids[j] & 0x0F) << 4) | ((data.length - 1) & 0x0F);
    data.copy(buf, off);
    off += data.length;
  }
  while (off < buf.length) buf[off++] = 0;
  return buf;
}

// abs-send-time RTP header extension (webrtc-experiments).
//
// Wire format per the spec (webrtc.org/experiments/rtp-hdrext/abs-send-time):
//   24-bit unsigned, 6.18 fixed-point seconds — i.e., 18 fractional bits,
//   yielding 64-second wraparound and ~3.8µs resolution.
//
// The spec also gives the relation `abs_send_time_24 = (ntp64 >> 14) &
// 0x00ffffff` — the "14" there is shifting an NTP-64 timestamp (which
// has 32 fractional bits) down to 18 fractional bits, NOT a fractional-
// bit count. Earlier versions of this code used `1 << 14` here, which
// emits values 16x too small and breaks REMB-based BWE interop with
// Chrome (deltas appear to advance 16x slower than wall clock).
function absSendTime() {
  var sec = (Date.now() / 1000) + 2208988800;
  var fixed = ((sec * (1 << 18)) >>> 0) & 0x00FFFFFF;
  var buf = Buffer.allocUnsafe(3);
  buf[0] = (fixed >> 16) & 0xFF;
  buf[1] = (fixed >> 8) & 0xFF;
  buf[2] = fixed & 0xFF;
  return buf;
}

function transportCC(seq) {
  var buf = Buffer.allocUnsafe(2);
  buf.writeUInt16BE(seq & 0xFFFF, 0);
  return buf;
}

function audioLevel(level, voice) {
  return Buffer.from([(voice ? 0x80 : 0) | (level & 0x7F)]);
}

/**
 * Parse an audio-level RTP header extension payload (RFC 6464).
 *
 * Format (1 byte):
 *   bit 7   — V flag: 1 = voice activity, 0 = no voice
 *   bits 6-0 — audio level in -dBov (0 = loudest, 127 = silent)
 *
 * Inverse of audioLevel(). Used by receivers (e.g. SFUs detecting
 * active speakers, WebRTC stats consumers populating
 * RTCRtpReceiver.getSynchronizationSources().audioLevel) to read the
 * header extension stamped by the sender.
 *
 * Returns `null` if data is missing or empty — match the convention
 * used by parse() for missing/malformed input rather than throwing.
 *
 * @param {Buffer|Uint8Array} data — extension payload, exactly 1 byte
 * @returns {{level:number, voice:boolean}|null}
 */
function readAudioLevel(data) {
  if (!data || data.length < 1) return null;
  return {
    level: data[0] & 0x7F,
    voice: !!(data[0] & 0x80),
  };
}

// Inverse of absSendTime — see that function's header for the 6.18
// fixed-point format. Divisor must match the encoder side (was `1 << 14`
// before the spec-compliance fix).
function readAbsSendTime(data) {
  if (!data || data.length < 3) return 0;
  return ((data[0] << 16) | (data[1] << 8) | data[2]) / (1 << 18);
}


/**
 * Set (add or replace) a one-byte RTP header extension on an existing
 * packet, in-place semantically but returns a new Buffer. This is the
 * helper senders use when they need to stamp absolute-send-time or
 * transport-wide sequence numbers onto packets after the packetizer
 * has already built them.
 *
 * If the packet already has the RFC 5285 one-byte extension block, the
 * given extension ID is added or overwritten inside it. If the packet
 * has no extension block at all, a new one is created. Non-one-byte
 * extension profiles (e.g. two-byte form) are not handled — packet is
 * returned unchanged in that case.
 *
 * @param {Buffer} rtpPacket — existing serialized RTP packet
 * @param {number} id        — extension ID (1-14)
 * @param {Buffer} data      — extension payload, 1-16 bytes
 * @returns {Buffer} new packet with the extension applied
 */
function setHeaderExtension(rtpPacket, id, data) {
  rtpPacket = _toBuffer(rtpPacket);
  data = _toBuffer(data);
  if (!rtpPacket || rtpPacket.length < RTP_HEADER_SIZE) return rtpPacket;
  if (id < 1 || id > 14) return rtpPacket;
  if (!data || data.length < 1 || data.length > 16) return rtpPacket;

  var cc = rtpPacket[0] & 0x0F;
  var hasExt = !!(rtpPacket[0] & 0x10);
  var fixedHeaderEnd = RTP_HEADER_SIZE + cc * 4;    // end of CSRC list

  var existingExts = {};
  var extBlockLen = 0;
  var extProfile = PROFILE_ONE_BYTE;

  if (hasExt) {
    if (rtpPacket.length < fixedHeaderEnd + 4) return rtpPacket;
    extProfile = rtpPacket.readUInt16BE(fixedHeaderEnd);
    if (extProfile !== PROFILE_ONE_BYTE) return rtpPacket;   // two-byte form: skip
    var extDataWords = rtpPacket.readUInt16BE(fixedHeaderEnd + 2);
    extBlockLen = 4 + extDataWords * 4;
    if (rtpPacket.length < fixedHeaderEnd + extBlockLen) return rtpPacket;
    // Parse existing one-byte extensions into an id→data map.
    existingExts = parseExtensions(
      rtpPacket.subarray(fixedHeaderEnd + 4, fixedHeaderEnd + extBlockLen)
    );
  }

  // Add/overwrite our extension.
  existingExts[id] = data;

  var newExtBlock = writeExtensions(existingExts);
  var payload = rtpPacket.subarray(fixedHeaderEnd + extBlockLen);

  var out = Buffer.allocUnsafe(fixedHeaderEnd + newExtBlock.length + payload.length);
  rtpPacket.copy(out, 0, 0, fixedHeaderEnd);    // V, flags, CC, seq, ts, SSRC, CSRCs
  out[0] = out[0] | 0x10;                       // force X=1
  newExtBlock.copy(out, fixedHeaderEnd);
  payload.copy(out, fixedHeaderEnd + newExtBlock.length);
  return out;
}

export {
  serialize, parse, RTP_HEADER_SIZE, RTP_VERSION, DEFAULT_MTU,
  initPacketizer, makePacket, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError,
  parseExtensions, writeExtensions, setHeaderExtension, PROFILE_ONE_BYTE,
  absSendTime, transportCC, audioLevel, readAbsSendTime, readAudioLevel,
  _toBuffer,
};
