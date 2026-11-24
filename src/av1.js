/**
 * av1 — AV1 RTP packetizer + depacketizer (RFC 9798).
 *
 *   chunk {data, timestamp, type}  →  AV1Packetizer   →  Buffer[]
 *   RTP packet                      →  AV1Depacketizer →  chunk via output()
 */

import {
  initPacketizer, makePacketWithPrefix, validateChunk, usToRtp,
  initDepacketizer, emitError, checkDepacketizePayload, _toBuffer,
} from './rtp.js';

var CLOCK_RATE = 90000;

// ═══════════════════════════════════════════════════════════════════
//  Packetizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AV1Packetizer — fragments an AV1 encoded frame into RTP packets.
 *
 * @param {object}  opts
 * @param {number}  opts.ssrc                     required, 32-bit
 * @param {number}  opts.payloadType              required, 0-127
 * @param {number} [opts.mtu]                     default 1400
 * @param {number} [opts.initialSequenceNumber]   default random
 */
function AV1Packetizer(opts) {
  initPacketizer(this, opts);
}

/**
 * @param {object} chunk
 * @param {Buffer} chunk.data       AV1 OBUs
 * @param {number} chunk.timestamp  microseconds
 * @param {string} [chunk.type]     'key' | 'delta' — used to set N flag on keyframes
 * @returns {Buffer[]}
 */
AV1Packetizer.prototype.packetize = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, false);
};

/** @returns {Array<{buffer, sequenceNumber, timestamp, marker}>} */
AV1Packetizer.prototype.packetizeWithMeta = function (chunk) {
  validateChunk(this, chunk);
  return _packetize(this, chunk, true);
};

AV1Packetizer.prototype.close = function () {};


function _packetize(self, chunk, withMeta) {
  var data = _toBuffer(chunk.data);
  var rtpTs = usToRtp(chunk.timestamp, CLOCK_RATE);
  var isKey = (chunk.type === 'key');
  var maxPayload = self.mtu - 1;   // -1 for the 1-byte AV1 aggregation header

  // The chunk is a temporal unit in the Low Overhead Bitstream Format: OBUs
  // one after another, each with its obu_size. RFC 9798 sends them as OBU
  // ELEMENTS — one per OBU, obu_has_size_field cleared (§4.4: the element
  // carries the length), the temporal delimiter dropped (§5), as tile lists
  // and padding are (libwebrtc's RtpPacketizerAv1::ParseObus drops the same
  // three).
  //
  // The whole chunk used to go out as ONE element (W=1), size fields and
  // temporal delimiter included. A receiver reads an element as one OBU:
  // libwebrtc saw a temporal delimiter (0x12), dropped it — and with it the
  // sequence header and the frame behind it. Chrome received every packet
  // and decoded nothing (framesDecoded 0, not even a codec assigned). Our own
  // depacketizer took the element apart again by the size fields, which is
  // why a round trip through rtp-packet never showed it.
  var obus = _splitObus(data);
  if (obus === null) {
    throw new Error('AV1Packetizer: malformed OBU sequence in chunk.data');
  }
  if (obus.length === 0) return [];        // nothing but temporal delimiters / padding

  // Aggregation header (§4.4): Z (0x80) the first element continues an OBU
  // from the previous packet; Y (0x40) the last one goes on in the next;
  // W (0x30) the element count when 1..3 — the last element then has no
  // length in front — or 0, every element with its leb128 length; N (0x08)
  // the first packet of a coded video sequence: a keyframe that carries a
  // sequence header, first (libwebrtc checks the same: an encoder may make a
  // key frame without one).
  //
  // Filling: each packet takes whole elements, every one sized as if it
  // carried a length (W=0); a packet that ends up with 1..3 elements drops
  // the last one's length when written, so the estimate is never short. An
  // element that does not fit is split: the part that fits ends the packet
  // (Y), the rest opens the next (Z).
  var packets = [];        // [{els: [{obu, off, len}], z, y}]
  var cur = { els: [], size: 0, z: false, y: false };
  for (var i = 0; i < obus.length; i++) {
    var obu = obus[i];
    var off = 0;
    while (off < obu.length) {
      var rest = obu.length - off;
      var room = maxPayload - cur.size;
      // Whole (rest of the) OBU if it fits, else the largest fragment that
      // does: len bytes cost leb128(len) + len.
      // A packet with no room for a length and one byte is full. (Filled
      // exactly, it left room 0, and len came out -1: an element of length
      // -1 went in — subarray(0, -1), leb128(-1) written as 0xFF — the packet
      // went past the MTU, and the OBU's next part started at its last byte.)
      var len = room >= 2 ? Math.min(rest, room - 1) : 0;
      while (len > 0 && _leb128Len(len) + len > room) len--;
      if (len === 0) {
        if (cur.els.length === 0) throw new Error('AV1Packetizer: mtu too small');
        packets.push(cur);
        cur = { els: [], size: 0, z: false, y: false };
        continue;
      }
      if (off > 0) cur.z = true;           // a continuation only ever opens a packet
      cur.els.push({ obu: obu, off: off, len: len });
      cur.size += _leb128Len(len) + len;
      off += len;
      if (off < obu.length) {              // goes on in the next packet
        cur.y = true;
        packets.push(cur);
        cur = { els: [], size: 0, z: false, y: false };
      }
    }
  }
  if (cur.els.length) packets.push(cur);

  var nFlag = isKey && ((obus[0][0] >> 3) & 0x0F) === OBU_SEQUENCE_HEADER;
  var out = [];
  for (var p = 0; p < packets.length; p++) {
    var pk = packets[p];
    var n = pk.els.length;
    var w = (n <= 3) ? n : 0;
    var hdr = (pk.z ? 0x80 : 0) | (pk.y ? 0x40 : 0) | (w << 4) | ((p === 0 && nFlag) ? 0x08 : 0);
    var parts = [];
    for (var e = 0; e < n; e++) {
      var el = pk.els[e];
      if (!(w !== 0 && e === n - 1)) parts.push(_leb128(el.len));
      parts.push(el.obu.subarray(el.off, el.off + el.len));
    }
    var payload = Buffer.concat(parts);
    out.push(makePacketWithPrefix(
      self, hdr, 0, 0, 0, 1,
      payload, 0, payload.length,
      rtpTs, p === packets.length - 1, withMeta
    ));
  }
  return out;
}

var OBU_SEQUENCE_HEADER    = 1;
var OBU_TEMPORAL_DELIMITER = 2;
var OBU_TILE_LIST          = 8;
var OBU_PADDING            = 15;

/**
 * Low Overhead Bitstream Format → the OBUs to send, each as one Buffer:
 * header with obu_has_size_field cleared, extension byte if any, payload.
 * Temporal delimiters, tile lists and padding are left out. An OBU with no
 * size field runs to the end (only the last may lack one). null if malformed.
 */
function _splitObus(buf) {
  var out = [];
  var o = 0;
  while (o < buf.length) {
    var h = buf[o];
    var hasExt = (h & 0x04) !== 0, hasSize = (h & 0x02) !== 0;
    var hdrLen = hasExt ? 2 : 1;
    if (o + hdrLen > buf.length) return null;
    var payStart, payLen;
    if (hasSize) {
      var lv = _readLeb128(buf, o + hdrLen);
      if (!lv) return null;
      payStart = o + hdrLen + lv.n;
      payLen = lv.value;
      if (payStart + payLen > buf.length) return null;
    } else {
      payStart = o + hdrLen;
      payLen = buf.length - payStart;
    }
    var type = (h >> 3) & 0x0F;
    if (type !== OBU_TEMPORAL_DELIMITER && type !== OBU_TILE_LIST && type !== OBU_PADDING) {
      var el = Buffer.allocUnsafe(hdrLen + payLen);
      el[0] = h & ~0x02;
      if (hasExt) el[1] = buf[o + 1];
      buf.copy(el, hdrLen, payStart, payStart + payLen);
      out.push(el);
    }
    o = payStart + payLen;
  }
  return out;
}

function _leb128Len(v) {
  var n = 1;
  while (v >= 128) { v = Math.floor(v / 128); n++; }
  return n;
}


// ═══════════════════════════════════════════════════════════════════
//  Depacketizer
// ═══════════════════════════════════════════════════════════════════

/**
 * AV1Depacketizer — reassembles AV1 frames from RTP packets.
 *
 * Expects packets in sequence-number order. On lossy/reordering networks,
 * feed packets through a JitterBuffer first.
 *
 * @param {object}   opts
 * @param {function} opts.output  called with { data, timestamp, type }
 * @param {function} [opts.error]
 */
function AV1Depacketizer(opts) {
  initDepacketizer(this, opts);
  this._fragments = [];   // the frame's complete OBUs, each with its obu_size
  this._partial = null;   // an OBU whose rest comes in the next packet (Y)
  this._isKey = false;
  this._ts = null;        // the RTP timestamp of the temporal unit being built
}

/**
 * peekKeyframe — does THIS individual RTP packet's payload start an
 * AV1 keyframe? Static method (no Depacketizer state needed).
 *
 * RFC 9798 §4.3: the descriptor byte's N bit (0x08) signals "new
 * coded video sequence". A new coded video sequence starts with a
 * key frame, so N=1 means this packet contains the start of a
 * keyframe.
 *
 * The N bit is only meaningful at the START of a coded video
 * sequence — i.e., when Z=0 (this packet is NOT a continuation of a
 * previous OBU). The packetizer only sets N together with isFirst
 * (Z=0), so checking N alone would catch all our own output, but
 * being explicit about Z=0 makes peekKeyframe robust against
 * conforming-but-unusual senders too.
 *
 * Returns:
 *   true  — Z=0 (start of OBU sequence) AND N=1 (keyframe begins)
 *   false — continuation fragment, mid-stream OBU, or short payload
 *
 * @param {Buffer} payload
 * @returns {boolean}
 */
AV1Depacketizer.peekKeyframe = function (payload) {
  if (!payload || payload.length < 1) return false;
  var hdr = payload[0];
  var Z = !!(hdr & 0x80);   // continuation of previous OBU
  var N = !!(hdr & 0x08);   // new coded video sequence
  return !Z && N;
};

AV1Depacketizer.prototype.depacketize = function (packet) {
  if (!checkDepacketizePayload(this, packet, 1)) return;

  var payload = packet.payload;
  var hdr = payload[0];
  var Z = !!(hdr & 0x80);  // continuation of previous OBU
  var Y = !!(hdr & 0x40);  // OBU continues in next packet
  var W = (hdr >> 4) & 0x03;  // OBU elements in the packet; 0: each has its length
  var N = !!(hdr & 0x08);  // new coded video sequence

  // A temporal unit is every packet up to the marker, all with one RTP
  // timestamp (RFC 9798 §4.1). A new timestamp with OBUs still held means
  // the last one's marker was lost: what was gathered is let go. (Z = 0
  // used to start a new frame, but the spatial layers of one temporal unit
  // come in packets of their own, each with Z = 0.)
  if (this._ts !== null && packet.timestamp !== this._ts) {
    this._fragments = [];
    this._partial = null;
    this._isKey = false;
  }
  this._ts = packet.timestamp;
  if (!Z) this._partial = null;   // nothing continues: a held fragment's rest was lost
  if (!Z && N && this._fragments.length === 0) this._isKey = true;

  // The OBU elements (RFC 9798 §4.4): with W = 0 each one has a leb128
  // length in front; with W = 1..3 the first W - 1 have one and the last
  // runs to the payload's end. The first continues the previous packet's
  // last when Z is set; the last goes on in the next packet when Y is.
  // (The payload was taken as one piece: a length was handed up as the
  // first byte of an OBU — Chrome's keyframes come with W = 2.)
  var off = 1, len = payload.length, count = 0;
  while (off < len) {
    var size;
    if (W !== 0 && count === W - 1) {
      size = len - off;
    } else {
      var lv = _readLeb128(payload, off);
      if (!lv || off + lv.n + lv.value > len) {
        emitError(this, new Error('AV1Depacketizer: OBU element length past the payload'));
        this._fragments = [];
        this._partial = null;
        return;
      }
      off += lv.n;
      size = lv.value;
    }
    var el = payload.subarray(off, off + size);
    off += size;
    var first = (count === 0);
    count++;
    if (first && Z) {
      if (!this._partial) continue;   // its start was lost: nothing to join it to
      el = Buffer.concat([this._partial, el]);
      this._partial = null;
    }
    if (off >= len && Y) { this._partial = el; continue; }
    _pushObu(this._fragments, el);
  }

  // The temporal unit ends at the marker. (It ended at every packet with
  // Y = 0 as well — with spatial layers, one temporal unit went up as one
  // chunk per layer: Chrome's L3T3_KEY, 233 chunks for 119 temporal units,
  // each decoded as two frames.)
  if (packet.marker) {
    if (this._fragments.length === 0) return;
    var frame = this._fragments.length === 1
      ? this._fragments[0]
      : Buffer.concat(this._fragments);
    var isKey = this._isKey;
    this._fragments = [];
    this._partial = null;
    this._isKey = false;
    this._ts = null;

    this._output({
      data: frame,
      timestamp: packet.timestamp,
      type: isKey ? 'key' : 'delta',
    });
  }
};

AV1Depacketizer.prototype.reset = function () {
  this._fragments = [];
  this._partial = null;
  this._isKey = false;
  this._ts = null;
};

AV1Depacketizer.prototype.close = function () {
  this._fragments = [];
  this._partial = null;
  this._output = null;
  this._error = null;
};


/**
 * An OBU as RTP carries it, as a decoder takes it: RFC 9798 §5 has the
 * sender drop obu_size (obu_has_size_field 0), and the Low Overhead
 * Bitstream Format a decoder reads (AV1 §5.2, what WebCodecs and dav1d
 * take) needs it on every OBU — so it is written back here: the header
 * with obu_has_size_field set, its extension byte if any, the leb128 size,
 * the rest. An OBU that already has its size is kept as it is.
 */
function _pushObu(list, obu) {
  if (obu.length === 0) return;
  var h = obu[0];
  if (h & 0x02) { list.push(obu); return; }
  var hdrLen = (h & 0x04) ? 2 : 1;   // obu_extension_flag: one more header byte
  if (obu.length < hdrLen) return;
  list.push(Buffer.concat([
    Buffer.from([h | 0x02]),
    obu.subarray(1, hdrLen),
    _leb128(obu.length - hdrLen),
    obu.subarray(hdrLen),
  ]));
}

/** leb128 (AV1 §4.10.5) at buf[off]: { value, n } or null when cut short. */
function _readLeb128(buf, off) {
  var value = 0;
  for (var i = 0; i < 8; i++) {
    if (off + i >= buf.length) return null;
    var b = buf[off + i];
    value += (b & 0x7F) * Math.pow(2, 7 * i);
    if (!(b & 0x80)) return { value: value, n: i + 1 };
  }
  return null;
}

function _leb128(v) {
  var out = [];
  do {
    var b = v % 128;
    v = Math.floor(v / 128);
    out.push(v > 0 ? (b | 0x80) : b);
  } while (v > 0);
  return Buffer.from(out);
}


export { AV1Packetizer, AV1Depacketizer };
