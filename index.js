/**
 * rtp-packet — Complete RTP/RTCP stack for Node.js.
 *
 * The API follows a simple, uniform shape across all codecs:
 *
 *   // Send side:
 *   var pktzr = new VP8Packetizer({ ssrc, payloadType });
 *   var buffers = pktzr.packetize({ data, timestamp });   // Buffer[]
 *
 *   // Receive side (WebCodecs-style callbacks):
 *   var depkt = new VP8Depacketizer({
 *     output: function(chunk) { decoder.decode(chunk); },
 *     error:  function(err)   { console.error(err); },
 *   });
 *   depkt.depacketize(rtpPacket);
 */

import {
  serialize, parse,
  RTP_HEADER_SIZE, DEFAULT_MTU,
  parseExtensions, writeExtensions, setHeaderExtension, setHeaderExtensions,
  absSendTime, transportCC, audioLevel, readAbsSendTime, readAudioLevel,
} from './src/rtp.js';

import { H264Packetizer, H264Depacketizer } from './src/h264.js';
import { VP8Packetizer, VP8Depacketizer } from './src/vp8.js';
import { VP9Packetizer, VP9Depacketizer } from './src/vp9.js';
import { AV1Packetizer, AV1Depacketizer } from './src/av1.js';
import { OpusPacketizer, OpusDepacketizer } from './src/opus.js';
import { G711Packetizer, G711Depacketizer } from './src/g711.js';
import { G722Packetizer, G722Depacketizer } from './src/g722.js';
import { H265Packetizer, H265Depacketizer } from './src/h265.js';
import { AacPacketizer, AacDepacketizer } from './src/aac.js';
import { DTMFPacketizer, DTMFDepacketizer } from './src/dtmf.js';

import { JitterBuffer } from './src/jitter_buffer.js';
import { SrtpSession, PROFILE_CM, PROFILE_GCM } from './src/srtp.js';
import { SenderBuffer, RtxStream, NackThrottle, NackGenerator, Histogram, buildRtxPacket, parseRtxPacket } from './src/retransmit.js';
import { parseTransportCC, parseREMB, BandwidthEstimator, TransportCCFeedbackGenerator } from './src/bandwidth.js';
import { RtpHeaderStamper } from './src/rtp_header_stamper.js';

import {
  buildSR, buildRR, buildPLI, buildNACK, buildFIR, buildREMB, buildTransportCC,
  buildSDES, buildBYE, buildCompound, parseRTCP, parseRTCPCompound,
  generateSDP,
} from './src/rtcp.js';


// ═══════════════════════════════════════════════════════════════════
//  Factory helpers (codec → class lookup)
// ═══════════════════════════════════════════════════════════════════
//
// These are convenience wrappers for the case where the codec is not
// known until runtime — typical examples are RTSP DESCRIBE responses
// (where the camera's SDP tells you what codec you'll receive),
// WebRTC negotiation, or anything config-driven.
//
// When the codec IS known at compile time, instantiate the specific
// class directly. That gives you better autocomplete, codec-specific
// methods (e.g. H264Packetizer.packetizeStapA), and lets bundlers
// tree-shake out unused codecs.
//
// Codec name aliases (case-insensitive):
//   h264                     → H264Packetizer / H264Depacketizer
//   h265, hevc               → H265Packetizer / H265Depacketizer
//   vp8                      → VP8Packetizer  / VP8Depacketizer
//   vp9                      → VP9Packetizer  / VP9Depacketizer
//   av1                      → AV1Packetizer  / AV1Depacketizer
//   opus                     → OpusPacketizer / OpusDepacketizer
//   pcmu, pcma, g711         → G711Packetizer / G711Depacketizer
//   g722                     → G722Packetizer / G722Depacketizer
//   aac, mpeg4-generic       → AacPacketizer  / AacDepacketizer
//   dtmf, telephone-event    → DTMFPacketizer / DTMFDepacketizer

var PACKETIZERS = {
  'h264':            H264Packetizer,
  'h265':            H265Packetizer,
  'hevc':            H265Packetizer,
  'vp8':             VP8Packetizer,
  'vp9':             VP9Packetizer,
  'av1':             AV1Packetizer,
  'opus':            OpusPacketizer,
  'pcmu':            G711Packetizer,
  'pcma':            G711Packetizer,
  'g711':            G711Packetizer,
  'g722':            G722Packetizer,
  'aac':             AacPacketizer,
  'mpeg4-generic':   AacPacketizer,
  'dtmf':            DTMFPacketizer,
  'telephone-event': DTMFPacketizer,
};

var DEPACKETIZERS = {
  'h264':            H264Depacketizer,
  'h265':            H265Depacketizer,
  'hevc':            H265Depacketizer,
  'vp8':             VP8Depacketizer,
  'vp9':             VP9Depacketizer,
  'av1':             AV1Depacketizer,
  'opus':            OpusDepacketizer,
  'pcmu':            G711Depacketizer,
  'pcma':            G711Depacketizer,
  'g711':            G711Depacketizer,
  'g722':            G722Depacketizer,
  'aac':             AacDepacketizer,
  'mpeg4-generic':   AacDepacketizer,
  'dtmf':            DTMFDepacketizer,
  'telephone-event': DTMFDepacketizer,
};

/**
 * Create a packetizer for the named codec.
 *
 * The remaining options are passed straight through to the underlying
 * class constructor — so `ssrc` and `payloadType` are still required,
 * and codec-specific options like `clockRate` (AAC) or `mtu` apply
 * the same as if you'd called the class directly.
 *
 * @param {object} opts
 * @param {string} opts.codec  codec name (case-insensitive); see PACKETIZERS
 *                             for the full alias list
 * @param {number} opts.ssrc          required — 32-bit
 * @param {number} opts.payloadType   required — 0-127
 * @param {number} [opts.mtu]         default 1400
 * @param {number} [opts.clockRate]   AAC only — default 48000
 * @param {number} [opts.initialSequenceNumber]   default random
 * @returns {object} a packetizer instance with .packetize() / .packetizeWithMeta() / .close()
 * @throws {Error} if the codec is unknown
 */
function createPacketizer(opts) {
  if (!opts || !opts.codec) {
    throw new Error('createPacketizer: opts.codec is required');
  }
  var key = String(opts.codec).toLowerCase();
  var Cls = PACKETIZERS[key];
  if (!Cls) {
    throw new Error('createPacketizer: unknown codec "' + opts.codec +
      '" (supported: ' + Object.keys(PACKETIZERS).join(', ') + ')');
  }
  return new Cls(opts);
}

/**
 * Create a depacketizer for the named codec.
 *
 * @param {object}   opts
 * @param {string}   opts.codec   codec name (case-insensitive)
 * @param {function} opts.output  called with the reassembled chunk
 * @param {function} [opts.error] called with Error on malformed input
 * @param {number}   [opts.constantDuration] AAC only — default 1024
 * @returns {object} a depacketizer instance with .depacketize() / .reset() / .close()
 * @throws {Error} if the codec is unknown
 */
function createDepacketizer(opts) {
  if (!opts || !opts.codec) {
    throw new Error('createDepacketizer: opts.codec is required');
  }
  var key = String(opts.codec).toLowerCase();
  var Cls = DEPACKETIZERS[key];
  if (!Cls) {
    throw new Error('createDepacketizer: unknown codec "' + opts.codec +
      '" (supported: ' + Object.keys(DEPACKETIZERS).join(', ') + ')');
  }
  return new Cls(opts);
}


export {
  // ── RTP core ──
  serialize, parse,
  RTP_HEADER_SIZE, DEFAULT_MTU,

  // ── Codec packetizers / depacketizers ──
  H264Packetizer, H264Depacketizer,
  H265Packetizer, H265Depacketizer,
  VP8Packetizer, VP8Depacketizer,
  VP9Packetizer, VP9Depacketizer,
  AV1Packetizer, AV1Depacketizer,
  OpusPacketizer, OpusDepacketizer,
  G711Packetizer, G711Depacketizer,
  G722Packetizer, G722Depacketizer,
  AacPacketizer, AacDepacketizer,
  DTMFPacketizer, DTMFDepacketizer,

  // ── Codec factory helpers (codec name → instance) ──
  // Use these when the codec is config-driven (RTSP DESCRIBE, WebRTC
  // negotiation). When the codec is known at compile time, prefer the
  // specific class — better autocomplete, codec-specific methods,
  // and tree-shaking.
  createPacketizer, createDepacketizer,
  PACKETIZERS, DEPACKETIZERS,

  // ── Jitter buffer ──
  JitterBuffer,

  // ── SRTP ──
  SrtpSession,

  // ── RTCP ──
  buildSR, buildRR, buildPLI, buildNACK, buildFIR, buildREMB, buildTransportCC,
  buildSDES, buildBYE, buildCompound, parseRTCP, parseRTCPCompound,

  // ── Retransmission (RFC 4585 NACK + RFC 4588 RTX) ──
  // Send side: keep recently-sent packets, wrap them in RTX on demand.
  SenderBuffer, RtxStream, NackThrottle, buildRtxPacket,
  // Receive side: detect gaps, build NACK feedback, parse incoming RTX.
  NackGenerator, Histogram, parseRtxPacket,

  // ── Bandwidth estimation (transport-cc + REMB) ──
  parseTransportCC, parseREMB, BandwidthEstimator,
  TransportCCFeedbackGenerator,

  // ── Sender-side RTP header extension stamping ──
  RtpHeaderStamper,

  // ── SDP ──
  generateSDP,

  // ── Header extensions (RFC 5285) ──
  parseExtensions, writeExtensions, setHeaderExtension, setHeaderExtensions,
  absSendTime, transportCC, audioLevel, readAbsSendTime, readAudioLevel,

  // ── SRTP profile name constants ──
  PROFILE_CM, PROFILE_GCM,
};

export default {
  serialize, parse,
  RTP_HEADER_SIZE, DEFAULT_MTU,
  H264Packetizer, H264Depacketizer,
  H265Packetizer, H265Depacketizer,
  VP8Packetizer, VP8Depacketizer,
  VP9Packetizer, VP9Depacketizer,
  AV1Packetizer, AV1Depacketizer,
  OpusPacketizer, OpusDepacketizer,
  G711Packetizer, G711Depacketizer,
  G722Packetizer, G722Depacketizer,
  AacPacketizer, AacDepacketizer,
  DTMFPacketizer, DTMFDepacketizer,
  createPacketizer, createDepacketizer,
  PACKETIZERS, DEPACKETIZERS,
  JitterBuffer, SrtpSession,
  SenderBuffer, RtxStream, NackThrottle, buildRtxPacket,
  NackGenerator, Histogram, parseRtxPacket,
  parseTransportCC, parseREMB, BandwidthEstimator, TransportCCFeedbackGenerator,
  RtpHeaderStamper,
  buildSR, buildRR, buildPLI, buildNACK, buildFIR, buildREMB, buildTransportCC,
  buildSDES, buildBYE, buildCompound, parseRTCP, parseRTCPCompound,
  generateSDP,
  parseExtensions, writeExtensions, setHeaderExtension, setHeaderExtensions,
  absSendTime, transportCC, audioLevel, readAbsSendTime, readAudioLevel,
  PROFILE_CM, PROFILE_GCM,
};
