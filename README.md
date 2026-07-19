# rtp-packet

A complete RTP/RTCP stack for Node.js. Parse and build RTP packets, packetize video and audio frames across all major codecs, reorder with a jitter buffer, encrypt with SRTP, drive bandwidth estimation, and emit RTCP feedback.

Works anywhere RTP is spoken: WebRTC, RTSP, SIP, WHIP/WHEP, plain RTP-over-UDP.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [What does this library do?](#what-does-this-library-do)
- [Quick start](#quick-start)
  - [Parse a received RTP packet](#parse-a-received-rtp-packet)
  - [Stream encoded video to ffplay](#stream-encoded-video-to-ffplay)
- [API](#api)
  - [RTP core](#rtp-core)
  - [Packetizers](#packetizers)
  - [Depacketizers](#depacketizers)
  - [Factory helpers](#factory-helpers)
  - [JitterBuffer](#jitterbuffer)
  - [SRTP](#srtp)
  - [RTCP](#rtcp)
  - [Retransmission (NACK + RTX)](#retransmission-rfc-4585-nack--rfc-4588-rtx)
  - [Bandwidth estimation](#bandwidth-estimation)
  - [Header extension stamping](#header-extension-stamping)
  - [SDP](#sdp)
  - [Header extensions (RFC 5285)](#header-extensions-rfc-5285)
- [Performance](#performance)
- [Use cases](#use-cases)
- [RFC compliance](#rfc-compliance)
- [Comparison to other libraries](#comparison-to-other-libraries)
- [Changelog](#changelog)
- [Sponsors](#-sponsors)
- [License](#-license)

## Features

- **Video codecs** — H.264, H.265 (HEVC), VP8, VP9, AV1
- **Audio codecs** — Opus, G.711 (μ-law/A-law), G.722, AAC (RFC 3640 AAC-hbr)
- **DTMF** — RFC 4733 named telephony events
- **RTP** — header serialize/parse, sequence/timestamp handling, RFC 5285 extensions, header stamping
- **RTCP** — SR, RR, NACK, PLI, FIR, REMB, transport-cc, SDES, BYE, RTX, compound packets
- **SRTP** — AES-128-CM (RFC 3711) and AEAD AES-128-GCM (RFC 7714), replay protection, ROC rollover recovery, RFC 5764 DTLS keying-material helpers
- **Jitter buffer** — reordering and loss detection with configurable latency, RTT-aware loss declaration, auto-resync on stream jumps, bounded memory
- **NACK + RTX** — NACK generator with throttle, RTX cache and retransmission (RFC 4585 + 4588)
- **Bandwidth estimation** — transport-cc and REMB feedback parsing + delay-based estimator
- **SDP** — session description generator covering all supported codecs
- **Pure JavaScript** — no native bindings, just two small pure-JS dependencies
- **Fast** — ~400K packets/sec on a single thread

## Install

```bash
npm install rtp-packet
```

Requires Node.js 18 or newer.

## What does this library do?

RTP is the format every real-time media stream rides on — WebRTC, RTSP cameras, SIP phones, video conferencing. Each RTP packet carries a small header (12 bytes) plus a chunk of codec data. But "a chunk of codec data" is more complicated than it sounds:

- A 50KB H.264 keyframe is too big for one UDP packet — it must be **fragmented** across many RTP packets.
- Several small audio AAC frames can be **aggregated** into one RTP packet to amortize header overhead.
- Some codecs (Opus, G.711) just go one-frame-per-packet with no special handling.

Each codec has its own rules for how to do this — RFC 6184 for H.264, RFC 7798 for H.265, RFC 7587 for Opus, RFC 3640 for AAC, etc. **The packetizer for a codec encodes those rules.** You feed it a frame, it gives you back the RTP packets ready for the wire. The depacketizer is the reverse: feed it RTP packets, get a reassembled frame.

```
   send side                              receive side
┌──────────┐    chunk    ┌──────────┐  RTP[]   ┌──────────┐
│ Encoder  │───────────► │Packetizer│─────────►│SRTP send │──► UDP
└──────────┘             └──────────┘          └──────────┘

                                                 UDP
                                                  │
┌──────────┐    chunk    ┌──────────────┐ packet ┌▼─────────┐
│ Decoder  │◄────────────│ Depacketizer │◄───────│SRTP recv │
└──────────┘             └──────────────┘        └──────────┘
                                ▲ packet
                          ┌─────┴──────┐
                          │JitterBuffer│  ← optional but recommended:
                          └────────────┘    reorder + loss detection
```

This library gives you all the boxes in that diagram — except the socket itself. That belongs to your transport layer (WebRTC server, RTSP client, SIP softphone). rtp-packet stays protocol-pure so it can be reused anywhere RTP is spoken.

## Quick start

### Parse a received RTP packet

```js
import { parse } from 'rtp-packet';

socket.on('message', (buf) => {
  const packet = parse(buf);
  if (!packet) return;  // not a valid RTP packet

  console.log(packet.payloadType, packet.sequenceNumber, packet.timestamp);
  console.log(packet.payload);   // codec-specific payload as Buffer
});
```

### Stream encoded video to ffplay

This sends VP8 frames to ffplay on `127.0.0.1:5004`.

```js
import dgram from 'node:dgram';
import fs from 'node:fs';
import { VideoEncoder } from 'media-processing';
import { VP8Packetizer, generateSDP } from 'rtp-packet';

const socket = dgram.createSocket('udp4');
const packetizer = new VP8Packetizer({ ssrc: 12345, payloadType: 96 });

fs.writeFileSync('stream.sdp', generateSDP({
  address: '127.0.0.1', port: 5004,
  codec: 'vp8', payloadType: 96,
}));

const encoder = new VideoEncoder({
  output: (chunk) => {
    const packets = packetizer.packetize(chunk);
    for (const pkt of packets) socket.send(pkt, 5004, '127.0.0.1');
  },
  error: (e) => console.error(e),
});

encoder.configure({ codec: 'vp8', width: 640, height: 480, bitrate: 1_000_000 });
```

Run ffplay to view:

```bash
ffplay -protocol_whitelist file,udp,rtp -fflags nobuffer -flags low_delay stream.sdp
```

## API

### RTP core

```js
import { serialize, parse } from 'rtp-packet';
```

**`serialize(packet) → Buffer`** — build an RTP packet from fields.

```js
const buf = serialize({
  payloadType: 96,
  sequenceNumber: 1234,
  timestamp: 90000,
  ssrc: 0xCAFEBABE,
  marker: true,
  payload: payloadBuffer,
});
```

**`parse(buffer) → object | null`** — parse a received buffer; returns `null` if not valid RTP.

The returned object has: `version`, `padding`, `extension`, `csrcCount`, `marker`, `payloadType`, `sequenceNumber`, `timestamp`, `ssrc`, `csrc[]`, `payload`, `headerLength`, and `extensions` — a `{ id: Buffer }` map of parsed RFC 5285 one-byte header extensions (or `null` if the packet has none).

### Packetizers

All packetizers share the same constructor and method shapes:

```js
import {
  // video
  H264Packetizer, H265Packetizer,
  VP8Packetizer, VP9Packetizer, AV1Packetizer,
  // audio
  OpusPacketizer, G711Packetizer, G722Packetizer, AacPacketizer,
  // DTMF
  DTMFPacketizer,
} from 'rtp-packet';

const p = new VP8Packetizer({
  ssrc: 12345,              // required — 32-bit
  payloadType: 96,          // required — 0-127
  mtu: 1200,                // optional — default 1400
  initialSequenceNumber: 0, // optional — default random
});
```

**`packetize(chunk) → Buffer[]`** — fragment an encoded frame into RTP packets.

```js
const packets = p.packetize({
  data: encodedFrameBuffer,  // codec bitstream
  timestamp: 33333,          // microseconds (monotonic)
  type: 'key',               // 'key' | 'delta' (used by AV1)
});
```

**`packetizeWithMeta(chunk) → Array<{buffer, sequenceNumber, timestamp, marker}>`** — same as `packetize()` but returns descriptors with the assigned seq/ts/marker. Useful for building an RTX cache.

**`close()`** — releases internal state.

#### Codec-specific notes

**H.264** — accepts Annex-B (start codes) or AVCC (4-byte length prefixes, as produced by MP4 demuxers and WebCodecs `avc` format); the framing is auto-detected per frame. `H264Packetizer.packetizeStapA(nalus, timestampUs, marker?)` bundles SPS+PPS into one STAP-A packet for low-overhead delivery of parameter sets.

**H.265** — same Annex-B / length-prefixed (hvcC) auto-detection; supports single-NAL, AP (aggregation, via `packetizeAP(nalus, timestampUs, marker?)`), and FU (fragmentation).

**VP8 / VP9** — pass `pictureId: true` (or an initial number) to emit a 15-bit PictureID in the payload descriptor, incremented once per frame. Off by default. Turn it **on for WebRTC/SFU use** — libwebrtc keys frame continuity and simulcast layer switching on the PictureID:

```js
const p = new VP8Packetizer({ ssrc: 1, payloadType: 96, pictureId: true });
```

**G.711** — works for both μ-law (PCMU, PT=0) and A-law (PCMA, PT=8); pick by setting `payloadType`.

**G.722** — RTP clock rate is 8 kHz despite 16 kHz audio sampling, per RFC 3551 §4.5.2. Static PT=9 by default. Pass `mtu` if you need other-than-default fragmentation behavior.

**AAC** — implements AAC-hbr mode (RFC 3640 §3.3.6), the variant used by ~all real deployments. Single-AU per packet by default; auto-fragments AUs that exceed MTU. Set `clockRate` to match the audio sampling rate (default 48000):

```js
const p = new AacPacketizer({
  ssrc: 1, payloadType: 96, clockRate: 48000,
});
```

**DTMF** — implements RFC 4733 named telephony events. Use it alongside an audio codec on a separate dynamic payload type:

```js
import { DTMFPacketizer } from 'rtp-packet';

const dtmf = new DTMFPacketizer({ ssrc: 1, payloadType: 101, clockRate: 8000 });

// One RTP packet per call. The caller drives the RFC 4733 state machine
// (start → interim every ~50ms → final packet sent 3× with end: true).
// All packets of one press share the SAME timestamp (event start time):
const pkt = dtmf.packetize({
  event: '5',              // '0'-'9', '*', '#', 'A'-'D', or numeric 0-255
  timestamp: tStartUs,     // µs — identical for every packet of this press
  durationSamples: 160,    // cumulative duration so far, in RTP clock ticks
  marker: true,            // true on the FIRST packet of a new event
  end: false,              // true on the final 3 packets
})[0];
```

### Depacketizers

Same shape across all codecs. Uses WebCodecs-style callbacks.

```js
import { H264Depacketizer } from 'rtp-packet';

const d = new H264Depacketizer({
  output: (chunk) => {
    // chunk: { data: Buffer, timestamp: number, type: 'key'|'delta' }
    decoder.decode(chunk);
  },
  error: (err) => console.error(err),  // optional
});

d.depacketize(parsedRtpPacket);
```

**`depacketize(packet)`** — feed a parsed RTP packet. When a frame is complete, `output()` is called with the reassembled chunk.

**`reset()`** — clear in-progress reassembly state (e.g., on SSRC change).

**`close()`** — release resources.

Depacketizers expect packets in sequence-number order. On lossy or reordering networks, feed them through a `JitterBuffer` first.

### Factory helpers

When the codec is known at coding time, prefer constructing the codec class directly (`new H264Packetizer(...)`) — it preserves codec-specific methods and lets bundlers tree-shake unused codecs. When the codec is determined at runtime (an RTSP client learning from `DESCRIBE`, a config-driven pipeline), use the factory:

```js
import { createPacketizer, createDepacketizer } from 'rtp-packet';

const p = createPacketizer({
  codec: 'h264',           // case-insensitive
  ssrc: 0xCAFE,
  payloadType: 96,
});
p.packetize({ data: encodedFrame, timestamp: 33333, type: 'key' });

const d = createDepacketizer({
  codec: 'h264',
  output: (chunk) => decoder.decode(chunk),
});
```

Recognized codec names (with aliases): `h264`, `h265`/`hevc`, `vp8`, `vp9`, `av1`, `opus`, `pcmu`/`pcma`/`g711`, `g722`, `aac`/`mpeg4-generic`, `dtmf`/`telephone-event`.

The lookup tables are also exported for inspection:

```js
import { PACKETIZERS, DEPACKETIZERS } from 'rtp-packet';

console.log(Object.keys(PACKETIZERS));
// → ['h264', 'h265', 'hevc', 'vp8', 'vp9', 'av1', 'opus', 'pcmu', 'pcma',
//    'g711', 'g722', 'aac', 'mpeg4-generic', 'dtmf', 'telephone-event']
```

### JitterBuffer

Reorders packets by sequence number; reports losses after a configurable delay.

```js
import { JitterBuffer, parse } from 'rtp-packet';

const jb = new JitterBuffer({
  latency: 50,              // ms to wait for late packets — default 50
  maxSize: 256,             // max buffered packets (hard-enforced) — default 256
  rttMs: 0,                 // optional: measured RTT; loss declaration waits
                            // max(latency, 2*RTT + rttSafetyMs) so NACK→RTX
                            // recoveries aren't declared lost prematurely
  output: (packet) => {
    depacketizer.depacketize(packet);
  },
  onLoss: (seq) => {
    // one callback per missing seq — feed your NACK path here
  },
});

socket.on('message', (buf) => {
  const packet = parse(buf);
  if (packet) jb.push(packet);
});

// EventEmitter API also available:
jb.on('packet', (pkt) => { /* same as output */ });
jb.on('loss',   (seq) => { /* same as onLoss */ });
jb.on('resync', (seq) => { /* stream jumped (camera restart / SSRC reuse) —
                              the buffer re-anchored itself at `seq` */ });
jb.on('gap',    ({ from, to, length }) => {
  // Discontinuity too large to NACK per-packet (loss callbacks are capped
  // at 512 per gap). Request a keyframe (PLI) instead.
});
```

**Robustness guarantees:**

- **Auto-resync** — a forward seq jump of more than 32768 looks like "old packets" under 16-bit wraparound math; after a sustained run of such rejects, the buffer re-anchors automatically instead of silently discarding the stream forever.
- **Bounded memory** — `maxSize` is enforced: when the head of the stream is stuck behind a gap, the buffer force-advances rather than growing without limit.
- **Large-gap recovery** — gaps beyond the fast search window are found via a full wrap-aware scan; loss floods are capped (512 events/gap + one `gap` event).
- The flush timer is `unref()`ed — it never keeps your process alive.

**Methods:** `push(packet)`, `setLatency(ms)`, `setRtt(ms)`, `size()`, `reset()`, `close()`.

### SRTP

Two cipher profiles, selectable at construction:

| Profile | Cipher | Auth | Master salt | Tag |
|---|---|---|---|---|
| `AES_CM_128_HMAC_SHA1_80` (default) | AES-128-CM | HMAC-SHA1-80 | 14 bytes | 10 bytes |
| `AEAD_AES_128_GCM` (RFC 7714) | AES-128-GCM | AEAD | 12 bytes | 16 bytes |

The profile also accepts the DTLS-SRTP spellings (`SRTP_AES128_CM_HMAC_SHA1_80`, `SRTP_AEAD_AES_128_GCM`) and the IANA numbers (`0x0001`, `0x0007`) — pass whatever your DTLS layer hands back from the `use_srtp` negotiation, no mapping table needed. GCM is what Chrome offers first, and it's also *faster* than CM in Node (single AEAD pass vs. CTR + separate HMAC).

```js
import { SrtpSession } from 'rtp-packet';

// Symmetric — SDES, RTSP, HomeKit (same key both directions):
const session = new SrtpSession({
  profile: 'AES_CM_128_HMAC_SHA1_80',  // or 'AEAD_AES_128_GCM' / 0x0007 / …
  masterKey,                            // Buffer (16 bytes)
  masterSalt,                           // Buffer (14 for CM, 12 for GCM)
});
// (positional form also works: new SrtpSession(masterKey, masterSalt, { profile }))

const encrypted = session.protectRtp(rtpPacket);     // Buffer → Buffer
const decrypted = session.unprotectRtp(srtpPacket);  // null on auth fail / replay

// Same for RTCP:
const encryptedRtcp = session.protectRtcp(rtcpPacket);
const decryptedRtcp = session.unprotectRtcp(srtcpPacket);

// encryptRtp / decryptRtp / encryptRtcp / decryptRtcp are equivalent aliases.
```

**WebRTC (DTLS-SRTP) — the two-liner.** After the DTLS handshake, ask the library how much keying material to export and let it apply the RFC 5764 §4.2 slicing (client key ‖ server key ‖ client salt ‖ server salt — both *keys* before both *salts*, the classic hand-slicing mistake):

```js
const profile = dtls.getNegotiatedSrtpProfile();  // string or IANA number
const ekm = dtls.exportKeyingMaterial(
  SrtpSession.keyingMaterialLength(profile),      // 60 for CM, 56 for GCM
  'EXTRACTOR-dtls_srtp'
);
const srtp = SrtpSession.fromDtlsKeyingMaterial(profile, ekm, /* isServer */ true);
```

The explicit duplex form remains available if you prefer to slice yourself:

```js
const session = new SrtpSession({
  clientKey, serverKey, clientSalt, serverSalt,
  isServer: true,
  profile: 'AEAD_AES_128_GCM',
});
```

**Security features (both profiles):**

- **Replay protection (RFC 3711 §3.3.2)** — a 128-packet sliding window per SSRC rejects replayed and too-old RTP packets; SRTCP has index-based replay tracking. On by default; pass `{ replayProtection: false }` to disable (e.g. when decrypting capture files offline, where re-processing the same packets is intentional).
- **ROC index guessing (libsrtp-style)** — late packets that straddle a sequence-number rollover decrypt correctly with `roc − 1`; early post-wrap packets use `roc + 1`. Without this, one packet in every 65,536 window is silently lost — reliably, right when RTX retransmissions are in flight.
- Send and receive state are tracked separately per SSRC, so symmetric-key sessions don't poison their own replay window.
- Constant-time tag comparison (CM profile); AEAD tag verification (GCM).

### RTCP

```js
import {
  buildSR, buildRR, buildNACK, buildPLI, buildFIR,
  buildREMB, buildTransportCC, buildSDES, buildBYE,
  buildCompound, parseRTCP, parseRTCPCompound,
} from 'rtp-packet';

const sr = buildSR({
  ssrc: 12345,
  rtpTimestamp: 90000,
  packetCount: 100,
  octetCount: 150000,
});

const nack = buildNACK(senderSsrc, mediaSsrc, [1234, 1235, 1240]);

const compound = buildCompound([sr, sdes]);

const packets = parseRTCPCompound(buffer);  // RTCP often arrives as compound
```

### Retransmission (RFC 4585 NACK + RFC 4588 RTX)

Sender side — keep recently-sent packets in a ring buffer; on incoming NACK, wrap and retransmit them as RTX.

```js
import {
  SenderBuffer, RtxStream, NackThrottle,
} from 'rtp-packet';

const senderBuf = new SenderBuffer({ size: 1024 });        // ring slots per SSRC
const rtxStream = new RtxStream({
  rtxSsrc: 0x12345678,    // separate SSRC for the RTX stream
  rtxPt: 97,              // RTX payload type (from a=fmtp apt=…)
});
const throttle = new NackThrottle({ windowMs: 100 });

// On each outgoing packet (before SRTP):
senderBuf.store(rtpPacket);          // keyed by (ssrc, seq) read from the packet

// On incoming NACK for mediaSsrc:
parsedNack.lostSequenceNumbers.forEach((seq) => {
  const original = senderBuf.get(mediaSsrc, seq);
  if (!original) return;                             // evicted or never sent
  if (!throttle.shouldSend(mediaSsrc, seq)) return;  // dedup NACK storms
  socket.send(srtp.protectRtp(rtxStream.wrap(original)));
});
```

Receiver side — `NackGenerator` detects gaps **itself** from the arrival stream (it's a faithful port of libwebrtc's `NackModule`, including the reordering histogram and keyframe-aware eviction). Feed it every arriving packet; poll it periodically for the NACK list.

```js
import { NackGenerator, parseRtxPacket, buildNACK } from 'rtp-packet';

const nackGen = new NackGenerator();       // libwebrtc-tuned defaults
nackGen.updateRtt(measuredRttMs);          // from RTCP RR — gates re-NACKs

// On every arriving media packet (extSeq = seq + 65536*cycles you track):
nackGen.observePacket(extSeq, isKeyframePacket, /* isRecovered */ false);

// On every RTX-recovered packet:
const original = parseRtxPacket(rtxPkt, { primarySsrc, primaryPt });
if (original) {
  jitterBuffer.push(parse(original));
  nackGen.observePacket(recoveredExtSeq, false, /* isRecovered */ true);
}

// Every 20–100ms:
const lost = nackGen.buildFeedback(Date.now());       // 16-bit seqs, ready to send
if (lost.length) socket.send(buildNACK(ourSsrc, mediaSsrc, lost));
if (nackGen.needKeyframe()) {                          // loss beyond RTX recovery
  socket.send(buildPLI(ourSsrc, mediaSsrc));
  nackGen.acknowledgeKeyframeRequested();
}
```

To know whether an arriving packet starts a keyframe without decoding it, every depacketizer exposes a static `peekKeyframe(payload)` — e.g. `VP8Depacketizer.peekKeyframe(pkt.payload)`.

### Bandwidth estimation

Parse incoming transport-cc feedback and feed it to a delay-based estimator.

```js
import {
  parseTransportCC, parseREMB,
  BandwidthEstimator, TransportCCFeedbackGenerator,
} from 'rtp-packet';

const estimator = new BandwidthEstimator({ startBps: 500_000 });

// Sender side — record each outgoing packet so incoming feedback can be
// matched to real send times (pairs with RtpHeaderStamper below):
estimator.recordSend(transportSeq, Date.now(), packetBytes);

// On incoming RTCP transport-cc:
const feedback = parseTransportCC(parsedRtcp.fci);
estimator.observeTransportCC(feedback);

// On incoming REMB:
estimator.observeRemb(parseREMB(parsedRtcp.fci).bitrate);

const targetBitrate = estimator.getEstimate();   // bps
encoder.updateBitrate(targetBitrate);

// Receiver side — produce transport-cc feedback for the remote sender:
const feedbackGen = new TransportCCFeedbackGenerator({
  senderSsrc: ourSsrc,
  mediaSsrc: theirMediaSsrc,
});
// For each received RTP packet, read the transport-cc header extension:
feedbackGen.recordArrival(transportWideSeq, Date.now());
// Every ~100ms:
const fb = feedbackGen.buildFeedback();          // RTCP packet or null
if (fb) socket.send(fb);
```

### Header extension stamping

Stamp `abs-send-time` and transport-wide sequence numbers onto outgoing packets without rebuilding them.

```js
import { RtpHeaderStamper } from 'rtp-packet';

const stamper = new RtpHeaderStamper({
  extMap: {                    // names → RFC 5285 IDs from SDP a=extmap lines
    'transport-cc': 5,
    'abs-send-time': 2,
    'mid': 3,                  // optional
  },
  mid: '0',                    // required only if 'mid' is mapped
});

// Just before SRTP + send. Returns a NEW Buffer (input is not mutated).
// All configured extensions are written in a single pass — one parse and
// one allocation per packet regardless of how many extensions you stamp.
packet = stamper.stamp(packet);
socket.send(srtp.protectRtp(packet));

// Pair the stamped transport-cc seq with the bandwidth estimator:
estimator.recordSend(stamper.lastTransportCcSeq(), Date.now(), packet.length);
```

Simulcast: register per-SSRC RIDs with `stamper.setRidForSsrc(ssrc, rid)` and RTX repair streams with `stamper.setRtxRids(rtxSsrc, rid, repairedRid)` (RFC 8852) — the right RID is picked automatically from each outgoing packet's SSRC.

### SDP

```js
import { generateSDP } from 'rtp-packet';

const sdp = generateSDP({
  address: '127.0.0.1',
  port: 5004,
  codec: 'aac',             // 'h264' | 'h265' | 'vp8' | 'vp9' | 'av1' |
                            // 'opus' | 'pcmu' | 'pcma' | 'g722' | 'aac' |
                            // 'telephone-event'
  payloadType: 96,
  clockRate: 48000,         // for opus/aac/dtmf
  channels: 2,              // for aac
  config: '1190',           // AudioSpecificConfig hex (aac only)
  // H.264/H.265 only: sps, pps, vps Buffers for sprop-parameter-sets
});
```

### Header extensions (RFC 5285)

```js
import {
  parseExtensions, writeExtensions,
  setHeaderExtension, setHeaderExtensions,
  absSendTime, transportCC, audioLevel, readAbsSendTime,
} from 'rtp-packet';

const extBlock = writeExtensions({
  2: absSendTime(),
  5: transportCC(seqNum),
  1: audioLevel(80, true),
});

// parse() already returns them decoded:
const packet = parse(buf);
if (packet.extensions) {
  const sendTime = readAbsSendTime(packet.extensions[2]);
}

// Add/replace extensions on an already-serialized packet:
pkt = setHeaderExtension(pkt, 2, absSendTime());          // one at a time
pkt = setHeaderExtensions(pkt, {                          // or batched —
  2: absSendTime(),                                       // one parse + one
  5: transportCC(seq),                                    // allocation total
});
```

## Performance

Measured on Node.js 22, single thread:

| Operation | Throughput |
|---|---|
| `parse()` single RTP packet | 4.5M ops/sec |
| VP8 packetize 100KB keyframe | ~4,200 frames/sec |
| VP8 packetize 2KB delta | 145K frames/sec |
| H.264 packetize single-packet AU | 565K frames/sec |
| H.265 packetize FU fragment | 410K frames/sec |
| Opus/G.711/G.722 packetize | 1.2M frames/sec |
| AAC packetize single AU | 850K frames/sec |
| JitterBuffer push | 380K ops/sec |
| SRTP encrypt AES-CM (1200B payload) | 126K pkts/sec (~1.2 Gbps) |
| SRTP encrypt AES-GCM (1200B payload) | 198K pkts/sec (~1.9 Gbps) |
| RtpHeaderStamper (3 extensions, batched) | 360K pkts/sec |

A server pushing 100 peers at 30fps uses roughly 1% of a core for packetization.

## Use cases

This library is the protocol layer for any RTP-based system. Combine it with a transport layer of your choice:

- **WebRTC server** — pair with ICE + DTLS for browser interop
- **RTSP NVR / camera client** — pair with an RTSP signaling parser
- **RTSP camera server** — pair with RTSP signaling + RTP-over-TCP framing
- **SIP softphone** — pair with SIP signaling + DTLS-SRTP or SDES
- **WHIP/WHEP server** — pair with HTTP server for the signaling
- **SFU** — combine with routing logic per peer
- **RTP recorder** — feed packets through JitterBuffer + depacketizer to a muxer

## RFC compliance

- RFC 3550 — RTP: A Transport Protocol for Real-Time Applications
- RFC 3551 — RTP Profile for Audio and Video Conferences (AVP)
- RFC 3640 — RTP Payload Format for Transport of MPEG-4 Elementary Streams (AAC)
- RFC 3711 — Secure Real-time Transport Protocol (SRTP)
- RFC 4585 — RTCP-based Feedback (NACK, PLI)
- RFC 4588 — RTP Retransmission Payload Format (RTX)
- RFC 4733 — RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
- RFC 5104 — Codec Control Messages (FIR)
- RFC 5285 — RTP header extensions (one-byte format)
- RFC 5761 — Multiplexing RTP and RTCP
- RFC 6184 — RTP Payload Format for H.264
- RFC 7587 — RTP Payload Format for Opus
- RFC 7714 — AES-GCM Authenticated Encryption for SRTP
- RFC 7741 — RTP Payload Format for VP8
- RFC 7798 — RTP Payload Format for HEVC (H.265)
- RFC 8285 — RTP header extensions (two-byte format)
- AOMedia AV1 RTP Specification — RTP Payload Format for AV1 (https://aomediacodec.github.io/av1-rtp-spec/)
- draft-ietf-payload-vp9 — RTP Payload Format for VP9
- draft-holmer-rmcat-transport-wide-cc — Transport-wide Congestion Control feedback

## Comparison to other libraries

`rtp-packet` is the most complete RTP/RTCP stack available as pure JavaScript on Node.js. Here's how it compares to the alternatives in the broader ecosystem.

### Pure-JS Node.js libraries

These run on plain Node without native bindings:

| Feature | rtp-packet | werift-rtp | yellowstone | node-rtp |
|---|---|---|---|---|
| RTP serialize/parse | ✅ | ✅ | ⚪ parse only | ✅ |
| RTCP (SR/RR/NACK/PLI/FIR/REMB) | ✅ | ✅ | ❌ | ❌ |
| RTCP transport-cc | ✅ | ✅ | ❌ | ❌ |
| H.264 packetize + depacketize | ✅ | ⚪ depack only | ⚪ depack only | ❌ |
| H.265 packetize + depacketize | ✅ | ❌ | ⚪ depack only | ❌ |
| VP8 / VP9 packetize + depacketize | ✅ | ⚪ depack only | ❌ | ❌ |
| AV1 packetize + depacketize | ✅ | ⚪ depack only | ❌ | ❌ |
| Opus / G.711 / G.722 / AAC | ✅ | partial | partial | ❌ |
| DTMF (RFC 4733) | ✅ | ❌ | ❌ | ❌ |
| SRTP (AES-CM and AES-GCM) | ✅ | ✅ | ❌ | ❌ |
| SRTP replay protection + ROC recovery | ✅ | partial | ❌ | ❌ |
| JitterBuffer | ✅ | ✅ | ❌ | ❌ |
| NACK + RTX (RFC 4585+4588) | ✅ | partial | ❌ | ❌ |
| Bandwidth estimation | ✅ | ❌ | ❌ | ❌ |
| SDP generation | ✅ | ❌ | ❌ | ❌ |
| Header extension stamping | ✅ | partial | ❌ | ❌ |
| RFC 5285 extensions | ✅ | ✅ | ❌ | ❌ |
| DTLS keying-material helpers (RFC 5764) | ✅ | internal only | ❌ | ❌ |

The closest competitor is **werift-rtp** (part of the [werift](https://github.com/shinyoshiaki/werift-webrtc) project). werift is TypeScript-based and includes ICE/DTLS/SCTP, and its RTCP/SRTP layers are solid — but its codec layer is depacketize-oriented (no send-side packetizers for H.264/VP8/VP9/AV1, no H.265, no G.722, no AAC, no DTMF) and it has no bandwidth estimator or SDP generation. **yellowstone** is RTSP-focused and only handles a few depacketizers. **node-rtp** is a basic parser, unmaintained.

### Native or non-Node alternatives

Outside pure JS, the standards in the field are:

| Library | Language | Scope | When to use |
|---|---|---|---|
| **mediasoup** | C++/Node | SFU + RTP | Production SFU at scale; you accept native bindings |
| **pion** | Go | Full WebRTC | Go shop; WebRTC server in a separate process |
| **gortsplib** | Go | RTSP client/server | RTSP-focused service in Go |
| **sipsorcery** | C# | SIP + WebRTC | .NET ecosystem |
| **libwebrtc** | C++ | The reference | You're embedding it via Chromium or building a custom port |

If you need RTP in pure JavaScript without spawning native workers, `rtp-packet` is currently the most complete option. If you need a turn-key SFU and don't mind native code, mediasoup is the standard. If you're building in Go, pion is excellent.

### What's deliberately *not* in rtp-packet

To keep the library focused and reusable, these belong in separate packages:

- **ICE / STUN / TURN** — these are NAT traversal, not RTP. They typically live in a `webrtc-ice` package.
- **DTLS handshake** — produces master keys for SRTP, but the handshake itself is its own protocol.
- **SDP parser** — `generateSDP` is a minimal generator for VLC/ffplay/RTSP receivers; a full RFC 8866 parser/builder belongs in a dedicated `sdp-protocol` package.
- **SIP / RTSP / WHIP signaling** — these are signaling protocols that *use* RTP. They belong in `sip-protocol`, `rtsp-protocol`, `whip-server`, etc.
- **SFU routing logic** — "which subscriber gets which simulcast layer" is application policy, not RTP.

This keeps rtp-packet at ~5000 lines and minimal dependencies, while letting it be the RTP foundation for any of those higher-level systems.


## Changelog

### 0.2.0

**Interop & spec-compliance fixes**

- **AV1**: the aggregation header now sets **W=1** on every packet (exactly one OBU element, no LEB128 length prefix). Previous output declared W=0 while writing no length fields — libwebrtc/Chrome would misparse the first payload byte as a length. Round-trips with rtp-packet's own depacketizer were unaffected, which is why this only surfaced against real browsers.
- **SRTP**: `AEAD_AES_128_GCM` (RFC 7714) is now fully implemented — previously only AES-CM existed despite the README claiming both.
- **H.264 / H.265**: AVCC / length-prefixed input is now genuinely auto-detected (previously Annex-B only, despite the README claiming both).

**Security**

- SRTP **replay protection** (RFC 3711 §3.3.2): 128-packet sliding window per SSRC, on by default (`replayProtection: false` to disable). SRTCP index replay tracking retained.
- SRTP **ROC index guessing** (libsrtp-style): late packets straddling a sequence rollover now decrypt with `roc − 1` instead of failing authentication; early post-wrap packets use `roc + 1`.
- Send/receive SRTP state separated per direction, so symmetric-key sessions can't poison their own replay window.

**Robustness**

- **JitterBuffer**: auto-resync on stream jumps (previously a forward jump > 32768 silently killed the stream forever); `maxSize` actually enforced (previously unbounded growth when a gap exceeded the 64-seq search window); gaps of any size are recoverable; per-gap loss callbacks capped at 512 with a single `gap` event beyond that; per-tick emit budget raised from 30 (which capped throughput at ~1,200 pkts/s); startup reordering handled; flush timer `unref()`ed.
- **buildNACK**: duplicate sequence numbers no longer crash with a RangeError.
- **usToRtp**: exact for epoch-scale microsecond timestamps (previously lost precision past 2⁵³ ≈ 29 hours of stream time at 90 kHz).
- **AAC**: an AU larger than the 13-bit size field (8191 bytes) is now dropped with a warning instead of sent with a truncated, undecodable size.
- **VP8 depacketizer**: fixed a bounds check in 16-bit PictureID parsing.

**Performance**

- `RtpHeaderStamper.stamp()` batches all extensions into one `setHeaderExtensions()` pass — one parse and one allocation per packet instead of one per extension (~3× less work for transport-cc + abs-send-time + mid).
- `TransportCCFeedbackGenerator` dedup is now O(1) via `Map` (was a linear scan per arriving packet).

**New APIs**

- `SrtpSession.fromDtlsKeyingMaterial(profile, ekm, isServer, opts?)` and `SrtpSession.keyingMaterialLength(profile)` — RFC 5764 §4.2 slicing done for you; accepts profile as canonical string, DTLS-SRTP name, or IANA number (`0x0001` / `0x0007`).
- `SrtpSession` construction: options-object symmetric form (`{ profile, masterKey, masterSalt }`), positional-with-opts, and duplex — plus `protectRtp` / `unprotectRtp` / `protectRtcp` / `unprotectRtcp` aliases.
- `setHeaderExtensions(pkt, map)` — write several RFC 5285 extensions in one allocation.
- `VP8Packetizer` / `VP9Packetizer`: `pictureId` option (15-bit, per-frame increment) for WebRTC/SFU use.
- `JitterBuffer`: `'resync'` and `'gap'` events, `size()`, `setRtt()`.
- `H265Packetizer.packetizeAP(nalus, ts, marker?)` — optional marker for parity with `packetizeStapA`.
- Exports: `PROFILE_CM`, `PROFILE_GCM`.

**Behavior changes to be aware of**

- SRTP rejects replays by default — pass `{ replayProtection: false }` if you intentionally decrypt the same packets twice (offline analysis, tests).
- Oversized AAC AUs return `[]` from `packetize()` instead of corrupt packets.
- The JitterBuffer drops late packets for positions it has already played or declared lost (correct behavior; previously they leaked into the buffer).

## 🙏 Sponsors

rtp-packet is an evenings-and-weekends project.  
Support development via **GitHub Sponsors** or simply share the project.



## 📜 License

**Apache License 2.0**

```
Copyright © 2026 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```