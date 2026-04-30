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
- [Sponsors](#-sponsors)
- [License](#-license)

## Features

- **Video codecs** — H.264, H.265 (HEVC), VP8, VP9, AV1
- **Audio codecs** — Opus, G.711 (μ-law/A-law), G.722, AAC (RFC 3640 AAC-hbr)
- **DTMF** — RFC 4733 named telephony events
- **RTP** — header serialize/parse, sequence/timestamp handling, RFC 5285 extensions, header stamping
- **RTCP** — SR, RR, NACK, PLI, FIR, REMB, transport-cc, SDES, BYE, RTX, compound packets
- **SRTP** — AES-128-CM and AES-128-GCM with HMAC-SHA1-80 authentication (RFC 3711, RFC 7714)
- **Jitter buffer** — reordering and loss detection with configurable latency
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

The returned object has: `version`, `padding`, `extension`, `csrcCount`, `marker`, `payloadType`, `sequenceNumber`, `timestamp`, `ssrc`, `csrc[]`, `payload`, `headerLength`.

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

**H.264** — accepts Annex-B (start codes) or AVCC (length-prefixed). `H264Packetizer.packetizeStapA(nalus, timestampUs)` bundles SPS+PPS into one STAP-A packet for low-overhead delivery of parameter sets.

**H.265** — same Annex-B/AVCC handling; supports single-NAL, AP (aggregation), and FU (fragmentation).

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

const dtmf = new DTMFPacketizer({ ssrc: 1, payloadType: 101 });
const packets = dtmf.packetize({ event: '5', duration: 160 });  // press '5', 20ms
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
  maxSize: 256,             // max buffered packets — default 256
  output: (packet) => {
    depacketizer.depacketize(packet);
  },
  onLoss: (seq) => {
    nackGenerator.markLost(seq);
  },
});

socket.on('message', (buf) => {
  const packet = parse(buf);
  if (packet) jb.push(packet);
});
```

**Methods:** `push(packet)`, `reset()`, `close()`.

### SRTP

```js
import { SrtpSession } from 'rtp-packet';

const session = new SrtpSession({
  profile: 'AES_CM_128_HMAC_SHA1_80',  // or 'AEAD_AES_128_GCM'
  masterKey,                            // Buffer (16 bytes for AES-128)
  masterSalt,                           // Buffer (14 bytes for CM, 12 for GCM)
});

const encrypted = session.protectRtp(rtpPacket);     // Buffer → Buffer
const decrypted = session.unprotectRtp(srtpPacket);  // null on auth fail

// Same for RTCP:
const encryptedRtcp = session.protectRtcp(rtcpPacket);
const decryptedRtcp = session.unprotectRtcp(srtcpPacket);
```

Master key and salt come from DTLS-SRTP key exchange (WebRTC) or SDES (SIP/RTSP). Both AES-CM and AES-GCM profiles are supported.

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
  SenderBuffer, RtxStream, NackThrottle, buildRtxPacket,
} from 'rtp-packet';

const senderBuf = new SenderBuffer({ capacity: 1024 });
const rtxStream = new RtxStream({
  ssrc: 0x12345678,       // separate SSRC for RTX
  payloadType: 97,        // RTX-specific PT
});

// On each outgoing packet:
senderBuf.add(packet, sequenceNumber);

// On incoming NACK:
parsedNack.lostSequenceNumbers.forEach((seq) => {
  const original = senderBuf.get(seq);
  if (original) {
    const rtxPkt = rtxStream.wrap(original, seq);
    socket.send(rtxPkt);
  }
});
```

Receiver side — detect gaps and rate-limit NACK feedback.

```js
import { NackGenerator, NackThrottle, parseRtxPacket } from 'rtp-packet';

const nackGen = new NackGenerator({ maxNackList: 100 });
const throttle = new NackThrottle({ minIntervalMs: 30 });

jitterBuffer.onLoss = (seq) => {
  nackGen.markLost(seq);
  if (throttle.canSendNow()) {
    const lostList = nackGen.collect();
    if (lostList.length > 0) {
      socket.send(buildNACK(ourSsrc, mediaSsrc, lostList));
      throttle.markSent();
    }
  }
};

// On receiving an RTX packet:
const original = parseRtxPacket(rtxPacket);
if (original) jitterBuffer.push(original);
```

### Bandwidth estimation

Parse incoming transport-cc feedback and feed it to a delay-based estimator.

```js
import {
  parseTransportCC, parseREMB,
  BandwidthEstimator, TransportCCFeedbackGenerator,
} from 'rtp-packet';

const estimator = new BandwidthEstimator();

// On incoming RTCP transport-cc:
const feedback = parseTransportCC(parsedRtcp.fci);
estimator.processFeedback(feedback);
const targetBitrate = estimator.getEstimate();   // bps
encoder.updateBitrate(targetBitrate);

// To send your own transport-cc feedback (when you're the receiver):
const feedbackGen = new TransportCCFeedbackGenerator({ ssrc, mediaSsrc });
parsedPackets.forEach((p) => feedbackGen.markReceived(p.transportSeq, Date.now()));
const fb = feedbackGen.build();   // RTCP packet ready to send
```

### Header extension stamping

Stamp `abs-send-time` and transport-wide sequence numbers onto outgoing packets without rebuilding them.

```js
import { RtpHeaderStamper } from 'rtp-packet';

const stamper = new RtpHeaderStamper({
  absSendTimeId: 2,         // RFC 5285 ID negotiated in SDP
  transportCCId: 5,
});

// Just before send:
stamper.stamp(packet, { transportSeq: 12345 });   // mutates in place
socket.send(packet);
```

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
  parseExtensions, writeExtensions, setHeaderExtension,
  absSendTime, transportCC, audioLevel, readAbsSendTime,
} from 'rtp-packet';

const extBlock = writeExtensions({
  2: absSendTime(),
  5: transportCC(seqNum),
  1: audioLevel(80, true),
});

const packet = parse(buf);
if (packet.extension) {
  const exts = parseExtensions(buf.subarray(...));
  const sendTime = readAbsSendTime(exts[2]);
}
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
| RTCP (SR/RR/NACK/PLI/FIR/REMB) | ✅ | partial | ❌ | ❌ |
| RTCP transport-cc | ✅ | ❌ | ❌ | ❌ |
| H.264 packetize + depacketize | ✅ | ⚪ depack only | ⚪ depack only | ❌ |
| H.265 packetize + depacketize | ✅ | ❌ | ⚪ depack only | ❌ |
| VP8 / VP9 / AV1 | ✅ | ✅ | ❌ | ❌ |
| Opus / G.711 / G.722 / AAC | ✅ | partial | partial | ❌ |
| DTMF (RFC 4733) | ✅ | ❌ | ❌ | ❌ |
| SRTP (AES-CM and AES-GCM) | ✅ | partial | ❌ | ❌ |
| JitterBuffer | ✅ | ✅ | ❌ | ❌ |
| NACK + RTX (RFC 4585+4588) | ✅ | partial | ❌ | ❌ |
| Bandwidth estimation | ✅ | ❌ | ❌ | ❌ |
| SDP generation | ✅ | ❌ | ❌ | ❌ |
| Header extension stamping | ✅ | partial | ❌ | ❌ |
| RFC 5285 extensions | ✅ | ✅ | ❌ | ❌ |

The closest competitor is **werift-rtp** (part of the [werift](https://github.com/shinyoshiaki/werift-webrtc) project). werift is TypeScript-based and includes ICE/DTLS/SCTP, but its RTP layer covers fewer codecs — no H.265, no G.722, no AAC, partial DTMF, and no bandwidth estimator. **yellowstone** is RTSP-focused and only handles a few depacketizers. **node-rtp** is a basic parser, unmaintained.

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