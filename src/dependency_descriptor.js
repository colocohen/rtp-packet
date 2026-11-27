/**
 * dependency_descriptor — the Dependency Descriptor RTP header extension
 * (AV1 RTP payload format, AOMedia v1.0.0, Appendix A).
 *
 *   parseDependencyDescriptor(data, structure)  → descriptor | null
 *   serializeDependencyDescriptor(descriptor)   → Buffer
 *   activeDecodeTargetsFor(structure, maxSpatialId, maxTemporalId)
 *   decodeTargetFor(structure, maxSpatialId, maxTemporalId)
 *
 * The descriptor tells a forwarder, without reading the payload, which
 * decode targets (a spatial and temporal fidelity) each frame belongs to,
 * the frames it references, and the chains that say whether a loss broke
 * a decode target. Most packets carry 3 bytes and name a template of the
 * Template Dependency Structure, which comes in the first packet of each
 * coded video sequence (A.8.3: template_dependency_structure_present_flag
 * "MUST be set to 1 for the first packet of a coded video sequence"), so
 * parsing a packet needs the structure last received on the stream.
 *
 * A descriptor:
 *   startOfFrame, endOfFrame           booleans
 *   frameDependencyTemplateId          0..63
 *   frameNumber                        0..65535
 *   extended                           the extended fields were present
 *                                      (a descriptor of more than 3 bytes)
 *   structure                          the Template Dependency Structure the
 *                                      packet carried (A.8.2), else null
 *   activeDecodeTargetsBitmask         the bitmask it carried, else null
 *                                      (a new structure makes every decode
 *                                      target active: see activeDecodeTargets)
 *   activeDecodeTargets                the active set this packet signals:
 *                                      the bitmask, all ones with a new
 *                                      structure, else null (no update)
 *   customDtis, customFdiffs, customChains   which frame fields were explicit
 *   frame                              the frame dependency definition, or
 *                                      null when no structure in effect has
 *                                      the template (A.8.3: a lost or late
 *                                      new structure):
 *     { spatialId, temporalId, dtis[], fdiffs[], chainFdiffs[],
 *       maxRenderWidth, maxRenderHeight }  (the last two when the
 *       structure has resolutions)
 *
 * A structure:
 *   templateIdOffset, decodeTargetCount, chainCount
 *   templates: [{ spatialId, temporalId, dtis[], fdiffs[], chainFdiffs[] }]
 *   decodeTargetProtectedBy: [chain index per decode target] (chainCount > 0)
 *   decodeTargetLayers: [{ spatialId, temporalId }]  (derived, A.8.2
 *                       decode_target_layers)
 *   resolutions: [{ width, height }] per spatial id, or null
 *   maxSpatialId, maxTemporalId
 *
 * DTI values (Table A.1): 0 not present, 1 discardable, 2 switch,
 * 3 required.
 */

var URI = 'https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension';

var DTI = { NOT_PRESENT: 0, DISCARDABLE: 1, SWITCH: 2, REQUIRED: 3 };

// The header extension's data is at most 255 bytes (RFC 8285 two-byte form).
var MAX_SIZE = 255;

/* ── bit reader / writer (f(n): high to low order, A.8.2) ── */

function Reader(data) {
  this.d = data;
  this.pos = 0;              // in bits
  this.len = data.length * 8;
  this.overrun = false;
}
Reader.prototype.f = function (n) {
  var x = 0;
  for (var i = 0; i < n; i++) {
    if (this.pos >= this.len) { this.overrun = true; this.pos++; x = x * 2; continue; }
    var bit = (this.d[this.pos >> 3] >> (7 - (this.pos & 7))) & 1;
    this.pos++;
    x = x * 2 + bit;
  }
  return x;
};
// ns(n): non-symmetric unsigned, 0..n-1 (A.8.2).
Reader.prototype.ns = function (n) {
  var w = 0, x = n;
  while (x !== 0) { x = x >> 1; w++; }
  var m = (1 << w) - n;
  var v = this.f(w - 1);
  if (v < m) return v;
  var extra = this.f(1);
  return (v << 1) - m + extra;
};

function Writer() {
  this.bytes = [];
  this.pos = 0;
}
Writer.prototype.f = function (n, v) {
  for (var i = n - 1; i >= 0; i--) {
    var bit = Math.floor(v / Math.pow(2, i)) & 1;
    var byte = this.pos >> 3;
    if (byte >= this.bytes.length) this.bytes.push(0);
    if (bit) this.bytes[byte] |= (1 << (7 - (this.pos & 7)));
    this.pos++;
  }
};
// write_ns(n, v) (A.8.2).
Writer.prototype.ns = function (n, v) {
  if (n === 1) return;
  var w = 0, x = n;
  while (x !== 0) { x = x >> 1; w++; }
  var m = (1 << w) - n;
  if (v < m) this.f(w - 1, v);
  else this.f(w, v + m);
};

function isUint(v, max) {
  return typeof v === 'number' && v >= 0 && v <= max && Math.floor(v) === v;
}

/* ── parse ── */

function readStructure(r) {
  var s = {
    templateIdOffset: r.f(6),
    decodeTargetCount: r.f(5) + 1,
    chainCount: 0,
    templates: [],
    decodeTargetProtectedBy: [],
    decodeTargetLayers: [],
    resolutions: null,
    maxSpatialId: 0,
    maxTemporalId: 0,
  };
  var dtCnt = s.decodeTargetCount;
  // template_layers()
  var sid = 0, tid = 0, maxTid = 0, idc;
  do {
    if (s.templates.length >= 64) return null;          // frame_dependency_template_id is 6 bits
    s.templates.push({ spatialId: sid, temporalId: tid, dtis: [], fdiffs: [], chainFdiffs: [] });
    idc = r.f(2);
    if (idc === 1) { tid++; if (tid > maxTid) maxTid = tid; }
    else if (idc === 2) { tid = 0; sid++; }
    if (r.overrun) return null;
  } while (idc !== 3);
  s.maxSpatialId = sid;
  s.maxTemporalId = maxTid;
  var t, i;
  // template_dtis()
  for (t = 0; t < s.templates.length; t++) {
    for (i = 0; i < dtCnt; i++) s.templates[t].dtis.push(r.f(2));
  }
  // template_fdiffs()
  for (t = 0; t < s.templates.length; t++) {
    while (r.f(1)) {
      s.templates[t].fdiffs.push(r.f(4) + 1);
      if (r.overrun) return null;
    }
  }
  // template_chains()
  s.chainCount = r.ns(dtCnt + 1);
  if (s.chainCount > 0) {
    for (i = 0; i < dtCnt; i++) s.decodeTargetProtectedBy.push(r.ns(s.chainCount));
    for (t = 0; t < s.templates.length; t++) {
      for (i = 0; i < s.chainCount; i++) s.templates[t].chainFdiffs.push(r.f(4));
    }
  }
  // decode_target_layers()
  s.decodeTargetLayers = decodeTargetLayersOf(s.templates, dtCnt);
  // resolutions
  if (r.f(1)) {
    s.resolutions = [];
    for (i = 0; i <= s.maxSpatialId; i++) {
      var w = r.f(16) + 1, h = r.f(16) + 1;
      s.resolutions.push({ width: w, height: h });
    }
  }
  if (r.overrun) return null;
  return s;
}

function decodeTargetLayersOf(templates, dtCnt) {
  var out = [];
  for (var d = 0; d < dtCnt; d++) {
    var sid = 0, tid = 0;
    for (var t = 0; t < templates.length; t++) {
      if (templates[t].dtis[d] !== 0) {
        if (templates[t].spatialId > sid) sid = templates[t].spatialId;
        if (templates[t].temporalId > tid) tid = templates[t].temporalId;
      }
    }
    out.push({ spatialId: sid, temporalId: tid });
  }
  return out;
}

/**
 * Parse one Dependency Descriptor (the extension element's data).
 *
 * @param {Uint8Array} data       the extension's bytes
 * @param {object|null} structure the Template Dependency Structure in
 *                                effect on this stream (the last one a
 *                                packet carried), or null
 * @returns {object|null}  the descriptor, or null when it is malformed
 *                         (shorter than 3 bytes, longer than 255, or its
 *                         fields run past its end)
 */
function parseDependencyDescriptor(data, structure) {
  if (!data || data.length < 3 || data.length > MAX_SIZE) return null;
  var r = new Reader(data);
  var dd = {
    startOfFrame: r.f(1) === 1,
    endOfFrame: r.f(1) === 1,
    frameDependencyTemplateId: r.f(6),
    frameNumber: r.f(16),
    extended: data.length > 3,
    structure: null,
    activeDecodeTargetsBitmask: null,
    activeDecodeTargets: null,
    customDtis: false,
    customFdiffs: false,
    customChains: false,
    frame: null,
  };
  var structurePresent = false, activePresent = false;
  if (dd.extended) {
    structurePresent = r.f(1) === 1;
    activePresent = r.f(1) === 1;
    dd.customDtis = r.f(1) === 1;
    dd.customFdiffs = r.f(1) === 1;
    dd.customChains = r.f(1) === 1;
    if (structurePresent) {
      var s = readStructure(r);
      if (!s) return null;
      dd.structure = s;
      structure = s;
      dd.activeDecodeTargets = Math.pow(2, s.decodeTargetCount) - 1;
    }
    if (activePresent) {
      // f(DtCnt): without a structure the count is unknown and nothing
      // after it can be read.
      if (!structure) return null;
      dd.activeDecodeTargetsBitmask = r.f(structure.decodeTargetCount);
      dd.activeDecodeTargets = dd.activeDecodeTargetsBitmask;
    }
  }
  if (r.overrun) return null;
  // frame_dependency_definition()
  if (!structure) {
    // The custom fields' sizes come from the structure too.
    return (dd.customDtis || dd.customChains) ? null : dd;
  }
  var idx = (dd.frameDependencyTemplateId + 64 - structure.templateIdOffset) % 64;
  if (idx >= structure.templates.length) {
    // A.8.3: "values outside of the valid range may be caused by a change
    // of the template dependency structure" — the frame is not known.
    return dd;
  }
  var tpl = structure.templates[idx];
  var frame = { spatialId: tpl.spatialId, temporalId: tpl.temporalId, dtis: null, fdiffs: null, chainFdiffs: null };
  var i;
  if (dd.customDtis) {
    frame.dtis = [];
    for (i = 0; i < structure.decodeTargetCount; i++) frame.dtis.push(r.f(2));
  } else {
    frame.dtis = tpl.dtis.slice();
  }
  if (dd.customFdiffs) {
    frame.fdiffs = [];
    var size = r.f(2);
    while (size) {
      frame.fdiffs.push(r.f(4 * size) + 1);
      size = r.f(2);
      if (r.overrun) return null;
    }
  } else {
    frame.fdiffs = tpl.fdiffs.slice();
  }
  if (dd.customChains) {
    frame.chainFdiffs = [];
    for (i = 0; i < structure.chainCount; i++) frame.chainFdiffs.push(r.f(8));
  } else {
    frame.chainFdiffs = tpl.chainFdiffs.slice();
  }
  if (structure.resolutions && structure.resolutions[tpl.spatialId]) {
    frame.maxRenderWidth = structure.resolutions[tpl.spatialId].width;
    frame.maxRenderHeight = structure.resolutions[tpl.spatialId].height;
  }
  if (r.overrun) return null;
  dd.frame = frame;
  return dd;
}

/* ── serialize ── */

function writeStructure(w, s) {
  var dtCnt = s.decodeTargetCount;
  var tps = s.templates;
  if (!isUint(s.templateIdOffset, 63)) throw new RangeError('templateIdOffset must be 0..63');
  if (!isUint(dtCnt, 32) || dtCnt < 1) throw new RangeError('decodeTargetCount must be 1..32');
  if (!tps || !tps.length || tps.length > 64) throw new RangeError('a structure has 1..64 templates');
  if (tps[0].spatialId !== 0 || tps[0].temporalId !== 0) throw new RangeError('the first template is spatial 0, temporal 0');
  w.f(6, s.templateIdOffset);
  w.f(5, dtCnt - 1);
  var t, i;
  for (t = 0; t < tps.length; t++) {
    var cur = tps[t], next = tps[t + 1];
    if (!next) { w.f(2, 3); break; }
    if (next.spatialId === cur.spatialId && next.temporalId === cur.temporalId) w.f(2, 0);
    else if (next.spatialId === cur.spatialId && next.temporalId === cur.temporalId + 1) w.f(2, 1);
    else if (next.spatialId === cur.spatialId + 1 && next.temporalId === 0) w.f(2, 2);
    else throw new RangeError('template ' + (t + 1) + ' does not follow template ' + t + ' (Table A.2)');
  }
  for (t = 0; t < tps.length; t++) {
    if (!tps[t].dtis || tps[t].dtis.length !== dtCnt) throw new RangeError('template ' + t + ': one DTI per decode target');
    for (i = 0; i < dtCnt; i++) {
      if (!isUint(tps[t].dtis[i], 3)) throw new RangeError('a DTI is 0..3');
      w.f(2, tps[t].dtis[i]);
    }
  }
  for (t = 0; t < tps.length; t++) {
    var fd = tps[t].fdiffs || [];
    for (i = 0; i < fd.length; i++) {
      if (!isUint(fd[i], 16) || fd[i] < 1) throw new RangeError('a template fdiff is 1..16');
      w.f(1, 1); w.f(4, fd[i] - 1);
    }
    w.f(1, 0);
  }
  var chains = s.chainCount || 0;
  if (!isUint(chains, dtCnt)) throw new RangeError('chainCount must be 0..decodeTargetCount');
  w.ns(dtCnt + 1, chains);
  if (chains > 0) {
    var pb = s.decodeTargetProtectedBy || [];
    if (pb.length !== dtCnt) throw new RangeError('one protecting chain per decode target');
    for (i = 0; i < dtCnt; i++) {
      if (!isUint(pb[i], chains - 1)) throw new RangeError('a protecting chain is 0..chainCount-1');
      w.ns(chains, pb[i]);
    }
    for (t = 0; t < tps.length; t++) {
      var cf = tps[t].chainFdiffs || [];
      if (cf.length !== chains) throw new RangeError('template ' + t + ': one chain fdiff per chain');
      for (i = 0; i < chains; i++) {
        if (!isUint(cf[i], 15)) throw new RangeError('a template chain fdiff is 0..15');
        w.f(4, cf[i]);
      }
    }
  }
  if (s.resolutions) {
    var maxSid = tps[tps.length - 1].spatialId;
    if (s.resolutions.length !== maxSid + 1) throw new RangeError('one resolution per spatial id');
    w.f(1, 1);
    for (i = 0; i <= maxSid; i++) {
      var res = s.resolutions[i];
      if (!res || !isUint(res.width, 65536) || !isUint(res.height, 65536) || res.width < 1 || res.height < 1) {
        throw new RangeError('a resolution is 1..65536 by 1..65536');
      }
      w.f(16, res.width - 1); w.f(16, res.height - 1);
    }
  } else {
    w.f(1, 0);
  }
}

/**
 * Serialize a descriptor (the shape parseDependencyDescriptor returns).
 *
 *   structure                  written when non-null (the packet then
 *                              starts a coded video sequence)
 *   activeDecodeTargetsBitmask written when non-null
 *   customDtis / customFdiffs / customChains  write frame.dtis / .fdiffs /
 *                              .chainFdiffs explicitly
 *   extended                   force the extended fields (5 flags) even
 *                              when all are zero
 * The structure the sizes come from (decode targets, chains) is
 * `descriptor.structure`, else the `structure` argument (the one in
 * effect). Zero bits pad the last byte (A.8.2 zero_padding).
 *
 * @returns {Buffer}
 * @throws {RangeError} a field out of range, or a structure Table A.2
 *                      cannot express
 */
function serializeDependencyDescriptor(dd, structure) {
  if (!dd) throw new RangeError('no descriptor');
  if (!isUint(dd.frameDependencyTemplateId, 63)) throw new RangeError('frameDependencyTemplateId must be 0..63');
  if (!isUint(dd.frameNumber, 0xFFFF)) throw new RangeError('frameNumber must be 0..65535');
  var s = dd.structure || structure || null;
  var w = new Writer();
  w.f(1, dd.startOfFrame ? 1 : 0);
  w.f(1, dd.endOfFrame ? 1 : 0);
  w.f(6, dd.frameDependencyTemplateId);
  w.f(16, dd.frameNumber);
  var hasActive = dd.activeDecodeTargetsBitmask != null;
  var extended = !!(dd.extended || dd.structure || hasActive || dd.customDtis || dd.customFdiffs || dd.customChains);
  if (extended) {
    w.f(1, dd.structure ? 1 : 0);
    w.f(1, hasActive ? 1 : 0);
    w.f(1, dd.customDtis ? 1 : 0);
    w.f(1, dd.customFdiffs ? 1 : 0);
    w.f(1, dd.customChains ? 1 : 0);
    if (dd.structure) writeStructure(w, dd.structure);
    if (hasActive) {
      if (!s) throw new RangeError('an active decode targets bitmask needs the structure');
      if (!isUint(dd.activeDecodeTargetsBitmask, Math.pow(2, s.decodeTargetCount) - 1)) {
        throw new RangeError('the bitmask has one bit per decode target');
      }
      w.f(s.decodeTargetCount, dd.activeDecodeTargetsBitmask);
    }
    var f = dd.frame || {};
    var i;
    if (dd.customDtis) {
      if (!s || !f.dtis || f.dtis.length !== s.decodeTargetCount) throw new RangeError('custom DTIs: one per decode target');
      for (i = 0; i < f.dtis.length; i++) {
        if (!isUint(f.dtis[i], 3)) throw new RangeError('a DTI is 0..3');
        w.f(2, f.dtis[i]);
      }
    }
    if (dd.customFdiffs) {
      var fd = f.fdiffs || [];
      for (i = 0; i < fd.length; i++) {
        if (!isUint(fd[i], 4096) || fd[i] < 1) throw new RangeError('a frame fdiff is 1..4096');
        var v = fd[i] - 1;
        var size = v < 16 ? 1 : v < 256 ? 2 : 3;
        w.f(2, size); w.f(4 * size, v);
      }
      w.f(2, 0);
    }
    if (dd.customChains) {
      var cf = f.chainFdiffs || [];
      if (!s || cf.length !== s.chainCount) throw new RangeError('custom chains: one fdiff per chain');
      for (i = 0; i < cf.length; i++) {
        if (!isUint(cf[i], 255)) throw new RangeError('a frame chain fdiff is 0..255');
        w.f(8, cf[i]);
      }
    }
  }
  var out = Buffer.from(w.bytes);
  if (out.length > MAX_SIZE) throw new RangeError('a descriptor is at most 255 bytes');
  // An extended descriptor is more than 3 bytes (A.8.2: sz > 3); five
  // flags alone fit in a fourth byte, which the padding fills.
  if (extended && out.length === 3) out = Buffer.concat([out, Buffer.alloc(1)]);
  return out;
}

/* ── forwarding helpers ── */

/**
 * The decode targets a receiver capped at (maxSpatialId, maxTemporalId)
 * can use: bit i set when decode target i's layers (decode_target_layers)
 * are at or under both caps. For a forwarder that writes
 * active_decode_targets_bitmask (A.4) for what it forwards.
 */
function activeDecodeTargetsFor(structure, maxSpatialId, maxTemporalId) {
  var mask = 0;
  if (!structure) return mask;
  for (var d = 0; d < structure.decodeTargetCount; d++) {
    var l = structure.decodeTargetLayers[d];
    if (l.spatialId <= maxSpatialId && l.temporalId <= maxTemporalId) mask += Math.pow(2, d);
  }
  return mask;
}

/**
 * The decode target to forward to a receiver capped at (maxSpatialId,
 * maxTemporalId): of those at or under both caps (and in `active`, the
 * sender's active set, when given), the highest spatial then temporal
 * layer; -1 when none fits.
 */
function decodeTargetFor(structure, maxSpatialId, maxTemporalId, active) {
  var best = -1;
  if (!structure) return best;
  for (var d = 0; d < structure.decodeTargetCount; d++) {
    if (active != null && !(Math.floor(active / Math.pow(2, d)) & 1)) continue;
    var l = structure.decodeTargetLayers[d];
    if (l.spatialId > maxSpatialId || l.temporalId > maxTemporalId) continue;
    if (best < 0) { best = d; continue; }
    var b = structure.decodeTargetLayers[best];
    if (l.spatialId > b.spatialId || (l.spatialId === b.spatialId && l.temporalId > b.temporalId)) best = d;
  }
  return best;
}

export {
  URI as DEPENDENCY_DESCRIPTOR_URI,
  DTI,
  parseDependencyDescriptor,
  serializeDependencyDescriptor,
  activeDecodeTargetsFor,
  decodeTargetFor,
};
