function decodeMacSigpipeAudit(log, decodeGzipBase64, sha256Utf8, sha256Bytes) {
  const frames = [], byLabel = new Map();
  let active = null, chunks = 0, rawTotal = 0, gzipTotal = 0;
  const base64Bytes = (encoded) => {
    if (encoded.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw Error("base64 form");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let accumulator = 0, bits = 0; const bytes = [];
    for (const c of encoded.replace(/=+$/, "")) {
      accumulator = (accumulator << 6) | alphabet.indexOf(c); bits += 6;
      if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
    }
    return bytes;
  };
  for (const originalLine of log.split("\n")) {
    const line = originalLine.replace(/^\uFEFF?(?=\d{4}-\d\d-\d\dT)/, "").replace(/^\d{4}-\d\d-\d\dT[0-9:.]+Z /, "").replace(/\r$/, "");
    if (line.startsWith("LSC_AUDIT_FRAME_BEGIN ")) {
      if (active) throw Error("nested frame");
      const meta = JSON.parse(line.slice("LSC_AUDIT_FRAME_BEGIN ".length));
      if (typeof meta.label !== "string" || !/^(?:native\/arm64\/|audit\/)[A-Za-z0-9_.\/-]+$/.test(meta.label) ||
          meta.label.split("/").some(x => !x || x === "." || x === "..") || byLabel.has(meta.label)) throw Error("frame label");
      if (meta.encoding !== "gzip+base64" || meta.chunk_characters !== 8192 ||
          !Number.isSafeInteger(meta.chunks) || meta.chunks < 1 || meta.chunks > 1024 ||
          !Number.isSafeInteger(meta.bytes) || meta.bytes < 0 || meta.bytes > 16 * 1024 * 1024 ||
          !Number.isSafeInteger(meta.raw_limit) || meta.raw_limit < meta.bytes || meta.raw_limit > 16 * 1024 * 1024 ||
          !Number.isSafeInteger(meta.compressed_bytes) || meta.compressed_bytes < 18 || meta.compressed_bytes > 4 * 1024 * 1024 ||
          !/^[0-9a-f]{64}$/.test(meta.sha256) || !/^[0-9a-f]{64}$/.test(meta.compressed_sha256)) throw Error("frame metadata");
      active = {meta, parts: []};
    } else if (line.startsWith("LSC_AUDIT_FRAME_CHUNK ")) {
      if (!active) throw Error("orphan chunk");
      const match = /^LSC_AUDIT_FRAME_CHUNK ([^ ]+) ([0-9]+)\/([0-9]+) ([A-Za-z0-9+/=]+)$/.exec(line);
      if (!match || match[1] !== active.meta.label || Number(match[2]) !== active.parts.length + 1 ||
          Number(match[3]) !== active.meta.chunks || match[4].length > 8192 ||
          (Number(match[2]) < Number(match[3]) && match[4].length !== 8192)) throw Error("chunk identity/order");
      active.parts.push(match[4]); chunks++;
    } else if (line.startsWith("LSC_AUDIT_FRAME_END ")) {
      if (!active) throw Error("orphan end");
      const end = JSON.parse(line.slice("LSC_AUDIT_FRAME_END ".length));
      if (JSON.stringify(end) !== JSON.stringify(active.meta) || active.parts.length !== end.chunks) throw Error("frame end");
      const encoded = active.parts.join(""), compressed = base64Bytes(encoded);
      if (compressed.length !== end.compressed_bytes || sha256Bytes(compressed) !== end.compressed_sha256) throw Error("compressed binding");
      const decoded = decodeGzipBase64(encoded, end.raw_limit);
      if (decoded.output_bytes !== end.bytes || decoded.compressed_bytes !== end.compressed_bytes ||
          sha256Utf8(decoded.text) !== end.sha256) throw Error("decoded binding");
      rawTotal += end.bytes; gzipTotal += end.compressed_bytes;
      if (rawTotal > 48 * 1024 * 1024 || gzipTotal > 8 * 1024 * 1024) throw Error("aggregate limit");
      const value = {metadata: end, content: decoded.text, gzip_crc32: decoded.crc32, gzip_blocks: decoded.blocks};
      frames.push(value); byLabel.set(end.label, value); active = null;
    } else if (line.startsWith("LSC_AUDIT_FRAME_")) {
      throw Error("unknown frame syntax");
    }
  }
  if (active || !frames.length) throw Error("incomplete or empty stream");
  return {frames, by_label: Object.fromEntries(byLabel), counts: {frames:frames.length,chunks,raw_bytes:rawTotal,gzip_bytes:gzipTotal}};
}
