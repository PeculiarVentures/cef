// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n, title = "") {
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new Error(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error('"digestInto() output" expected to be of length >=' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts2) => hashCons(opts2).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts2) => hashCons(opts2);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/hashes/sha3.js
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0; x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
var sha3_256 = /* @__PURE__ */ genKeccak(
  6,
  136,
  32,
  /* @__PURE__ */ oidNist(8)
);
var sha3_512 = /* @__PURE__ */ genKeccak(
  6,
  72,
  64,
  /* @__PURE__ */ oidNist(10)
);
var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts2 = {}) => new Keccak(blockLen, suffix, opts2.dkLen === void 0 ? outputLen : opts2.dkLen, true), info);
var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

// node_modules/@noble/curves/abstract/fft.js
function checkU32(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
    throw new Error("wrong u32 integer:" + n);
  return n;
}
function isPowerOfTwo(x) {
  checkU32(x);
  return (x & x - 1) === 0 && x !== 0;
}
function reverseBits(n, bits) {
  checkU32(n);
  let reversed = 0;
  for (let i = 0; i < bits; i++, n >>>= 1)
    reversed = reversed << 1 | n & 1;
  return reversed;
}
function log2(n) {
  checkU32(n);
  return 31 - Math.clz32(n);
}
function bitReversalInplace(values) {
  const n = values.length;
  if (n < 2 || !isPowerOfTwo(n))
    throw new Error("n must be a power of 2 and greater than 1. Got " + n);
  const bits = log2(n);
  for (let i = 0; i < n; i++) {
    const j = reverseBits(i, bits);
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }
  return values;
}
var FFTCore = (F3, coreOpts) => {
  const { N: N3, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
  const bits = log2(N3);
  if (!isPowerOfTwo(N3))
    throw new Error("FFT: Polynomial size should be power of two");
  const isDit = dit !== invertButterflies;
  isDit;
  return (values) => {
    if (values.length !== N3)
      throw new Error("FFT: wrong Polynomial length");
    if (dit && brp)
      bitReversalInplace(values);
    for (let i = 0, g = 1; i < bits - skipStages; i++) {
      const s = dit ? i + 1 + skipStages : bits - i;
      const m = 1 << s;
      const m2 = m >> 1;
      const stride = N3 >> s;
      for (let k = 0; k < N3; k += m) {
        for (let j = 0, grp = g++; j < m2; j++) {
          const rootPos = invertButterflies ? dit ? N3 - grp : grp : j * stride;
          const i0 = k + j;
          const i1 = k + j + m2;
          const omega = roots[rootPos];
          const b = values[i1];
          const a = values[i0];
          if (isDit) {
            const t = F3.mul(b, omega);
            values[i0] = F3.add(a, t);
            values[i1] = F3.sub(a, t);
          } else if (invertButterflies) {
            values[i0] = F3.add(b, a);
            values[i1] = F3.mul(F3.sub(b, a), omega);
          } else {
            values[i0] = F3.add(a, b);
            values[i1] = F3.mul(F3.sub(a, b), omega);
          }
        }
      }
    }
    if (!dit && brp)
      bitReversalInplace(values);
    return values;
  };
};

// node_modules/@noble/post-quantum/utils.js
var randomBytes2 = randomBytes;
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
function validateOpts(opts2) {
  if (typeof opts2 !== "object" || opts2 === null || isBytes(opts2))
    throw new Error("expected opts to be an object");
}
function validateVerOpts(opts2) {
  validateOpts(opts2);
  if (opts2.context !== void 0)
    abytes(opts2.context, void 0, "opts.context");
}
function validateSigOpts(opts2) {
  validateVerOpts(opts2);
  if (opts2.extraEntropy !== false && opts2.extraEntropy !== void 0)
    abytes(opts2.extraEntropy, void 0, "opts.extraEntropy");
}
function splitCoder(label, ...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
        abytes(b, l, label);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf3) => {
      abytes(buf3, bytesLen, label);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf3.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf3 = buf3.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const bytesLen = vecLen * c.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new Error(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = c.encode(u[i]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      abytes(a, bytesLen);
      const r = [];
      for (let i = 0; i < a.length; i += c.bytesLen)
        r.push(c.decode(a.subarray(i, i + c.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits) {
  return (1 << bits) - 1;
}
var EMPTY = Uint8Array.of();
function getMessage(msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new Error("context should be less than 255 bytes");
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}
var oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2]);
function checkHash(hash, requiredStrength = 0) {
  if (!hash.oid || !equalBytes(hash.oid.subarray(0, 10), oidNistP))
    throw new Error("hash.oid is invalid: expected NIST hash");
  const collisionResistance = hash.outputLen * 8 / 2;
  if (requiredStrength > collisionResistance) {
    throw new Error("Pre-hash security strength too low: " + collisionResistance + ", required: " + requiredStrength);
  }
}
function getMessagePrehash(hash, msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new Error("context should be less than 255 bytes");
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid, hashed);
}

// node_modules/@noble/post-quantum/_crystals.js
var genCrystals = (opts2) => {
  const { newPoly: newPoly2, N: N3, Q: Q3, F: F3, ROOT_OF_UNITY: ROOT_OF_UNITY3, brvBits, isKyber } = opts2;
  const mod3 = (a, modulo = Q3) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod2 = (a, modulo = Q3) => {
    const r = mod3(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly2(N3);
    for (let i = 0; i < N3; i++) {
      const b = reverseBits(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY3) ** BigInt(b) % BigInt(Q3);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas2 = getZettas();
  const field = {
    add: (a, b) => mod3((a | 0) + (b | 0)) | 0,
    sub: (a, b) => mod3((a | 0) - (b | 0)) | 0,
    mul: (a, b) => mod3((a | 0) * (b | 0)) | 0,
    inv: (_a) => {
      throw new Error("not implemented");
    }
  };
  const nttOpts = {
    N: N3,
    roots: nttZetas2,
    invertButterflies: true,
    skipStages: isKyber ? 1 : 0,
    brp: false
  };
  const dif = FFTCore(field, { dit: false, ...nttOpts });
  const dit = FFTCore(field, { dit: true, ...nttOpts });
  const NTT3 = {
    encode: (r) => {
      return dif(r);
    },
    decode: (r) => {
      dit(r);
      for (let i = 0; i < r.length; i++)
        r[i] = mod3(F3 * r[i]);
      return r;
    }
  };
  const bitsCoder3 = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N3 / 8);
    return {
      bytesLen,
      encode: (poly) => {
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf3 = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf3 |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf3 >>= 8)
            r[pos++] = buf3 & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly2(N3);
        for (let i = 0, buf3 = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf3 |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf3 >>= d)
            r[pos++] = c.decode(buf3 & mask);
        }
        return r;
      }
    };
  };
  return { mod: mod3, smod: smod2, nttZetas: nttZetas2, NTT: NTT3, bitsCoder: bitsCoder3 };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf3 = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen + 0] = x;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf3);
      };
    },
    clean: () => {
      h.destroy();
      cleanBytes(buf3, _seed);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);
var XOF256 = /* @__PURE__ */ createXofShake(shake256);

// node_modules/@noble/post-quantum/ml-kem.js
var N = 256;
var Q = 3329;
var F = 3303;
var ROOT_OF_UNITY = 17;
var { mod, nttZetas, NTT, bitsCoder } = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly: (n) => new Uint16Array(n),
  brvBits: 7,
  isKyber: true
});
var PARAMS = {
  512: { N, Q, K: 2, ETA1: 3, ETA2: 2, du: 10, dv: 4, RBGstrength: 128 },
  768: { N, Q, K: 3, ETA1: 2, ETA2: 2, du: 10, dv: 4, RBGstrength: 192 },
  1024: { N, Q, K: 4, ETA1: 2, ETA2: 2, du: 11, dv: 5, RBGstrength: 256 }
};
var compress = (d) => {
  if (d >= 12)
    return { encode: (i) => i, decode: (i) => i };
  const a = 2 ** (d - 1);
  return {
    // const compress = (i: number) => round((2 ** d / Q) * i) % 2 ** d;
    encode: (i) => ((i << d) + Q / 2) / Q,
    // const decompress = (i: number) => round((Q / 2 ** d) * i);
    decode: (i) => i * Q + a >>> d
  };
};
var polyCoder = (d) => bitsCoder(d, compress(d));
function polyAdd(a, b) {
  for (let i = 0; i < N; i++)
    a[i] = mod(a[i] + b[i]);
}
function polySub(a, b) {
  for (let i = 0; i < N; i++)
    a[i] = mod(a[i] - b[i]);
}
function BaseCaseMultiply(a0, a1, b0, b1, zeta) {
  const c0 = mod(a1 * b1 * zeta + a0 * b0);
  const c1 = mod(a0 * b1 + a1 * b0);
  return { c0, c1 };
}
function MultiplyNTTs(f, g) {
  for (let i = 0; i < N / 2; i++) {
    let z = nttZetas[64 + (i >> 1)];
    if (i & 1)
      z = -z;
    const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
    f[2 * i + 0] = c0;
    f[2 * i + 1] = c1;
  }
  return f;
}
function SampleNTT(xof) {
  const r = new Uint16Array(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("SampleNTT: unaligned block");
    for (let i = 0; j < N && i + 3 <= b.length; i += 3) {
      const d1 = (b[i + 0] >> 0 | b[i + 1] << 8) & 4095;
      const d2 = (b[i + 1] >> 4 | b[i + 2] << 4) & 4095;
      if (d1 < Q)
        r[j++] = d1;
      if (j < N && d2 < Q)
        r[j++] = d2;
    }
  }
  return r;
}
function sampleCBD(PRF, seed, nonce, eta) {
  const buf3 = PRF(eta * N / 4, seed, nonce);
  const r = new Uint16Array(N);
  const b32 = u32(buf3);
  let len = 0;
  for (let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++) {
    let b = b32[i];
    for (let j = 0; j < 32; j++) {
      bb += b & 1;
      b >>= 1;
      len += 1;
      if (len === eta) {
        t0 = bb;
        bb = 0;
      } else if (len === 2 * eta) {
        r[p++] = mod(t0 - bb);
        bb = 0;
        len = 0;
      }
    }
  }
  if (len)
    throw new Error(`sampleCBD: leftover bits: ${len}`);
  return r;
}
var genKPKE = (opts2) => {
  const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts2;
  const poly1 = polyCoder(1);
  const polyV = polyCoder(dv);
  const polyU = polyCoder(du);
  const publicCoder = splitCoder("publicKey", vecCoder(polyCoder(12), K), 32);
  const secretCoder = vecCoder(polyCoder(12), K);
  const cipherCoder = splitCoder("ciphertext", vecCoder(polyU, K), polyV);
  const seedCoder = splitCoder("seed", 32, 32);
  return {
    secretCoder,
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      cipherText: cipherCoder.bytesLen
    },
    keygen: (seed) => {
      abytes(seed, 32, "seed");
      const seedDst = new Uint8Array(33);
      seedDst.set(seed);
      seedDst[32] = K;
      const seedHash = HASH512(seedDst);
      const [rho, sigma] = seedCoder.decode(seedHash);
      const sHat = [];
      const tHat = [];
      for (let i = 0; i < K; i++)
        sHat.push(NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
      const x = XOF(rho);
      for (let i = 0; i < K; i++) {
        const e = NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
        for (let j = 0; j < K; j++) {
          const aji = SampleNTT(x.get(j, i));
          polyAdd(e, MultiplyNTTs(aji, sHat[j]));
        }
        tHat.push(e);
      }
      x.clean();
      const res = {
        publicKey: publicCoder.encode([tHat, rho]),
        secretKey: secretCoder.encode(sHat)
      };
      cleanBytes(rho, sigma, sHat, tHat, seedDst, seedHash);
      return res;
    },
    encrypt: (publicKey, msg, seed) => {
      const [tHat, rho] = publicCoder.decode(publicKey);
      const rHat = [];
      for (let i = 0; i < K; i++)
        rHat.push(NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
      const x = XOF(rho);
      const tmp2 = new Uint16Array(N);
      const u = [];
      for (let i = 0; i < K; i++) {
        const e1 = sampleCBD(PRF, seed, K + i, ETA2);
        const tmp = new Uint16Array(N);
        for (let j = 0; j < K; j++) {
          const aij = SampleNTT(x.get(i, j));
          polyAdd(tmp, MultiplyNTTs(aij, rHat[j]));
        }
        polyAdd(e1, NTT.decode(tmp));
        u.push(e1);
        polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i]));
        cleanBytes(tmp);
      }
      x.clean();
      const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
      polyAdd(e2, NTT.decode(tmp2));
      const v = poly1.decode(msg);
      polyAdd(v, e2);
      cleanBytes(tHat, rHat, tmp2, e2);
      return cipherCoder.encode([u, v]);
    },
    decrypt: (cipherText, privateKey) => {
      const [u, v] = cipherCoder.decode(cipherText);
      const sk = secretCoder.decode(privateKey);
      const tmp = new Uint16Array(N);
      for (let i = 0; i < K; i++)
        polyAdd(tmp, MultiplyNTTs(sk[i], NTT.encode(u[i])));
      polySub(v, NTT.decode(tmp));
      cleanBytes(tmp, sk, u);
      return poly1.encode(v);
    }
  };
};
function createKyber(opts2) {
  const KPKE = genKPKE(opts2);
  const { HASH256, HASH512, KDF } = opts2;
  const { secretCoder: KPKESecretCoder, lengths } = KPKE;
  const secretCoder = splitCoder("secretKey", lengths.secretKey, lengths.publicKey, 32, 32);
  const msgLen = 32;
  const seedLen = 64;
  return {
    info: { type: "ml-kem" },
    lengths: {
      ...lengths,
      seed: 64,
      msg: msgLen,
      msgRand: msgLen,
      secretKey: secretCoder.bytesLen
    },
    keygen: (seed = randomBytes2(seedLen)) => {
      abytes(seed, seedLen, "seed");
      const { publicKey, secretKey: sk } = KPKE.keygen(seed.subarray(0, 32));
      const publicKeyHash = HASH256(publicKey);
      const secretKey = secretCoder.encode([sk, publicKey, publicKeyHash, seed.subarray(32)]);
      cleanBytes(sk, publicKeyHash);
      return { publicKey, secretKey };
    },
    getPublicKey: (secretKey) => {
      const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
      return Uint8Array.from(publicKey);
    },
    encapsulate: (publicKey, msg = randomBytes2(msgLen)) => {
      abytes(publicKey, lengths.publicKey, "publicKey");
      abytes(msg, msgLen, "message");
      const eke = publicKey.subarray(0, 384 * opts2.K);
      const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes(eke)));
      if (!equalBytes(ek, eke)) {
        cleanBytes(ek);
        throw new Error("ML-KEM.encapsulate: wrong publicKey modulus");
      }
      cleanBytes(ek);
      const kr = HASH512.create().update(msg).update(HASH256(publicKey)).digest();
      const cipherText = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
      cleanBytes(kr.subarray(32));
      return { cipherText, sharedSecret: kr.subarray(0, 32) };
    },
    decapsulate: (cipherText, secretKey) => {
      abytes(secretKey, secretCoder.bytesLen, "secretKey");
      abytes(cipherText, lengths.cipherText, "cipherText");
      const k768 = secretCoder.bytesLen - 96;
      const start = k768 + 32;
      const test = HASH256(secretKey.subarray(k768 / 2, start));
      if (!equalBytes(test, secretKey.subarray(start, start + 32)))
        throw new Error("invalid secretKey: hash check failed");
      const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
      const msg = KPKE.decrypt(cipherText, sk);
      const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
      const Khat = kr.subarray(0, 32);
      const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
      const isValid = equalBytes(cipherText, cipherText2);
      const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
      cleanBytes(msg, cipherText2, !isValid ? Khat : Kbar);
      return isValid ? Khat : Kbar;
    }
  };
}
function shakePRF(dkLen, key, nonce) {
  return shake256.create({ dkLen }).update(key).update(new Uint8Array([nonce])).digest();
}
var opts = {
  HASH256: sha3_256,
  HASH512: sha3_512,
  KDF: shake256,
  XOF: XOF128,
  PRF: shakePRF
};
var ml_kem512 = /* @__PURE__ */ createKyber({
  ...opts,
  ...PARAMS[512]
});
var ml_kem768 = /* @__PURE__ */ createKyber({
  ...opts,
  ...PARAMS[768]
});
var ml_kem1024 = /* @__PURE__ */ createKyber({
  ...opts,
  ...PARAMS[1024]
});

// node_modules/@noble/curves/utils.js
function abool(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}" `;
    throw new Error(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}

// node_modules/@noble/post-quantum/ml-dsa.js
function validateInternalOpts(opts2) {
  validateOpts(opts2);
  if (opts2.externalMu !== void 0)
    abool(opts2.externalMu, "opts.externalMu");
}
var N2 = 256;
var Q2 = 8380417;
var ROOT_OF_UNITY2 = 1753;
var F2 = 8347681;
var D = 13;
var GAMMA2_1 = Math.floor((Q2 - 1) / 88) | 0;
var GAMMA2_2 = Math.floor((Q2 - 1) / 32) | 0;
var PARAMS2 = {
  2: { K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80 },
  3: { K: 6, L: 5, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 49, ETA: 4, OMEGA: 55 },
  5: { K: 8, L: 7, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 60, ETA: 2, OMEGA: 75 }
};
var newPoly = (n) => new Int32Array(n);
var { mod: mod2, smod, NTT: NTT2, bitsCoder: bitsCoder2 } = genCrystals({
  N: N2,
  Q: Q2,
  F: F2,
  ROOT_OF_UNITY: ROOT_OF_UNITY2,
  newPoly,
  isKyber: false,
  brvBits: 8
});
var id = (n) => n;
var polyCoder2 = (d, compress2 = id, verify = id) => bitsCoder2(d, {
  encode: (i) => compress2(verify(i)),
  decode: (i) => verify(compress2(i))
});
var polyAdd2 = (a, b) => {
  for (let i = 0; i < a.length; i++)
    a[i] = mod2(a[i] + b[i]);
  return a;
};
var polySub2 = (a, b) => {
  for (let i = 0; i < a.length; i++)
    a[i] = mod2(a[i] - b[i]);
  return a;
};
var polyShiftl = (p) => {
  for (let i = 0; i < N2; i++)
    p[i] <<= D;
  return p;
};
var polyChknorm = (p, B) => {
  for (let i = 0; i < N2; i++)
    if (Math.abs(smod(p[i])) >= B)
      return true;
  return false;
};
var MultiplyNTTs2 = (a, b) => {
  const c = newPoly(N2);
  for (let i = 0; i < a.length; i++)
    c[i] = mod2(a[i] * b[i]);
  return c;
};
function RejNTTPoly(xof) {
  const r = newPoly(N2);
  for (let j = 0; j < N2; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("RejNTTPoly: unaligned block");
    for (let i = 0; j < N2 && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | b[i + 1] << 8 | b[i + 2] << 16) & 8388607;
      if (t < Q2)
        r[j++] = t;
    }
  }
  return r;
}
function getDilithium(opts2) {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts2;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562, securityLevel } = opts2;
  if (![2, 4].includes(ETA))
    throw new Error("Wrong ETA");
  if (![1 << 17, 1 << 19].includes(GAMMA1))
    throw new Error("Wrong GAMMA1");
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
    throw new Error("Wrong GAMMA2");
  const BETA = TAU * ETA;
  const decompose = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q2 - 1)
      return { r1: 0 | 0, r0: r0 - 1 | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r) => decompose(r).r1;
  const LowBits = (r) => decompose(r).r0;
  const MakeHint = (z, r) => {
    const res0 = z <= GAMMA2 || z > Q2 - GAMMA2 || z === Q2 - GAMMA2 && r === 0 ? 0 : 1;
    return res0;
  };
  const UseHint = (h, r) => {
    const m = Math.floor((Q2 - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1)
      return r0 > 0 ? mod2(r1 + 1, m) | 0 : mod2(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h) => {
      if (h === false)
        throw new Error("hint.encode: hint is false");
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N2; j++)
          if (h[i][j] !== 0)
            res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf3) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N2);
        if (buf3[OMEGA + i] < k || buf3[OMEGA + i] > OMEGA)
          return false;
        for (let j = k; j < buf3[OMEGA + i]; j++) {
          if (j > k && buf3[j] <= buf3[j - 1])
            return false;
          hi[buf3[j]] = 1;
        }
        k = buf3[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++)
        if (buf3[j] !== 0)
          return false;
      return h;
    }
  };
  const ETACoder = polyCoder2(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
    if (!(-ETA <= i && i <= ETA))
      throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
    return i;
  });
  const T0Coder = polyCoder2(13, (i) => (1 << D - 1) - i);
  const T1Coder = polyCoder2(10);
  const ZCoder = polyCoder2(GAMMA1 === 1 << 17 ? 18 : 20, (i) => smod(GAMMA1 - i));
  const W1Coder = polyCoder2(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const publicCoder = splitCoder("publicKey", 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder("secretKey", 32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder("signature", C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
  function RejBoundedPoly(xof) {
    const r = newPoly(N2);
    for (let j = 0; j < N2; ) {
      const b = xof();
      for (let i = 0; j < N2 && i < b.length; i += 1) {
        const d1 = CoefFromHalfByte(b[i] & 15);
        const d2 = CoefFromHalfByte(b[i] >> 4 & 15);
        if (d1 !== false)
          r[j++] = d1;
        if (j < N2 && d2 !== false)
          r[j++] = d2;
      }
    }
    return r;
  }
  const SampleInBall = (seed) => {
    const pre = newPoly(N2);
    const s = shake256.create({}).update(seed);
    const buf3 = new Uint8Array(shake256.blockLen);
    s.xofInto(buf3);
    const masks = buf3.slice(0, 8);
    for (let i = N2 - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N2; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf3[pos++];
        if (pos < shake256.blockLen)
          continue;
        s.xofInto(buf3);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const polyPowerRound = (p) => {
    const res0 = newPoly(N2);
    const res1 = newPoly(N2);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u, h) => {
    for (let i = 0; i < N2; i++)
      u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a, b) => {
    const v = newPoly(N2);
    let cnt = 0;
    for (let i = 0; i < N2; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };
  const signRandBytes = 32;
  const seedCoder = splitCoder("seed", 32, 64, 32);
  const internal = {
    info: { type: "internal-ml-dsa" },
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      seed: 32,
      signature: sigCoder.bytesLen,
      signRand: signRandBytes
    },
    keygen: (seed) => {
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === void 0;
      if (randSeed)
        seed = randomBytes2(32);
      abytes(seed, 32, "seed");
      seedDst.set(seed);
      if (randSeed)
        cleanBytes(seed);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
      const xofPrime = XOF2562(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++)
        s1.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s1Hat = s1.map((i) => NTT2.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF1282(rho);
      const t = newPoly(N2);
      for (let i = 0; i < K; i++) {
        cleanBytes(t);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd2(t, MultiplyNTTs2(aij, s1Hat[j]));
        }
        NTT2.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd2(t, s2[i]));
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return { publicKey, secretKey };
    },
    getPublicKey: (secretKey) => {
      const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey);
      const xof = XOF1282(rho);
      const s1Hat = s1.map((p) => NTT2.encode(p.slice()));
      const t1 = [];
      const tmp = newPoly(N2);
      for (let i = 0; i < K; i++) {
        tmp.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd2(tmp, MultiplyNTTs2(aij, s1Hat[j]));
        }
        NTT2.decode(tmp);
        polyAdd2(tmp, s2[i]);
        const { r1 } = polyPowerRound(tmp);
        t1.push(r1);
      }
      xof.clean();
      cleanBytes(tmp, s1Hat, _t0, s1, s2);
      return publicCoder.encode([rho, t1]);
    },
    // NOTE: random is optional.
    sign: (msg, secretKey, opts3 = {}) => {
      validateSigOpts(opts3);
      validateInternalOpts(opts3);
      let { extraEntropy: random, externalMu = false } = opts3;
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey);
      const A = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++)
          pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++)
        NTT2.encode(s1[i]);
      for (let i = 0; i < K; i++) {
        NTT2.encode(s2[i]);
        NTT2.encode(t0[i]);
      }
      const mu = externalMu ? msg : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const rnd = random === false ? new Uint8Array(32) : random === void 0 ? randomBytes2(signRandBytes) : random;
      abytes(rnd, 32, "extraEntropy");
      const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
      abytes(rhoprime, CRH_BYTES);
      const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
        const z = y.map((i) => NTT2.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          const wi = newPoly(N2);
          for (let j = 0; j < L; j++)
            polyAdd2(wi, MultiplyNTTs2(A[i][j], z[j]));
          NTT2.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits));
        const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
        const cHat = NTT2.encode(SampleInBall(cTilde));
        const cs1 = s1.map((i) => MultiplyNTTs2(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd2(NTT2.decode(cs1[i]), y[i]);
          if (polyChknorm(cs1[i], GAMMA1 - BETA))
            continue main_loop;
        }
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = NTT2.decode(MultiplyNTTs2(s2[i], cHat));
          const r0 = polySub2(w[i], cs2).map(LowBits);
          if (polyChknorm(r0, GAMMA2 - BETA))
            continue main_loop;
          const ct0 = NTT2.decode(MultiplyNTTs2(t0[i], cHat));
          if (polyChknorm(ct0, GAMMA2))
            continue main_loop;
          polyAdd2(r0, ct0);
          const hint = polyMakeHint(r0, w1[i]);
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA)
          continue;
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]);
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, mu, s1, s2, t0, ...A);
        return res;
      }
      throw new Error("Unreachable code path reached, report this error");
    },
    verify: (sig, msg, publicKey, opts3 = {}) => {
      validateInternalOpts(opts3);
      const { externalMu = false } = opts3;
      const [rho, t1] = publicCoder.decode(publicKey);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false)
        return false;
      for (let i = 0; i < L; i++)
        if (polyChknorm(z[i], GAMMA1 - BETA))
          return false;
      const mu = externalMu ? msg : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const c = NTT2.encode(SampleInBall(cTilde));
      const zNtt = z.map((i) => i.slice());
      for (let i = 0; i < L; i++)
        NTT2.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs2(NTT2.encode(polyShiftl(t1[i])), c);
        const Az = newPoly(N2);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd2(Az, MultiplyNTTs2(aij, zNtt[j]));
        }
        const wApprox = NTT2.decode(polySub2(Az, ct12d));
        wTick1.push(polyUseHint(wApprox, h[i]));
      }
      xof.clean();
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA))
          return false;
      }
      for (const t of z)
        if (polyChknorm(t, GAMMA1 - BETA))
          return false;
      return equalBytes(cTilde, c2);
    }
  };
  return {
    info: { type: "ml-dsa" },
    internal,
    securityLevel,
    keygen: internal.keygen,
    lengths: internal.lengths,
    getPublicKey: internal.getPublicKey,
    sign: (msg, secretKey, opts3 = {}) => {
      validateSigOpts(opts3);
      const M = getMessage(msg, opts3.context);
      const res = internal.sign(M, secretKey, opts3);
      cleanBytes(M);
      return res;
    },
    verify: (sig, msg, publicKey, opts3 = {}) => {
      validateVerOpts(opts3);
      return internal.verify(sig, getMessage(msg, opts3.context), publicKey);
    },
    prehash: (hash) => {
      checkHash(hash, securityLevel);
      return {
        info: { type: "hashml-dsa" },
        securityLevel,
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg, secretKey, opts3 = {}) => {
          validateSigOpts(opts3);
          const M = getMessagePrehash(hash, msg, opts3.context);
          const res = internal.sign(M, secretKey, opts3);
          cleanBytes(M);
          return res;
        },
        verify: (sig, msg, publicKey, opts3 = {}) => {
          validateVerOpts(opts3);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts3.context), publicKey);
        }
      };
    }
  };
}
var ml_dsa44 = /* @__PURE__ */ getDilithium({
  ...PARAMS2[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256,
  securityLevel: 128
});
var ml_dsa65 = /* @__PURE__ */ getDilithium({
  ...PARAMS2[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256,
  securityLevel: 192
});
var ml_dsa87 = /* @__PURE__ */ getDilithium({
  ...PARAMS2[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256,
  securityLevel: 256
});

// src/format/crypto.ts
var subtle = globalThis.crypto.subtle;
function buf(data) {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}
async function aesKeyWrap(kek, plaintext) {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error(`keywrap: KEK must be 16, 24, or 32 bytes, got ${kek.length}`);
  }
  if (plaintext.length % 8 !== 0 || plaintext.length < 16) {
    throw new Error(`keywrap: plaintext must be \u226516 bytes and a multiple of 8, got ${plaintext.length}`);
  }
  const wrapKey = await subtle.importKey("raw", buf(kek), "AES-KW", false, ["wrapKey"]);
  const keyToWrap = await subtle.importKey("raw", buf(plaintext), { name: "AES-GCM", length: plaintext.length * 8 }, true, ["encrypt"]);
  const wrapped = await subtle.wrapKey("raw", keyToWrap, wrapKey, "AES-KW");
  return new Uint8Array(wrapped);
}
async function aesKeyUnwrap(kek, ciphertext) {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error(`keyunwrap: KEK must be 16, 24, or 32 bytes, got ${kek.length}`);
  }
  if (ciphertext.length % 8 !== 0 || ciphertext.length < 24) {
    throw new Error(`keyunwrap: ciphertext must be \u226524 bytes and a multiple of 8, got ${ciphertext.length}`);
  }
  const unwrapKey = await subtle.importKey("raw", buf(kek), "AES-KW", false, ["unwrapKey"]);
  const keyLength = (ciphertext.length - 8) * 8;
  try {
    const unwrapped = await subtle.unwrapKey(
      "raw",
      buf(ciphertext),
      unwrapKey,
      "AES-KW",
      { name: "AES-GCM", length: keyLength },
      true,
      ["encrypt"]
    );
    const exported = await subtle.exportKey("raw", unwrapped);
    return new Uint8Array(exported);
  } catch {
    throw new Error("keyunwrap: integrity check failed");
  }
}
function zeroize(buf3) {
  buf3.fill(0);
}

// node_modules/cbor-x/decode.js
var decoder;
try {
  decoder = new TextDecoder();
} catch (error) {
}
var src;
var srcEnd;
var position = 0;
var EMPTY_ARRAY = [];
var LEGACY_RECORD_INLINE_ID = 105;
var RECORD_DEFINITIONS_ID = 57342;
var RECORD_INLINE_ID = 57343;
var BUNDLED_STRINGS_ID = 57337;
var PACKED_REFERENCE_TAG_ID = 6;
var STOP_CODE = {};
var maxArraySize = 11281e4;
var maxMapSize = 1681e4;
var strings = EMPTY_ARRAY;
var stringPosition = 0;
var currentDecoder = {};
var currentStructures;
var srcString;
var srcStringStart = 0;
var srcStringEnd = 0;
var bundledStrings;
var referenceMap;
var currentExtensions = [];
var currentExtensionRanges = [];
var packedValues;
var dataView;
var restoreMapsAsObject;
var defaultOptions = {
  useRecords: false,
  mapsAsObjects: true
};
var sequentialMode = false;
var inlineObjectReadThreshold = 2;
try {
  new Function("");
} catch (error) {
  inlineObjectReadThreshold = Infinity;
}
var Decoder = class _Decoder {
  constructor(options) {
    if (options) {
      if ((options.keyMap || options._keyMap) && !options.useRecords) {
        options.useRecords = false;
        options.mapsAsObjects = true;
      }
      if (options.useRecords === false && options.mapsAsObjects === void 0)
        options.mapsAsObjects = true;
      if (options.getStructures)
        options.getShared = options.getStructures;
      if (options.getShared && !options.structures)
        (options.structures = []).uninitialized = true;
      if (options.keyMap) {
        this.mapKey = /* @__PURE__ */ new Map();
        for (let [k, v] of Object.entries(options.keyMap)) this.mapKey.set(v, k);
      }
    }
    Object.assign(this, options);
  }
  /*
  decodeKey(key) {
  	return this.keyMap
  		? Object.keys(this.keyMap)[Object.values(this.keyMap).indexOf(key)] || key
  		: key
  }
  */
  decodeKey(key) {
    return this.keyMap ? this.mapKey.get(key) || key : key;
  }
  encodeKey(key) {
    return this.keyMap && this.keyMap.hasOwnProperty(key) ? this.keyMap[key] : key;
  }
  encodeKeys(rec) {
    if (!this._keyMap) return rec;
    let map = /* @__PURE__ */ new Map();
    for (let [k, v] of Object.entries(rec)) map.set(this._keyMap.hasOwnProperty(k) ? this._keyMap[k] : k, v);
    return map;
  }
  decodeKeys(map) {
    if (!this._keyMap || map.constructor.name != "Map") return map;
    if (!this._mapKey) {
      this._mapKey = /* @__PURE__ */ new Map();
      for (let [k, v] of Object.entries(this._keyMap)) this._mapKey.set(v, k);
    }
    let res = {};
    map.forEach((v, k) => res[safeKey(this._mapKey.has(k) ? this._mapKey.get(k) : k)] = v);
    return res;
  }
  mapDecode(source, end) {
    let res = this.decode(source);
    if (this._keyMap) {
      switch (res.constructor.name) {
        case "Array":
          return res.map((r) => this.decodeKeys(r));
      }
    }
    return res;
  }
  decode(source, end) {
    if (src) {
      return saveState(() => {
        clearSource();
        return this ? this.decode(source, end) : _Decoder.prototype.decode.call(defaultOptions, source, end);
      });
    }
    srcEnd = end > -1 ? end : source.length;
    position = 0;
    stringPosition = 0;
    srcStringEnd = 0;
    srcString = null;
    strings = EMPTY_ARRAY;
    bundledStrings = null;
    src = source;
    try {
      dataView = source.dataView || (source.dataView = new DataView(source.buffer, source.byteOffset, source.byteLength));
    } catch (error) {
      src = null;
      if (source instanceof Uint8Array)
        throw error;
      throw new Error("Source must be a Uint8Array or Buffer but was a " + (source && typeof source == "object" ? source.constructor.name : typeof source));
    }
    if (this instanceof _Decoder) {
      currentDecoder = this;
      packedValues = this.sharedValues && (this.pack ? new Array(this.maxPrivatePackedValues || 16).concat(this.sharedValues) : this.sharedValues);
      if (this.structures) {
        currentStructures = this.structures;
        return checkedRead();
      } else if (!currentStructures || currentStructures.length > 0) {
        currentStructures = [];
      }
    } else {
      currentDecoder = defaultOptions;
      if (!currentStructures || currentStructures.length > 0)
        currentStructures = [];
      packedValues = null;
    }
    return checkedRead();
  }
  decodeMultiple(source, forEach) {
    let values, lastPosition = 0;
    try {
      let size = source.length;
      sequentialMode = true;
      let value = this ? this.decode(source, size) : defaultDecoder.decode(source, size);
      if (forEach) {
        if (forEach(value) === false) {
          return;
        }
        while (position < size) {
          lastPosition = position;
          if (forEach(checkedRead()) === false) {
            return;
          }
        }
      } else {
        values = [value];
        while (position < size) {
          lastPosition = position;
          values.push(checkedRead());
        }
        return values;
      }
    } catch (error) {
      error.lastPosition = lastPosition;
      error.values = values;
      throw error;
    } finally {
      sequentialMode = false;
      clearSource();
    }
  }
};
function checkedRead() {
  try {
    let result = read();
    if (bundledStrings) {
      if (position >= bundledStrings.postBundlePosition) {
        let error = new Error("Unexpected bundle position");
        error.incomplete = true;
        throw error;
      }
      position = bundledStrings.postBundlePosition;
      bundledStrings = null;
    }
    if (position == srcEnd) {
      currentStructures = null;
      src = null;
      if (referenceMap)
        referenceMap = null;
    } else if (position > srcEnd) {
      let error = new Error("Unexpected end of CBOR data");
      error.incomplete = true;
      throw error;
    } else if (!sequentialMode) {
      throw new Error("Data read, but end of buffer not reached");
    }
    return result;
  } catch (error) {
    clearSource();
    if (error instanceof RangeError || error.message.startsWith("Unexpected end of buffer")) {
      error.incomplete = true;
    }
    throw error;
  }
}
function read() {
  let token = src[position++];
  let majorType = token >> 5;
  token = token & 31;
  if (token > 23) {
    switch (token) {
      case 24:
        token = src[position++];
        break;
      case 25:
        if (majorType == 7) {
          return getFloat16();
        }
        token = dataView.getUint16(position);
        position += 2;
        break;
      case 26:
        if (majorType == 7) {
          let value = dataView.getFloat32(position);
          if (currentDecoder.useFloat32 > 2) {
            let multiplier = mult10[(src[position] & 127) << 1 | src[position + 1] >> 7];
            position += 4;
            return (multiplier * value + (value > 0 ? 0.5 : -0.5) >> 0) / multiplier;
          }
          position += 4;
          return value;
        }
        token = dataView.getUint32(position);
        position += 4;
        if (majorType === 1) return -1 - token;
        break;
      case 27:
        if (majorType == 7) {
          let value = dataView.getFloat64(position);
          position += 8;
          return value;
        }
        if (majorType > 1) {
          if (dataView.getUint32(position) > 0)
            throw new Error("JavaScript does not support arrays, maps, or strings with length over 4294967295");
          token = dataView.getUint32(position + 4);
        } else if (currentDecoder.int64AsNumber) {
          token = dataView.getUint32(position) * 4294967296;
          token += dataView.getUint32(position + 4);
        } else token = dataView.getBigUint64(position);
        position += 8;
        break;
      case 31:
        switch (majorType) {
          case 2:
          // byte string
          case 3:
            throw new Error("Indefinite length not supported for byte or text strings");
          case 4:
            let array = [];
            let value, i = 0;
            while ((value = read()) != STOP_CODE) {
              if (i >= maxArraySize) throw new Error(`Array length exceeds ${maxArraySize}`);
              array[i++] = value;
            }
            return majorType == 4 ? array : majorType == 3 ? array.join("") : Buffer.concat(array);
          case 5:
            let key;
            if (currentDecoder.mapsAsObjects) {
              let object = {};
              let i2 = 0;
              if (currentDecoder.keyMap) {
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) throw new Error(`Property count exceeds ${maxMapSize}`);
                  object[safeKey(currentDecoder.decodeKey(key))] = read();
                }
              } else {
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) throw new Error(`Property count exceeds ${maxMapSize}`);
                  object[safeKey(key)] = read();
                }
              }
              return object;
            } else {
              if (restoreMapsAsObject) {
                currentDecoder.mapsAsObjects = true;
                restoreMapsAsObject = false;
              }
              let map = /* @__PURE__ */ new Map();
              if (currentDecoder.keyMap) {
                let i2 = 0;
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) {
                    throw new Error(`Map size exceeds ${maxMapSize}`);
                  }
                  map.set(currentDecoder.decodeKey(key), read());
                }
              } else {
                let i2 = 0;
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) {
                    throw new Error(`Map size exceeds ${maxMapSize}`);
                  }
                  map.set(key, read());
                }
              }
              return map;
            }
          case 7:
            return STOP_CODE;
          default:
            throw new Error("Invalid major type for indefinite length " + majorType);
        }
      default:
        throw new Error("Unknown token " + token);
    }
  }
  switch (majorType) {
    case 0:
      return token;
    case 1:
      return ~token;
    case 2:
      return readBin(token);
    case 3:
      if (srcStringEnd >= position) {
        return srcString.slice(position - srcStringStart, (position += token) - srcStringStart);
      }
      if (srcStringEnd == 0 && srcEnd < 140 && token < 32) {
        let string = token < 16 ? shortStringInJS(token) : longStringInJS(token);
        if (string != null)
          return string;
      }
      return readFixedString(token);
    case 4:
      if (token >= maxArraySize) throw new Error(`Array length exceeds ${maxArraySize}`);
      let array = new Array(token);
      for (let i = 0; i < token; i++) array[i] = read();
      return array;
    case 5:
      if (token >= maxMapSize) throw new Error(`Map size exceeds ${maxArraySize}`);
      if (currentDecoder.mapsAsObjects) {
        let object = {};
        if (currentDecoder.keyMap) for (let i = 0; i < token; i++) object[safeKey(currentDecoder.decodeKey(read()))] = read();
        else for (let i = 0; i < token; i++) object[safeKey(read())] = read();
        return object;
      } else {
        if (restoreMapsAsObject) {
          currentDecoder.mapsAsObjects = true;
          restoreMapsAsObject = false;
        }
        let map = /* @__PURE__ */ new Map();
        if (currentDecoder.keyMap) for (let i = 0; i < token; i++) map.set(currentDecoder.decodeKey(read()), read());
        else for (let i = 0; i < token; i++) map.set(read(), read());
        return map;
      }
    case 6:
      if (token >= BUNDLED_STRINGS_ID) {
        let structure = currentStructures[token & 8191];
        if (structure) {
          if (!structure.read) structure.read = createStructureReader(structure);
          return structure.read();
        }
        if (token < 65536) {
          if (token == RECORD_INLINE_ID) {
            let length = readJustLength();
            let id2 = read();
            let structure2 = read();
            recordDefinition(id2, structure2);
            let object = {};
            if (currentDecoder.keyMap) for (let i = 2; i < length; i++) {
              let key = currentDecoder.decodeKey(structure2[i - 2]);
              object[safeKey(key)] = read();
            }
            else for (let i = 2; i < length; i++) {
              let key = structure2[i - 2];
              object[safeKey(key)] = read();
            }
            return object;
          } else if (token == RECORD_DEFINITIONS_ID) {
            let length = readJustLength();
            let id2 = read();
            for (let i = 2; i < length; i++) {
              recordDefinition(id2++, read());
            }
            return read();
          } else if (token == BUNDLED_STRINGS_ID) {
            return readBundleExt();
          }
          if (currentDecoder.getShared) {
            loadShared();
            structure = currentStructures[token & 8191];
            if (structure) {
              if (!structure.read)
                structure.read = createStructureReader(structure);
              return structure.read();
            }
          }
        }
      }
      let extension = currentExtensions[token];
      if (extension) {
        if (extension.handlesRead)
          return extension(read);
        else
          return extension(read());
      } else {
        let input = read();
        for (let i = 0; i < currentExtensionRanges.length; i++) {
          let value = currentExtensionRanges[i](token, input);
          if (value !== void 0)
            return value;
        }
        return new Tag(input, token);
      }
    case 7:
      switch (token) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return;
        // undefined
        case 31:
        default:
          let packedValue = (packedValues || getPackedValues())[token];
          if (packedValue !== void 0)
            return packedValue;
          throw new Error("Unknown token " + token);
      }
    default:
      if (isNaN(token)) {
        let error = new Error("Unexpected end of CBOR data");
        error.incomplete = true;
        throw error;
      }
      throw new Error("Unknown CBOR token " + token);
  }
}
var validName = /^[a-zA-Z_$][a-zA-Z\d_$]*$/;
function createStructureReader(structure) {
  if (!structure) throw new Error("Structure is required in record definition");
  function readObject() {
    let length = src[position++];
    length = length & 31;
    if (length > 23) {
      switch (length) {
        case 24:
          length = src[position++];
          break;
        case 25:
          length = dataView.getUint16(position);
          position += 2;
          break;
        case 26:
          length = dataView.getUint32(position);
          position += 4;
          break;
        default:
          throw new Error("Expected array header, but got " + src[position - 1]);
      }
    }
    let compiledReader = this.compiledReader;
    while (compiledReader) {
      if (compiledReader.propertyCount === length)
        return compiledReader(read);
      compiledReader = compiledReader.next;
    }
    if (this.slowReads++ >= inlineObjectReadThreshold) {
      let array = this.length == length ? this : this.slice(0, length);
      compiledReader = currentDecoder.keyMap ? new Function("r", "return {" + array.map((k) => currentDecoder.decodeKey(k)).map((k) => validName.test(k) ? safeKey(k) + ":r()" : "[" + JSON.stringify(k) + "]:r()").join(",") + "}") : new Function("r", "return {" + array.map((key) => validName.test(key) ? safeKey(key) + ":r()" : "[" + JSON.stringify(key) + "]:r()").join(",") + "}");
      if (this.compiledReader)
        compiledReader.next = this.compiledReader;
      compiledReader.propertyCount = length;
      this.compiledReader = compiledReader;
      return compiledReader(read);
    }
    let object = {};
    if (currentDecoder.keyMap) for (let i = 0; i < length; i++) object[safeKey(currentDecoder.decodeKey(this[i]))] = read();
    else for (let i = 0; i < length; i++) {
      object[safeKey(this[i])] = read();
    }
    return object;
  }
  structure.slowReads = 0;
  return readObject;
}
function safeKey(key) {
  if (typeof key === "string") return key === "__proto__" ? "__proto_" : key;
  if (typeof key === "number" || typeof key === "boolean" || typeof key === "bigint") return key.toString();
  if (key == null) return key + "";
  throw new Error("Invalid property name type " + typeof key);
}
var readFixedString = readStringJS;
function readStringJS(length) {
  let result;
  if (length < 16) {
    if (result = shortStringInJS(length))
      return result;
  }
  if (length > 64 && decoder)
    return decoder.decode(src.subarray(position, position += length));
  const end = position + length;
  const units = [];
  result = "";
  while (position < end) {
    const byte1 = src[position++];
    if ((byte1 & 128) === 0) {
      units.push(byte1);
    } else if ((byte1 & 224) === 192) {
      const byte2 = src[position++] & 63;
      const codePoint = (byte1 & 31) << 6 | byte2;
      if (codePoint < 128) {
        units.push(65533);
      } else {
        units.push(codePoint);
      }
    } else if ((byte1 & 240) === 224) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      const codePoint = (byte1 & 31) << 12 | byte2 << 6 | byte3;
      if (codePoint < 2048 || codePoint >= 55296 && codePoint <= 57343) {
        units.push(65533);
      } else {
        units.push(codePoint);
      }
    } else if ((byte1 & 248) === 240) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      const byte4 = src[position++] & 63;
      let unit = (byte1 & 7) << 18 | byte2 << 12 | byte3 << 6 | byte4;
      if (unit < 65536 || unit > 1114111) {
        units.push(65533);
      } else if (unit > 65535) {
        unit -= 65536;
        units.push(unit >>> 10 & 1023 | 55296);
        unit = 56320 | unit & 1023;
        units.push(unit);
      } else {
        units.push(unit);
      }
    } else {
      units.push(65533);
    }
    if (units.length >= 4096) {
      result += fromCharCode.apply(String, units);
      units.length = 0;
    }
  }
  if (units.length > 0) {
    result += fromCharCode.apply(String, units);
  }
  return result;
}
var fromCharCode = String.fromCharCode;
function longStringInJS(length) {
  let start = position;
  let bytes = new Array(length);
  for (let i = 0; i < length; i++) {
    const byte = src[position++];
    if ((byte & 128) > 0) {
      position = start;
      return;
    }
    bytes[i] = byte;
  }
  return fromCharCode.apply(String, bytes);
}
function shortStringInJS(length) {
  if (length < 4) {
    if (length < 2) {
      if (length === 0)
        return "";
      else {
        let a = src[position++];
        if ((a & 128) > 1) {
          position -= 1;
          return;
        }
        return fromCharCode(a);
      }
    } else {
      let a = src[position++];
      let b = src[position++];
      if ((a & 128) > 0 || (b & 128) > 0) {
        position -= 2;
        return;
      }
      if (length < 3)
        return fromCharCode(a, b);
      let c = src[position++];
      if ((c & 128) > 0) {
        position -= 3;
        return;
      }
      return fromCharCode(a, b, c);
    }
  } else {
    let a = src[position++];
    let b = src[position++];
    let c = src[position++];
    let d = src[position++];
    if ((a & 128) > 0 || (b & 128) > 0 || (c & 128) > 0 || (d & 128) > 0) {
      position -= 4;
      return;
    }
    if (length < 6) {
      if (length === 4)
        return fromCharCode(a, b, c, d);
      else {
        let e = src[position++];
        if ((e & 128) > 0) {
          position -= 5;
          return;
        }
        return fromCharCode(a, b, c, d, e);
      }
    } else if (length < 8) {
      let e = src[position++];
      let f = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0) {
        position -= 6;
        return;
      }
      if (length < 7)
        return fromCharCode(a, b, c, d, e, f);
      let g = src[position++];
      if ((g & 128) > 0) {
        position -= 7;
        return;
      }
      return fromCharCode(a, b, c, d, e, f, g);
    } else {
      let e = src[position++];
      let f = src[position++];
      let g = src[position++];
      let h = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0 || (g & 128) > 0 || (h & 128) > 0) {
        position -= 8;
        return;
      }
      if (length < 10) {
        if (length === 8)
          return fromCharCode(a, b, c, d, e, f, g, h);
        else {
          let i = src[position++];
          if ((i & 128) > 0) {
            position -= 9;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i);
        }
      } else if (length < 12) {
        let i = src[position++];
        let j = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0) {
          position -= 10;
          return;
        }
        if (length < 11)
          return fromCharCode(a, b, c, d, e, f, g, h, i, j);
        let k = src[position++];
        if ((k & 128) > 0) {
          position -= 11;
          return;
        }
        return fromCharCode(a, b, c, d, e, f, g, h, i, j, k);
      } else {
        let i = src[position++];
        let j = src[position++];
        let k = src[position++];
        let l = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0 || (k & 128) > 0 || (l & 128) > 0) {
          position -= 12;
          return;
        }
        if (length < 14) {
          if (length === 12)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l);
          else {
            let m = src[position++];
            if ((m & 128) > 0) {
              position -= 13;
              return;
            }
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m);
          }
        } else {
          let m = src[position++];
          let n = src[position++];
          if ((m & 128) > 0 || (n & 128) > 0) {
            position -= 14;
            return;
          }
          if (length < 15)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n);
          let o = src[position++];
          if ((o & 128) > 0) {
            position -= 15;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o);
        }
      }
    }
  }
}
function readBin(length) {
  return currentDecoder.copyBuffers ? (
    // specifically use the copying slice (not the node one)
    Uint8Array.prototype.slice.call(src, position, position += length)
  ) : src.subarray(position, position += length);
}
var f32Array = new Float32Array(1);
var u8Array = new Uint8Array(f32Array.buffer, 0, 4);
function getFloat16() {
  let byte0 = src[position++];
  let byte1 = src[position++];
  let exponent = (byte0 & 127) >> 2;
  if (exponent === 31) {
    if (byte1 || byte0 & 3)
      return NaN;
    return byte0 & 128 ? -Infinity : Infinity;
  }
  if (exponent === 0) {
    let abs = ((byte0 & 3) << 8 | byte1) / (1 << 24);
    return byte0 & 128 ? -abs : abs;
  }
  u8Array[3] = byte0 & 128 | // sign bit
  (exponent >> 1) + 56;
  u8Array[2] = (byte0 & 7) << 5 | // last exponent bit and first two mantissa bits
  byte1 >> 3;
  u8Array[1] = byte1 << 5;
  u8Array[0] = 0;
  return f32Array[0];
}
var keyCache = new Array(4096);
var Tag = class {
  constructor(value, tag) {
    this.value = value;
    this.tag = tag;
  }
};
currentExtensions[0] = (dateString) => {
  return new Date(dateString);
};
currentExtensions[1] = (epochSec) => {
  return new Date(Math.round(epochSec * 1e3));
};
currentExtensions[2] = (buffer) => {
  let value = BigInt(0);
  for (let i = 0, l = buffer.byteLength; i < l; i++) {
    value = BigInt(buffer[i]) + (value << BigInt(8));
  }
  return value;
};
currentExtensions[3] = (buffer) => {
  return BigInt(-1) - currentExtensions[2](buffer);
};
currentExtensions[4] = (fraction) => {
  return +(fraction[1] + "e" + fraction[0]);
};
currentExtensions[5] = (fraction) => {
  return fraction[1] * Math.exp(fraction[0] * Math.log(2));
};
var recordDefinition = (id2, structure) => {
  id2 = id2 - 57344;
  let existingStructure = currentStructures[id2];
  if (existingStructure && existingStructure.isShared) {
    (currentStructures.restoreStructures || (currentStructures.restoreStructures = []))[id2] = existingStructure;
  }
  currentStructures[id2] = structure;
  structure.read = createStructureReader(structure);
};
currentExtensions[LEGACY_RECORD_INLINE_ID] = (data) => {
  let length = data.length;
  let structure = data[1];
  recordDefinition(data[0], structure);
  let object = {};
  for (let i = 2; i < length; i++) {
    let key = structure[i - 2];
    object[safeKey(key)] = data[i];
  }
  return object;
};
currentExtensions[14] = (value) => {
  if (bundledStrings)
    return bundledStrings[0].slice(bundledStrings.position0, bundledStrings.position0 += value);
  return new Tag(value, 14);
};
currentExtensions[15] = (value) => {
  if (bundledStrings)
    return bundledStrings[1].slice(bundledStrings.position1, bundledStrings.position1 += value);
  return new Tag(value, 15);
};
var glbl = { Error, RegExp };
currentExtensions[27] = (data) => {
  return (glbl[data[0]] || Error)(data[1], data[2]);
};
var packedTable = (read2) => {
  if (src[position++] != 132) {
    let error = new Error("Packed values structure must be followed by a 4 element array");
    if (src.length < position)
      error.incomplete = true;
    throw error;
  }
  let newPackedValues = read2();
  if (!newPackedValues || !newPackedValues.length) {
    let error = new Error("Packed values structure must be followed by a 4 element array");
    error.incomplete = true;
    throw error;
  }
  packedValues = packedValues ? newPackedValues.concat(packedValues.slice(newPackedValues.length)) : newPackedValues;
  packedValues.prefixes = read2();
  packedValues.suffixes = read2();
  return read2();
};
packedTable.handlesRead = true;
currentExtensions[51] = packedTable;
currentExtensions[PACKED_REFERENCE_TAG_ID] = (data) => {
  if (!packedValues) {
    if (currentDecoder.getShared)
      loadShared();
    else
      return new Tag(data, PACKED_REFERENCE_TAG_ID);
  }
  if (typeof data == "number")
    return packedValues[16 + (data >= 0 ? 2 * data : -2 * data - 1)];
  let error = new Error("No support for non-integer packed references yet");
  if (data === void 0)
    error.incomplete = true;
  throw error;
};
currentExtensions[28] = (read2) => {
  if (!referenceMap) {
    referenceMap = /* @__PURE__ */ new Map();
    referenceMap.id = 0;
  }
  let id2 = referenceMap.id++;
  let startingPosition = position;
  let token = src[position];
  let target2;
  if (token >> 5 == 4)
    target2 = [];
  else
    target2 = {};
  let refEntry = { target: target2 };
  referenceMap.set(id2, refEntry);
  let targetProperties = read2();
  if (refEntry.used) {
    if (Object.getPrototypeOf(target2) !== Object.getPrototypeOf(targetProperties)) {
      position = startingPosition;
      target2 = targetProperties;
      referenceMap.set(id2, { target: target2 });
      targetProperties = read2();
    }
    return Object.assign(target2, targetProperties);
  }
  refEntry.target = targetProperties;
  return targetProperties;
};
currentExtensions[28].handlesRead = true;
currentExtensions[29] = (id2) => {
  let refEntry = referenceMap.get(id2);
  refEntry.used = true;
  return refEntry.target;
};
currentExtensions[258] = (array) => new Set(array);
(currentExtensions[259] = (read2) => {
  if (currentDecoder.mapsAsObjects) {
    currentDecoder.mapsAsObjects = false;
    restoreMapsAsObject = true;
  }
  return read2();
}).handlesRead = true;
function combine(a, b) {
  if (typeof a === "string")
    return a + b;
  if (a instanceof Array)
    return a.concat(b);
  return Object.assign({}, a, b);
}
function getPackedValues() {
  if (!packedValues) {
    if (currentDecoder.getShared)
      loadShared();
    else
      throw new Error("No packed values available");
  }
  return packedValues;
}
var SHARED_DATA_TAG_ID = 1399353956;
currentExtensionRanges.push((tag, input) => {
  if (tag >= 225 && tag <= 255)
    return combine(getPackedValues().prefixes[tag - 224], input);
  if (tag >= 28704 && tag <= 32767)
    return combine(getPackedValues().prefixes[tag - 28672], input);
  if (tag >= 1879052288 && tag <= 2147483647)
    return combine(getPackedValues().prefixes[tag - 1879048192], input);
  if (tag >= 216 && tag <= 223)
    return combine(input, getPackedValues().suffixes[tag - 216]);
  if (tag >= 27647 && tag <= 28671)
    return combine(input, getPackedValues().suffixes[tag - 27639]);
  if (tag >= 1811940352 && tag <= 1879048191)
    return combine(input, getPackedValues().suffixes[tag - 1811939328]);
  if (tag == SHARED_DATA_TAG_ID) {
    return {
      packedValues,
      structures: currentStructures.slice(0),
      version: input
    };
  }
  if (tag == 55799)
    return input;
});
var isLittleEndianMachine = new Uint8Array(new Uint16Array([1]).buffer)[0] == 1;
var typedArrays = [
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  typeof BigUint64Array == "undefined" ? { name: "BigUint64Array" } : BigUint64Array,
  Int8Array,
  Int16Array,
  Int32Array,
  typeof BigInt64Array == "undefined" ? { name: "BigInt64Array" } : BigInt64Array,
  Float32Array,
  Float64Array
];
var typedArrayTags = [64, 68, 69, 70, 71, 72, 77, 78, 79, 85, 86];
for (let i = 0; i < typedArrays.length; i++) {
  registerTypedArray(typedArrays[i], typedArrayTags[i]);
}
function registerTypedArray(TypedArray, tag) {
  let dvMethod = "get" + TypedArray.name.slice(0, -5);
  let bytesPerElement;
  if (typeof TypedArray === "function")
    bytesPerElement = TypedArray.BYTES_PER_ELEMENT;
  else
    TypedArray = null;
  for (let littleEndian = 0; littleEndian < 2; littleEndian++) {
    if (!littleEndian && bytesPerElement == 1)
      continue;
    let sizeShift = bytesPerElement == 2 ? 1 : bytesPerElement == 4 ? 2 : bytesPerElement == 8 ? 3 : 0;
    currentExtensions[littleEndian ? tag : tag - 4] = bytesPerElement == 1 || littleEndian == isLittleEndianMachine ? (buffer) => {
      if (!TypedArray)
        throw new Error("Could not find typed array for code " + tag);
      if (!currentDecoder.copyBuffers) {
        if (bytesPerElement === 1 || bytesPerElement === 2 && !(buffer.byteOffset & 1) || bytesPerElement === 4 && !(buffer.byteOffset & 3) || bytesPerElement === 8 && !(buffer.byteOffset & 7))
          return new TypedArray(buffer.buffer, buffer.byteOffset, buffer.byteLength >> sizeShift);
      }
      return new TypedArray(Uint8Array.prototype.slice.call(buffer, 0).buffer);
    } : (buffer) => {
      if (!TypedArray)
        throw new Error("Could not find typed array for code " + tag);
      let dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      let elements = buffer.length >> sizeShift;
      let ta = new TypedArray(elements);
      let method = dv[dvMethod];
      for (let i = 0; i < elements; i++) {
        ta[i] = method.call(dv, i << sizeShift, littleEndian);
      }
      return ta;
    };
  }
}
function readBundleExt() {
  let length = readJustLength();
  let bundlePosition = position + read();
  for (let i = 2; i < length; i++) {
    let bundleLength = readJustLength();
    position += bundleLength;
  }
  let dataPosition = position;
  position = bundlePosition;
  bundledStrings = [readStringJS(readJustLength()), readStringJS(readJustLength())];
  bundledStrings.position0 = 0;
  bundledStrings.position1 = 0;
  bundledStrings.postBundlePosition = position;
  position = dataPosition;
  return read();
}
function readJustLength() {
  let token = src[position++] & 31;
  if (token > 23) {
    switch (token) {
      case 24:
        token = src[position++];
        break;
      case 25:
        token = dataView.getUint16(position);
        position += 2;
        break;
      case 26:
        token = dataView.getUint32(position);
        position += 4;
        break;
    }
  }
  return token;
}
function loadShared() {
  if (currentDecoder.getShared) {
    let sharedData = saveState(() => {
      src = null;
      return currentDecoder.getShared();
    }) || {};
    let updatedStructures = sharedData.structures || [];
    currentDecoder.sharedVersion = sharedData.version;
    packedValues = currentDecoder.sharedValues = sharedData.packedValues;
    if (currentStructures === true)
      currentDecoder.structures = currentStructures = updatedStructures;
    else
      currentStructures.splice.apply(currentStructures, [0, updatedStructures.length].concat(updatedStructures));
  }
}
function saveState(callback) {
  let savedSrcEnd = srcEnd;
  let savedPosition = position;
  let savedStringPosition = stringPosition;
  let savedSrcStringStart = srcStringStart;
  let savedSrcStringEnd = srcStringEnd;
  let savedSrcString = srcString;
  let savedStrings = strings;
  let savedReferenceMap = referenceMap;
  let savedBundledStrings = bundledStrings;
  let savedSrc = new Uint8Array(src.slice(0, srcEnd));
  let savedStructures = currentStructures;
  let savedDecoder = currentDecoder;
  let savedSequentialMode = sequentialMode;
  let value = callback();
  srcEnd = savedSrcEnd;
  position = savedPosition;
  stringPosition = savedStringPosition;
  srcStringStart = savedSrcStringStart;
  srcStringEnd = savedSrcStringEnd;
  srcString = savedSrcString;
  strings = savedStrings;
  referenceMap = savedReferenceMap;
  bundledStrings = savedBundledStrings;
  src = savedSrc;
  sequentialMode = savedSequentialMode;
  currentStructures = savedStructures;
  currentDecoder = savedDecoder;
  dataView = new DataView(src.buffer, src.byteOffset, src.byteLength);
  return value;
}
function clearSource() {
  src = null;
  referenceMap = null;
  currentStructures = null;
}
var mult10 = new Array(147);
for (let i = 0; i < 256; i++) {
  mult10[i] = +("1e" + Math.floor(45.15 - i * 0.30103));
}
var defaultDecoder = new Decoder({ useRecords: false });
var decode = defaultDecoder.decode;
var decodeMultiple = defaultDecoder.decodeMultiple;
var FLOAT32_OPTIONS = {
  NEVER: 0,
  ALWAYS: 1,
  DECIMAL_ROUND: 3,
  DECIMAL_FIT: 4
};

// node_modules/cbor-x/encode.js
var textEncoder;
try {
  textEncoder = new TextEncoder();
} catch (error) {
}
var extensions;
var extensionClasses;
var Buffer2 = typeof globalThis === "object" && globalThis.Buffer;
var hasNodeBuffer = typeof Buffer2 !== "undefined";
var ByteArrayAllocate = hasNodeBuffer ? Buffer2.allocUnsafeSlow : Uint8Array;
var ByteArray = hasNodeBuffer ? Buffer2 : Uint8Array;
var MAX_STRUCTURES = 256;
var MAX_BUFFER_SIZE = hasNodeBuffer ? 4294967296 : 2144337920;
var throwOnIterable;
var target;
var targetView;
var position2 = 0;
var safeEnd;
var bundledStrings2 = null;
var MAX_BUNDLE_SIZE = 61440;
var hasNonLatin = /[\u0080-\uFFFF]/;
var RECORD_SYMBOL = /* @__PURE__ */ Symbol("record-id");
var Encoder = class extends Decoder {
  constructor(options) {
    super(options);
    this.offset = 0;
    let typeBuffer;
    let start;
    let sharedStructures;
    let hasSharedUpdate;
    let structures;
    let referenceMap2;
    options = options || {};
    let encodeUtf8 = ByteArray.prototype.utf8Write ? function(string, position3) {
      return target.utf8Write(string, position3, target.byteLength - position3);
    } : textEncoder && textEncoder.encodeInto ? function(string, position3) {
      return textEncoder.encodeInto(string, target.subarray(position3)).written;
    } : false;
    let encoder = this;
    let hasSharedStructures = options.structures || options.saveStructures;
    let maxSharedStructures = options.maxSharedStructures;
    if (maxSharedStructures == null)
      maxSharedStructures = hasSharedStructures ? 128 : 0;
    if (maxSharedStructures > 8190)
      throw new Error("Maximum maxSharedStructure is 8190");
    let isSequential = options.sequential;
    if (isSequential) {
      maxSharedStructures = 0;
    }
    if (!this.structures)
      this.structures = [];
    if (this.saveStructures)
      this.saveShared = this.saveStructures;
    let samplingPackedValues, packedObjectMap2, sharedValues = options.sharedValues;
    let sharedPackedObjectMap2;
    if (sharedValues) {
      sharedPackedObjectMap2 = /* @__PURE__ */ Object.create(null);
      for (let i = 0, l = sharedValues.length; i < l; i++) {
        sharedPackedObjectMap2[sharedValues[i]] = i;
      }
    }
    let recordIdsToRemove = [];
    let transitionsCount = 0;
    let serializationsSinceTransitionRebuild = 0;
    this.mapEncode = function(value, encodeOptions) {
      if (this._keyMap && !this._mapped) {
        switch (value.constructor.name) {
          case "Array":
            value = value.map((r) => this.encodeKeys(r));
            break;
        }
      }
      return this.encode(value, encodeOptions);
    };
    this.encode = function(value, encodeOptions) {
      if (!target) {
        target = new ByteArrayAllocate(8192);
        targetView = new DataView(target.buffer, 0, 8192);
        position2 = 0;
      }
      safeEnd = target.length - 10;
      if (safeEnd - position2 < 2048) {
        target = new ByteArrayAllocate(target.length);
        targetView = new DataView(target.buffer, 0, target.length);
        safeEnd = target.length - 10;
        position2 = 0;
      } else if (encodeOptions === REUSE_BUFFER_MODE)
        position2 = position2 + 7 & 2147483640;
      start = position2;
      if (encoder.useSelfDescribedHeader) {
        targetView.setUint32(position2, 3654940416);
        position2 += 3;
      }
      referenceMap2 = encoder.structuredClone ? /* @__PURE__ */ new Map() : null;
      if (encoder.bundleStrings && typeof value !== "string") {
        bundledStrings2 = [];
        bundledStrings2.size = Infinity;
      } else
        bundledStrings2 = null;
      sharedStructures = encoder.structures;
      if (sharedStructures) {
        if (sharedStructures.uninitialized) {
          let sharedData = encoder.getShared() || {};
          encoder.structures = sharedStructures = sharedData.structures || [];
          encoder.sharedVersion = sharedData.version;
          let sharedValues2 = encoder.sharedValues = sharedData.packedValues;
          if (sharedValues2) {
            sharedPackedObjectMap2 = {};
            for (let i = 0, l = sharedValues2.length; i < l; i++)
              sharedPackedObjectMap2[sharedValues2[i]] = i;
          }
        }
        let sharedStructuresLength = sharedStructures.length;
        if (sharedStructuresLength > maxSharedStructures && !isSequential)
          sharedStructuresLength = maxSharedStructures;
        if (!sharedStructures.transitions) {
          sharedStructures.transitions = /* @__PURE__ */ Object.create(null);
          for (let i = 0; i < sharedStructuresLength; i++) {
            let keys = sharedStructures[i];
            if (!keys)
              continue;
            let nextTransition, transition = sharedStructures.transitions;
            for (let j = 0, l = keys.length; j < l; j++) {
              if (transition[RECORD_SYMBOL] === void 0)
                transition[RECORD_SYMBOL] = i;
              let key = keys[j];
              nextTransition = transition[key];
              if (!nextTransition) {
                nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
              }
              transition = nextTransition;
            }
            transition[RECORD_SYMBOL] = i | 1048576;
          }
        }
        if (!isSequential)
          sharedStructures.nextId = sharedStructuresLength;
      }
      if (hasSharedUpdate)
        hasSharedUpdate = false;
      structures = sharedStructures || [];
      packedObjectMap2 = sharedPackedObjectMap2;
      if (options.pack) {
        let packedValues2 = /* @__PURE__ */ new Map();
        packedValues2.values = [];
        packedValues2.encoder = encoder;
        packedValues2.maxValues = options.maxPrivatePackedValues || (sharedPackedObjectMap2 ? 16 : Infinity);
        packedValues2.objectMap = sharedPackedObjectMap2 || false;
        packedValues2.samplingPackedValues = samplingPackedValues;
        findRepetitiveStrings(value, packedValues2);
        if (packedValues2.values.length > 0) {
          target[position2++] = 216;
          target[position2++] = 51;
          writeArrayHeader(4);
          let valuesArray = packedValues2.values;
          encode2(valuesArray);
          writeArrayHeader(0);
          writeArrayHeader(0);
          packedObjectMap2 = Object.create(sharedPackedObjectMap2 || null);
          for (let i = 0, l = valuesArray.length; i < l; i++) {
            packedObjectMap2[valuesArray[i]] = i;
          }
        }
      }
      throwOnIterable = encodeOptions & THROW_ON_ITERABLE;
      try {
        if (throwOnIterable)
          return;
        encode2(value);
        if (bundledStrings2) {
          writeBundles(start, encode2);
        }
        encoder.offset = position2;
        if (referenceMap2 && referenceMap2.idsToInsert) {
          position2 += referenceMap2.idsToInsert.length * 2;
          if (position2 > safeEnd)
            makeRoom(position2);
          encoder.offset = position2;
          let serialized = insertIds(target.subarray(start, position2), referenceMap2.idsToInsert);
          referenceMap2 = null;
          return serialized;
        }
        if (encodeOptions & REUSE_BUFFER_MODE) {
          target.start = start;
          target.end = position2;
          return target;
        }
        return target.subarray(start, position2);
      } finally {
        if (sharedStructures) {
          if (serializationsSinceTransitionRebuild < 10)
            serializationsSinceTransitionRebuild++;
          if (sharedStructures.length > maxSharedStructures)
            sharedStructures.length = maxSharedStructures;
          if (transitionsCount > 1e4) {
            sharedStructures.transitions = null;
            serializationsSinceTransitionRebuild = 0;
            transitionsCount = 0;
            if (recordIdsToRemove.length > 0)
              recordIdsToRemove = [];
          } else if (recordIdsToRemove.length > 0 && !isSequential) {
            for (let i = 0, l = recordIdsToRemove.length; i < l; i++) {
              recordIdsToRemove[i][RECORD_SYMBOL] = void 0;
            }
            recordIdsToRemove = [];
          }
        }
        if (hasSharedUpdate && encoder.saveShared) {
          if (encoder.structures.length > maxSharedStructures) {
            encoder.structures = encoder.structures.slice(0, maxSharedStructures);
          }
          let returnBuffer = target.subarray(start, position2);
          if (encoder.updateSharedData() === false)
            return encoder.encode(value);
          return returnBuffer;
        }
        if (encodeOptions & RESET_BUFFER_MODE)
          position2 = start;
      }
    };
    this.findCommonStringsToPack = () => {
      samplingPackedValues = /* @__PURE__ */ new Map();
      if (!sharedPackedObjectMap2)
        sharedPackedObjectMap2 = /* @__PURE__ */ Object.create(null);
      return (options2) => {
        let threshold = options2 && options2.threshold || 4;
        let position3 = this.pack ? options2.maxPrivatePackedValues || 16 : 0;
        if (!sharedValues)
          sharedValues = this.sharedValues = [];
        for (let [key, status] of samplingPackedValues) {
          if (status.count > threshold) {
            sharedPackedObjectMap2[key] = position3++;
            sharedValues.push(key);
            hasSharedUpdate = true;
          }
        }
        while (this.saveShared && this.updateSharedData() === false) {
        }
        samplingPackedValues = null;
      };
    };
    const encode2 = (value) => {
      if (position2 > safeEnd)
        target = makeRoom(position2);
      var type = typeof value;
      var length;
      if (type === "string") {
        if (packedObjectMap2) {
          let packedPosition = packedObjectMap2[value];
          if (packedPosition >= 0) {
            if (packedPosition < 16)
              target[position2++] = packedPosition + 224;
            else {
              target[position2++] = 198;
              if (packedPosition & 1)
                encode2(15 - packedPosition >> 1);
              else
                encode2(packedPosition - 16 >> 1);
            }
            return;
          } else if (samplingPackedValues && !options.pack) {
            let status = samplingPackedValues.get(value);
            if (status)
              status.count++;
            else
              samplingPackedValues.set(value, {
                count: 1
              });
          }
        }
        let strLength = value.length;
        if (bundledStrings2 && strLength >= 4 && strLength < 1024) {
          if ((bundledStrings2.size += strLength) > MAX_BUNDLE_SIZE) {
            let extStart;
            let maxBytes2 = (bundledStrings2[0] ? bundledStrings2[0].length * 3 + bundledStrings2[1].length : 0) + 10;
            if (position2 + maxBytes2 > safeEnd)
              target = makeRoom(position2 + maxBytes2);
            target[position2++] = 217;
            target[position2++] = 223;
            target[position2++] = 249;
            target[position2++] = bundledStrings2.position ? 132 : 130;
            target[position2++] = 26;
            extStart = position2 - start;
            position2 += 4;
            if (bundledStrings2.position) {
              writeBundles(start, encode2);
            }
            bundledStrings2 = ["", ""];
            bundledStrings2.size = 0;
            bundledStrings2.position = extStart;
          }
          let twoByte = hasNonLatin.test(value);
          bundledStrings2[twoByte ? 0 : 1] += value;
          target[position2++] = twoByte ? 206 : 207;
          encode2(strLength);
          return;
        }
        let headerSize;
        if (strLength < 32) {
          headerSize = 1;
        } else if (strLength < 256) {
          headerSize = 2;
        } else if (strLength < 65536) {
          headerSize = 3;
        } else {
          headerSize = 5;
        }
        let maxBytes = strLength * 3;
        if (position2 + maxBytes > safeEnd)
          target = makeRoom(position2 + maxBytes);
        if (strLength < 64 || !encodeUtf8) {
          let i, c1, c2, strPosition = position2 + headerSize;
          for (i = 0; i < strLength; i++) {
            c1 = value.charCodeAt(i);
            if (c1 < 128) {
              target[strPosition++] = c1;
            } else if (c1 < 2048) {
              target[strPosition++] = c1 >> 6 | 192;
              target[strPosition++] = c1 & 63 | 128;
            } else if ((c1 & 64512) === 55296 && ((c2 = value.charCodeAt(i + 1)) & 64512) === 56320) {
              c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
              i++;
              target[strPosition++] = c1 >> 18 | 240;
              target[strPosition++] = c1 >> 12 & 63 | 128;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            } else {
              target[strPosition++] = c1 >> 12 | 224;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            }
          }
          length = strPosition - position2 - headerSize;
        } else {
          length = encodeUtf8(value, position2 + headerSize, maxBytes);
        }
        if (length < 24) {
          target[position2++] = 96 | length;
        } else if (length < 256) {
          if (headerSize < 2) {
            target.copyWithin(position2 + 2, position2 + 1, position2 + 1 + length);
          }
          target[position2++] = 120;
          target[position2++] = length;
        } else if (length < 65536) {
          if (headerSize < 3) {
            target.copyWithin(position2 + 3, position2 + 2, position2 + 2 + length);
          }
          target[position2++] = 121;
          target[position2++] = length >> 8;
          target[position2++] = length & 255;
        } else {
          if (headerSize < 5) {
            target.copyWithin(position2 + 5, position2 + 3, position2 + 3 + length);
          }
          target[position2++] = 122;
          targetView.setUint32(position2, length);
          position2 += 4;
        }
        position2 += length;
      } else if (type === "number") {
        if (!this.alwaysUseFloat && value >>> 0 === value) {
          if (value < 24) {
            target[position2++] = value;
          } else if (value < 256) {
            target[position2++] = 24;
            target[position2++] = value;
          } else if (value < 65536) {
            target[position2++] = 25;
            target[position2++] = value >> 8;
            target[position2++] = value & 255;
          } else {
            target[position2++] = 26;
            targetView.setUint32(position2, value);
            position2 += 4;
          }
        } else if (!this.alwaysUseFloat && value >> 0 === value) {
          if (value >= -24) {
            target[position2++] = 31 - value;
          } else if (value >= -256) {
            target[position2++] = 56;
            target[position2++] = ~value;
          } else if (value >= -65536) {
            target[position2++] = 57;
            targetView.setUint16(position2, ~value);
            position2 += 2;
          } else {
            target[position2++] = 58;
            targetView.setUint32(position2, ~value);
            position2 += 4;
          }
        } else if (!this.alwaysUseFloat && value < 0 && value >= -4294967296 && Math.floor(value) === value) {
          target[position2++] = 58;
          targetView.setUint32(position2, -1 - value);
          position2 += 4;
        } else {
          let useFloat32;
          if ((useFloat32 = this.useFloat32) > 0 && value < 4294967296 && value >= -2147483648) {
            target[position2++] = 250;
            targetView.setFloat32(position2, value);
            let xShifted;
            if (useFloat32 < 4 || // this checks for rounding of numbers that were encoded in 32-bit float to nearest significant decimal digit that could be preserved
            (xShifted = value * mult10[(target[position2] & 127) << 1 | target[position2 + 1] >> 7]) >> 0 === xShifted) {
              position2 += 4;
              return;
            } else
              position2--;
          }
          target[position2++] = 251;
          targetView.setFloat64(position2, value);
          position2 += 8;
        }
      } else if (type === "object") {
        if (!value)
          target[position2++] = 246;
        else {
          if (referenceMap2) {
            let referee = referenceMap2.get(value);
            if (referee) {
              target[position2++] = 216;
              target[position2++] = 29;
              target[position2++] = 25;
              if (!referee.references) {
                let idsToInsert = referenceMap2.idsToInsert || (referenceMap2.idsToInsert = []);
                referee.references = [];
                idsToInsert.push(referee);
              }
              referee.references.push(position2 - start);
              position2 += 2;
              return;
            } else
              referenceMap2.set(value, { offset: position2 - start });
          }
          let constructor = value.constructor;
          if (constructor === Object) {
            if (this.skipFunction === true) {
              value = Object.fromEntries([...Object.keys(value).filter((x) => typeof value[x] !== "function").map((x) => [x, value[x]])]);
            }
            writeObject(value);
          } else if (constructor === Array) {
            length = value.length;
            if (length < 24) {
              target[position2++] = 128 | length;
            } else {
              writeArrayHeader(length);
            }
            for (let i = 0; i < length; i++) {
              encode2(value[i]);
            }
          } else if (constructor === Map) {
            if (this.mapsAsObjects ? this.useTag259ForMaps !== false : this.useTag259ForMaps) {
              target[position2++] = 217;
              target[position2++] = 1;
              target[position2++] = 3;
            }
            length = value.size;
            if (length < 24) {
              target[position2++] = 160 | length;
            } else if (length < 256) {
              target[position2++] = 184;
              target[position2++] = length;
            } else if (length < 65536) {
              target[position2++] = 185;
              target[position2++] = length >> 8;
              target[position2++] = length & 255;
            } else {
              target[position2++] = 186;
              targetView.setUint32(position2, length);
              position2 += 4;
            }
            if (encoder.keyMap) {
              for (let [key, entryValue] of value) {
                encode2(encoder.encodeKey(key));
                encode2(entryValue);
              }
            } else {
              for (let [key, entryValue] of value) {
                encode2(key);
                encode2(entryValue);
              }
            }
          } else {
            for (let i = 0, l = extensions.length; i < l; i++) {
              let extensionClass = extensionClasses[i];
              if (value instanceof extensionClass) {
                let extension = extensions[i];
                let tag = extension.tag;
                if (tag == void 0)
                  tag = extension.getTag && extension.getTag.call(this, value);
                if (tag < 24) {
                  target[position2++] = 192 | tag;
                } else if (tag < 256) {
                  target[position2++] = 216;
                  target[position2++] = tag;
                } else if (tag < 65536) {
                  target[position2++] = 217;
                  target[position2++] = tag >> 8;
                  target[position2++] = tag & 255;
                } else if (tag > -1) {
                  target[position2++] = 218;
                  targetView.setUint32(position2, tag);
                  position2 += 4;
                }
                extension.encode.call(this, value, encode2, makeRoom);
                return;
              }
            }
            if (value[Symbol.iterator]) {
              if (throwOnIterable) {
                let error = new Error("Iterable should be serialized as iterator");
                error.iteratorNotHandled = true;
                throw error;
              }
              target[position2++] = 159;
              for (let entry of value) {
                encode2(entry);
              }
              target[position2++] = 255;
              return;
            }
            if (value[Symbol.asyncIterator] || isBlob(value)) {
              let error = new Error("Iterable/blob should be serialized as iterator");
              error.iteratorNotHandled = true;
              throw error;
            }
            if (this.useToJSON && value.toJSON) {
              const json = value.toJSON();
              if (json !== value)
                return encode2(json);
            }
            writeObject(value);
          }
        }
      } else if (type === "boolean") {
        target[position2++] = value ? 245 : 244;
      } else if (type === "bigint") {
        if (value < BigInt(1) << BigInt(64) && value >= 0) {
          target[position2++] = 27;
          targetView.setBigUint64(position2, value);
        } else if (value > -(BigInt(1) << BigInt(64)) && value < 0) {
          target[position2++] = 59;
          targetView.setBigUint64(position2, -value - BigInt(1));
        } else {
          if (this.largeBigIntToFloat) {
            target[position2++] = 251;
            targetView.setFloat64(position2, Number(value));
          } else {
            if (value >= BigInt(0))
              target[position2++] = 194;
            else {
              target[position2++] = 195;
              value = BigInt(-1) - value;
            }
            let bytes = [];
            while (value) {
              bytes.push(Number(value & BigInt(255)));
              value >>= BigInt(8);
            }
            writeBuffer(new Uint8Array(bytes.reverse()), makeRoom);
            return;
          }
        }
        position2 += 8;
      } else if (type === "undefined") {
        target[position2++] = 247;
      } else {
        throw new Error("Unknown type: " + type);
      }
    };
    const writeObject = this.useRecords === false ? this.variableMapSize ? (object) => {
      let keys = Object.keys(object);
      let vals = Object.values(object);
      let length = keys.length;
      if (length < 24) {
        target[position2++] = 160 | length;
      } else if (length < 256) {
        target[position2++] = 184;
        target[position2++] = length;
      } else if (length < 65536) {
        target[position2++] = 185;
        target[position2++] = length >> 8;
        target[position2++] = length & 255;
      } else {
        target[position2++] = 186;
        targetView.setUint32(position2, length);
        position2 += 4;
      }
      let key;
      if (encoder.keyMap) {
        for (let i = 0; i < length; i++) {
          encode2(encoder.encodeKey(keys[i]));
          encode2(vals[i]);
        }
      } else {
        for (let i = 0; i < length; i++) {
          encode2(keys[i]);
          encode2(vals[i]);
        }
      }
    } : (object) => {
      target[position2++] = 185;
      let objectOffset = position2 - start;
      position2 += 2;
      let size = 0;
      if (encoder.keyMap) {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          encode2(encoder.encodeKey(key));
          encode2(object[key]);
          size++;
        }
      } else {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          encode2(key);
          encode2(object[key]);
          size++;
        }
      }
      target[objectOffset++ + start] = size >> 8;
      target[objectOffset + start] = size & 255;
    } : (object, skipValues) => {
      let nextTransition, transition = structures.transitions || (structures.transitions = /* @__PURE__ */ Object.create(null));
      let newTransitions = 0;
      let length = 0;
      let parentRecordId;
      let keys;
      if (this.keyMap) {
        keys = Object.keys(object).map((k) => this.encodeKey(k));
        length = keys.length;
        for (let i = 0; i < length; i++) {
          let key = keys[i];
          nextTransition = transition[key];
          if (!nextTransition) {
            nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
            newTransitions++;
          }
          transition = nextTransition;
        }
      } else {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          nextTransition = transition[key];
          if (!nextTransition) {
            if (transition[RECORD_SYMBOL] & 1048576) {
              parentRecordId = transition[RECORD_SYMBOL] & 65535;
            }
            nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
            newTransitions++;
          }
          transition = nextTransition;
          length++;
        }
      }
      let recordId = transition[RECORD_SYMBOL];
      if (recordId !== void 0) {
        recordId &= 65535;
        target[position2++] = 217;
        target[position2++] = recordId >> 8 | 224;
        target[position2++] = recordId & 255;
      } else {
        if (!keys)
          keys = transition.__keys__ || (transition.__keys__ = Object.keys(object));
        if (parentRecordId === void 0) {
          recordId = structures.nextId++;
          if (!recordId) {
            recordId = 0;
            structures.nextId = 1;
          }
          if (recordId >= MAX_STRUCTURES) {
            structures.nextId = (recordId = maxSharedStructures) + 1;
          }
        } else {
          recordId = parentRecordId;
        }
        structures[recordId] = keys;
        if (recordId < maxSharedStructures) {
          target[position2++] = 217;
          target[position2++] = recordId >> 8 | 224;
          target[position2++] = recordId & 255;
          transition = structures.transitions;
          for (let i = 0; i < length; i++) {
            if (transition[RECORD_SYMBOL] === void 0 || transition[RECORD_SYMBOL] & 1048576)
              transition[RECORD_SYMBOL] = recordId;
            transition = transition[keys[i]];
          }
          transition[RECORD_SYMBOL] = recordId | 1048576;
          hasSharedUpdate = true;
        } else {
          transition[RECORD_SYMBOL] = recordId;
          targetView.setUint32(position2, 3655335680);
          position2 += 3;
          if (newTransitions)
            transitionsCount += serializationsSinceTransitionRebuild * newTransitions;
          if (recordIdsToRemove.length >= MAX_STRUCTURES - maxSharedStructures)
            recordIdsToRemove.shift()[RECORD_SYMBOL] = void 0;
          recordIdsToRemove.push(transition);
          writeArrayHeader(length + 2);
          encode2(57344 + recordId);
          encode2(keys);
          if (skipValues) return;
          for (let key in object)
            if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key))
              encode2(object[key]);
          return;
        }
      }
      if (length < 24) {
        target[position2++] = 128 | length;
      } else {
        writeArrayHeader(length);
      }
      if (skipValues) return;
      for (let key in object)
        if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key))
          encode2(object[key]);
    };
    const makeRoom = (end) => {
      let newSize;
      if (end > 16777216) {
        if (end - start > MAX_BUFFER_SIZE)
          throw new Error("Encoded buffer would be larger than maximum buffer size");
        newSize = Math.min(
          MAX_BUFFER_SIZE,
          Math.round(Math.max((end - start) * (end > 67108864 ? 1.25 : 2), 4194304) / 4096) * 4096
        );
      } else
        newSize = (Math.max(end - start << 2, target.length - 1) >> 12) + 1 << 12;
      let newBuffer = new ByteArrayAllocate(newSize);
      targetView = new DataView(newBuffer.buffer, 0, newSize);
      if (target.copy)
        target.copy(newBuffer, 0, start, end);
      else
        newBuffer.set(target.slice(start, end));
      position2 -= start;
      start = 0;
      safeEnd = newBuffer.length - 10;
      return target = newBuffer;
    };
    let chunkThreshold = 100;
    let continuedChunkThreshold = 1e3;
    this.encodeAsIterable = function(value, options2) {
      return startEncoding(value, options2, encodeObjectAsIterable);
    };
    this.encodeAsAsyncIterable = function(value, options2) {
      return startEncoding(value, options2, encodeObjectAsAsyncIterable);
    };
    function* encodeObjectAsIterable(object, iterateProperties, finalIterable) {
      let constructor = object.constructor;
      if (constructor === Object) {
        let useRecords = encoder.useRecords !== false;
        if (useRecords)
          writeObject(object, true);
        else
          writeEntityLength(Object.keys(object).length, 160);
        for (let key in object) {
          let value = object[key];
          if (!useRecords) encode2(key);
          if (value && typeof value === "object") {
            if (iterateProperties[key])
              yield* encodeObjectAsIterable(value, iterateProperties[key]);
            else
              yield* tryEncode(value, iterateProperties, key);
          } else encode2(value);
        }
      } else if (constructor === Array) {
        let length = object.length;
        writeArrayHeader(length);
        for (let i = 0; i < length; i++) {
          let value = object[i];
          if (value && (typeof value === "object" || position2 - start > chunkThreshold)) {
            if (iterateProperties.element)
              yield* encodeObjectAsIterable(value, iterateProperties.element);
            else
              yield* tryEncode(value, iterateProperties, "element");
          } else encode2(value);
        }
      } else if (object[Symbol.iterator] && !object.buffer) {
        target[position2++] = 159;
        for (let value of object) {
          if (value && (typeof value === "object" || position2 - start > chunkThreshold)) {
            if (iterateProperties.element)
              yield* encodeObjectAsIterable(value, iterateProperties.element);
            else
              yield* tryEncode(value, iterateProperties, "element");
          } else encode2(value);
        }
        target[position2++] = 255;
      } else if (isBlob(object)) {
        writeEntityLength(object.size, 64);
        yield target.subarray(start, position2);
        yield object;
        restartEncoding();
      } else if (object[Symbol.asyncIterator]) {
        target[position2++] = 159;
        yield target.subarray(start, position2);
        yield object;
        restartEncoding();
        target[position2++] = 255;
      } else {
        encode2(object);
      }
      if (finalIterable && position2 > start) yield target.subarray(start, position2);
      else if (position2 - start > chunkThreshold) {
        yield target.subarray(start, position2);
        restartEncoding();
      }
    }
    function* tryEncode(value, iterateProperties, key) {
      let restart = position2 - start;
      try {
        encode2(value);
        if (position2 - start > chunkThreshold) {
          yield target.subarray(start, position2);
          restartEncoding();
        }
      } catch (error) {
        if (error.iteratorNotHandled) {
          iterateProperties[key] = {};
          position2 = start + restart;
          yield* encodeObjectAsIterable.call(this, value, iterateProperties[key]);
        } else throw error;
      }
    }
    function restartEncoding() {
      chunkThreshold = continuedChunkThreshold;
      encoder.encode(null, THROW_ON_ITERABLE);
    }
    function startEncoding(value, options2, encodeIterable) {
      if (options2 && options2.chunkThreshold)
        chunkThreshold = continuedChunkThreshold = options2.chunkThreshold;
      else
        chunkThreshold = 100;
      if (value && typeof value === "object") {
        encoder.encode(null, THROW_ON_ITERABLE);
        return encodeIterable(value, encoder.iterateProperties || (encoder.iterateProperties = {}), true);
      }
      return [encoder.encode(value)];
    }
    async function* encodeObjectAsAsyncIterable(value, iterateProperties) {
      for (let encodedValue of encodeObjectAsIterable(value, iterateProperties, true)) {
        let constructor = encodedValue.constructor;
        if (constructor === ByteArray || constructor === Uint8Array)
          yield encodedValue;
        else if (isBlob(encodedValue)) {
          let reader = encodedValue.stream().getReader();
          let next;
          while (!(next = await reader.read()).done) {
            yield next.value;
          }
        } else if (encodedValue[Symbol.asyncIterator]) {
          for await (let asyncValue of encodedValue) {
            restartEncoding();
            if (asyncValue)
              yield* encodeObjectAsAsyncIterable(asyncValue, iterateProperties.async || (iterateProperties.async = {}));
            else yield encoder.encode(asyncValue);
          }
        } else {
          yield encodedValue;
        }
      }
    }
  }
  useBuffer(buffer) {
    target = buffer;
    targetView = new DataView(target.buffer, target.byteOffset, target.byteLength);
    position2 = 0;
  }
  clearSharedData() {
    if (this.structures)
      this.structures = [];
    if (this.sharedValues)
      this.sharedValues = void 0;
  }
  updateSharedData() {
    let lastVersion = this.sharedVersion || 0;
    this.sharedVersion = lastVersion + 1;
    let structuresCopy = this.structures.slice(0);
    let sharedData = new SharedData(structuresCopy, this.sharedValues, this.sharedVersion);
    let saveResults = this.saveShared(
      sharedData,
      (existingShared) => (existingShared && existingShared.version || 0) == lastVersion
    );
    if (saveResults === false) {
      sharedData = this.getShared() || {};
      this.structures = sharedData.structures || [];
      this.sharedValues = sharedData.packedValues;
      this.sharedVersion = sharedData.version;
      this.structures.nextId = this.structures.length;
    } else {
      structuresCopy.forEach((structure, i) => this.structures[i] = structure);
    }
    return saveResults;
  }
};
function writeEntityLength(length, majorValue) {
  if (length < 24)
    target[position2++] = majorValue | length;
  else if (length < 256) {
    target[position2++] = majorValue | 24;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = majorValue | 25;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = majorValue | 26;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
}
var SharedData = class {
  constructor(structures, values, version) {
    this.structures = structures;
    this.packedValues = values;
    this.version = version;
  }
};
function writeArrayHeader(length) {
  if (length < 24)
    target[position2++] = 128 | length;
  else if (length < 256) {
    target[position2++] = 152;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = 153;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = 154;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
}
var BlobConstructor = typeof Blob === "undefined" ? function() {
} : Blob;
function isBlob(object) {
  if (object instanceof BlobConstructor)
    return true;
  let tag = object[Symbol.toStringTag];
  return tag === "Blob" || tag === "File";
}
function findRepetitiveStrings(value, packedValues2) {
  switch (typeof value) {
    case "string":
      if (value.length > 3) {
        if (packedValues2.objectMap[value] > -1 || packedValues2.values.length >= packedValues2.maxValues)
          return;
        let packedStatus = packedValues2.get(value);
        if (packedStatus) {
          if (++packedStatus.count == 2) {
            packedValues2.values.push(value);
          }
        } else {
          packedValues2.set(value, {
            count: 1
          });
          if (packedValues2.samplingPackedValues) {
            let status = packedValues2.samplingPackedValues.get(value);
            if (status)
              status.count++;
            else
              packedValues2.samplingPackedValues.set(value, {
                count: 1
              });
          }
        }
      }
      break;
    case "object":
      if (value) {
        if (value instanceof Array) {
          for (let i = 0, l = value.length; i < l; i++) {
            findRepetitiveStrings(value[i], packedValues2);
          }
        } else {
          let includeKeys = !packedValues2.encoder.useRecords;
          for (var key in value) {
            if (value.hasOwnProperty(key)) {
              if (includeKeys)
                findRepetitiveStrings(key, packedValues2);
              findRepetitiveStrings(value[key], packedValues2);
            }
          }
        }
      }
      break;
    case "function":
      console.log(value);
  }
}
var isLittleEndianMachine2 = new Uint8Array(new Uint16Array([1]).buffer)[0] == 1;
extensionClasses = [
  Date,
  Set,
  Error,
  RegExp,
  Tag,
  ArrayBuffer,
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  typeof BigUint64Array == "undefined" ? function() {
  } : BigUint64Array,
  Int8Array,
  Int16Array,
  Int32Array,
  typeof BigInt64Array == "undefined" ? function() {
  } : BigInt64Array,
  Float32Array,
  Float64Array,
  SharedData
];
extensions = [
  {
    // Date
    tag: 1,
    encode(date, encode2) {
      let seconds = date.getTime() / 1e3;
      if ((this.useTimestamp32 || date.getMilliseconds() === 0) && seconds >= 0 && seconds < 4294967296) {
        target[position2++] = 26;
        targetView.setUint32(position2, seconds);
        position2 += 4;
      } else {
        target[position2++] = 251;
        targetView.setFloat64(position2, seconds);
        position2 += 8;
      }
    }
  },
  {
    // Set
    tag: 258,
    // https://github.com/input-output-hk/cbor-sets-spec/blob/master/CBOR_SETS.md
    encode(set, encode2) {
      let array = Array.from(set);
      encode2(array);
    }
  },
  {
    // Error
    tag: 27,
    // http://cbor.schmorp.de/generic-object
    encode(error, encode2) {
      encode2([error.name, error.message]);
    }
  },
  {
    // RegExp
    tag: 27,
    // http://cbor.schmorp.de/generic-object
    encode(regex, encode2) {
      encode2(["RegExp", regex.source, regex.flags]);
    }
  },
  {
    // Tag
    getTag(tag) {
      return tag.tag;
    },
    encode(tag, encode2) {
      encode2(tag.value);
    }
  },
  {
    // ArrayBuffer
    encode(arrayBuffer, encode2, makeRoom) {
      writeBuffer(arrayBuffer, makeRoom);
    }
  },
  {
    // Uint8Array
    getTag(typedArray) {
      if (typedArray.constructor === Uint8Array) {
        if (this.tagUint8Array || hasNodeBuffer && this.tagUint8Array !== false)
          return 64;
      }
    },
    encode(typedArray, encode2, makeRoom) {
      writeBuffer(typedArray, makeRoom);
    }
  },
  typedArrayEncoder(68, 1),
  typedArrayEncoder(69, 2),
  typedArrayEncoder(70, 4),
  typedArrayEncoder(71, 8),
  typedArrayEncoder(72, 1),
  typedArrayEncoder(77, 2),
  typedArrayEncoder(78, 4),
  typedArrayEncoder(79, 8),
  typedArrayEncoder(85, 4),
  typedArrayEncoder(86, 8),
  {
    encode(sharedData, encode2) {
      let packedValues2 = sharedData.packedValues || [];
      let sharedStructures = sharedData.structures || [];
      if (packedValues2.values.length > 0) {
        target[position2++] = 216;
        target[position2++] = 51;
        writeArrayHeader(4);
        let valuesArray = packedValues2.values;
        encode2(valuesArray);
        writeArrayHeader(0);
        writeArrayHeader(0);
        packedObjectMap = Object.create(sharedPackedObjectMap || null);
        for (let i = 0, l = valuesArray.length; i < l; i++) {
          packedObjectMap[valuesArray[i]] = i;
        }
      }
      if (sharedStructures) {
        targetView.setUint32(position2, 3655335424);
        position2 += 3;
        let definitions = sharedStructures.slice(0);
        definitions.unshift(57344);
        definitions.push(new Tag(sharedData.version, 1399353956));
        encode2(definitions);
      } else
        encode2(new Tag(sharedData.version, 1399353956));
    }
  }
];
function typedArrayEncoder(tag, size) {
  if (!isLittleEndianMachine2 && size > 1)
    tag -= 4;
  return {
    tag,
    encode: function writeExtBuffer(typedArray, encode2) {
      let length = typedArray.byteLength;
      let offset = typedArray.byteOffset || 0;
      let buffer = typedArray.buffer || typedArray;
      encode2(hasNodeBuffer ? Buffer2.from(buffer, offset, length) : new Uint8Array(buffer, offset, length));
    }
  };
}
function writeBuffer(buffer, makeRoom) {
  let length = buffer.byteLength;
  if (length < 24) {
    target[position2++] = 64 + length;
  } else if (length < 256) {
    target[position2++] = 88;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = 89;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = 90;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
  if (position2 + length >= target.length) {
    makeRoom(position2 + length);
  }
  target.set(buffer.buffer ? buffer : new Uint8Array(buffer), position2);
  position2 += length;
}
function insertIds(serialized, idsToInsert) {
  let nextId;
  let distanceToMove = idsToInsert.length * 2;
  let lastEnd = serialized.length - distanceToMove;
  idsToInsert.sort((a, b) => a.offset > b.offset ? 1 : -1);
  for (let id2 = 0; id2 < idsToInsert.length; id2++) {
    let referee = idsToInsert[id2];
    referee.id = id2;
    for (let position3 of referee.references) {
      serialized[position3++] = id2 >> 8;
      serialized[position3] = id2 & 255;
    }
  }
  while (nextId = idsToInsert.pop()) {
    let offset = nextId.offset;
    serialized.copyWithin(offset + distanceToMove, offset, lastEnd);
    distanceToMove -= 2;
    let position3 = offset + distanceToMove;
    serialized[position3++] = 216;
    serialized[position3++] = 28;
    lastEnd = offset;
  }
  return serialized;
}
function writeBundles(start, encode2) {
  targetView.setUint32(bundledStrings2.position + start, position2 - bundledStrings2.position - start + 1);
  let writeStrings = bundledStrings2;
  bundledStrings2 = null;
  encode2(writeStrings[0]);
  encode2(writeStrings[1]);
}
var defaultEncoder = new Encoder({ useRecords: false });
var encode = defaultEncoder.encode;
var encodeAsIterable = defaultEncoder.encodeAsIterable;
var encodeAsAsyncIterable = defaultEncoder.encodeAsAsyncIterable;
var { NEVER, ALWAYS, DECIMAL_ROUND, DECIMAL_FIT } = FLOAT32_OPTIONS;
var REUSE_BUFFER_MODE = 512;
var RESET_BUFFER_MODE = 1024;
var THROW_ON_ITERABLE = 2048;

// src/format/cose.ts
var AlgMLDSA65 = -49;
var AlgMLKEM768_A256KW = -70010;
var cborEncoder = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false
});

// src/format/pq.ts
var subtle2 = globalThis.crypto.subtle;
function buf2(data) {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}
var DOMAIN_LABEL = "CEF-ML-KEM-768-A256KW";
function mlkemKeygen() {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}
async function deriveMLKEMKEK(sharedSecret) {
  const info = new TextEncoder().encode(DOMAIN_LABEL);
  const ikm = await subtle2.importKey("raw", buf2(sharedSecret), "HKDF", false, ["deriveBits"]);
  const derived = await subtle2.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: buf2(info) },
    ikm,
    256
    // 32 bytes
  );
  return new Uint8Array(derived);
}
function mlkemWrapCEK(recipientPublicKeys) {
  return async (cek, recipient) => {
    const pk = recipientPublicKeys.get(recipient.keyId);
    if (!pk) {
      throw new Error(`mlkem: no public key for recipient ${recipient.keyId}`);
    }
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pk);
    const kek = await deriveMLKEMKEK(sharedSecret);
    zeroize(sharedSecret);
    const wrappedCEK = await aesKeyWrap(kek, cek);
    zeroize(kek);
    const result = new Uint8Array(cipherText.length + wrappedCEK.length);
    result.set(cipherText);
    result.set(wrappedCEK, cipherText.length);
    return result;
  };
}
function mlkemUnwrapCEK(secretKey) {
  return async (wrappedData, _recipient) => {
    const ctLen = 1088;
    if (wrappedData.length <= ctLen) {
      throw new Error(`mlkem: wrapped data too short (${wrappedData.length} bytes, need >${ctLen})`);
    }
    const cipherText = wrappedData.slice(0, ctLen);
    const wrappedCEK = wrappedData.slice(ctLen);
    const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);
    const kek = await deriveMLKEMKEK(sharedSecret);
    zeroize(sharedSecret);
    const cekResult = await aesKeyUnwrap(kek, wrappedCEK);
    zeroize(kek);
    return cekResult;
  };
}
function mldsaKeygen() {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return { publicKey, secretKey };
}
function mldsaSign(secretKey) {
  return async (sigStructure) => {
    return ml_dsa65.sign(sigStructure, secretKey);
  };
}
function mldsaVerify(publicKey) {
  return async (sigStructure, signature) => {
    const valid = ml_dsa65.verify(signature, sigStructure, publicKey);
    if (!valid) {
      throw new Error("ML-DSA-65: signature verification failed");
    }
  };
}
function mldsaSignRaw(secretKey) {
  return (message) => {
    return ml_dsa65.sign(message, secretKey);
  };
}
export {
  AlgMLDSA65,
  AlgMLKEM768_A256KW,
  mldsaKeygen,
  mldsaSign,
  mldsaSignRaw,
  mldsaVerify,
  mlkemKeygen,
  mlkemUnwrapCEK,
  mlkemWrapCEK
};
/*! Bundled license information:

@noble/hashes/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/utils.js:
@noble/post-quantum/_crystals.js:
@noble/post-quantum/ml-kem.js:
@noble/post-quantum/ml-dsa.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)

@noble/curves/utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
