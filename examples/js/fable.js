// Fable v0.5 — single-file JavaScript (Node.js >= 16, no dependencies) example:
// Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256. Research draft, NOT for production.
// Run: node fable.js
'use strict';

const RC = new Uint32Array([
  0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
  0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7]);
const IV0 = 0x4661626C, IV1_HASH = 0x01202000;
const SETS = { 'fable': { rounds: 8, iv1: 0x012020C8 }, 'fable-f': { rounds: 6, iv1: 0x012020C6 } };

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

/** `rounds` rounds of Fable-P on a Uint32Array(16), using the LAST `rounds` constants. */
function permute(s, rounds) {
  const q = (a, b, c, d) => {
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
  };
  for (let i = 12 - rounds; i < 12; i++) {
    s[0] ^= RC[i]; s[5] ^= rotl(RC[i], 16);
    q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15);
    q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14);
  }
  return s;
}

const ld32 = (p, o) => (p[o] | p[o + 1] << 8 | p[o + 2] << 16 | p[o + 3] << 24) >>> 0;
function st32(p, o, x) { p[o] = x & 255; p[o + 1] = (x >>> 8) & 255; p[o + 2] = (x >>> 16) & 255; p[o + 3] = (x >>> 24) & 255; }
function xorRate(s, blk, off) { for (let j = 0; j < 8; j++) s[j] ^= ld32(blk, off + 4 * j); }
function xorRatePadded(s, blk, off, len) { const buf = new Uint8Array(32); buf.set(blk.subarray(off, off + len)); buf[len] = 0x80; xorRate(s, buf, 0); }
function storeRate(out, off, s) { for (let j = 0; j < 8; j++) st32(out, off + 4 * j, s[j]); }

function init(setName, key, nonce, ad) {
  const set = SETS[setName]; if (!set) throw new Error('unknown parameter set');
  const k = new Uint32Array(8); for (let j = 0; j < 8; j++) k[j] = ld32(key, 4 * j);
  const s = new Uint32Array(16);
  s[0] = IV0; s[1] = set.iv1; s.set(k, 2); for (let j = 0; j < 6; j++) s[10 + j] = ld32(nonce, 4 * j);
  permute(s, 12);
  for (let j = 0; j < 8; j++) s[8 + j] ^= k[j];
  if (ad.length > 0) {
    const full = Math.floor(ad.length / 32);
    for (let i = 0; i < full; i++) { xorRate(s, ad, 32 * i); permute(s, set.rounds); }
    xorRatePadded(s, ad, 32 * full, ad.length - 32 * full); permute(s, set.rounds);
  }
  s[15] ^= 0x80000000;
  return { s, k, rl: set.rounds };
}
function finalize(c, out, off) { for (let j = 0; j < 8; j++) c.s[8 + j] ^= c.k[j]; permute(c.s, 12); storeRate(out, off, c.s); }

/** Returns Uint8Array: ciphertext || 32-byte tag. */
function encrypt(setName, key, nonce, ad, m) {
  const c = init(setName, key, nonce, ad);
  const out = new Uint8Array(m.length + 32), full = Math.floor(m.length / 32);
  for (let i = 0; i < full; i++) { xorRate(c.s, m, 32 * i); storeRate(out, 32 * i, c.s); permute(c.s, c.rl); }
  const rem = m.length - 32 * full, ks = new Uint8Array(32);
  xorRatePadded(c.s, m, 32 * full, rem); storeRate(ks, 0, c.s); out.set(ks.subarray(0, rem), 32 * full);
  finalize(c, out, m.length);
  return out;
}
/** Returns the plaintext Uint8Array, or null on authentication failure. */
function decrypt(setName, key, nonce, ad, ct) {
  if (ct.length < 32) return null;
  const blen = ct.length - 32, c = init(setName, key, nonce, ad), pt = new Uint8Array(blen), full = Math.floor(blen / 32);
  for (let i = 0; i < full; i++) {
    for (let j = 0; j < 8; j++) { const cw = ld32(ct, 32 * i + 4 * j); st32(pt, 32 * i + 4 * j, c.s[j] ^ cw); c.s[j] = cw; }
    permute(c.s, c.rl);
  }
  const rem = blen - 32 * full, ks = new Uint8Array(32), last = new Uint8Array(32);
  storeRate(ks, 0, c.s);
  for (let j = 0; j < rem; j++) last[j] = ct[32 * full + j] ^ ks[j];
  xorRatePadded(c.s, last, 0, rem);
  const exp = new Uint8Array(32); finalize(c, exp, 0);
  let d = 0; for (let j = 0; j < 32; j++) d |= exp[j] ^ ct[blen + j];   // constant time
  if (d !== 0) return null;
  pt.set(last.subarray(0, rem), 32 * full);
  return pt;
}
/** Fable-Hash-256. */
function hash256(data) {
  const s = new Uint32Array(16); s[0] = IV0; s[1] = IV1_HASH;
  const full = Math.floor(data.length / 32);
  for (let i = 0; i < full; i++) { xorRate(s, data, 32 * i); permute(s, 12); }
  xorRatePadded(s, data, 32 * full, data.length - 32 * full); permute(s, 12);
  const out = new Uint8Array(32); storeRate(out, 0, s); return out;
}

module.exports = { permute, encrypt, decrypt, hash256, SETS };

// ---------------- self-test ----------------
if (require.main === module) {
  const hex = (b) => Buffer.from(b).toString('hex');
  const stateHex = (s) => { const b = new Uint8Array(64); for (let j = 0; j < 16; j++) st32(b, 4 * j, s[j]); return hex(b); };
  let ok = true;
  const check = (name, got, exp) => { const r = got === exp; ok = ok && r; console.log(name.padEnd(28) + ' ' + (r ? 'OK' : 'FAIL')); };
  const key = Uint8Array.from({ length: 32 }, (_, i) => i), nonce = Uint8Array.from({ length: 24 }, (_, i) => i), m64 = Uint8Array.from({ length: 64 }, (_, i) => i);
  check('permute12_zero', stateHex(permute(new Uint32Array(16), 12)), '987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd');
  check('permute8_zero', stateHex(permute(new Uint32Array(16), 8)), '13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302');
  const hdr = Buffer.from('header'), none = new Uint8Array(0);
  const vs = [
    ['fable', 'fable/empty', none, 0, '13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb'],
    ['fable', 'fable/block', hdr, 32, '59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37'],
    ['fable', 'fable/two_blocks', none, 64, 'cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc'],
    ['fable-f', 'fable-f/empty', none, 0, '1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641'],
    ['fable-f', 'fable-f/block', hdr, 32, '9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768'],
    ['fable-f', 'fable-f/two_blocks', none, 64, '323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd'],
  ];
  for (const [set, name, ad, mlen, exp] of vs) {
    const m = m64.subarray(0, mlen), ct = encrypt(set, key, nonce, ad, m);
    check(name, hex(ct), exp);
    const pt = decrypt(set, key, nonce, ad, ct), rt = pt !== null && Buffer.compare(Buffer.from(pt), Buffer.from(m)) === 0;
    ct[ct.length - 1] ^= 1;
    check('  decrypt/tamper', String(rt && decrypt(set, key, nonce, ad, ct) === null), 'true');
  }
  check('hash256(abc)', hex(hash256(Buffer.from('abc'))), 'd0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d');
  check('hash256(empty)', hex(hash256(none)), '22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607');
  console.log('RESULT: ' + (ok ? 'ALL OK' : 'FAILURES'));
  process.exit(ok ? 0 : 1);
}
