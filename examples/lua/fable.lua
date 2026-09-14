-- Fable v0.5 — single-file Lua 5.3/5.4 example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
-- Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
-- Run: lua fable.lua        (needs 64-bit integers, i.e. Lua >= 5.3)
local M = {}

local RC = {0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
            0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7}
local IV0, IV1_HASH = 0x4661626C, 0x01202000
M.SETS = { fable = {rounds = 8, iv1 = 0x012020C8}, ["fable-f"] = {rounds = 6, iv1 = 0x012020C6} }
local MASK = 0xFFFFFFFF

local function rotl(x, n) return ((x << n) | (x >> (32 - n))) & MASK end

-- s: 1-based table of 16 words; `rounds` rounds with the LAST `rounds` constants
function M.permute(s, rounds)
  local function q(a, b, c, d)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl(s[b] ~ s[c], 7)
  end
  for i = 12 - rounds, 11 do
    s[1] = s[1] ~ RC[i + 1]; s[6] = s[6] ~ rotl(RC[i + 1], 16)
    q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15); q(4, 8, 12, 16)
    q(1, 6, 11, 16); q(2, 7, 12, 13); q(3, 8, 9, 14); q(4, 5, 10, 15)
  end
  return s
end

local function ld32(str, o)   -- o: 1-based offset of the first byte
  local a, b, c, d = str:byte(o, o + 3); return a | (b << 8) | (c << 16) | (d << 24)
end
local function st32(x) return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff) end
local function pad32(blk) return blk .. "\x80" .. string.rep("\0", 31 - #blk) end       -- #blk < 32
local function xor_rate(s, blk) for j = 1, 8 do s[j] = s[j] ~ ld32(blk, 4 * j - 3) end end
local function rate_bytes(s) local t = {} for j = 1, 8 do t[j] = st32(s[j]) end return table.concat(t) end
local function state_bytes(s) local t = {} for j = 1, 16 do t[j] = st32(s[j]) end return table.concat(t) end

local function init(setname, key, nonce, ad)
  local set = assert(M.SETS[setname], "unknown parameter set")
  assert(#key == 32 and #nonce == 24)
  local k = {} for j = 1, 8 do k[j] = ld32(key, 4 * j - 3) end
  local s = {IV0, set.iv1}
  for j = 1, 8 do s[2 + j] = k[j] end
  for j = 1, 6 do s[10 + j] = ld32(nonce, 4 * j - 3) end
  M.permute(s, 12)
  for j = 1, 8 do s[8 + j] = s[8 + j] ~ k[j] end
  if #ad > 0 then
    local full = #ad // 32
    for i = 0, full - 1 do xor_rate(s, ad:sub(32 * i + 1, 32 * i + 32)); M.permute(s, set.rounds) end
    xor_rate(s, pad32(ad:sub(32 * full + 1))); M.permute(s, set.rounds)
  end
  s[16] = s[16] ~ 0x80000000
  return s, k, set.rounds
end
local function finalize(s, k) for j = 1, 8 do s[8 + j] = s[8 + j] ~ k[j] end; M.permute(s, 12); return rate_bytes(s) end

-- returns ciphertext .. 32-byte tag
function M.encrypt(setname, key, nonce, ad, m)
  local s, k, rl = init(setname, key, nonce, ad)
  local out, full = {}, #m // 32
  for i = 0, full - 1 do xor_rate(s, m:sub(32 * i + 1, 32 * i + 32)); out[#out + 1] = rate_bytes(s); M.permute(s, rl) end
  local last = m:sub(32 * full + 1)
  xor_rate(s, pad32(last)); out[#out + 1] = rate_bytes(s):sub(1, #last)
  out[#out + 1] = finalize(s, k)
  return table.concat(out)
end
-- returns plaintext, or nil on authentication failure
function M.decrypt(setname, key, nonce, ad, ct)
  if #ct < 32 then return nil end
  local body, tag = ct:sub(1, #ct - 32), ct:sub(#ct - 31)
  local s, k, rl = init(setname, key, nonce, ad)
  local out, full = {}, #body // 32
  for i = 0, full - 1 do
    local blk = body:sub(32 * i + 1, 32 * i + 32)
    local p = {}
    for j = 1, 8 do local cw = ld32(blk, 4 * j - 3); p[j] = st32(s[j] ~ cw); s[j] = cw end
    out[#out + 1] = table.concat(p); M.permute(s, rl)
  end
  local lastc, ks = body:sub(32 * full + 1), rate_bytes(s)
  local lp = {}
  for j = 1, #lastc do lp[j] = string.char(lastc:byte(j) ~ ks:byte(j)) end
  local lastp = table.concat(lp)
  xor_rate(s, pad32(lastp))
  local exp = finalize(s, k)
  local d = 0
  for j = 1, 32 do d = d | (exp:byte(j) ~ tag:byte(j)) end     -- constant time
  if d ~= 0 then return nil end
  out[#out + 1] = lastp
  return table.concat(out)
end

function M.hash256(data)
  local s = {IV0, IV1_HASH}; for j = 3, 16 do s[j] = 0 end
  local full = #data // 32
  for i = 0, full - 1 do xor_rate(s, data:sub(32 * i + 1, 32 * i + 32)); M.permute(s, 12) end
  xor_rate(s, pad32(data:sub(32 * full + 1))); M.permute(s, 12)
  return rate_bytes(s)
end

-- ---------------- self-test ----------------
local function hex(str) return (str:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function bytes(n) local t = {} for i = 0, n - 1 do t[#t + 1] = string.char(i) end return table.concat(t) end
local allok = true
local function check(name, got, exp) local ok = got == exp; print(string.format("%-28s %s", name, ok and "OK" or "FAIL")); allok = allok and ok end

local z = {} for j = 1, 16 do z[j] = 0 end
check("permute12_zero", hex(state_bytes(M.permute(z, 12))), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd")
z = {} for j = 1, 16 do z[j] = 0 end
check("permute8_zero", hex(state_bytes(M.permute(z, 8))), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302")
local key, nonce, m64 = bytes(32), bytes(24), bytes(64)
local vs = {
  {"fable", "fable/empty", "", 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"},
  {"fable", "fable/block", "header", 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"},
  {"fable", "fable/two_blocks", "", 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"},
  {"fable-f", "fable-f/empty", "", 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"},
  {"fable-f", "fable-f/block", "header", 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"},
  {"fable-f", "fable-f/two_blocks", "", 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"},
}
for _, v in ipairs(vs) do
  local set, name, ad, mlen, exp = table.unpack(v)
  local m = m64:sub(1, mlen)
  local ct = M.encrypt(set, key, nonce, ad, m)
  check(name, hex(ct), exp)
  local rt = M.decrypt(set, key, nonce, ad, ct) == m
  local bad = ct:sub(1, #ct - 1) .. string.char(ct:byte(#ct) ~ 1)
  local tamper = M.decrypt(set, key, nonce, ad, bad) == nil
  check("  decrypt/tamper", tostring(rt and tamper), "true")
end
check("hash256(abc)", hex(M.hash256("abc")), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d")
check("hash256(empty)", hex(M.hash256("")), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607")
print("RESULT: " .. (allok and "ALL OK" or "FAILURES"))
os.exit(allok and 0 or 1)
