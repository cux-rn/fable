// Fable v0.5 — single-file Go example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
// Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
// Run: go run fable.go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"os"
)

var rc = [12]uint32{
	0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
	0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7}

const (
	iv0     = 0x4661626C
	iv1Hash = 0x01202000
)

// Set is a parameter set: Fable = P_12/P_8 (default), FableF = P_12/P_6.
type Set struct {
	LightRounds int
	IV1         uint32
}

var (
	Fable  = Set{8, 0x012020C8}
	FableF = Set{6, 0x012020C6}
)

func q(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]; s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]; s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]; s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]; s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

// Permute applies `rounds` rounds using the LAST `rounds` constants (P_8 -> RC[4..11], P_6 -> RC[6..11]).
func Permute(s *[16]uint32, rounds int) {
	for i := 12 - rounds; i < 12; i++ {
		s[0] ^= rc[i]
		s[5] ^= bits.RotateLeft32(rc[i], 16)
		q(s, 0, 4, 8, 12); q(s, 1, 5, 9, 13); q(s, 2, 6, 10, 14); q(s, 3, 7, 11, 15)
		q(s, 0, 5, 10, 15); q(s, 1, 6, 11, 12); q(s, 2, 7, 8, 13); q(s, 3, 4, 9, 14)
	}
}

func xorRate(s *[16]uint32, blk []byte) {
	for j := 0; j < 8; j++ {
		s[j] ^= binary.LittleEndian.Uint32(blk[4*j:])
	}
}
func xorRatePadded(s *[16]uint32, blk []byte) { // len(blk) < 32, 10* padding
	var buf [32]byte
	copy(buf[:], blk)
	buf[len(blk)] = 0x80
	xorRate(s, buf[:])
}
func storeRate(out []byte, s *[16]uint32) {
	for j := 0; j < 8; j++ {
		binary.LittleEndian.PutUint32(out[4*j:], s[j])
	}
}

type ctx struct {
	s  [16]uint32
	k  [8]uint32
	rl int
}

func newCtx(set Set, key, nonce, ad []byte) *ctx {
	c := &ctx{rl: set.LightRounds}
	for j := 0; j < 8; j++ {
		c.k[j] = binary.LittleEndian.Uint32(key[4*j:])
	}
	c.s[0], c.s[1] = iv0, set.IV1
	for j := 0; j < 8; j++ {
		c.s[2+j] = c.k[j]
	}
	for j := 0; j < 6; j++ {
		c.s[10+j] = binary.LittleEndian.Uint32(nonce[4*j:])
	}
	Permute(&c.s, 12)
	for j := 0; j < 8; j++ {
		c.s[8+j] ^= c.k[j]
	}
	if len(ad) > 0 {
		full := len(ad) / 32
		for i := 0; i < full; i++ {
			xorRate(&c.s, ad[32*i:])
			Permute(&c.s, c.rl)
		}
		xorRatePadded(&c.s, ad[32*full:])
		Permute(&c.s, c.rl)
	}
	c.s[15] ^= 0x80000000
	return c
}
func (c *ctx) finalize(tag []byte) {
	for j := 0; j < 8; j++ {
		c.s[8+j] ^= c.k[j]
	}
	Permute(&c.s, 12)
	storeRate(tag, &c.s)
}

// Encrypt returns ciphertext || 32-byte tag.
func Encrypt(set Set, key, nonce, ad, m []byte) []byte {
	c := newCtx(set, key, nonce, ad)
	out := make([]byte, len(m)+32)
	full := len(m) / 32
	for i := 0; i < full; i++ {
		xorRate(&c.s, m[32*i:])
		storeRate(out[32*i:], &c.s)
		Permute(&c.s, c.rl)
	}
	rem := len(m) - 32*full
	var ks [32]byte
	xorRatePadded(&c.s, m[32*full:])
	storeRate(ks[:], &c.s)
	copy(out[32*full:], ks[:rem])
	c.finalize(out[len(m):])
	return out
}

// Decrypt returns the plaintext and true, or nil and false on authentication failure.
func Decrypt(set Set, key, nonce, ad, ct []byte) ([]byte, bool) {
	if len(ct) < 32 {
		return nil, false
	}
	blen := len(ct) - 32
	c := newCtx(set, key, nonce, ad)
	pt := make([]byte, blen)
	full := blen / 32
	for i := 0; i < full; i++ {
		for j := 0; j < 8; j++ {
			cw := binary.LittleEndian.Uint32(ct[32*i+4*j:])
			binary.LittleEndian.PutUint32(pt[32*i+4*j:], c.s[j]^cw)
			c.s[j] = cw
		}
		Permute(&c.s, c.rl)
	}
	rem := blen - 32*full
	var ks, last [32]byte
	storeRate(ks[:], &c.s)
	for j := 0; j < rem; j++ {
		last[j] = ct[32*full+j] ^ ks[j]
	}
	xorRatePadded(&c.s, last[:rem])
	var exp [32]byte
	c.finalize(exp[:])
	var d byte
	for j := 0; j < 32; j++ { // constant time
		d |= exp[j] ^ ct[blen+j]
	}
	if d != 0 {
		return nil, false
	}
	copy(pt[32*full:], last[:rem])
	return pt, true
}

// Hash256 is Fable-Hash-256 (sponge, r = c = 256, P_12 throughout).
func Hash256(in []byte) []byte {
	var s [16]uint32
	s[0], s[1] = iv0, iv1Hash
	full := len(in) / 32
	for i := 0; i < full; i++ {
		xorRate(&s, in[32*i:])
		Permute(&s, 12)
	}
	xorRatePadded(&s, in[32*full:])
	Permute(&s, 12)
	out := make([]byte, 32)
	storeRate(out, &s)
	return out
}

// ---------------- self-test ----------------
func stateHex(s *[16]uint32) string {
	b := make([]byte, 64)
	for j := 0; j < 16; j++ {
		binary.LittleEndian.PutUint32(b[4*j:], s[j])
	}
	return hex.EncodeToString(b)
}

func main() {
	ok := true
	check := func(name, got, exp string) {
		r := got == exp
		ok = ok && r
		fmt.Printf("%-28s %s\n", name, map[bool]string{true: "OK", false: "FAIL"}[r])
	}
	key, nonce, m64 := make([]byte, 32), make([]byte, 24), make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i)
	}
	for i := range m64 {
		m64[i] = byte(i)
	}
	var s [16]uint32
	Permute(&s, 12)
	check("permute12_zero", stateHex(&s), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd")
	s = [16]uint32{}
	Permute(&s, 8)
	check("permute8_zero", stateHex(&s), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302")
	vs := []struct {
		set  Set
		name string
		ad   []byte
		mlen int
		ct   string
	}{
		{Fable, "fable/empty", nil, 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"},
		{Fable, "fable/block", []byte("header"), 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"},
		{Fable, "fable/two_blocks", nil, 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"},
		{FableF, "fable-f/empty", nil, 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"},
		{FableF, "fable-f/block", []byte("header"), 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"},
		{FableF, "fable-f/two_blocks", nil, 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"},
	}
	for _, v := range vs {
		m := m64[:v.mlen]
		ct := Encrypt(v.set, key, nonce, v.ad, m)
		check(v.name, hex.EncodeToString(ct), v.ct)
		pt, good := Decrypt(v.set, key, nonce, v.ad, ct)
		rt := good && bytes.Equal(pt, m)
		ct[len(ct)-1] ^= 1
		_, bad := Decrypt(v.set, key, nonce, v.ad, ct)
		check("  decrypt/tamper", fmt.Sprint(rt && !bad), "true")
	}
	check("hash256(abc)", hex.EncodeToString(Hash256([]byte("abc"))), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d")
	check("hash256(empty)", hex.EncodeToString(Hash256(nil)), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607")
	if ok {
		fmt.Println("RESULT: ALL OK")
	} else {
		fmt.Println("RESULT: FAILURES")
		os.Exit(1)
	}
}
