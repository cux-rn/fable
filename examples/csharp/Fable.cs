// Fable v0.5 — single-file C# (.NET 6+) example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
// Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
// Run: dotnet run
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Numerics;

public enum FableSet { Fable, FableF }   // P_12/P_8 (default), P_12/P_6

public static class Fable
{
    static readonly uint[] RC = {
        0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
        0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7 };
    const uint IV0 = 0x4661626C, IV1_HASH = 0x01202000;
    static int LightRounds(FableSet s) => s == FableSet.FableF ? 6 : 8;
    static uint Iv1(FableSet s) => s == FableSet.FableF ? 0x012020C6u : 0x012020C8u;

    static void Q(uint[] s, int a, int b, int c, int d)
    {
        s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 7);
    }
    /// <summary>`rounds` rounds of Fable-P using the LAST `rounds` constants (P_8 -> RC[4..11], P_6 -> RC[6..11]).</summary>
    public static void Permute(uint[] s, int rounds)
    {
        for (int i = 12 - rounds; i < 12; i++)
        {
            s[0] ^= RC[i]; s[5] ^= BitOperations.RotateLeft(RC[i], 16);
            Q(s, 0, 4, 8, 12); Q(s, 1, 5, 9, 13); Q(s, 2, 6, 10, 14); Q(s, 3, 7, 11, 15);
            Q(s, 0, 5, 10, 15); Q(s, 1, 6, 11, 12); Q(s, 2, 7, 8, 13); Q(s, 3, 4, 9, 14);
        }
    }

    static uint Ld32(ReadOnlySpan<byte> p) => BinaryPrimitives.ReadUInt32LittleEndian(p);
    static void XorRate(uint[] s, ReadOnlySpan<byte> blk) { for (int j = 0; j < 8; j++) s[j] ^= Ld32(blk.Slice(4 * j)); }
    static void XorRatePadded(uint[] s, ReadOnlySpan<byte> blk) { Span<byte> buf = stackalloc byte[32]; blk.CopyTo(buf); buf[blk.Length] = 0x80; XorRate(s, buf); }
    static void StoreRate(Span<byte> o, uint[] s) { for (int j = 0; j < 8; j++) BinaryPrimitives.WriteUInt32LittleEndian(o.Slice(4 * j), s[j]); }

    sealed class Ctx
    {
        public uint[] S = new uint[16], K = new uint[8]; public int Rl;
        public Ctx(FableSet set, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ad)
        {
            Rl = LightRounds(set);
            for (int j = 0; j < 8; j++) K[j] = Ld32(key.Slice(4 * j));
            S[0] = IV0; S[1] = Iv1(set);
            for (int j = 0; j < 8; j++) S[2 + j] = K[j];
            for (int j = 0; j < 6; j++) S[10 + j] = Ld32(nonce.Slice(4 * j));
            Permute(S, 12);
            for (int j = 0; j < 8; j++) S[8 + j] ^= K[j];
            if (ad.Length > 0)
            {
                int full = ad.Length / 32;
                for (int i = 0; i < full; i++) { XorRate(S, ad.Slice(32 * i)); Permute(S, Rl); }
                XorRatePadded(S, ad.Slice(32 * full)); Permute(S, Rl);
            }
            S[15] ^= 0x80000000;
        }
        public void Finalize(Span<byte> tag) { for (int j = 0; j < 8; j++) S[8 + j] ^= K[j]; Permute(S, 12); StoreRate(tag, S); }
    }

    /// <summary>Returns ciphertext || 32-byte tag.</summary>
    public static byte[] Encrypt(FableSet set, byte[] key, byte[] nonce, byte[] ad, byte[] m)
    {
        var c = new Ctx(set, key, nonce, ad);
        var output = new byte[m.Length + 32]; int full = m.Length / 32;
        for (int i = 0; i < full; i++) { XorRate(c.S, m.AsSpan(32 * i)); StoreRate(output.AsSpan(32 * i), c.S); Permute(c.S, c.Rl); }
        int rem = m.Length - 32 * full; Span<byte> ks = stackalloc byte[32];
        XorRatePadded(c.S, m.AsSpan(32 * full)); StoreRate(ks, c.S); ks.Slice(0, rem).CopyTo(output.AsSpan(32 * full));
        c.Finalize(output.AsSpan(m.Length));
        return output;
    }
    /// <summary>Returns the plaintext, or null on authentication failure.</summary>
    public static byte[]? Decrypt(FableSet set, byte[] key, byte[] nonce, byte[] ad, byte[] ct)
    {
        if (ct.Length < 32) return null;
        int blen = ct.Length - 32; var c = new Ctx(set, key, nonce, ad);
        var pt = new byte[blen]; int full = blen / 32;
        for (int i = 0; i < full; i++)
        {
            for (int j = 0; j < 8; j++) { uint cw = Ld32(ct.AsSpan(32 * i + 4 * j)); BinaryPrimitives.WriteUInt32LittleEndian(pt.AsSpan(32 * i + 4 * j), c.S[j] ^ cw); c.S[j] = cw; }
            Permute(c.S, c.Rl);
        }
        int rem = blen - 32 * full; Span<byte> ks = stackalloc byte[32]; Span<byte> last = stackalloc byte[32];
        StoreRate(ks, c.S);
        for (int j = 0; j < rem; j++) last[j] = (byte)(ct[32 * full + j] ^ ks[j]);
        XorRatePadded(c.S, last.Slice(0, rem));
        Span<byte> exp = stackalloc byte[32]; c.Finalize(exp);
        int d = 0; for (int j = 0; j < 32; j++) d |= exp[j] ^ ct[blen + j];   // constant time
        if (d != 0) return null;
        last.Slice(0, rem).CopyTo(pt.AsSpan(32 * full));
        return pt;
    }
    /// <summary>Fable-Hash-256 (sponge, r = c = 256, P_12 throughout).</summary>
    public static byte[] Hash256(byte[] data)
    {
        var s = new uint[16]; s[0] = IV0; s[1] = IV1_HASH;
        int full = data.Length / 32;
        for (int i = 0; i < full; i++) { XorRate(s, data.AsSpan(32 * i)); Permute(s, 12); }
        XorRatePadded(s, data.AsSpan(32 * full)); Permute(s, 12);
        var o = new byte[32]; StoreRate(o, s); return o;
    }
}

public static class Program
{
    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    static string StateHex(uint[] s) { var b = new byte[64]; for (int j = 0; j < 16; j++) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4 * j), s[j]); return Hex(b); }
    public static int Main()
    {
        bool ok = true;
        void Check(string name, string got, string exp) { bool r = got == exp; ok &= r; Console.WriteLine($"{name,-28} {(r ? "OK" : "FAIL")}"); }
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var nonce = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray();
        var m64 = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        var s = new uint[16]; Fable.Permute(s, 12);
        Check("permute12_zero", StateHex(s), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd");
        s = new uint[16]; Fable.Permute(s, 8);
        Check("permute8_zero", StateHex(s), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302");
        var hdr = System.Text.Encoding.ASCII.GetBytes("header"); var none = Array.Empty<byte>();
        var vs = new (FableSet set, string name, byte[] ad, int mlen, string ct)[] {
            (FableSet.Fable, "fable/empty", none, 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"),
            (FableSet.Fable, "fable/block", hdr, 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"),
            (FableSet.Fable, "fable/two_blocks", none, 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"),
            (FableSet.FableF, "fable-f/empty", none, 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"),
            (FableSet.FableF, "fable-f/block", hdr, 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"),
            (FableSet.FableF, "fable-f/two_blocks", none, 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"),
        };
        foreach (var v in vs)
        {
            var m = m64.Take(v.mlen).ToArray();
            var ct = Fable.Encrypt(v.set, key, nonce, v.ad, m);
            Check(v.name, Hex(ct), v.ct);
            var pt = Fable.Decrypt(v.set, key, nonce, v.ad, ct); bool rt = pt != null && pt.SequenceEqual(m);
            ct[^1] ^= 1; bool tamper = Fable.Decrypt(v.set, key, nonce, v.ad, ct) == null;
            Check("  decrypt/tamper", (rt && tamper).ToString().ToLowerInvariant(), "true");
        }
        Check("hash256(abc)", Hex(Fable.Hash256(System.Text.Encoding.ASCII.GetBytes("abc"))), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d");
        Check("hash256(empty)", Hex(Fable.Hash256(none)), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607");
        Console.WriteLine("RESULT: " + (ok ? "ALL OK" : "FAILURES"));
        return ok ? 0 : 1;
    }
}
