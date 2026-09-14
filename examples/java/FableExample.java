// Fable v0.5 — single-file Java example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
// Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
// Build/run: javac FableExample.java && java FableExample      (Java 11+)
import java.util.Arrays;

public final class FableExample {

    static final int[] RC = {
        0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
        0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7};
    static final int IV0 = 0x4661626C, IV1_HASH = 0x01202000;

    public enum Set {
        FABLE(8, 0x012020C8),      // P_12 / P_8 (default)
        FABLE_F(6, 0x012020C6);    // P_12 / P_6
        final int lightRounds, iv1;
        Set(int r, int iv) { lightRounds = r; iv1 = iv; }
    }

    // ---- permutation: `rounds` rounds with the LAST `rounds` constants ----
    public static void permute(int[] s, int rounds) {
        for (int i = 12 - rounds; i < 12; i++) {
            s[0] ^= RC[i]; s[5] ^= Integer.rotateLeft(RC[i], 16);
            q(s, 0, 4, 8, 12); q(s, 1, 5, 9, 13); q(s, 2, 6, 10, 14); q(s, 3, 7, 11, 15);
            q(s, 0, 5, 10, 15); q(s, 1, 6, 11, 12); q(s, 2, 7, 8, 13); q(s, 3, 4, 9, 14);
        }
    }
    private static void q(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    static int ld32(byte[] p, int o) { return (p[o] & 0xff) | (p[o + 1] & 0xff) << 8 | (p[o + 2] & 0xff) << 16 | (p[o + 3] & 0xff) << 24; }
    static void st32(byte[] p, int o, int x) { p[o] = (byte) x; p[o + 1] = (byte) (x >>> 8); p[o + 2] = (byte) (x >>> 16); p[o + 3] = (byte) (x >>> 24); }
    static void xorRate(int[] s, byte[] blk, int off) { for (int j = 0; j < 8; j++) s[j] ^= ld32(blk, off + 4 * j); }
    static void xorRatePadded(int[] s, byte[] blk, int off, int len) {   // len < 32, 10* padding
        byte[] buf = new byte[32]; System.arraycopy(blk, off, buf, 0, len); buf[len] = (byte) 0x80; xorRate(s, buf, 0);
    }
    static void storeRate(byte[] out, int off, int[] s) { for (int j = 0; j < 8; j++) st32(out, off + 4 * j, s[j]); }

    private static final class Ctx {
        final int[] s = new int[16], k = new int[8]; final int rl;
        Ctx(Set set, byte[] key, byte[] nonce, byte[] ad) {
            rl = set.lightRounds;
            for (int j = 0; j < 8; j++) k[j] = ld32(key, 4 * j);
            s[0] = IV0; s[1] = set.iv1;
            for (int j = 0; j < 8; j++) s[2 + j] = k[j];
            for (int j = 0; j < 6; j++) s[10 + j] = ld32(nonce, 4 * j);
            permute(s, 12);
            for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
            if (ad.length > 0) {
                int full = ad.length / 32;
                for (int i = 0; i < full; i++) { xorRate(s, ad, 32 * i); permute(s, rl); }
                xorRatePadded(s, ad, 32 * full, ad.length - 32 * full); permute(s, rl);
            }
            s[15] ^= 0x80000000;
        }
        void finalize(byte[] tag, int off) { for (int j = 0; j < 8; j++) s[8 + j] ^= k[j]; permute(s, 12); storeRate(tag, off, s); }
    }

    /** Returns ciphertext || 32-byte tag. */
    public static byte[] encrypt(Set set, byte[] key, byte[] nonce, byte[] ad, byte[] m) {
        Ctx c = new Ctx(set, key, nonce, ad);
        byte[] out = new byte[m.length + 32];
        int full = m.length / 32;
        for (int i = 0; i < full; i++) { xorRate(c.s, m, 32 * i); storeRate(out, 32 * i, c.s); permute(c.s, c.rl); }
        int rem = m.length - 32 * full; byte[] ks = new byte[32];
        xorRatePadded(c.s, m, 32 * full, rem); storeRate(ks, 0, c.s); System.arraycopy(ks, 0, out, 32 * full, rem);
        c.finalize(out, m.length);
        return out;
    }
    /** Returns the plaintext, or null on authentication failure. */
    public static byte[] decrypt(Set set, byte[] key, byte[] nonce, byte[] ad, byte[] ct) {
        if (ct.length < 32) return null;
        int blen = ct.length - 32; Ctx c = new Ctx(set, key, nonce, ad);
        byte[] pt = new byte[blen];
        int full = blen / 32;
        for (int i = 0; i < full; i++) {
            for (int j = 0; j < 8; j++) { int cw = ld32(ct, 32 * i + 4 * j); st32(pt, 32 * i + 4 * j, c.s[j] ^ cw); c.s[j] = cw; }
            permute(c.s, c.rl);
        }
        int rem = blen - 32 * full; byte[] ks = new byte[32], last = new byte[32];
        storeRate(ks, 0, c.s);
        for (int j = 0; j < rem; j++) last[j] = (byte) (ct[32 * full + j] ^ ks[j]);
        xorRatePadded(c.s, last, 0, rem);
        byte[] exp = new byte[32]; c.finalize(exp, 0);
        int d = 0; for (int j = 0; j < 32; j++) d |= exp[j] ^ ct[blen + j];   // constant time
        if (d != 0) return null;
        System.arraycopy(last, 0, pt, 32 * full, rem);
        return pt;
    }

    public static byte[] hash256(byte[] in) {
        int[] s = new int[16]; s[0] = IV0; s[1] = IV1_HASH;
        int full = in.length / 32;
        for (int i = 0; i < full; i++) { xorRate(s, in, 32 * i); permute(s, 12); }
        xorRatePadded(s, in, 32 * full, in.length - 32 * full); permute(s, 12);
        byte[] out = new byte[32]; storeRate(out, 0, s); return out;
    }

    // ---------------- self-test ----------------
    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static boolean check(String name, String got, String exp) { boolean ok = got.equals(exp); System.out.printf("%-28s %s%n", name, ok ? "OK" : "FAIL"); return ok; }
    static String stateHex(int[] s) { byte[] b = new byte[64]; for (int j = 0; j < 16; j++) st32(b, 4 * j, s[j]); return hex(b); }

    public static void main(String[] args) {
        boolean ok = true;
        byte[] key = new byte[32], nonce = new byte[24], m64 = new byte[64];
        for (int i = 0; i < 32; i++) key[i] = (byte) i; for (int i = 0; i < 24; i++) nonce[i] = (byte) i; for (int i = 0; i < 64; i++) m64[i] = (byte) i;
        int[] s = new int[16]; permute(s, 12);
        ok &= check("permute12_zero", stateHex(s), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd");
        s = new int[16]; permute(s, 8);
        ok &= check("permute8_zero", stateHex(s), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302");
        byte[] hdr = "header".getBytes(), none = new byte[0];
        Object[][] vs = {
            {Set.FABLE, "fable/empty", none, 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"},
            {Set.FABLE, "fable/block", hdr, 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"},
            {Set.FABLE, "fable/two_blocks", none, 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"},
            {Set.FABLE_F, "fable-f/empty", none, 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"},
            {Set.FABLE_F, "fable-f/block", hdr, 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"},
            {Set.FABLE_F, "fable-f/two_blocks", none, 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"},
        };
        for (Object[] v : vs) {
            Set set = (Set) v[0]; byte[] ad = (byte[]) v[2]; int mlen = (Integer) v[3];
            byte[] m = Arrays.copyOf(m64, mlen);
            byte[] ct = encrypt(set, key, nonce, ad, m);
            ok &= check((String) v[1], hex(ct), (String) v[4]);
            byte[] pt = decrypt(set, key, nonce, ad, ct); boolean rt = pt != null && Arrays.equals(pt, m);
            ct[ct.length - 1] ^= 1; boolean tamper = decrypt(set, key, nonce, ad, ct) == null;
            System.out.printf("%-28s %s%n", "  decrypt/tamper", rt && tamper ? "OK" : "FAIL"); ok &= rt && tamper;
        }
        ok &= check("hash256(abc)", hex(hash256("abc".getBytes())), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d");
        ok &= check("hash256(empty)", hex(hash256(none)), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607");
        System.out.println("RESULT: " + (ok ? "ALL OK" : "FAILURES"));
        System.exit(ok ? 0 : 1);
    }
}
