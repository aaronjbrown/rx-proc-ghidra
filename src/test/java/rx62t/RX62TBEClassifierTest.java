// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import rx62t.RX62TBEClassifier.Block;
import rx62t.RX62TBEClassifier.Kind;

public final class RX62TBEClassifierTest {
    private static final String SUITE = "be_classifier";
    private static final long B = 0xFFCFFF00L;

    /** MOV.L #0xFFD00000,R1; MVTC R1,INTB; 3 x NOP (instruction byte order, before swapping). */
    private static final byte[] STUB = bytes(0xFB, 0x12, 0x00, 0x00, 0xD0, 0xFF, 0xFD, 0x68, 0x1C, 3, 3, 3);

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    private static byte[] be32(long... v) {
        byte[] b = new byte[4 * v.length];
        for (int i = 0; i < v.length; i++)
            for (int k = 0; k < 4; k++) b[4 * i + k] = (byte) (v[i] >>> (24 - 8 * k));
        return b;
    }

    private static byte[] ff(int n) {
        byte[] b = new byte[n];
        java.util.Arrays.fill(b, (byte) 0xFF);
        return b;
    }

    /** swap(stub) + ff(4) + 0x600 bytes of swap(stub) repeated. */
    private static byte[] stubImage() {
        byte[] sw = RX62TBEUtils.swapWords(STUB);
        byte[] img = new byte[sw.length + 4 + 0x600];
        System.arraycopy(sw, 0, img, 0, sw.length);
        System.arraycopy(ff(4), 0, img, sw.length, 4);
        for (int o = 0; o < 0x600; o++) img[sw.length + 4 + o] = sw[o % sw.length];
        return img;
    }

    /** The stub image with 16 BE pointers (to base+0x5C0) at offset 0x540 (ruling R1). */
    private static byte[] ptrTableImage() {
        byte[] img = stubImage();
        long[] ptrs = new long[16];
        java.util.Arrays.fill(ptrs, B + 0x5C0);
        System.arraycopy(be32(ptrs), 0, img, 0x540, 64);
        return img;
    }

    private static boolean covered(List<Block> blocks, int start, int end, Kind kind) {
        for (int o = start; o < end; o += 4) {
            boolean hit = false;
            for (Block b : blocks) if (b.start() <= o && o + 4 <= b.end() && b.kind() == kind) hit = true;
            if (!hit) return false;
        }
        return true;
    }

    private static String tiling(List<Block> blocks, int len) {
        int at = 0;
        for (Block b : blocks) {
            if (b.start() != at || b.end() <= b.start()) return "gap/overlap at " + b;
            at = b.end();
        }
        return at == (len & ~3) ? null : "ends at " + at + " want " + (len & ~3);
    }

    private static long word(byte[] b, int o) {
        return (b[o] & 0xFFL) << 24 | (b[o + 1] & 0xFFL) << 16 | (b[o + 2] & 0xFFL) << 8 | (b[o + 3] & 0xFFL);
    }

    /** Fraction of the words in [start, end) that lie in a block of {@code kind}. */
    private static double fraction(List<Block> blocks, int start, int end, Kind kind) {
        int hit = 0;
        for (int o = start; o < end; o += 4)
            for (Block b : blocks) if (b.start() <= o && o + 4 <= b.end() && b.kind() == kind) hit++;
        return (double) hit / ((end - start) / 4);
    }

    public static void main(String[] args) {
        Check.suite(SUITE);

        byte[] stub = stubImage();
        List<Block> stubBlocks = RX62TBEClassifier.classify(stub, B);
        Check.ok("stub_is_code", covered(stubBlocks, 0, 12, Kind.CODE), "blocks=" + stubBlocks);

        byte[] ptr = ptrTableImage();
        List<Block> ptrBlocks = RX62TBEClassifier.classify(ptr, B);
        Check.ok("ptr_table_is_data", covered(ptrBlocks, 0x540, 0x580, Kind.DATA), "blocks=" + ptrBlocks);

        Random rnd = new Random(1);
        byte[] noise = new byte[0x1003];
        rnd.nextBytes(noise);
        byte[][] images = {stub, ptr, noise, new byte[0x2A], ff(0x101)};
        String bad = null;
        for (byte[] img : images) {
            String why = tiling(RX62TBEClassifier.classify(img, 0x1000), img.length);
            if (why != null && bad == null) bad = "len=" + img.length + ": " + why;
        }
        Check.ok("blocks_tile_image", bad == null, String.valueOf(bad));

        String threw = "no exception";
        try {
            RX62TBEClassifier.buildFetchOrderImage(stub, stubBlocks, 0x1002);
        } catch (IllegalArgumentException e) {
            threw = e.getMessage();
        }
        Check.eq("unaligned_base", "image base 0x00001002 is not word aligned; cannot un-swap code words", threw);

        List<Block> mixed = new ArrayList<>();
        Kind[] kinds = Kind.values();
        for (int o = 0; o < 0x1000; o += 0x40) mixed.add(new Block(o, o + 0x40, kinds[(o >> 6) % 3]));
        byte[] out = RX62TBEClassifier.buildFetchOrderImage(noise, mixed, 0x1000);
        String diff = out.length == noise.length ? null : "length " + out.length;
        for (Block b : mixed)
            for (int o = b.start(); o < b.end() && diff == null; o += 4) {
                long want = b.kind() == Kind.CODE ? Integer.toUnsignedLong(Integer.reverseBytes((int) word(noise, o))) : word(noise, o);
                if (word(out, o) != want) diff = "word at 0x" + Integer.toHexString(o);
            }
        for (int o = 0x1000; o < noise.length && diff == null; o++) if (out[o] != noise[o]) diff = "tail byte " + o;
        Check.ok("fetch_order_swaps_code_only", diff == null, String.valueOf(diff));

        RealisticImage.Image real = RealisticImage.build();
        List<Block> realBlocks = RX62TBEClassifier.classify(real.raw(), real.base());
        String why = null;
        for (RX62TBEUtils.Range r : List.of(real.header(), real.strings(), real.numeric(), real.pointers()))
            if (why == null && !covered(realBlocks, r.start(), r.end(), Kind.DATA)) why = "data region " + r + " not all DATA";
        // data islands between functions: their edge words may go either way, the bulk must be DATA
        for (RX62TBEUtils.Range r : real.islands())
            if (why == null && fraction(realBlocks, r.start(), r.end(), Kind.DATA) < 0.9) why = "island " + r + " mostly not DATA";
        if (why == null && !covered(realBlocks, real.stub().start(), real.stub().end(), Kind.CODE)) why = "stub not CODE";
        if (why == null && !covered(realBlocks, real.fill().start(), real.fill().end(), Kind.FILL)) why = "fill not FILL";
        // code words outside the data islands; the short pool is absorbed into code by design and is
        // pinned only by realistic_image_blocks
        double codeWords = (real.code().end() - real.code().start()) / 4, codeHits =
                fraction(realBlocks, real.code().start(), real.code().end(), Kind.CODE) * codeWords;
        List<RX62TBEUtils.Range> notCode = new ArrayList<>(real.islands());
        notCode.add(real.shortPool());
        for (RX62TBEUtils.Range r : notCode) {
            codeWords -= (r.end() - r.start()) / 4;
            codeHits -= fraction(realBlocks, r.start(), r.end(), Kind.CODE) * ((r.end() - r.start()) / 4);
        }
        double code = codeHits / codeWords;
        if (why == null && code < 0.95) why = "code region only " + code + " CODE";
        Check.ok("realistic_image_semantics", why == null, why + " blocks=" + realBlocks);

        // expected output of the reference implementation of this model on the same bytes
        List<Block> wantReal = List.of(
                new Block(0x00000, 0x00014, Kind.CODE),
                new Block(0x00014, 0x00020, Kind.DATA),
                new Block(0x00020, 0x00060, Kind.FILL),
                new Block(0x00060, 0x00DC4, Kind.DATA),
                new Block(0x00DC4, 0x01E04, Kind.CODE),
                new Block(0x01E04, 0x01F10, Kind.DATA),
                new Block(0x01F10, 0x02E18, Kind.CODE),
                new Block(0x02E18, 0x02E58, Kind.DATA),
                new Block(0x02E58, 0x04DE0, Kind.CODE),
                new Block(0x04DE0, 0x05F80, Kind.FILL),
                new Block(0x05F80, 0x06000, Kind.DATA));
        Check.eq("realistic_image_blocks", wantReal, realBlocks);

        System.exit(Check.summary(SUITE));
    }
}
