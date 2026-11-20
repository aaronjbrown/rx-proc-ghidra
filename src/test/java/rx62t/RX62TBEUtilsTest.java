// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.util.List;
import java.util.Map;
import rx62t.RX62TBEUtils.Entry;
import rx62t.RX62TBEUtils.Range;

public final class RX62TBEUtilsTest {
    private static byte[] be32(int... v) {
        byte[] b = new byte[4 * v.length];
        for (int i = 0; i < v.length; i++)
            for (int k = 0; k < 4; k++) b[4 * i + k] = (byte) (v[i] >>> (24 - 8 * k));
        return b;
    }

    private static byte[] le32(int... v) {
        byte[] b = new byte[4 * v.length];
        for (int i = 0; i < v.length; i++)
            for (int k = 0; k < 4; k++) b[4 * i + k] = (byte) (v[i] >>> (8 * k));
        return b;
    }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static byte[] ff(int n) {
        byte[] b = new byte[n];
        java.util.Arrays.fill(b, (byte) 0xFF);
        return b;
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    private static byte[] put(byte[] img, int off, byte[] data) {
        System.arraycopy(data, 0, img, off, data.length);
        return img;
    }

    private static byte[] table(boolean be, int off, int... words) {
        byte[] img = new byte[0x100];
        return put(img, off, be ? be32(words) : le32(words));
    }

    private static final byte[] MOVL_MVTC = bytes(0xFB, 0x12, 0x00, 0x00, 0xD0, 0xFF, 0xFD, 0x68, 0x1C, 3, 3, 3);
    private static final byte[] MVTC_IMM = bytes(0xFD, 0x73, 0x0D, 0x00, 0x00, 0xD0, 0xFF, 0x03);

    private static byte[] stubImage(byte[] stub, boolean swapped) {
        return put(new byte[0x600], 0, swapped ? RX62TBEUtils.swapWords(stub) : stub);
    }

    public static void main(String[] args) {
        Check.suite("be_utils");
        final long B = 0xFFCFFF00L;

        Check.eq("swap_words", bytes(4, 3, 2, 1, 6, 5), RX62TBEUtils.swapWords(bytes(1, 2, 3, 4, 5, 6)));

        int P = 0x1010;
        byte[] t4 = table(true, 0x20, P, P, P, P);
        Check.eq("ptr_table_min", List.of(new Range(0x20, 0x30)), RX62TBEUtils.findPointerTables(t4, 0x1000, 4, true));
        byte[] t3 = table(true, 0x20, P, P, P);
        Check.eq("ptr_table_min_3", List.of(), RX62TBEUtils.findPointerTables(t3, 0x1000, 4, true));

        byte[] gap1 = table(true, 0x20, P, P, 0, P, P);
        Check.eq("ptr_table_zero_gap", List.of(new Range(0x20, 0x34)), RX62TBEUtils.findPointerTables(gap1, 0x1000, 4, true));
        byte[] gap2 = table(true, 0x20, P, P, 0, 0, P, P);
        Check.eq("ptr_table_zero_gap2", List.of(), RX62TBEUtils.findPointerTables(gap2, 0x1000, 4, true));

        byte[] atEnd = table(true, 0xF0, P, P, P, P);
        Check.eq("ptr_table_at_end", List.of(new Range(0xF0, atEnd.length)), RX62TBEUtils.findPointerTables(atEnd, 0x1000, 4, true));

        byte[] le = table(false, 0x20, P, P, P, P);
        Check.eq("ptr_table_le", List.of(new Range(0x20, 0x30)), RX62TBEUtils.findPointerTables(le, 0x1000, 4, false));
        Check.eq("ptr_table_le_scanned_be", List.of(), RX62TBEUtils.findPointerTables(le, 0x1000, 4, true));

        Check.eq("intb_movl_mvtc", Map.of("INTB", 0x100), RX62TBEUtils.findVectorTables(stubImage(MOVL_MVTC, true), B, true));
        Check.eq("intb_unswapped", Map.of("INTB", 0x100), RX62TBEUtils.findVectorTables(stubImage(MOVL_MVTC, false), B, false));
        Check.eq("intb_swapped_not_codeSwapped", Map.of(), RX62TBEUtils.findVectorTables(stubImage(MOVL_MVTC, true), B, false));
        Check.eq("extb_mvtc_imm", Map.of("EXTB", 0x100), RX62TBEUtils.findVectorTables(stubImage(MVTC_IMM, true), B, true));

        Check.eq("vector_setup_be", List.of(true, false), List.of(
                RX62TBEUtils.hasVectorSetup(stubImage(MOVL_MVTC, true), true),
                RX62TBEUtils.hasVectorSetup(stubImage(MOVL_MVTC, true), false)));
        Check.eq("vector_setup_le", List.of(false, true), List.of(
                RX62TBEUtils.hasVectorSetup(stubImage(MOVL_MVTC, false), true),
                RX62TBEUtils.hasVectorSetup(stubImage(MOVL_MVTC, false), false)));
        Check.eq("vector_setup_none", List.of(false, false), List.of(
                RX62TBEUtils.hasVectorSetup(new byte[0x100], true), RX62TBEUtils.hasVectorSetup(new byte[0x100], false)));
        byte[] five = java.util.Arrays.copyOf(MVTC_IMM, 5);
        Check.eq("vector_setup_short", List.of(false, false), List.of(
                RX62TBEUtils.hasVectorSetup(five, true), RX62TBEUtils.hasVectorSetup(five, false)));

        byte[] outside = bytes(0xFB, 0x12, 0x00, 0x10, 0x00, 0x00, 0xFD, 0x68, 0x1C, 3, 3, 3);
        Check.eq("vectors_outside_image", Map.of(), RX62TBEUtils.findVectorTables(stubImage(outside, true), B, true));

        byte[] r = put(new byte[0x100], 0xFC, be32(0xFFFFFF10));
        Check.eq("reset_vector_mapped", new Entry(0xFFFFFF10L, true), RX62TBEUtils.resetEntry(r, 0xFFFFFF00L, true));
        byte[] bogus = put(new byte[0x100], 0xFC, be32(0x30A264B5));
        Check.eq("reset_vector_bogus", new Entry(0xFFFFFF00L, false), RX62TBEUtils.resetEntry(bogus, 0xFFFFFF00L, true));
        Check.eq("reset_vector_unmapped", new Entry(0xFFF80000L, false), RX62TBEUtils.resetEntry(new byte[0x100], 0xFFF80000L, true));
        byte[] rle = put(new byte[0x100], 0xFC, le32(0xFFFFFF20));
        Check.eq("reset_vector_le", new Entry(0xFFFFFF20L, true), RX62TBEUtils.resetEntry(rle, 0xFFFFFF00L, false));

        System.exit(Check.summary("be_utils"));
    }
}
