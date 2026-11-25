// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongPredicate;

/**
 * Structural scans of Renesas RX raw flash images (no Ghidra dependencies): word swapping, pointer
 * tables, the INTB/EXTB setup in the reset code, the vector-table sizes and the reset entry.
 */
public final class RX62TBEUtils {
    /** Byte range in an image; end is exclusive. */
    public record Range(int start, int end) {}

    /** Program entry point; fromVector is true when taken from the reset vector. */
    public record Entry(long address, boolean fromVector) {}

    public static final long RESET_VECTOR = 0xFFFFFFFCL;
    public static final int INTB_LEN = 1024, EXTB_LEN = 128;

    /**
     * Vector-table entries as the RXv2/RXv3 manuals define them (section 1.7): INTB holds 256 vectors; EXTB
     * holds the exception vectors at ExtBase+00h to +78h, plus the reset vector at +7Ch only when ExtBase
     * is the fixed vector table {@link #FIXED_EXTB} (the reset vector is always at {@link #RESET_VECTOR}).
     */
    public static final int INTB_ENTRIES = 256, EXTB_ENTRIES = 31;

    /** Reset value of EXTB: the fixed vector table, whose last slot is the reset vector. */
    public static final long FIXED_EXTB = 0xFFFFFF80L;

    /** Bytes at the image start scanned for the reset code's INTB/EXTB setup. */
    static final int CODE_WINDOW = 0x100;

    private RX62TBEUtils() {}

    /** Reverses each 4-byte chunk (a trailing partial chunk too) into a new array. */
    public static byte[] swapWords(byte[] buf) {
        byte[] out = new byte[buf.length];
        for (int i = 0; i < buf.length; i += 4) {
            int n = Math.min(4, buf.length - i);
            for (int k = 0; k < n; k++) out[i + k] = buf[i + n - 1 - k];
        }
        return out;
    }

    private static long u32(byte[] b, int o, boolean bigEndian) {
        int v = bigEndian
                ? (b[o] & 0xFF) << 24 | (b[o + 1] & 0xFF) << 16 | (b[o + 2] & 0xFF) << 8 | (b[o + 3] & 0xFF)
                : (b[o + 3] & 0xFF) << 24 | (b[o + 2] & 0xFF) << 16 | (b[o + 1] & 0xFF) << 8 | (b[o] & 0xFF);
        return Integer.toUnsignedLong(v);
    }

    /** Runs of aligned dwords pointing into the image (zeros allowed between pointers). */
    public static List<Range> findPointerTables(byte[] img, long base, int minPtrs, boolean bigEndian) {
        long top = base + img.length;
        return findPointerRuns(img, base, minPtrs, bigEndian, v -> base <= v && v < top);
    }

    /**
     * Runs of at least {@code minPtrs} aligned dwords whose values satisfy {@code isTarget}, with single
     * zero dwords allowed between them; offsets in {@code img}, which starts at {@code base}. A run says
     * only that these slots hold pointers, not where a table starts or ends.
     */
    public static List<Range> findPointerRuns(byte[] img, long base, int minPtrs, boolean bigEndian,
            LongPredicate isTarget) {
        List<Range> tables = new ArrayList<>();
        int runStart = -1, runLast = -1, runCount = 0;
        for (int o = 0; o + 4 <= img.length; o += 4) {
            long v = u32(img, o, bigEndian);
            if (isTarget.test(v)) {
                if (runCount == 0) runStart = o;
                runLast = o;
                runCount++;
                continue;
            }
            if (runCount > 0 && v == 0 && o - runLast <= 4) continue;
            if (runCount >= minPtrs) tables.add(new Range(runStart, runLast + 4));
            runCount = 0;
        }
        if (runCount >= minPtrs) tables.add(new Range(runStart, runLast + 4));
        return tables;
    }

    // Encodings verified against the RXv2 software manual (R01US0071EJ0100), Section 4.
    // MOV.L #IMM:32,Rd (MOV (6), p.254): 1111 1011 | rd[3:0] li[1:0]=00 10 | imm32 LE; 6 bytes.
    private static final int OP_MOV_IMM = 0xFB;
    private static final int MOV_IMM32_LOW_NIBBLE = 0x02;   // li[1:0]=00b (#IMM:32), then 10b
    private static final int MOV_IMM32_LEN = 6;
    // MVTC prefix byte for both forms (pp.269-270): 1111 1101.
    private static final int OP_PREFIX_FD = 0xFD;
    // MVTC Rs,CR (form 2): FD 68 | rs[3:0] cr[3:0]; 3 bytes.
    private static final int OP_MVTC_REG = 0x68;
    private static final int MVTC_REG_LEN = 3;
    // MVTC #IMM:32,CR (form 1, li=00b): FD 73 | 0000 cr[3:0] | imm32 LE; 7 bytes.
    private static final int OP_MVTC_IMM32 = 0x73;
    private static final int MVTC_IMM32_LEN = 7;
    // Control register numbers cr[3:0] (p.269): 1100b = INTB, 1101b = EXTB.
    private static final int CR_INTB = 0x0C;
    private static final int CR_EXTB = 0x0D;

    /**
     * Reads INTB/EXTB from the reset code at the image base by following MOV.L #imm32,Rn,
     * MVTC Rn,CR and MVTC #imm32,CR. Returns name -> offset for tables inside the image.
     * codeSwapped: the image is a raw BE file whose code words are swapped, so the first 0x100
     * bytes are swapped before scanning.
     */
    public static Map<String, Integer> findVectorTables(byte[] img, long base, boolean codeSwapped) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map.Entry<String, Long> e : scanVectorSetup(img, codeSwapped).entrySet()) {
            long off = e.getValue() - base;
            if (0 <= off && off < img.length) out.put(e.getKey(), (int) off);
        }
        return out;
    }

    /**
     * True when the first {@link #CODE_WINDOW} bytes, in this order (swapped first when codeSwapped),
     * set INTB or EXTB with MVTC from an immediate or a register loaded by MOV.L #imm32. Unlike
     * {@link #findVectorTables} the table address is not checked against any base.
     */
    public static boolean hasVectorSetup(byte[] head, boolean codeSwapped) {
        return !scanVectorSetup(head, codeSwapped).isEmpty();
    }

    /**
     * The INTB/EXTB values set by the reset code in the first {@link #CODE_WINDOW} bytes of {@code code},
     * which is in instruction-fetch order, by register name. The values are not checked against any base.
     */
    public static Map<String, Long> vectorSetup(byte[] code) {
        return scanVectorSetup(code, false);
    }

    /** Entries of the named vector table ("INTB" or "EXTB") at {@code address}: 256, or 31 (32 at FFFFFF80h). */
    public static int vectorTableEntries(String name, long address) {
        if (name.equals("INTB")) return INTB_ENTRIES;
        return address == FIXED_EXTB ? EXTB_ENTRIES + 1 : EXTB_ENTRIES;
    }

    /** The label of slot {@code slot} of the named vector table: {@code int_vect_NNN} or {@code exc_vect_NN}. */
    public static String vectorSlotLabel(String table, int slot) {
        return table.equals("INTB") ? String.format("int_vect_%03d", slot) : String.format("exc_vect_%02d", slot);
    }

    /**
     * The architected EXTB slots, by slot index (offset / 4), from RXv3 R01US0316EJ0100 Figure 1.8 (p. 34)
     * and RXv2 R01US0071EJ0100 Figure 1.8 (p. 32). Slot 31 (+7Ch) is the reset vector, which only the fixed
     * table at {@link #FIXED_EXTB} holds.
     */
    private static final Map<Integer, String> EXTB_COMMENTS = Map.of(
            20, "Privileged instruction exception",
            21, "Access exception",
            23, "Undefined instruction exception",
            24, "Address exception (RXv3; reserved on RXv2)",
            25, "Floating-point exception (single-precision on RXv3)",
            30, "Non-maskable interrupt");

    /** The manual's name for EXTB slot {@code slot}, {@code Reset} for slot 31 when {@code fixed}, else null. */
    public static String extbSlotComment(int slot, boolean fixed) {
        if (slot == 31) return fixed ? "Reset" : null;
        return EXTB_COMMENTS.get(slot);
    }

    /** A pointer run makes functions only with this many code slots pointing to this many distinct targets. */
    public static final int MIN_CODE_SLOTS = 4, MIN_CODE_TARGETS = 2;

    /**
     * The distinct code targets of a pointer run's slots, in first-seen order, or an empty list unless at
     * least {@link #MIN_CODE_SLOTS} slots satisfy {@code isCode} and they name at least
     * {@link #MIN_CODE_TARGETS} distinct targets. The distinct-target rule leaves out linker section tables,
     * whose entries repeat one end-of-code address.
     */
    public static List<Long> codePointerTargets(long[] slots, LongPredicate isCode) {
        int code = 0;
        java.util.LinkedHashSet<Long> targets = new java.util.LinkedHashSet<>();
        for (long v : slots) {
            if (!isCode.test(v)) continue;
            code++;
            targets.add(v);
        }
        if (code < MIN_CODE_SLOTS || targets.size() < MIN_CODE_TARGETS) return List.of();
        return List.copyOf(targets);
    }

    /**
     * Runs of at least {@link #MIN_CODE_SLOTS} aligned dwords in {@code img} whose values satisfy {@code isCode},
     * with at most one dword of any value between two of them, as in tables of {handler, flag} or {id, handler}
     * entries; two such dwords in a row end the run. A run starts at its first code slot and ends after its last.
     */
    public static List<Range> findCodePointerRuns(byte[] img, boolean bigEndian, LongPredicate isCode) {
        List<Range> runs = new ArrayList<>();
        int start = -1, last = -1, count = 0;
        for (int o = 0; o + 4 <= img.length; o += 4) {
            if (!isCode.test(u32(img, o, bigEndian))) continue;
            if (count > 0 && o - last > 8) {
                if (count >= MIN_CODE_SLOTS) runs.add(new Range(start, last + 4));
                count = 0;
            }
            if (count == 0) start = o;
            last = o;
            count++;
        }
        if (count >= MIN_CODE_SLOTS) runs.add(new Range(start, last + 4));
        return runs;
    }

    /** The INTB/EXTB values the reset code at the start of img sets, by register name. */
    private static Map<String, Long> scanVectorSetup(byte[] img, boolean codeSwapped) {
        byte[] head = java.util.Arrays.copyOf(img, Math.min(CODE_WINDOW, img.length));
        byte[] code = codeSwapped ? swapWords(head) : head;
        Map<Integer, Long> regs = new java.util.HashMap<>();
        Map<String, Long> found = new LinkedHashMap<>();
        int i = 0;
        while (i < code.length - 7) {
            int b0 = code[i] & 0xFF, b1 = code[i + 1] & 0xFF, b2 = code[i + 2] & 0xFF;
            if (b0 == OP_MOV_IMM && (b1 & 0x0F) == MOV_IMM32_LOW_NIBBLE) {
                regs.put(b1 >> 4, u32(code, i + 2, false));
                i += MOV_IMM32_LEN;
            } else if (b0 == OP_PREFIX_FD && b1 == OP_MVTC_REG && crName(b2 & 0x0F) != null) {
                Long val = regs.get(b2 >> 4);
                if (val != null) found.put(crName(b2 & 0x0F), val);
                i += MVTC_REG_LEN;
            } else if (b0 == OP_PREFIX_FD && b1 == OP_MVTC_IMM32 && crName(b2) != null) {
                found.put(crName(b2), u32(code, i + 3, false));
                i += MVTC_IMM32_LEN;
            } else {
                i++;
            }
        }
        return found;
    }

    private static String crName(int cr) {
        return cr == CR_INTB ? "INTB" : cr == CR_EXTB ? "EXTB" : null;
    }

    /**
     * Entry point (decision D1): the dword at 0xFFFFFFFC if the image covers it and the value
     * points into the image; otherwise the image base.
     */
    public static Entry resetEntry(byte[] img, long base, boolean bigEndian) {
        long off = RESET_VECTOR - base;
        if (off >= 0 && off + 4 <= img.length) {
            long v = u32(img, (int) off, bigEndian);
            if (base <= v && v < base + img.length) return new Entry(v, true);
        }
        return new Entry(base, false);
    }
}
