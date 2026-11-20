// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import rx62t.RX62TBEUtils.Range;

/**
 * A deterministic synthetic raw big-endian RX flash image laid out like real firmware, for tests
 * that must not depend on private images. Layout (offsets from {@link #BASE}):
 *
 * <pre>
 *   reset stub    MOV.L #INTB,R1; MVTC R1,INTB; MVTC #EXTB,EXTB; BRA.A main   (code, word-swapped)
 *   FF word       ends the reset stub
 *   header        8 bytes: big-endian build number and checksum
 *   FF padding    up to 0x60
 *   strings       NUL-terminated ASCII messages
 *   pointers      big-endian table of code pointers (a dispatch table)
 *   numeric       16-bit big-endian tables (sine and calibration curves; sign lanes 00/FF)
 *   INTB          256 big-endian pointers to interrupt handlers
 *   code          functions made of real RX encodings (from test/vectors/*.vec), word-swapped, with three
 *                 data islands between functions (two string pools and a 16-bit table), stored as is
 *   fill          0xFF
 *   EXTB          32 big-endian pointers to exception handlers, at the end of the image
 * </pre>
 *
 * The output depends only on the fixed seed: no files are read.
 */
public final class RealisticImage {
    public static final long BASE = 0xFFF00000L;
    public static final int SIZE = 0x6000;

    /**
     * The image and its regions (offsets into {@code raw}; end exclusive).
     *
     * @param raw      the image as stored in flash: code words byte-swapped, data big-endian
     * @param base     load address of {@code raw[0]}
     * @param intb     address of the INTB table the reset stub sets up
     * @param extb     address of the EXTB table the reset stub sets up
     * @param entry    reset entry (the image base: the image does not cover the reset vector)
     * @param code     the whole code section, including {@code islands}
     * @param islands   data islands inside {@code code} long enough for the model to see (a string pool
     *                  and a 16-bit table)
     * @param shortPool a string pool inside {@code code} shorter than the model's switch cost can split
     *                  off: it is data, but the model absorbs it into the surrounding code
     */
    public record Image(byte[] raw, long base, long intb, long extb, long entry, Range stub, Range header,
            Range strings, Range numeric, Range pointers, Range code, List<Range> islands, Range shortPool,
            Range fill) {}

    private static final long SEED = 0x52583632L;
    private static final int CODE_BYTES = 0x4000;
    private static final int POINTERS = 24;
    private static final int SHORT_POOL = 0x60;

    // Instruction encodings in fetch order, each taken from a test/vectors/*.vec line.
    private static final int[][] BODY = {
        {0xFD, 0x74, 0x81, 0x03},             // DIV #0x3,R1
        {0xFC, 0x27, 0x21},                   // DIVU R2,R1
        {0xFC, 0x23, 0x21},                   // DIV R2,R1
        {0xFD, 0x74, 0x91, 0x03},             // DIVU #0x3,R1
        {0xFC, 0x97, 0x21},                   // FTOI R2,R1
        {0xFC, 0xA7, 0x21},                   // FTOU R2,R1
        {0x47, 0xF1},                         // CMP R15,R1
        {0x4B, 0x21},                         // ADD R2,R1
        {0x53, 0x21},                         // AND R2,R1
        {0x4F, 0x21},                         // MUL R2,R1
        {0xFC, 0x57, 0x21},                   // UTOF R2,R1
        {0x06, 0x88, 0x21},                   // ADD [R2].L,R1
        {0x45, 0x21, 0x04},                   // CMP 0x4[R2].UB,R1
        {0x5B, 0x21},                         // MOVU.B R2,R1
        {0x5F, 0x21},                         // MOVU.W R2,R1
        {0xCF, 0x21},                         // MOV.B R2,R1
        {0xFC, 0x60, 0x12},                   // BSET R2,[R1].B
        {0xFC, 0x64, 0x12},                   // BCLR R2,[R1].B
        {0xFC, 0x6C, 0x12},                   // BNOT R2,[R1].B
        {0xFC, 0x68, 0x12},                   // BTST R2,[R1].B
        {0xFC, 0x6F, 0x12},                   // BNOT R2,R1
        {0xF0, 0x10},                         // BSET #0x0,[R1].B
        {0xE3, 0x21},                         // MOV.L R1,[R2]
        {0xCC, 0x21},                         // MOV.B [R2],R1
        {0xDC, 0x21},                         // MOV.W [R2],R1
        {0xFD, 0x74, 0x4E, 0xFF},             // MAX #-0x1,R14
        {0xFC, 0x13, 0x21},                   // MAX R2,R1
        {0xFC, 0x17, 0x21},                   // MIN R2,R1
        {0x06, 0xA1, 0x05, 0x61, 0x0C},       // MIN 0x30[R6].L,R1
        {0xFC, 0x4B, 0xEC},                   // STZ R14,R12
        {0xFC, 0x4F, 0xEC},                   // STNZ R14,R12
        {0xFD, 0x74, 0xE1, 0x05},             // STZ #0x5,R1
        {0xFC, 0x40, 0x21},                   // XCHG [R2].UB,R1
        {0x06, 0xA0, 0x10, 0x21},             // XCHG [R2].L,R1
        {0xFB, 0x12, 0x78, 0x56, 0x34, 0x12}, // MOV.L #0x12345678,R1
        {0x62, 0x51},                         // ADD #0x5,R1
        {0x61, 0x01},                         // CMP #0x0,R1
        {0xEE, 0x21, 0x00, 0x08},             // MOV.L 0x2000[R2],R1
        {0xFC, 0xDB, 0xE0},                   // SCEQ.L R14
        {0xFC, 0xDB, 0xE1},                   // SCNE.L R14
        {0xFC, 0xD0, 0xE0},                   // SCEQ.B [R14]
        {0x6C, 0x31},                         // SHLL #0x3,R1
        {0xFD, 0x62, 0x21},                   // SHLL R2,R1
        {0x6D, 0xF1},                         // SHLL #0x1f,R1
        {0xFD, 0xC3, 0x21},                   // SHLL #0x3,R2,R1
        {0xFD, 0xA2, 0x21},                   // SHAR #0x2,R2,R1
        {0xFC, 0x0B, 0x42},                   // ADC R4,R2
        {0xFD, 0x74, 0x22, 0x01},             // ADC #0x1,R2
        {0x06, 0xA0, 0x02, 0x42},             // ADC [R4].L,R2
        {0xFC, 0x03, 0x42},                   // SBB R4,R2
        {0x7E, 0x54},                         // ROLC R4
        {0x7E, 0x42},                         // RORC R2
        {0x7F, 0x84},                         // SWHILE.B
        {0x7F, 0x85},                         // SWHILE.W
        {0x7F, 0x80},                         // SUNTIL.B
    };
    private static final int[] PUSHM = {0x6E, 0x13};      // PUSHM R1-R3
    private static final int[] POPM = {0x6F, 0x13};       // POPM R1-R3
    private static final int[] RTSD = {0x3F, 0x13, 0x03}; // RTSD #0xc,R1-R3
    private static final int[] RTS = {0x02};
    private static final int[] RTE = {0x7F, 0x95};
    private static final int NOP = 0x03, BRA_A = 0x04;    // BRA.A pcdsp:24 (04 dsp24 LE)

    private static final String[] NOUNS = {
        "Battery", "Display", "Memory", "Channel", "Timer", "Clock", "Sensor", "Config", "Backlight",
        "Volume", "Speaker", "Keypad", "Network", "Storage", "Calibration", "Power supply", "Serial port",
        "Temperature", "Scan list", "Squelch", "Antenna", "Receiver", "Transmitter", "Audio codec",
    };
    private static final String[] STATES = {
        " error", " ready", " saved", " failed", " enabled", " disabled", " locked", " reset",
        " timeout", " not found", " out of range", " busy", " restored", " updated",
    };

    private RealisticImage() {}

    public static Image build() {
        Random rnd = new Random(SEED);
        byte[] fetch = new byte[SIZE];       // the image in instruction-fetch order
        Arrays.fill(fetch, (byte) 0xFF);

        // constant section
        Range headerR = put(fetch, 0x18, new byte[] {0x00, 0x00, 0x01, 0x2C, 0x5A, (byte) 0xC3, 0x1E, 0x77});
        int at = 0x60;
        byte[] strings = strings(rnd, 0x500);
        Range stringsR = put(fetch, at, strings);
        Range pointersR = new Range(stringsR.end(), stringsR.end() + 4 * POINTERS); // filled once code is placed
        byte[] numeric = numeric(rnd);
        Range numericR = put(fetch, pointersR.end(), numeric);
        int intbOff = numericR.end();
        int codeOff = intbOff + RX62TBEUtils.INTB_LEN;
        int extbOff = SIZE - RX62TBEUtils.EXTB_LEN;

        // code: main, the default handler, then interrupt handlers and functions in a seeded mix
        ByteArrayOutputStream code = new ByteArrayOutputStream();
        int main = codeOff;
        body(code, rnd, 24);
        emitBra(code, main - (codeOff + code.size()));      // main loop: BRA.A back to main
        int dflt = codeOff + code.size();
        emit(code, RTE);
        List<Integer> handlers = new ArrayList<>(), functions = new ArrayList<>();
        List<Range> islands = new ArrayList<>();
        while (code.size() < CODE_BYTES) {
            if (islands.size() < 3 && code.size() >= (islands.size() + 1) * CODE_BYTES / 4) {
                while (code.size() % 4 != 0) code.write(NOP);
                int start = codeOff + code.size();
                byte[] island = switch (islands.size()) {
                    case 0 -> strings(rnd, 0x100);                  // string pool
                    case 1 -> Arrays.copyOf(numeric(rnd), 0x40);    // 16-bit table
                    default -> strings(rnd, SHORT_POOL);            // short string pool
                };
                code.write(island, 0, island.length);
                islands.add(new Range(start, start + island.length));
                continue;
            }
            int start = codeOff + code.size();
            if (rnd.nextInt(5) == 0) {
                handlers.add(start);
                emit(code, PUSHM);
                body(code, rnd, 4 + rnd.nextInt(12));
                emit(code, POPM);
                emit(code, RTE);
            } else {
                functions.add(start);
                boolean frame = rnd.nextBoolean();
                if (frame) emit(code, PUSHM);
                body(code, rnd, 6 + rnd.nextInt(40));
                emit(code, frame ? RTSD : RTS);
            }
        }
        while (code.size() % 4 != 0) code.write(NOP);
        Range codeR = put(fetch, codeOff, code.toByteArray());
        Range fillR = new Range((codeR.end() + 31) & ~31, extbOff);

        // pointer table: a dispatch table of function entries
        for (int i = 0; i < POINTERS; i++)
            putBe32(fetch, pointersR.start() + 4 * i, BASE + functions.get(rnd.nextInt(functions.size())));

        // INTB: a few vectors have their own handler, the rest share the default one
        for (int i = 0; i < 256; i++) putBe32(fetch, intbOff + 4 * i, BASE + dflt);
        for (int i = 0; i < handlers.size() && i < 24; i++)
            putBe32(fetch, intbOff + 4 * (16 + rnd.nextInt(240)), BASE + handlers.get(i));
        // EXTB: the exception vectors in use get a handler, the rest the default one
        int exc = handlers.get(handlers.size() - 1);
        for (int i = 0; i < 32; i++)
            putBe32(fetch, extbOff + 4 * i, BASE + (i == 20 || i == 21 || i == 23 || i == 30 ? exc : dflt));

        long intb = BASE + intbOff, extb = BASE + extbOff;
        ByteArrayOutputStream stub = new ByteArrayOutputStream();
        emit(stub, new int[] {0xFB, 0x12});                // MOV.L #intb,R1
        emitLe32(stub, intb);
        emit(stub, new int[] {0xFD, 0x68, 0x1C});          // MVTC R1,INTB
        emit(stub, new int[] {0xFD, 0x73, 0x0D});          // MVTC #extb,EXTB
        emitLe32(stub, extb);
        emitBra(stub, main - stub.size());                 // BRA.A main
        Range stubR = put(fetch, 0, stub.toByteArray());

        // store: code word-swapped, everything else as is
        byte[] raw = fetch.clone();
        List<Range> swapped = new ArrayList<>(List.of(stubR));
        int from = codeR.start();
        for (Range island : islands) {
            swapped.add(new Range(from, island.start()));
            from = island.end();
        }
        swapped.add(new Range(from, codeR.end()));
        for (Range r : swapped)
            System.arraycopy(RX62TBEUtils.swapWords(Arrays.copyOfRange(fetch, r.start(), r.end())), 0, raw, r.start(),
                    r.end() - r.start());
        return new Image(raw, BASE, intb, extb, BASE, stubR, headerR, stringsR, numericR, pointersR, codeR,
                List.copyOf(islands.subList(0, 2)), islands.get(2), fillR);
    }

    /** NUL-terminated messages, at least {@code min} bytes, padded with NULs to a word boundary. */
    private static byte[] strings(Random rnd, int min) {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < min) {
            switch (rnd.nextInt(4)) {
                case 0 -> sb.append(String.format(Locale.ROOT, "Version %d.%02d", 1 + rnd.nextInt(4), rnd.nextInt(100)));
                case 1 -> sb.append(NOUNS[rnd.nextInt(NOUNS.length)]).append(" level %d%%");
                default -> sb.append(NOUNS[rnd.nextInt(NOUNS.length)]).append(STATES[rnd.nextInt(STATES.length)]);
            }
            sb.append('\0');
        }
        while (sb.length() % 4 != 0) sb.append('\0');
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Four 128-entry 16-bit big-endian tables with values in [-255, 255]. */
    private static byte[] numeric(Random rnd) {
        short[] v = new short[512];
        for (int i = 0; i < 128; i++) {
            v[i] = (short) Math.round(250 * StrictMath.sin(2 * Math.PI * i / 128));      // sine
            v[128 + i] = (short) (2 * i - 128 + rnd.nextInt(9) - 4);                       // calibration ramp
            v[256 + i] = (short) Math.round(240 * StrictMath.cos(2 * Math.PI * i / 128)); // cosine
            v[384 + i] = (short) (rnd.nextInt(201) - 100);                                 // offsets
        }
        byte[] b = new byte[2 * v.length];
        for (int i = 0; i < v.length; i++) {
            b[2 * i] = (byte) (v[i] >> 8);
            b[2 * i + 1] = (byte) v[i];
        }
        return b;
    }

    private static void body(ByteArrayOutputStream out, Random rnd, int n) {
        for (int i = 0; i < n; i++) emit(out, BODY[rnd.nextInt(BODY.length)]);
    }

    private static void emit(ByteArrayOutputStream out, int[] insn) {
        for (int b : insn) out.write(b);
    }

    private static void emitLe32(ByteArrayOutputStream out, long v) {
        for (int k = 0; k < 4; k++) out.write((int) (v >>> (8 * k)) & 0xFF);
    }

    /** BRA.A to {@code disp} bytes from the instruction start. */
    private static void emitBra(ByteArrayOutputStream out, int disp) {
        out.write(BRA_A);
        for (int k = 0; k < 3; k++) out.write((disp >>> (8 * k)) & 0xFF);
    }

    private static Range put(byte[] img, int at, byte[] b) {
        System.arraycopy(b, 0, img, at, b.length);
        return new Range(at, at + b.length);
    }

    private static void putBe32(byte[] img, int at, long v) {
        for (int k = 0; k < 4; k++) img[at + k] = (byte) (v >>> (24 - 8 * k));
    }
}
