// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
// Headless tests for the "RX62T Raw Binary" loader (rx62t.RX62TLoader) and the "RX62T Platform Setup"
// analyzer (rx62t.RX62TAnalyzer), both from the staged extension jar.
// Each case loads a synthetic image in-process through ProgramLoader and checks the resulting program;
// analyzer cases then run RX62TAnalyzer.added over all of memory.
// Results are printed as "RXTEST PASS|FAIL loader:<case> ..." and "RXTEST SUMMARY loader pass= fail=".
// realistic_image_end_to_end uses rx62t.RealisticImage from the staged tests jar (lib/RX62T-tests.jar).
// Usage: -postScript RxLoaderTest.java (the current program is not used)
//@category Test
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import ghidra.program.model.symbol.SymbolIterator;
import rx62t.RX62TAnalyzer;
import rx62t.RX62TBEClassifier;
import rx62t.RX62TBEUtils;
import rx62t.RX62TLoader;
import rx62t.RealisticImage;

public class RxLoaderTest extends GhidraScript {

    private static final String LE = "rx62t:LE:32:default", BE = "rx62t:BE:32:default";
    private static final long STUB_BASE = 0xFFCFFF00L;
    /** MOV.L #0xFFD00000,R1; MVTC R1,INTB; 3 x NOP (instruction byte order, before swapping). */
    private static final byte[] STUB = bytes(0xFB, 0x12, 0x00, 0x00, 0xD0, 0xFF, 0xFD, 0x68, 0x1C, 3, 3, 3);

    private int pass, fail;

    @Override
    public void run() throws Exception {
        caseRun("le_verbatim", this::leVerbatim);
        caseRun("be_entry_vector", this::beEntryVector);
        caseRun("be_fixed_vectors_unswapped", this::beFixedVectorsUnswapped);
        caseRun("be_entry_fallback", this::beEntryFallback);
        caseRun("be_matches_classifier", this::beMatchesClassifier);
        caseRun("be_pointer_table_unswapped", this::bePointerTableUnswapped);
        caseRun("be_odd_length", this::beOddLength);
        caseRun("options_validation", this::optionsValidation);
        caseRun("load_checks_options", this::loadChecksOptions);
        caseRun("analyzer_reset", this::analyzerReset);
        caseRun("analyzer_intb", this::analyzerIntb);
        caseRun("analyzer_extb_le", this::analyzerExtbLe);
        caseRun("analyzer_vectors_before_code", this::analyzerVectorsBeforeCode);
        caseRun("analyzer_ptr_table", this::analyzerPtrTable);
        caseRun("vector_table_truncated", this::vectorTableTruncated);
        caseRun("analyzer_rerun", this::analyzerRerun);
        caseRun("analyzer_binaryloader", this::analyzerBinaryLoader);
        caseRun("analyzer_no_ptr_tables_other_format", this::analyzerNoPtrTablesOtherFormat);
        caseRun("analyzer_ptr_table_skips_code", this::analyzerPtrTableSkipsCode);
        caseRun("analyzer_ptr_table_skips_straddling_code", this::analyzerPtrTableSkipsStraddlingCode);
        caseRun("analyzer_ptr_table_keeps_user_data", this::analyzerPtrTableKeepsUserData);
        caseRun("analyzer_entry_extra_block", this::analyzerEntryExtraBlock);
        caseRun("analyzer_handler_into_table_skipped", this::analyzerHandlerIntoTableSkipped);
        caseRun("realistic_image_end_to_end", this::realisticImageEndToEnd);
        caseRun("loadspec_prefers_be", () -> loadSpecs(intbImage(), BE));
        caseRun("loadspec_prefers_le", () -> loadSpecs(leStubImage(), LE));
        caseRun("loadspec_short_file", () -> loadSpecs(new byte[3], null));
        caseRun("loadspec_empty", this::loadSpecEmpty);
        caseRun("memmap_default", this::memmapDefault);
        caseRun("memmap_off", this::memmapOff);
        caseRun("memmap_overlap", this::memmapOverlap);
        caseRun("memmap_overlap_periph", this::memmapOverlapPeriph);
        caseRun("param_id_default", this::paramIdDefault);
        caseRun("param_id_only_this_loader", this::paramIdOnlyThisLoader);
        caseRun("add_to_program_no_side_effects", this::addToProgramNoSideEffects);
        caseRun("orphan_functions", this::orphanFunctions);
        caseRun("fix_signatures", this::fixSignatures);
        caseRun("fix_signatures_refuses_other_language", this::fixSignaturesRefuses);
        println("RXTEST SUMMARY loader pass=" + pass + " fail=" + fail);
    }

    // ---- cases: each returns null on success, else a failure description ----

    private String leVerbatim() throws Exception {
        byte[] img = new byte[64];
        for (int i = 0; i < img.length; i++) img[i] = (byte) i;
        return withProgram("le_verbatim", img, LE, 0x1000, p -> {
            String err = checkBlock(p, 0x1000, img.length);
            if (err != null) return err;
            if (!Arrays.equals(memBytes(p, 0x1000, img.length), img)) return "bytes differ from input";
            if (!RX62TLoader.NAME.equals(p.getExecutableFormat())) return "executable format " + p.getExecutableFormat();
            return checkEntry(p, 0x1000);
        });
    }

    private static byte[] entryVectorImage() {
        byte[] img = new byte[0x100];
        System.arraycopy(be32(0xFFFFFF10L), 0, img, 0xFC, 4);
        return img;
    }

    private String beEntryVector() throws Exception {
        return withProgram("be_entry_vector", entryVectorImage(), BE, 0xFFFFFF00L, p -> checkEntry(p, 0xFFFFFF10L));
    }

    /** Ruling R3: the fixed vector table 0xFFFFFF80..0xFFFFFFFF is never word-swapped. */
    private String beFixedVectorsUnswapped() throws Exception {
        byte[] img = entryVectorImage();
        long base = 0xFFFFFF00L;
        byte[] fetch = RX62TBEClassifier.buildFetchOrderImage(img, RX62TBEClassifier.classify(img, base), base);
        return withProgram("be_fixed_vectors_unswapped", img, BE, base, p -> {
            byte[] got = memBytes(p, base, img.length);
            if (!Arrays.equals(got, 0x80, 0x100, img, 0x80, 0x100))
                return "fixed vector table changed: " + HexFormat.of().formatHex(got, 0x80, 0x100);
            if (!Arrays.equals(got, 0, 0x80, fetch, 0, 0x80)) return "bytes below 0xFFFFFF80 differ from buildFetchOrderImage";
            return checkEntry(p, 0xFFFFFF10L);
        });
    }

    private String beEntryFallback() throws Exception {
        return withProgram("be_entry_fallback", new byte[0x100], BE, 0xFFF80000L, p -> checkEntry(p, 0xFFF80000L));
    }

    private String beMatchesClassifier() throws Exception {
        byte[] img = ptrTableImage();
        byte[] want = RX62TBEClassifier.buildFetchOrderImage(img, RX62TBEClassifier.classify(img, STUB_BASE), STUB_BASE);
        return withProgram("be_matches_classifier", img, BE, STUB_BASE, p -> {
            String err = checkBlock(p, STUB_BASE, img.length);
            if (err != null) return err;
            byte[] got = memBytes(p, STUB_BASE, img.length);
            if (!Arrays.equals(got, want)) return "memory differs from buildFetchOrderImage at " + firstDiff(got, want);
            if (!Arrays.equals(Arrays.copyOf(got, STUB.length), STUB)) return "reset stub not in fetch order";
            List<ghidra.program.database.mem.FileBytes> fbs = p.getMemory().getAllFileBytes();
            if (fbs.size() != 1) return "FileBytes count " + fbs.size();
            byte[] orig = new byte[img.length];
            int n = fbs.get(0).getOriginalBytes(0, orig);
            if (n != img.length || !Arrays.equals(orig, img)) return "FileBytes original bytes differ from input";
            return null;
        });
    }

    private String bePointerTableUnswapped() throws Exception {
        byte[] img = ptrTableImage();
        return withProgram("be_pointer_table_unswapped", img, BE, STUB_BASE, p -> {
            byte[] got = memBytes(p, STUB_BASE + 0x540, 64);
            byte[] want = Arrays.copyOfRange(img, 0x540, 0x580);
            return Arrays.equals(got, want) ? null : "pointer table words changed: " + HexFormat.of().formatHex(got);
        });
    }

    private String beOddLength() throws Exception {
        byte[] img = Arrays.copyOf(stubImage(), 0x103);
        return withProgram("be_odd_length", img, BE, STUB_BASE, p -> {
            String err = checkBlock(p, STUB_BASE, img.length);
            if (err != null) return err;
            byte[] got = memBytes(p, STUB_BASE, img.length);
            if (!Arrays.equals(Arrays.copyOf(got, STUB.length), STUB)) return "reset stub not in fetch order";
            byte[] tail = Arrays.copyOfRange(got, 0x100, 0x103), want = Arrays.copyOfRange(img, 0x100, 0x103);
            return Arrays.equals(tail, want) ? null : "tail " + HexFormat.of().formatHex(tail) + " want " + HexFormat.of().formatHex(want);
        });
    }

    private String optionsValidation() throws Exception {
        RX62TLoader loader = new RX62TLoader();
        LoadSpec le = new LoadSpec(loader, 0, new LanguageCompilerSpecPair(LE, "default"), false);
        LoadSpec be = new LoadSpec(loader, 0, new LanguageCompilerSpecPair(BE, "default"), false);
        List<String> errs = new ArrayList<>();
        expect(errs, loader, be, 0x100, "FFF80000", null);
        expect(errs, loader, be, 0x100, " 0x10 ", null);
        expect(errs, loader, be, 0x100, "zz", "Base address");
        expect(errs, loader, be, 0x100, "0x1002", "aligned");
        expect(errs, loader, le, 0x100, "0x1002", null);
        expect(errs, loader, be, 0x200, "0xFFFFFF00", "exceeds");
        expect(errs, loader, be, 0x100, "0x100000000", "Base address");
        expect(errs, loader, be, 0, "0x0", "empty");
        return errs.isEmpty() ? null : String.join("; ", errs);
    }

    /** ProgramLoader does not call validateOptions, so load itself must reject what validation would. */
    private String loadChecksOptions() throws Exception {
        try {
            withProgram("load_checks_options", new byte[0x100], BE, 0x1002, p -> "unaligned BE base loaded");
        }
        catch (ghidra.app.util.opinion.LoadException e) {
            return e.getMessage() != null && e.getMessage().contains("aligned") ? null : "message: " + e.getMessage();
        }
        return "unaligned BE base loaded";
    }

    private void expect(List<String> errs, RX62TLoader loader, LoadSpec spec, int len, String base, String want)
            throws Exception {
        ByteArrayProvider provider = new ByteArrayProvider(new byte[len]);
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        boolean found = false;
        for (Option o : options) {
            if (o.getName().equals(RX62TLoader.OPTION_BASE)) {
                o.setValue(base);
                found = true;
            }
        }
        if (!found) {
            errs.add("no '" + RX62TLoader.OPTION_BASE + "' option");
            return;
        }
        String got;
        try {
            got = loader.validateOptions(provider, spec, options, null);
        }
        catch (Throwable t) {
            errs.add("'" + base + "' threw " + t);
            return;
        }
        boolean ok = want == null ? got == null : got != null && got.contains(want);
        if (!ok) errs.add("'" + base + "' len=0x" + Integer.toHexString(len) + " " + spec.getLanguageCompilerSpec().languageID
                + " -> " + got + " (want " + (want == null ? "null" : "'" + want + "'") + ")");
    }

    // ---- analyzer cases ----

    private String analyzerReset() throws Exception {
        return withProgram("analyzer_reset", entryVectorImage(), BE, 0xFFFFFF00L, p -> {
            String err = runAnalyzer(p);
            return err != null ? err : checkFunction(p, 0xFFFFFF10L, "reset", null);
        });
    }

    private static final long INTB_ADDR = 0xFFD00000L, HANDLER = 0xFFD00400L;

    /** Stub image (base STUB_BASE, len 0x600) whose INTB at offset 0x100 holds 256 BE pointers to an RTE at 0x500. */
    private static byte[] intbImage() {
        byte[] img = new byte[0x600];
        byte[] sw = RX62TBEUtils.swapWords(STUB);
        System.arraycopy(sw, 0, img, 0, sw.length);
        Arrays.fill(img, sw.length, sw.length + 4, (byte) 0xFF);
        for (int i = 0; i < 256; i++) System.arraycopy(be32(HANDLER), 0, img, 0x100 + 4 * i, 4);
        System.arraycopy(RX62TBEUtils.swapWords(bytes(0x7F, 0x95, 0x03, 0x03)), 0, img, 0x500, 4); // RTE; NOP; NOP
        return img;
    }

    private static String checkIntb(Program p) {
        String err = checkLabel(p, INTB_ADDR, "INTB");
        if (err == null) err = checkPointerArray(p, INTB_ADDR, 256);
        return err != null ? err : checkFunction(p, HANDLER, null, "RTE");
    }

    private String analyzerIntb() throws Exception {
        return withProgram("analyzer_intb", intbImage(), BE, STUB_BASE, p -> {
            String err = runAnalyzer(p);
            return err != null ? err : checkIntb(p);
        });
    }

    private String analyzerExtbLe() throws Exception {
        long base = 0x1000, extb = base + 0x100, handler = base + 0x180;
        byte[] img = new byte[0x200];
        byte[] stub = bytes(0xFD, 0x73, 0x0D, (int) extb & 0xFF, (int) (extb >> 8) & 0xFF, 0, 0, 3, 3, 2); // MVTC #extb,EXTB; NOP; NOP; RTS
        System.arraycopy(stub, 0, img, 0, stub.length);
        for (int i = 0; i < 32; i++) System.arraycopy(le32(handler), 0, img, 0x100 + 4 * i, 4);
        img[0x180] = 0x7F;
        img[0x181] = (byte) 0x95; // RTE
        return withProgram("analyzer_extb_le", img, LE, base, p -> {
            String err = runAnalyzer(p);
            if (err == null) err = checkLabel(p, extb, "EXTB");
            if (err == null) err = checkPointerArray(p, extb, 32);
            return err != null ? err : checkFunction(p, handler, null, "RTE");
        });
    }

    /** Reset code that falls through zero bytes (BRK) into EXTB: the table is laid before any disassembly. */
    private String analyzerVectorsBeforeCode() throws Exception {
        long base = 0x1000, extb = base + 0x100;
        byte[] img = new byte[0x200];
        byte[] stub = bytes(0xFD, 0x73, 0x0D, (int) extb & 0xFF, (int) (extb >> 8) & 0xFF, 0, 0, 3, 3, 3); // MVTC #extb,EXTB; 3 x NOP
        System.arraycopy(stub, 0, img, 0, stub.length);
        return withProgram("analyzer_vectors_before_code", img, LE, base, p -> {
            String err = runAnalyzer(p);
            if (err == null) err = checkLabel(p, extb, "EXTB");
            if (err == null) err = checkPointerArray(p, extb, 32);
            return err != null ? err : checkFunction(p, base, null, null);
        });
    }

    private String analyzerPtrTable() throws Exception {
        return withProgram("analyzer_ptr_table", ptrTableImage(), BE, STUB_BASE, p -> {
            String err = runAnalyzer(p);
            return err != null ? err : checkPointerArray(p, STUB_BASE + 0x540, 16);
        });
    }

    /** INTB 0x40 bytes before the image end: the array is cut to the 16 entries inside the image. */
    private String vectorTableTruncated() throws Exception {
        long intb = STUB_BASE + 0x5C0;
        byte[] stub = bytes(0xFB, 0x12, (int) intb & 0xFF, (int) (intb >> 8) & 0xFF, (int) (intb >> 16) & 0xFF,
                (int) (intb >>> 24) & 0xFF, 0xFD, 0x68, 0x1C, 3, 3, 3); // MOV.L #intb,R1; MVTC R1,INTB
        byte[] img = new byte[0x600];
        byte[] sw = RX62TBEUtils.swapWords(stub);
        System.arraycopy(sw, 0, img, 0, sw.length);
        Arrays.fill(img, sw.length, sw.length + 4, (byte) 0xFF);
        return withProgram("vector_table_truncated", img, BE, STUB_BASE, p -> {
            String err = runAnalyzer(p);
            if (err == null) err = checkLabel(p, intb, "INTB");
            return err != null ? err : checkPointerArray(p, intb, 16);
        });
    }

    private String analyzerRerun() throws Exception {
        return withProgram("analyzer_rerun", intbImage(), BE, STUB_BASE, p -> {
            String err = runAnalyzer(p);
            if (err == null) err = runAnalyzer(p);
            if (err != null) return "second run: " + err;
            int n = 0;
            for (SymbolIterator it = p.getSymbolTable().getSymbols("INTB"); it.hasNext(); it.next()) n++;
            return n != 1 ? n + " INTB labels" : checkIntb(p);
        });
    }

    /** An image already in fetch order (un-swapped beforehand) imported with BinaryLoader gets the same INTB markup. */
    private String analyzerBinaryLoader() throws Exception {
        byte[] img = intbImage();
        byte[] fetch = RX62TBEClassifier.buildFetchOrderImage(img, RX62TBEClassifier.classify(img, STUB_BASE), STUB_BASE);
        return withProgram("analyzer_binaryloader", fetch, BE, STUB_BASE, BinaryLoader.class, p -> {
            if (!BinaryLoader.BINARY_NAME.equals(p.getExecutableFormat())) return "executable format " + p.getExecutableFormat();
            String err = runAnalyzer(p);
            if (err == null) err = checkIntb(p);
            return err != null ? err : checkFunction(p, STUB_BASE, "reset", null); // no loader label: the analyzer names it
        });
    }

    /** Ruling R8: the heuristic pointer-table step runs only for raw-image formats; vector tables still do. */
    private String analyzerNoPtrTablesOtherFormat() throws Exception {
        return withProgram("analyzer_no_ptr_tables_other_format", ptrTableImage(), BE, STUB_BASE, p -> {
            int tx = p.startTransaction("set format");
            try {
                p.setExecutableFormat("Executable and Linking Format (ELF)");
            }
            finally {
                p.endTransaction(tx, true);
            }
            String err = runAnalyzer(p);
            if (err == null) err = checkLabel(p, INTB_ADDR, "INTB");
            if (err != null) return err;
            Data d = p.getListing().getDefinedDataAt(addr(p, STUB_BASE + 0x540));
            return d == null ? null : "data at 0x" + Long.toHexString(STUB_BASE + 0x540) + ": " + d.getDataType().getName();
        });
    }

    /** Review focus 4: a pointer table that overlaps existing instructions is left alone. */
    private String analyzerPtrTableSkipsCode() throws Exception {
        long start = STUB_BASE + 0x540;
        return withProgram("analyzer_ptr_table_skips_code", ptrTableImage(), BE, STUB_BASE, p -> {
            AddressSet range = new AddressSet(addr(p, start), addr(p, start + 64 - 1));
            int tx = p.startTransaction("disassemble");
            try {
                new DisassembleCommand(range, range, false).applyTo(p, monitor);
            }
            finally {
                p.endTransaction(tx, true);
            }
            int before = countInstructions(p, range);
            if (before == 0) return "setup: no instructions disassembled at 0x" + Long.toHexString(start);
            String err = runAnalyzer(p);
            if (err != null) return err;
            Data d = p.getListing().getDefinedDataContaining(addr(p, start));
            if (d != null && d.isArray()) return "pointer array created over code: " + d.getDataType().getName();
            int after = countInstructions(p, range);
            return after == before ? null : "instructions " + before + " -> " + after;
        });
    }

    /** Finding I1: an instruction starting 2 bytes before the table and running into it survives. */
    private String analyzerPtrTableSkipsStraddlingCode() throws Exception {
        long table = STUB_BASE + 0x540, insn = table - 2;
        return withProgram("analyzer_ptr_table_skips_straddling_code", ptrTableImage(), BE, STUB_BASE, p -> {
            int tx = p.startTransaction("setup");
            try {
                p.getMemory().setBytes(addr(p, insn), bytes(0xFB, 0x12)); // MOV.L #imm32,R1 (6 bytes)
                AddressSet range = new AddressSet(addr(p, insn), addr(p, insn + 5));
                new DisassembleCommand(range, range, false).applyTo(p, monitor);
            }
            finally {
                p.endTransaction(tx, true);
            }
            Instruction i = p.getListing().getInstructionAt(addr(p, insn));
            if (i == null || i.getLength() != 6) return "setup: no 6-byte instruction at 0x" + Long.toHexString(insn);
            String err = runAnalyzer(p);
            if (err != null) return err;
            if (p.getListing().getInstructionAt(addr(p, insn)) == null) return "straddling instruction removed";
            Data d = p.getListing().getDefinedDataContaining(addr(p, table));
            return d == null ? null : "data created over code: " + d.getDataType().getName();
        });
    }

    /** Ruling R4: user data inside a heuristic pointer table survives re-analysis. */
    private String analyzerPtrTableKeepsUserData() throws Exception {
        long table = STUB_BASE + 0x540, user = table + 8;
        return withProgram("analyzer_ptr_table_keeps_user_data", ptrTableImage(), BE, STUB_BASE, p -> {
            int tx = p.startTransaction("setup");
            try {
                p.getListing().createData(addr(p, user),
                        new ghidra.program.model.data.ArrayDataType(ghidra.program.model.data.DWordDataType.dataType, 4, 4));
            }
            finally {
                p.endTransaction(tx, true);
            }
            String err = runAnalyzer(p);
            if (err != null) return err;
            Data d = p.getListing().getDefinedDataAt(addr(p, user));
            if (d == null || !d.getDataType().getName().equals("dword[4]"))
                return "user data replaced: " + (d == null ? "none" : d.getDataType().getName());
            Data t = p.getListing().getDefinedDataAt(addr(p, table));
            return t == null ? null : "data created at table start: " + t.getDataType().getName();
        });
    }

    /** Above the RAM and PERIPH blocks the loader adds. */
    private static final long EXTRA = 0x00100000L;

    /** Ruling R5: a second initialized block gets no image-base reset function. */
    private String analyzerEntryExtraBlock() throws Exception {
        return withProgram("analyzer_entry_extra_block", intbImage(), BE, STUB_BASE, p -> {
            int tx = p.startTransaction("setup");
            try {
                p.getMemory().createInitializedBlock("extra", addr(p, EXTRA), 0x100, (byte) 0, monitor, false);
            }
            finally {
                p.endTransaction(tx, true);
            }
            String err = runAnalyzer(p);
            if (err != null) return err;
            if (p.getFunctionManager().getFunctionAt(addr(p, EXTRA)) != null) return "function at 0x" + Long.toHexString(EXTRA);
            if (p.getListing().getInstructionAt(addr(p, EXTRA)) != null) return "code at 0x" + Long.toHexString(EXTRA);
            return checkFunction(p, STUB_BASE, null, null); // the flash block still gets its base entry
        });
    }

    /** Review focus 5: a vector entry pointing into a table gets no function. */
    private String analyzerHandlerIntoTableSkipped() throws Exception {
        byte[] img = intbImage();
        long into = INTB_ADDR + 0x10;
        System.arraycopy(be32(into), 0, img, 0x100, 4);
        System.arraycopy(be32(into), 0, img, 0x104, 4);
        return withProgram("analyzer_handler_into_table_skipped", img, BE, STUB_BASE, p -> {
            String err = runAnalyzer(p);
            if (err == null) err = checkPointerArray(p, INTB_ADDR, 256);
            if (err != null) return err;
            if (p.getFunctionManager().getFunctionAt(addr(p, into)) != null) return "function inside INTB";
            return checkFunction(p, HANDLER, null, "RTE");
        });
    }

    /**
     * The committed realistic BE image: the {@code flash} block is the classifier's fetch-order image (by
     * name, so other blocks may exist), and the analyzer lays INTB, EXTB, the pointer table and functions.
     */
    private String realisticImageEndToEnd() throws Exception {
        RealisticImage.Image im = RealisticImage.build();
        byte[] raw = im.raw();
        long base = im.base();
        byte[] want = RX62TBEClassifier.buildFetchOrderImage(raw, RX62TBEClassifier.classify(raw, base), base);
        return withProgram("realistic_image_end_to_end", raw, BE, base, p -> {
            MemoryBlock flash = p.getMemory().getBlock(RX62TLoader.BLOCK);
            if (flash == null) return "no " + RX62TLoader.BLOCK + " block";
            if (flash.getStart().getOffset() != base || flash.getSize() != raw.length)
                return "flash block " + flash.getStart() + " size 0x" + Long.toHexString(flash.getSize());
            byte[] got = memBytes(p, base, raw.length);
            if (!Arrays.equals(got, want)) return "flash differs from buildFetchOrderImage at " + firstDiff(got, want);
            String err = checkEntry(p, 0xFFF00000L);
            if (err == null) err = runAnalyzer(p);
            if (err == null) err = checkFunction(p, im.entry(), "reset", null);
            if (err == null) err = checkLabel(p, im.intb(), "INTB");
            if (err == null) err = checkPointerArray(p, im.intb(), 256);
            if (err == null) err = checkLabel(p, im.extb(), "EXTB");
            if (err == null) err = checkPointerArray(p, im.extb(), 32);
            RX62TBEUtils.Range ptrs = im.pointers();
            if (err == null) err = checkPointerArray(p, base + ptrs.start(), (ptrs.end() - ptrs.start()) / 4);
            long handler = Integer.toUnsignedLong(java.nio.ByteBuffer.wrap(raw, (int) (im.intb() - base), 4).getInt());
            return err != null ? err : checkFunction(p, handler, null, "RTE");
        });
    }

    // ---- load specs, memory map, analysis options ----

    /** The unswapped stub at the start of a 0x600-byte image (a little-endian reset sequence). */
    private static byte[] leStubImage() {
        byte[] img = new byte[0x600];
        System.arraycopy(STUB, 0, img, 0, STUB.length);
        return img;
    }

    /** Both specs are offered; only {@code preferred} (a language id, or null for none) is preferred. */
    private String loadSpecs(byte[] img, String preferred) throws Exception {
        List<LoadSpec> specs = new ArrayList<>(new RX62TLoader().findSupportedLoadSpecs(new ByteArrayProvider(img)));
        List<String> got = new ArrayList<>();
        for (LoadSpec s : specs) got.add(s.getLanguageCompilerSpec().languageID + (s.isPreferred() ? "*" : ""));
        List<String> want = new ArrayList<>();
        for (String id : List.of(LE, BE)) want.add(id + (id.equals(preferred) ? "*" : ""));
        return got.equals(want) ? null : "specs " + got + " want " + want;
    }

    private String loadSpecEmpty() throws Exception {
        java.util.Collection<LoadSpec> specs = new RX62TLoader().findSupportedLoadSpecs(new ByteArrayProvider(new byte[0]));
        return specs.isEmpty() ? null : specs.size() + " specs for an empty file";
    }

    private static String checkMemMapBlock(Program p, String name, long start, long size, boolean isVolatile) {
        MemoryBlock b = p.getMemory().getBlock(name);
        if (b == null) return "no " + name + " block";
        if (b.getStart().getOffset() != start || b.getSize() != size)
            return name + " at " + b.getStart() + " size 0x" + Long.toHexString(b.getSize());
        if (b.isInitialized()) return name + " initialized";
        if (!b.isRead() || !b.isWrite() || b.isExecute()) return name + " permissions not rw-";
        if (b.isVolatile() != isVolatile) return name + " volatile=" + b.isVolatile();
        return null;
    }

    private static List<String> blockNames(Program p) {
        List<String> names = new ArrayList<>();
        for (MemoryBlock b : p.getMemory().getBlocks()) names.add(b.getName());
        return names;
    }

    private String memmapDefault() throws Exception {
        byte[] img = intbImage();
        return withProgram("memmap_default", img, BE, STUB_BASE, p -> {
            List<String> names = blockNames(p);
            if (!names.equals(List.of("RAM", "PERIPH", RX62TLoader.BLOCK))) return "blocks " + names;
            String err = checkBlock(p, STUB_BASE, img.length);
            if (err == null) err = checkMemMapBlock(p, "RAM", 0, 0x80000, false);
            if (err == null) err = checkMemMapBlock(p, "PERIPH", 0x80000, 0x80000, true);
            if (err == null) err = runAnalyzer(p); // R5/R8: RAM and PERIPH are uninitialized, the analysis is unchanged
            return err != null ? err : checkIntb(p);
        });
    }

    private String memmapOff() throws Exception {
        byte[] img = intbImage();
        return withProgram("memmap_off", img, BE, STUB_BASE, RX62TLoader.class, List.of("-loader-rxMemoryMap", "false"),
                new MessageLog(), p -> {
                    List<String> names = blockNames(p);
                    return names.equals(List.of(RX62TLoader.BLOCK)) ? checkBlock(p, STUB_BASE, img.length) : "blocks " + names;
                });
    }

    /** Review focus 1: an image at 0 overlaps RAM, which is skipped with a log line; PERIPH is still added. */
    private String memmapOverlap() throws Exception {
        byte[] img = leStubImage();
        MessageLog log = new MessageLog();
        return withProgram("memmap_overlap", img, LE, 0, RX62TLoader.class, List.of(), log, p -> {
            List<String> names = blockNames(p);
            if (!names.equals(List.of(RX62TLoader.BLOCK, "PERIPH"))) return "blocks " + names;
            String err = checkBlock(p, 0, img.length);
            if (err == null) err = checkMemMapBlock(p, "PERIPH", 0x80000, 0x80000, true);
            if (err != null) return err;
            String text = log.toString();
            return text.contains("RAM") && text.contains("skipped") ? null : "no log line for the skipped RAM block: " + text;
        });
    }

    /** An image at 0x80000 overlaps PERIPH, which is skipped with a log line; RAM is still added. */
    private String memmapOverlapPeriph() throws Exception {
        byte[] img = leStubImage();
        MessageLog log = new MessageLog();
        return withProgram("memmap_overlap_periph", img, LE, 0x80000, RX62TLoader.class, List.of(), log, p -> {
            List<String> names = blockNames(p);
            if (!names.equals(List.of("RAM", RX62TLoader.BLOCK))) return "blocks " + names;
            String err = checkBlock(p, 0x80000, img.length);
            if (err == null) err = checkMemMapBlock(p, "RAM", 0, 0x80000, false);
            if (err != null) return err;
            String text = log.toString();
            return text.contains("PERIPH") && text.contains("skipped") ? null
                    : "no log line for the skipped PERIPH block: " + text;
        });
    }

    private static final String PARAM_ID = "Decompiler Parameter ID";

    private String paramIdDefault() throws Exception {
        return withProgram("param_id_default", intbImage(), BE, STUB_BASE, p -> {
            if (!p.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(PARAM_ID, false)) return PARAM_ID + " not true after load";
            // the auto-analysis manager registering its analyzers' defaults must not override the stored value
            int tx = p.startTransaction("init analysis options");
            try {
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p).initializeOptions();
            }
            finally {
                p.endTransaction(tx, true);
            }
            return p.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(PARAM_ID, false) ? null
                    : PARAM_ID + " reset by AutoAnalysisManager.initializeOptions";
        });
    }

    /** Review focus 2: only this loader turns Parameter ID on; a BinaryLoader import of the same bytes does not. */
    private String paramIdOnlyThisLoader() throws Exception {
        return withProgram("param_id_only_this_loader", intbImage(), BE, STUB_BASE, BinaryLoader.class, p -> {
            if (!BinaryLoader.BINARY_NAME.equals(p.getExecutableFormat())) return "executable format " + p.getExecutableFormat();
            ghidra.framework.options.Options o = p.getOptions(Program.ANALYSIS_PROPERTIES);
            return o.contains(PARAM_ID) && o.getBoolean(PARAM_ID, false) ? PARAM_ID + " true for BinaryLoader" : null;
        });
    }

    private static Object optionValue(List<Option> options, String name) {
        for (Option o : options)
            if (o.getName().equals(name)) return o.getValue();
        return "<missing>";
    }

    /**
     * Ruling R3: Add To Program (Loader.loadInto, which the GUI's Add To Program runs with options from
     * getDefaultOptions(..., loadIntoProgram=true, ...)) adds the image only: the memory-map option
     * defaults to false and the program's Parameter ID setting is left alone. A fresh import still
     * defaults the option to true.
     */
    private String addToProgramNoSideEffects() throws Exception {
        RX62TLoader loader = new RX62TLoader();
        byte[] img = leStubImage();
        ByteArrayProvider provider = new ByteArrayProvider("add_to_program.bin", img);
        LoadSpec spec = new LoadSpec(loader, 0, new LanguageCompilerSpecPair(LE, "default"), false);
        Object fresh = optionValue(loader.getDefaultOptions(provider, spec, null, false, false), RX62TLoader.OPTION_MEMORY_MAP);
        if (!Boolean.TRUE.equals(fresh)) return "fresh import: memory-map option default " + fresh;
        try (LoadResults<Program> results = ProgramLoader.builder().source(nops(0x20)).name("add_to_program_host")
                .loaders(BinaryLoader.class).language(LE).compiler("default")
                .addLoaderArg("-loader-baseAddr", "0x00200000").log(new MessageLog()).monitor(monitor).load()) {
            Program p = results.getPrimaryDomainObject(this);
            try {
                List<Option> options = new ArrayList<>();
                for (Option o : loader.getDefaultOptions(provider, spec, p, true, false)) {
                    if (o.getName().equals(RX62TLoader.OPTION_BASE)) o.setValue("0x00300000");
                    options.add(o);
                }
                Object into = optionValue(options, RX62TLoader.OPTION_MEMORY_MAP);
                if (!Boolean.FALSE.equals(into)) return "add to program: memory-map option default " + into;
                String err = loader.validateOptions(provider, spec, options, p);
                if (err != null) return "validateOptions: " + err;
                MessageLog log = new MessageLog();
                loader.loadInto(p, new ghidra.app.util.opinion.Loader.ImporterSettings(provider, "add", null, null,
                        false, spec, options, this, log, monitor));
                List<String> names = blockNames(p);
                if (names.size() != 2 || !names.contains(RX62TLoader.BLOCK) || names.contains("RAM") || names.contains("PERIPH"))
                    return "blocks " + names;
                err = checkBlock(p, 0x00300000, img.length);
                if (err != null) return err;
                ghidra.framework.options.Options o = p.getOptions(Program.ANALYSIS_PROPERTIES);
                return o.contains(PARAM_ID) && o.getBoolean(PARAM_ID, false) ? PARAM_ID + " set by Add To Program" : null;
            }
            finally {
                p.release(this);
            }
        }
    }

    // ---- ghidra_scripts/RxOrphanFunctions.java and RxFixSignatures.java (found through -scriptPath) ----

    /** Runs the named script (found through -scriptPath) against {@code p} inside one transaction. */
    private void runOn(Program p, String script) throws Exception {
        GhidraState st = new GhidraState(null, null, p, null, null, null);
        int tx = p.startTransaction("run " + script);
        try {
            runScript(script, st);
        }
        finally {
            p.endTransaction(tx, true);
        }
    }

    private static byte[] nops(int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) 0x03);
        return b;
    }

    private String orphanFunctions() throws Exception {
        return withProgram("orphan_functions", nops(0x20), LE, 0x1000, p -> {
            int tx = p.startTransaction("disassemble");
            try {
                AddressSet set = new AddressSet(addr(p, 0x1008), addr(p, 0x100B));
                new DisassembleCommand(addr(p, 0x1008), set, true).applyTo(p, monitor);
            }
            finally {
                p.endTransaction(tx, true);
            }
            if (countInstructions(p, new AddressSet(addr(p, 0x1008), addr(p, 0x100B))) != 4) return "setup: 4 instructions expected";
            if (p.getFunctionManager().getFunctionContaining(addr(p, 0x1008)) != null) return "setup: function already there";
            runOn(p, "RxOrphanFunctions.java");
            return checkFunction(p, 0x1008, null, "NOP");
        });
    }

    private String fixSignatures() throws Exception {
        return withProgram("fix_signatures", nops(0x20), LE, 0x1000, p -> {
            int tx = p.startTransaction("setup");
            try {
                for (long a : new long[] { 0x1000, 0x1010 }) {
                    new DisassembleCommand(addr(p, a), new AddressSet(addr(p, a), addr(p, a + 3)), true).applyTo(p, monitor);
                    Function f = p.getFunctionManager().createFunction("f" + Long.toHexString(a), addr(p, a),
                        new AddressSet(addr(p, a), addr(p, a + 3)), ghidra.program.model.symbol.SourceType.ANALYSIS);
                    f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
                    f.setReturnType(ghidra.program.model.data.DataType.DEFAULT, ghidra.program.model.symbol.SourceType.ANALYSIS);
                }
                // 0x1010 gets a user-defined signature
                Function u = p.getFunctionManager().getFunctionAt(addr(p, 0x1010));
                u.setSignatureSource(ghidra.program.model.symbol.SourceType.USER_DEFINED);
            }
            finally {
                p.endTransaction(tx, true);
            }
            Function a = p.getFunctionManager().getFunctionAt(addr(p, 0x1000));
            Function u = p.getFunctionManager().getFunctionAt(addr(p, 0x1010));
            if (!Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(a.getCallingConventionName())) return "setup: convention " + a.getCallingConventionName();
            if (u.getSignatureSource() != ghidra.program.model.symbol.SourceType.USER_DEFINED) return "setup: signature source " + u.getSignatureSource();
            String want = p.getCompilerSpec().getDefaultCallingConvention().getName();
            runOn(p, "RxFixSignatures.java");
            if (!want.equals(a.getCallingConventionName())) return "convention " + a.getCallingConventionName() + ", want " + want;
            if (!(a.getReturnType() instanceof ghidra.program.model.data.VoidDataType)) return "return type " + a.getReturnType().getName();
            if (!Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(u.getCallingConventionName())) return "user-defined convention changed to " + u.getCallingConventionName();
            if (u.getReturnType() != ghidra.program.model.data.DataType.DEFAULT) return "user-defined return changed to " + u.getReturnType().getName();
            return null;
        });
    }

    /** A program of another processor is left untouched (the script prints a message and returns). */
    private String fixSignaturesRefuses() throws Exception {
        try (LoadResults<Program> results = ProgramLoader.builder().source(nops(0x20)).name("refuse")
                .loaders(BinaryLoader.class).language("x86:LE:32:default").compiler("gcc")
                .addLoaderArg("-loader-baseAddr", "0x1000").log(new MessageLog()).monitor(monitor).load()) {
            Program p = results.getPrimaryDomainObject(this);
            try {
                int tx = p.startTransaction("setup");
                try {
                    AddressSet set = new AddressSet(addr(p, 0x1000), addr(p, 0x1003));
                    new DisassembleCommand(addr(p, 0x1000), set, true).applyTo(p, monitor);
                    Function f = p.getFunctionManager().createFunction("f", addr(p, 0x1000), set,
                        ghidra.program.model.symbol.SourceType.ANALYSIS);
                    f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
                }
                finally {
                    p.endTransaction(tx, true);
                }
                runOn(p, "RxFixSignatures.java");
                Function f = p.getFunctionManager().getFunctionAt(addr(p, 0x1000));
                if (f == null) return "setup: no function";
                return Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(f.getCallingConventionName()) ? null
                        : "convention changed to " + f.getCallingConventionName() + " on a non-RX program";
            }
            finally {
                p.release(this);
            }
        }
    }

    // ---- loading and checks ----

    private interface Case {
        String run() throws Exception;
    }

    private interface ProgramCheck {
        String check(Program p) throws Exception;
    }

    private void caseRun(String name, Case c) {
        String err;
        try {
            err = c.run();
        }
        catch (Throwable t) {
            err = "exception: " + t;
        }
        if (err == null) pass++;
        else fail++;
        println("RXTEST " + (err == null ? "PASS" : "FAIL") + " loader:" + name + (err == null ? "" : " " + err));
    }

    private String withProgram(String name, byte[] img, String lang, long base, ProgramCheck check) throws Exception {
        return withProgram(name, img, lang, base, RX62TLoader.class, check);
    }

    private String withProgram(String name, byte[] img, String lang, long base,
            Class<? extends ghidra.app.util.opinion.Loader> loader, ProgramCheck check) throws Exception {
        return withProgram(name, img, lang, base, loader, List.of(), new MessageLog(), check);
    }

    /** {@code args}: extra loader arguments as name, value pairs; {@code log} receives the loader's messages. */
    private String withProgram(String name, byte[] img, String lang, long base,
            Class<? extends ghidra.app.util.opinion.Loader> loader, List<String> args, MessageLog log,
            ProgramCheck check) throws Exception {
        ProgramLoader.Builder builder = ProgramLoader.builder()
                .source(img)
                .name(name)
                .loaders(loader)
                .language(lang)
                .compiler("default")
                .addLoaderArg("-loader-baseAddr", String.format("0x%08X", base));
        for (int i = 0; i + 1 < args.size(); i += 2) builder.addLoaderArg(args.get(i), args.get(i + 1));
        try (LoadResults<Program> results = builder
                .log(log)
                .monitor(monitor)
                .load()) {
            Program p = results.getPrimaryDomainObject(this);
            try {
                return check.check(p);
            }
            finally {
                p.release(this);
            }
        }
    }

    /** The {@code flash} block, looked up by name (the memory-map option adds RAM and PERIPH blocks). */
    private static String checkBlock(Program p, long start, long len) {
        MemoryBlock b = p.getMemory().getBlock(RX62TLoader.BLOCK);
        if (b == null) return "no " + RX62TLoader.BLOCK + " block; blocks " + blockNames(p);
        if (b.getStart().getOffset() != start) return "block start " + b.getStart();
        if (b.getSize() != len) return "block size 0x" + Long.toHexString(b.getSize());
        if (!b.isInitialized()) return "block not initialized";
        if (!b.isRead() || b.isWrite() || !b.isExecute()) return "block permissions not r-x";
        return null;
    }

    private static String checkEntry(Program p, long want) {
        List<Long> entries = new ArrayList<>();
        AddressIterator it = p.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) entries.add(it.next().getOffset());
        if (!entries.equals(List.of(want))) return "entry points " + hexList(entries) + " want 0x" + Long.toHexString(want);
        Address a = addr(p, want);
        for (Symbol s : p.getSymbolTable().getSymbols(a))
            if (s.getName().equals("reset") && s.getSource() == ghidra.program.model.symbol.SourceType.IMPORTED) return null;
        return "no IMPORTED 'reset' label at 0x" + Long.toHexString(want);
    }

    /** Runs RX62TAnalyzer.added over all of memory in a transaction; returns null when it reports success. */
    private String runAnalyzer(Program p) throws Exception {
        RX62TAnalyzer analyzer = new RX62TAnalyzer();
        if (!analyzer.canAnalyze(p)) return "canAnalyze false for " + p.getLanguageID();
        MessageLog log = new MessageLog();
        boolean ok;
        int tx = p.startTransaction("RX62T analyzer");
        try {
            ok = analyzer.added(p, p.getMemory(), monitor, log);
        }
        finally {
            p.endTransaction(tx, true);
        }
        if (!ok) return "added returned false";
        return log.hasMessages() ? "analyzer log: " + log.toString().trim() : null;
    }

    private static String checkLabel(Program p, long at, String name) {
        Symbol s = p.getSymbolTable().getGlobalSymbol(name, addr(p, at));
        return s != null ? null : "no label " + name + " at 0x" + Long.toHexString(at);
    }

    private static String checkPointerArray(Program p, long at, int count) {
        Data d = p.getListing().getDefinedDataAt(addr(p, at));
        if (d == null) return "no data at 0x" + Long.toHexString(at);
        DataType dt = d.getDataType();
        if (!(dt instanceof ghidra.program.model.data.Array a)) return "data at 0x" + Long.toHexString(at) + " is " + dt.getName();
        if (a.getNumElements() != count || !a.getDataType().getName().equals("pointer") || a.getElementLength() != 4)
            return "array at 0x" + Long.toHexString(at) + " is " + dt.getName() + " (want pointer[" + count + "])";
        return null;
    }

    /** A function at {@code at}, named {@code name} unless null, whose first instruction is {@code mnemonic} unless null. */
    private static String checkFunction(Program p, long at, String name, String mnemonic) {
        Function f = p.getFunctionManager().getFunctionAt(addr(p, at));
        if (f == null) return "no function at 0x" + Long.toHexString(at);
        if (name != null && !f.getName().equals(name)) return "function at 0x" + Long.toHexString(at) + " named " + f.getName();
        if (mnemonic == null) return null;
        Instruction i = p.getListing().getInstructionAt(addr(p, at));
        String got = i == null ? "none" : i.getMnemonicString();
        return got.equals(mnemonic) ? null : "first instruction at 0x" + Long.toHexString(at) + " is " + got;
    }

    private static int countInstructions(Program p, AddressSet range) {
        int n = 0;
        for (Instruction i : p.getListing().getInstructions(range, true)) n++;
        return n;
    }

    private static Address addr(Program p, long off) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }

    private static byte[] memBytes(Program p, long start, int len) throws Exception {
        Memory mem = p.getMemory();
        byte[] b = new byte[len];
        int n = mem.getBytes(addr(p, start), b);
        if (n != len) throw new IllegalStateException("read " + n + " of " + len + " bytes");
        return b;
    }

    // ---- fixtures (mirrors src/test/java/rx62t/RX62TBEClassifierTest.java) ----

    /** swap(stub) + ff(4) + 0x600 bytes of swap(stub) repeated. */
    private static byte[] stubImage() {
        byte[] sw = RX62TBEUtils.swapWords(STUB);
        byte[] img = new byte[sw.length + 4 + 0x600];
        System.arraycopy(sw, 0, img, 0, sw.length);
        Arrays.fill(img, sw.length, sw.length + 4, (byte) 0xFF);
        for (int o = 0; o < 0x600; o++) img[sw.length + 4 + o] = sw[o % sw.length];
        return img;
    }

    /** The stub image with 16 BE pointers (to base+0x5C0) at offset 0x540 (ruling R1). */
    private static byte[] ptrTableImage() {
        byte[] img = stubImage();
        for (int i = 0; i < 16; i++) System.arraycopy(be32(STUB_BASE + 0x5C0), 0, img, 0x540 + 4 * i, 4);
        return img;
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    private static byte[] be32(long v) {
        return new byte[] { (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v };
    }

    private static byte[] le32(long v) {
        return new byte[] { (byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24) };
    }

    private static String firstDiff(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++)
            if (a[i] != b[i]) return "offset 0x" + Integer.toHexString(i);
        return "length";
    }

    private static String hexList(List<Long> xs) {
        StringBuilder sb = new StringBuilder("[");
        for (Long x : xs) sb.append(sb.length() > 1 ? ", " : "").append("0x").append(Long.toHexString(x));
        return sb.append("]").toString();
    }
}
