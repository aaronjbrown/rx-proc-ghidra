// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import rx62t.RX62TBEUtils.Range;

/**
 * Marks up a raw RX image after loading: lays down the INTB/EXTB vector tables found in the reset code as
 * labelled pointer arrays and types the other pointer tables (raw-image imports only, ruling R8), and only
 * then makes functions at the reset entry and the vector handlers, so their disassembly stops at the tables
 * instead of running into them. It scans memory as loaded, which is already in instruction-fetch order
 * (decision D3), so it works for "RX62T Raw Binary" imports and for BinaryLoader imports of a
 * fetch-order image alike. Anything already present is left as is, so running it again changes nothing.
 */
public class RX62TAnalyzer extends AbstractAnalyzer {
    private static final int MIN_POINTERS = 4;

    public RX62TAnalyzer() {
        super("RX62T Platform Setup", "Labels the RX reset handler, INTB/EXTB vector tables and pointer tables",
                AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguageID().getIdAsString().startsWith("rx62t");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        boolean bigEndian = program.getLanguage().isBigEndian();
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        boolean single = java.util.Arrays.stream(blocks).filter(MemoryBlock::isInitialized).count() == 1;
        boolean rawImage = isRawImage(program);
        for (MemoryBlock block : blocks) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !set.intersects(block.getStart(), block.getEnd())) continue;
            if (block.getSize() > Integer.MAX_VALUE) {
                log.appendMsg(getName(), "skipped block " + block.getName() + ": larger than 2 GiB");
                continue;
            }
            byte[] img = new byte[(int) block.getSize()];
            try {
                block.getBytes(block.getStart(), img);
            } catch (MemoryAccessException e) {
                log.appendMsg(getName(), "skipped block " + block.getName() + ": " + e.getMessage());
                continue;
            }
            long base = block.getStart().getOffset();
            List<Range> pointers = rawImage
                    ? RX62TBEUtils.findPointerTables(img, base, MIN_POINTERS, bigEndian)
                    : List.of();
            List<Range> vectors = markVectorTables(program, block, img, log);
            markPointerTables(program, block, pointers, vectors, log);
            markEntry(program, block, img, bigEndian, single || block.getName().equals(RX62TLoader.BLOCK), monitor,
                    log);
            List<Range> tables = new ArrayList<>(vectors);
            tables.addAll(pointers);
            markHandlers(program, block, img, bigEndian, vectors, tables, monitor);
        }
        return true;
    }

    /**
     * The heuristic pointer-table step runs only for raw-image imports (ruling R8): in other formats
     * (ELF, ...) the format's own markup and symbols are better than a guess.
     */
    private static boolean isRawImage(Program program) {
        String format = program.getExecutableFormat();
        return RX62TLoader.NAME.equals(format) || BinaryLoader.BINARY_NAME.equals(format);
    }

    /**
     * Step 3: a {@code reset} label and a function named {@code reset} at the reset entry, also when the
     * loader made no label (e.g. a BinaryLoader import). The image-base fallback of decision D1 applies
     * only to the image block ({@code baseFallback}: the loader's {@code flash} block, or the only
     * initialized block); any other block needs a valid reset vector (ruling R5).
     */
    private void markEntry(Program program, MemoryBlock block, byte[] img, boolean bigEndian, boolean baseFallback,
            TaskMonitor monitor, MessageLog log) {
        RX62TBEUtils.Entry entry = RX62TBEUtils.resetEntry(img, block.getStart().getOffset(), bigEndian);
        if (!entry.fromVector() && !baseFallback) return;
        Address at = block.getStart().getNewAddress(entry.address());
        Function existing = program.getListing().getFunctionAt(at);
        if (program.getSymbolTable().getGlobalSymbol("reset", at) != null) {
            // named already (the loader's IMPORTED label, or an earlier run)
        } else if (existing != null && existing.getSymbol().getSource() == SourceType.DEFAULT) {
            try {
                existing.setName("reset", SourceType.ANALYSIS);
            } catch (DuplicateNameException | InvalidInputException e) {
                log.appendMsg(getName(), "function reset at " + at + ": " + e.getMessage());
            }
        } else {
            createLabel(program, at, "reset", log);
        }
        createFunction(program, at, blockSet(block), monitor);
    }

    /**
     * Step 1: each INTB/EXTB table becomes a labelled pointer array, cut to the block. Data there is
     * replaced, instructions never are.
     *
     * @return the vector-table ranges, as block offsets
     */
    private List<Range> markVectorTables(Program program, MemoryBlock block, byte[] img, MessageLog log) {
        long base = block.getStart().getOffset();
        List<Range> vectors = new ArrayList<>();
        for (Map.Entry<String, Integer> t : RX62TBEUtils.findVectorTables(img, base, false).entrySet()) {
            int off = t.getValue();
            int len = t.getKey().equals("INTB") ? RX62TBEUtils.INTB_LEN : RX62TBEUtils.EXTB_LEN;
            int count = Math.min(len, img.length - off) / 4;
            if (count == 0) continue;
            Address start = block.getStart().add(off);
            Address end = start.add(4L * count - 1);
            Listing listing = program.getListing();
            if (isPointerArray(listing, start, count)) {
                // already laid down
            } else if (hasCode(listing, start, end)) {
                log.appendMsg(getName(), t.getKey() + " at " + start + " overlaps instructions; no pointer array made");
            } else {
                listing.clearCodeUnits(start, end, false);
                createPointerArray(listing, start, count, log);
            }
            createLabel(program, start, t.getKey(), log);
            vectors.add(new Range(off, off + 4 * count));
        }
        return vectors;
    }

    /** Step 4: a function at each vector handler that is non-zero, in the block and outside every table. */
    private void markHandlers(Program program, MemoryBlock block, byte[] img, boolean bigEndian, List<Range> vectors,
            List<Range> tables, TaskMonitor monitor) throws CancelledException {
        long base = block.getStart().getOffset();
        ByteBuffer words = ByteBuffer.wrap(img).order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        AddressSetView restrict = blockSet(block);
        for (Range v : vectors) {
            for (int o = v.start(); o < v.end(); o += 4) {
                monitor.checkCancelled();
                long target = Integer.toUnsignedLong(words.getInt(o));
                long toff = target - base;
                if (target == 0 || toff < 0 || toff >= img.length || inAny(tables, (int) toff)) continue;
                createFunction(program, block.getStart().add(toff), restrict, monitor);
            }
        }
    }

    /**
     * Step 2: the other pointer tables become pointer arrays. These are heuristic, so a table is skipped
     * when it overlaps a vector table, any instruction (also one starting before it and running in) or any
     * defined data: un-swapped code can read as in-image pointers, and existing work wins (ruling R4).
     */
    private void markPointerTables(Program program, MemoryBlock block, List<Range> pointers, List<Range> vectors,
            MessageLog log) {
        Listing listing = program.getListing();
        for (Range r : pointers) {
            if (vectors.stream().anyMatch(v -> v.start() < r.end() && r.start() < v.end())) continue;
            Address start = block.getStart().add(r.start()), end = block.getStart().add(r.end() - 1);
            int count = (r.end() - r.start()) / 4;
            if (isPointerArray(listing, start, count) || hasCode(listing, start, end)) continue;
            if (listing.getDefinedDataContaining(start) != null
                    || listing.getDefinedData(new AddressSet(start, end), true).hasNext()) continue;
            createPointerArray(listing, start, count, log);
        }
    }

    private static AddressSetView blockSet(MemoryBlock block) {
        return new AddressSet(block.getStart(), block.getEnd());
    }

    private static boolean inAny(List<Range> ranges, int off) {
        for (Range r : ranges)
            if (r.start() <= off && off < r.end()) return true;
        return false;
    }

    /** Disassembles at {@code at} (within {@code restrict}) and makes a function there, unless one exists. */
    private static void createFunction(Program program, Address at, AddressSetView restrict, TaskMonitor monitor) {
        Listing listing = program.getListing();
        if (listing.getFunctionAt(at) != null) return;
        if (listing.getInstructionAt(at) == null) {
            if (listing.getDefinedDataContaining(at) != null) return;
            new DisassembleCommand(at, restrict, true).applyTo(program, monitor);
            if (listing.getInstructionAt(at) == null) return;
        }
        new CreateFunctionCmd(at).applyTo(program, monitor);
    }

    /** True when {@code pointer[count]} is already defined at {@code start}. */
    private static boolean isPointerArray(Listing listing, Address start, int count) {
        Data d = listing.getDefinedDataAt(start);
        return d != null && d.getDataType() instanceof Array a && a.getNumElements() == count
                && a.getDataType() instanceof Pointer;
    }

    /** True when an instruction lies in [start, end], including one that starts before and runs into it. */
    private static boolean hasCode(Listing listing, Address start, Address end) {
        return listing.getInstructionContaining(start) != null
                || listing.getInstructions(new AddressSet(start, end), true).hasNext();
    }

    /** Lays down {@code pointer[count]} at {@code start}; the range must hold only undefined units. */
    private void createPointerArray(Listing listing, Address start, int count, MessageLog log) {
        try {
            listing.createData(start, new ArrayDataType(PointerDataType.dataType, count, 4));
        } catch (CodeUnitInsertionException e) {
            log.appendMsg(getName(), "pointer table at " + start + ": " + e.getMessage());
        }
    }

    private void createLabel(Program program, Address at, String name, MessageLog log) {
        SymbolTable symbols = program.getSymbolTable();
        if (symbols.getGlobalSymbol(name, at) != null) return;
        try {
            symbols.createLabel(at, name, SourceType.ANALYSIS);
        } catch (InvalidInputException e) {
            log.appendMsg(getName(), "label " + name + " at " + at + ": " + e.getMessage());
        }
    }
}
