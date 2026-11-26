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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.LongPredicate;
import rx62t.RX62TBEUtils.Range;

/**
 * Marks up a raw RX image after loading. It resolves the program's reset entry once (the reset vector, else
 * the {@code reset} symbol, else the image base) and reads INTB/EXTB from the reset code there. It lays those
 * tables as labelled pointer arrays in whichever blocks hold them, sized by the RX manuals, with every slot
 * labelled {@code int_vect_NNN} or {@code exc_vect_NN} and the architected EXTB slots given the manual's
 * names as EOL comments. For raw-image imports only it marks the other pointer runs, one pointer per slot.
 * Only then does it make functions: at the reset entry; at the code targets of runs that lie in a
 * non-executable block (a raw image imported as one executable block gets none); and at the vector handlers.
 * So their disassembly stops at the tables instead of running into them. It scans memory as loaded, which is
 * already in instruction-fetch order (decision D3), so it works for "RX62T Raw Binary" imports and for
 * BinaryLoader imports of a fetch-order image alike. Anything already present is left as is, so running it
 * again changes nothing.
 */
public class RX62TAnalyzer extends AbstractAnalyzer {
    private static final int MIN_POINTERS = 4;
    /** Erased flash: never a pointer target (it is the last byte of the reset vector). */
    private static final long ERASED = 0xFFFFFFFFL;

    /** The vector-table ranges: all that the reset code sets up, and those laid in this call's set. */
    private record VectorTables(AddressSet all, AddressSet inSet) {}

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
        Address entry = resolveResetEntry(program);
        VectorTables vectors = entry == null ? new VectorTables(new AddressSet(), new AddressSet())
                : markVectorTables(program, set, entry, log);
        AddressSet tables = new AddressSet(vectors.all());
        boolean raw = isRawImage(program);
        if (raw) tables.add(markPointerRuns(program, set, vectors.all(), monitor, log));
        if (entry != null) markEntry(program, set, entry, monitor, log);
        if (raw) markCodePointers(program, set, vectors.all(), tables, monitor, log);
        markHandlers(program, vectors.inSet(), tables, monitor);
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
     * The program's reset entry, resolved once: the reset vector at {@code FFFFFFFC} when it is initialized
     * and points into initialized memory; else the only global {@code reset} symbol, which the loader makes
     * and which survives splitting or renaming blocks; else the start of the loader's {@code flash} block or
     * of the only initialized block (D1/R5). Null when none applies.
     */
    private Address resolveResetEntry(Program program) {
        Memory mem = program.getMemory();
        AddressSetView init = mem.getLoadedAndInitializedAddressSet();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address vector = space.getAddress(RX62TBEUtils.RESET_VECTOR);
        if (init.contains(vector, vector.add(3))) {
            try {
                Address target = space.getAddress(Integer.toUnsignedLong(mem.getInt(vector)));
                if (init.contains(target)) return target;
            } catch (MemoryAccessException | AddressOutOfBoundsException e) {
                // not a usable vector: fall through
            }
        }
        List<Symbol> resets = program.getSymbolTable().getGlobalSymbols("reset");
        if (resets.size() == 1 && init.contains(resets.get(0).getAddress())) return resets.get(0).getAddress();
        MemoryBlock flash = mem.getBlock(RX62TLoader.BLOCK);
        if (flash != null && flash.isInitialized()) return flash.getStart();
        MemoryBlock[] initialized = Arrays.stream(mem.getBlocks()).filter(MemoryBlock::isInitialized)
                .toArray(MemoryBlock[]::new);
        if (initialized.length == 1) return initialized[0].getStart();
        Msg.info(this, "no reset entry found; no vector tables laid");
        return null;
    }

    /**
     * Step 3: a {@code reset} label and a function named {@code reset} at the reset entry, also when the
     * loader made no label (e.g. a BinaryLoader import). The function stays in the entry's block.
     */
    private void markEntry(Program program, AddressSetView set, Address at, TaskMonitor monitor, MessageLog log) {
        if (!set.contains(at)) return;
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
        createFunction(program, at, blockSet(program.getMemory().getBlock(at)), monitor);
    }

    /**
     * Step 1: reads INTB/EXTB from the reset code at {@code entry} (never from the start of other blocks)
     * and lays each table as a labelled pointer array of the size the RX manuals give, in the block holding
     * its start and cut at that block's end. Data there is replaced, instructions never are, and neither is a
     * table laid earlier in this call: a table overlapping one is skipped. A table is laid only where it
     * intersects {@code set}, but every table is returned, so that later steps keep away from it whatever
     * {@code set} is.
     *
     * @return the vector-table ranges
     */
    private VectorTables markVectorTables(Program program, AddressSetView set, Address entry, MessageLog log) {
        Memory mem = program.getMemory();
        AddressSpace space = entry.getAddressSpace();
        AddressSetView init = mem.getLoadedAndInitializedAddressSet();
        long room = space.getMaxAddress().subtract(entry) + 1;
        byte[] window = new byte[(int) Math.min(RX62TBEUtils.CODE_WINDOW, room)];
        int read;
        try {
            read = mem.getBytes(entry, window);
        } catch (MemoryAccessException e) {
            Msg.info(this, "reset code at " + entry + " unreadable: " + e.getMessage());
            return new VectorTables(new AddressSet(), new AddressSet());
        }
        AddressSet all = new AddressSet(), inSet = new AddressSet();
        Listing listing = program.getListing();
        Map<String, Long> setup = RX62TBEUtils.vectorSetup(Arrays.copyOf(window, Math.max(read, 0)));
        for (Map.Entry<String, Long> t : setup.entrySet()) {
            String name = t.getKey();
            Address start;
            try {
                start = space.getAddress(t.getValue());
            } catch (AddressOutOfBoundsException e) {
                continue;
            }
            MemoryBlock block = mem.getBlock(start);
            if (block == null || !init.contains(start)) {
                Msg.info(this, name + " at " + start + " is not in initialized memory; no table laid");
                continue;
            }
            int want = RX62TBEUtils.vectorTableEntries(name, t.getValue());
            int count = (int) Math.min(want, (block.getEnd().subtract(start) + 1) / 4);
            if (count < want)
                Msg.info(this, name + " at " + start + " cut to " + count + " entries at the end of block "
                        + block.getName());
            if (count == 0) continue;
            Address end = start.add(4L * count - 1);
            if (inSet.intersects(start, end)) {
                Msg.info(this, name + " at " + start + " overlaps a vector table already laid; not laid");
                all.add(start, end);
                continue;
            }
            all.add(start, end);
            if (!set.intersects(start, end)) continue;
            if (isPointerArray(listing, start, count)) {
                // already laid down
            } else if (hasCode(listing, start, end)) {
                log.appendMsg(getName(), name + " at " + start + " overlaps instructions; no pointer array made");
            } else {
                listing.clearCodeUnits(start, end, false);
                createPointerArray(listing, start, count, log);
            }
            createLabel(program, start, name, log);
            if (isPointerArray(listing, start, count)) labelSlots(program, name, start, count, log);
            inSet.add(start, end);
        }
        return new VectorTables(all, inSet);
    }

    /**
     * Labels each of the {@code count} slots of the laid table {@code table} at {@code start}
     * ({@code int_vect_NNN} or {@code exc_vect_NN}); on EXTB it also puts the manual's name for each
     * architected slot in an EOL comment, unless the slot has one already. Labels are created only when absent
     * and never made primary over an existing label, so a user's name stays primary.
     */
    private void labelSlots(Program program, String table, Address start, int count, MessageLog log) {
        Listing listing = program.getListing();
        boolean fixed = start.getOffset() == RX62TBEUtils.FIXED_EXTB;
        for (int i = 0; i < count; i++) {
            Address slot = start.add(4L * i);
            createLabel(program, slot, RX62TBEUtils.vectorSlotLabel(table, i), log);
            if (!table.equals("EXTB")) continue;
            String comment = RX62TBEUtils.extbSlotComment(i, fixed);
            if (comment != null && listing.getComment(CommentType.EOL, slot) == null)
                listing.setComment(slot, CommentType.EOL, comment);
        }
    }

    /**
     * Step 4: a function at each vector handler that is non-zero, in initialized memory and outside every
     * table, confined to the block holding the handler.
     */
    private static void markHandlers(Program program, AddressSetView vectors, AddressSetView tables,
            TaskMonitor monitor) throws CancelledException {
        Memory mem = program.getMemory();
        AddressSetView init = mem.getLoadedAndInitializedAddressSet();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        for (AddressRange r : vectors) {
            for (long o = 0; o + 4 <= r.getLength(); o += 4) {
                monitor.checkCancelled();
                Address handler;
                try {
                    long target = Integer.toUnsignedLong(mem.getInt(r.getMinAddress().add(o)));
                    if (target == 0) continue;
                    handler = space.getAddress(target);
                } catch (MemoryAccessException | AddressOutOfBoundsException e) {
                    continue;
                }
                if (!init.contains(handler) || tables.contains(handler)) continue;
                createFunction(program, handler, blockSet(mem.getBlock(handler)), monitor);
            }
        }
    }

    /**
     * Step 2: the other pointer runs are marked one {@code pointer} per slot. A run only says "these slots
     * hold pointers", never where a table starts or ends: an array would claim boundaries the bytes cannot
     * support, and typing its first entry later would remove every other entry and its references. A
     * target may be in any initialized block, except {@code 0xFFFFFFFF} (erased flash). A run is skipped
     * when it overlaps a vector table or any instruction (also one starting before it and running in), since
     * un-swapped code can read as pointers. A slot that already holds defined data is left alone; NULL slots
     * stay undefined.
     *
     * @return every run found, laid or not
     */
    private AddressSet markPointerRuns(Program program, AddressSetView set, AddressSetView vectors,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        boolean bigEndian = program.getLanguage().isBigEndian();
        Listing listing = program.getListing();
        AddressSetView init = program.getMemory().getLoadedAndInitializedAddressSet();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        LongPredicate isTarget = v -> v != ERASED && v <= space.getMaxAddress().getOffset()
                && init.contains(space.getAddress(v));
        AddressSet runs = new AddressSet();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !set.intersects(block.getStart(), block.getEnd())) continue;
            byte[] img = blockBytes(block, log);
            if (img == null) continue;
            long base = block.getStart().getOffset();
            for (Range r : RX62TBEUtils.findPointerRuns(img, base, MIN_POINTERS, bigEndian, isTarget)) {
                Address start = block.getStart().add(r.start()), end = block.getStart().add(r.end() - 1);
                runs.add(start, end);
                if (vectors.intersects(start, end) || hasCode(listing, start, end)) continue;
                for (int o = r.start(); o < r.end(); o += 4) {
                    Address slot = block.getStart().add(o);
                    if (isNull(img, o) || !listing.isUndefined(slot, slot.add(3))) continue;
                    try {
                        listing.createData(slot, PointerDataType.dataType);
                    } catch (CodeUnitInsertionException e) {
                        log.appendMsg(getName(), "pointer at " + slot + ": " + e.getMessage());
                    }
                }
            }
        }
        return runs;
    }

    /**
     * Step 3b (after the reset entry, before the handlers): functions at the code targets of pointer tables in data
     * blocks (spec section 2). Only blocks whose execute flag is clear are scanned: a raw image imported as one block
     * is executable everywhere, so a single-block import gets no functions here until it is split into code and data
     * blocks with correct execute flags. A slot is a code slot when its target is in an initialized, executable
     * block, is not {@code 0xFFFFFFFF}, and its first word is not {@code FFFFFFFF} (erased flash). Runs are found by
     * {@link RX62TBEUtils#findCodePointerRuns}, which allows one dword of any value between code slots, so tables of
     * {handler, flag} entries count; a run needs {@link RX62TBEUtils#MIN_CODE_SLOTS} code slots naming {@link
     * RX62TBEUtils#MIN_CODE_TARGETS} distinct targets. Runs overlapping a vector table (left to the handler step) or
     * any instruction are skipped, and targets inside a vector table or pointer run get no function.
     */
    private void markCodePointers(Program program, AddressSetView set, AddressSetView vectors, AddressSetView tables,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        Memory mem = program.getMemory();
        Listing listing = program.getListing();
        boolean bigEndian = program.getLanguage().isBigEndian();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        long max = space.getMaxAddress().getOffset();
        LongPredicate isCode = v -> {
            if (v == ERASED || v > max) return false;
            Address a = space.getAddress(v);
            MemoryBlock b = mem.getBlock(a);
            if (b == null || !b.isInitialized() || !b.isExecute()) return false;
            try {
                return Integer.toUnsignedLong(mem.getInt(a)) != ERASED;
            } catch (MemoryAccessException e) {
                return false; // a short read: not code
            }
        };
        for (MemoryBlock block : mem.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.isExecute() || !set.intersects(block.getStart(), block.getEnd()))
                continue;
            byte[] img = blockBytes(block, log);
            if (img == null) continue;
            for (Range r : RX62TBEUtils.findCodePointerRuns(img, bigEndian, isCode)) {
                Address start = block.getStart().add(r.start()), end = block.getStart().add(r.end() - 1);
                if (vectors.intersects(start, end) || hasCode(listing, start, end)) continue;
                long[] slots = new long[(r.end() - r.start()) / 4];
                for (int i = 0; i < slots.length; i++)
                    slots[i] = Integer.toUnsignedLong(java.nio.ByteBuffer.wrap(img, r.start() + 4 * i, 4)
                            .order(bigEndian ? java.nio.ByteOrder.BIG_ENDIAN : java.nio.ByteOrder.LITTLE_ENDIAN)
                            .getInt());
                for (long t : RX62TBEUtils.codePointerTargets(slots, isCode)) {
                    Address target = space.getAddress(t);
                    if (tables.contains(target)) continue;
                    createFunction(program, target, blockSet(mem.getBlock(target)), monitor);
                }
            }
        }
    }

    private static boolean isNull(byte[] img, int o) {
        return (img[o] | img[o + 1] | img[o + 2] | img[o + 3]) == 0;
    }

    /** The block's bytes, or null (with a log note) when it is over 2 GiB or unreadable. */
    private byte[] blockBytes(MemoryBlock block, MessageLog log) {
        if (block.getSize() > Integer.MAX_VALUE) {
            log.appendMsg(getName(), "skipped block " + block.getName() + ": larger than 2 GiB");
            return null;
        }
        byte[] img = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), img);
            return img;
        } catch (MemoryAccessException e) {
            log.appendMsg(getName(), "skipped block " + block.getName() + ": " + e.getMessage());
            return null;
        }
    }

    private static AddressSetView blockSet(MemoryBlock block) {
        return new AddressSet(block.getStart(), block.getEnd());
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

    /** Lays down the vector table {@code pointer[count]} at {@code start}; the range must hold only undefined units. */
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
