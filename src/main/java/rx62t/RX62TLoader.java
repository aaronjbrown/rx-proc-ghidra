// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import rx62t.RX62TBEClassifier.Block;
import rx62t.RX62TBEClassifier.Kind;

/**
 * Imports a raw RX62T flash image as one {@code flash} block at a chosen base address, plus (option
 * {@link #OPTION_MEMORY_MAP}) uninitialized {@code RAM} and {@code PERIPH} blocks. For the
 * big-endian language the code words (which a big-endian RX fetches word-swapped) are put back into
 * instruction-fetch order using {@link RX62TBEClassifier}; data stays as stored. The original file
 * bytes are kept in the program's {@link FileBytes}. Decompiler Parameter ID is turned on in the
 * program's analysis options, and so is Scalar Operand References when the RAM block moves the
 * minimum address to 0 (which would otherwise turn it off). Of the two load specs, the byte order whose reset code sets INTB/EXTB is
 * preferred. Add To Program ({@link #loadProgramInto}) only adds the image: the memory-map option
 * defaults to off and the Parameter ID setting of the existing program is left alone (ruling R3).
 */
public class RX62TLoader extends AbstractProgramWrapperLoader {
    public static final String NAME = "RX62T Raw Binary";
    public static final String OPTION_BASE = "Base address";
    public static final String BLOCK = "flash";
    public static final String OPTION_MEMORY_MAP = "Add RX RAM and peripheral I/O blocks";

    /** An uninitialized r/w block from the RX62T memory map (datasheet section 3.1). */
    private record MapBlock(String name, long start, long size, boolean isVolatile) {}

    /** On-chip RAM area (the populated size varies by chip) and the peripheral I/O registers. */
    private static final List<MapBlock> MEMORY_MAP = List.of(
            new MapBlock("RAM", 0x00000000L, 0x00080000L, false),
            new MapBlock("PERIPH", 0x00080000L, 0x00080000L, true));
    /** Analysis option of Ghidra's DecompilerFunctionAnalyzer; by default it is on only for PE programs. */
    static final String PARAM_ID_ANALYZER = "Decompiler Parameter ID";
    /**
     * Ghidra's ScalarOperandAnalyzer, which turns immediates such as {@code MOV.L #imm32,Rn} into
     * references. Its default enablement is off for a program whose minimum address is 0.
     */
    static final String SCALAR_REFS_ANALYZER = "Scalar Operand References";

    private static final String LE_ID = "rx62t:LE:32:default", BE_ID = "rx62t:BE:32:default";
    private static final String COMPILER = "default";
    private static final long ADDRESS_SPACE = 1L << 32;
    /** RX fixed vector table (RXv1 manual 1.7.1): architecture-defined BE data, never word-swapped (ruling R3). */
    static final long FIXED_VECTORS = 0xFFFFFF80L;

    /**
     * Parses a base address: hex with or without {@code 0x}, surrounding blanks ignored.
     *
     * @throws NumberFormatException if it is not hex or lies outside 0..0xFFFFFFFF
     */
    static long parseBase(String s) {
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        if (t.isEmpty() || !t.chars().allMatch(c -> Character.digit(c, 16) >= 0))
            throw new NumberFormatException("not a hex number: '" + s + "'");
        BigInteger v = new BigInteger(t, 16);
        if (v.bitLength() > 32) throw new NumberFormatException("outside 0..0xFFFFFFFF: '" + s + "'");
        return v.longValueExact();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.UNTARGETED_LOADER;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        long len = provider.length();
        if (len == 0 || len > ADDRESS_SPACE) return List.of();
        // prefer the byte order whose reset code sets INTB/EXTB; neither when both or none do
        byte[] head = provider.readBytes(0, Math.min(len, RX62TBEUtils.CODE_WINDOW));
        boolean be = RX62TBEUtils.hasVectorSetup(head, true), le = RX62TBEUtils.hasVectorSetup(head, false);
        return List.of(
                new LoadSpec(this, 0, new LanguageCompilerSpecPair(LE_ID, COMPILER), le && !be),
                new LoadSpec(this, 0, new LanguageCompilerSpecPair(BE_ID, COMPILER), be && !le));
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean loadIntoProgram, boolean mirrorFsLayout) {
        List<Option> list = new ArrayList<>(
                super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout));
        list.add(new Option(OPTION_BASE, "0x00000000", String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
        // Add To Program (loadIntoProgram) adds only the image unless the user asks for the memory map
        list.add(new Option(OPTION_MEMORY_MAP, !loadIntoProgram, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-rxMemoryMap"));
        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        String err = super.validateOptions(provider, loadSpec, options, program);
        if (err != null) return err;
        long base;
        try {
            base = parseBase(baseOption(options));
        } catch (NumberFormatException e) {
            return badBase(e);
        }
        return checkImage(base, provider.length(), isBigEndian(loadSpec));
    }

    /** Checks a parsed base and image length; returns a readable message, or null when they can be loaded. */
    static String checkImage(long base, long len, boolean bigEndian) {
        if (len == 0) return "image is empty";
        if (len > Integer.MAX_VALUE) return String.format("image length 0x%X exceeds the 2 GiB loader limit", len);
        if (base + len > ADDRESS_SPACE)
            return String.format("%s 0x%08X + image length 0x%X exceeds the 32-bit address space", OPTION_BASE, base, len);
        if (bigEndian && base % 4 != 0)
            return String.format("%s 0x%08X must be 4-byte aligned for the big-endian language (code words are "
                    + "un-swapped per aligned word)", OPTION_BASE, base);
        return null;
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
        load(program, settings, false);
    }

    /**
     * Add To Program. Does the language check of {@link AbstractProgramWrapperLoader#loadProgramInto}
     * itself, so that the load knows it is not a fresh import.
     */
    @Override
    protected void loadProgramInto(Program program, ImporterSettings settings)
            throws CancelledException, LoadException, IOException {
        LanguageCompilerSpecPair pair = settings.loadSpec().getLanguageCompilerSpec();
        if (!pair.languageID.equals(program.getLanguageID())
                || !pair.compilerSpecID.equals(program.getCompilerSpec().getCompilerSpecID())) {
            String msg = "Language/compiler spec mismatch: " + settings.provider().getAbsolutePath() + " into "
                    + program.getName();
            settings.log().appendMsg(msg);
            throw new LoadException(msg);
        }
        load(program, settings, true);
    }

    /** {@code intoExisting}: Add To Program; the program's analysis options are then left alone. */
    private void load(Program program, ImporterSettings settings, boolean intoExisting)
            throws CancelledException, IOException {
        long base;
        try {
            base = parseBase(baseOption(settings.options()));
        } catch (NumberFormatException e) {
            throw new LoadException(badBase(e), e);
        }
        ByteProvider provider = settings.provider();
        long len = provider.length();
        boolean bigEndian = program.getLanguage().isBigEndian();
        String err = checkImage(base, len, bigEndian);
        if (err != null) throw new LoadException(err);
        byte[] img = provider.readBytes(0, len);

        Memory mem = program.getMemory();
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
        FileBytes fileBytes;
        try (InputStream in = provider.getInputStream(0)) {
            fileBytes = mem.createFileBytes(provider.getName(), 0, len, in, settings.monitor());
        }
        try {
            MemoryBlock block = mem.createInitializedBlock(BLOCK, start, fileBytes, 0, len, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);

            String summary;
            if (bigEndian) {
                List<Block> blocks = RX62TBEClassifier.classify(img, base);
                byte[] fetch = RX62TBEClassifier.buildFetchOrderImage(img, blocks, base);
                String vectors = "";
                long fv = Math.max(0, FIXED_VECTORS - base);
                if (fv < len) { // the classifier may label the fixed vector table CODE; keep it as stored
                    System.arraycopy(img, (int) fv, fetch, (int) fv, (int) (len - fv));
                    vectors = String.format(", fixed vectors 0x%08X-0xFFFFFFFF kept as stored", base + fv);
                }
                int[] count = new int[Kind.values().length];
                for (Block b : blocks) {
                    count[b.kind().ordinal()]++;
                    if (b.kind() == Kind.CODE && !Arrays.equals(img, b.start(), b.end(), fetch, b.start(), b.end()))
                        mem.setBytes(start.add(b.start()), fetch, b.start(), b.end() - b.start());
                }
                summary = String.format("%d code / %d data / %d fill blocks%s", count[Kind.CODE.ordinal()],
                        count[Kind.DATA.ordinal()], count[Kind.FILL.ordinal()], vectors);
            } else {
                summary = "little-endian, loaded verbatim";
            }

            if (memoryMapOption(settings.options(), !intoExisting)) addMemoryMap(program, settings);
            if (!intoExisting) {
                Options analysis = program.getOptions(Program.ANALYSIS_PROPERTIES);
                analysis.setBoolean(PARAM_ID_ANALYZER, true);
                // Ghidra defaults Scalar Operand References to off when the minimum address is 0, which
                // the RAM block makes it; keep the default the image alone would get (on, unless at 0)
                if (base != 0 && program.getMinAddress().getOffset() == 0)
                    analysis.setBoolean(SCALAR_REFS_ANALYZER, true);
            }

            RX62TBEUtils.Entry entry = RX62TBEUtils.resetEntry(img, base, bigEndian);
            Address entryAddr = start.getNewAddress(entry.address());
            program.getSymbolTable().addExternalEntryPoint(entryAddr);
            program.getSymbolTable().createLabel(entryAddr, "reset", SourceType.IMPORTED);
            settings.log().appendMsg(String.format("RX62T: %s, entry 0x%08X (%s)", summary, entry.address(),
                    entry.fromVector() ? "reset vector" : "image base"));
        } catch (IllegalArgumentException | LockException | MemoryConflictException | AddressOverflowException
                | MemoryAccessException | InvalidInputException e) {
            throw new LoadException("RX62T load failed: " + e.getMessage(), e);
        }
    }

    /** Adds the {@link #MEMORY_MAP} blocks; one that would intersect existing memory is skipped whole and logged. */
    private static void addMemoryMap(Program program, ImporterSettings settings)
            throws LockException, MemoryConflictException, AddressOverflowException {
        Memory mem = program.getMemory();
        for (MapBlock m : MEMORY_MAP) {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(m.start());
            Address end = start.add(m.size() - 1);
            if (mem.intersects(start, end)) {
                settings.log().appendMsg(String.format("RX62T: skipped %s block 0x%08X-0x%08X: overlaps existing memory",
                        m.name(), m.start(), m.start() + m.size() - 1));
                continue;
            }
            MemoryBlock b = mem.createUninitializedBlock(m.name(), start, m.size(), false);
            b.setRead(true);
            b.setWrite(true);
            b.setExecute(false);
            b.setVolatile(m.isVolatile());
        }
    }

    private static boolean memoryMapOption(List<Option> options, boolean dflt) {
        if (options != null)
            for (Option o : options)
                if (o.getName().equals(OPTION_MEMORY_MAP) && o.getValue() instanceof Boolean v) return v;
        return dflt;
    }

    private static String badBase(NumberFormatException e) {
        return OPTION_BASE + " must be a hex address 0..0xFFFFFFFF (" + e.getMessage() + ")";
    }

    private static String baseOption(List<Option> options) {
        if (options != null)
            for (Option o : options)
                if (o.getName().equals(OPTION_BASE)) return String.valueOf(o.getValue());
        return "0x00000000";
    }

    private static boolean isBigEndian(LoadSpec spec) {
        if (spec == null || spec.getLanguageCompilerSpec() == null) return false;
        try {
            return spec.getLanguageCompilerSpec().getLanguageDescription().getEndian() == Endian.BIG;
        } catch (LanguageNotFoundException e) {
            return false;
        }
    }
}
