// Headless test harness for the RX SLEIGH specification.
// For every vector: write the bytes into the scratch program, disassemble, compare the
// listing text, single-step the instruction in EmulatorHelper and check registers,
// flags and memory. Results are printed as "RXTEST PASS|FAIL <lang> <file>:<name> ...".
// Usage: -postScript RxVectorTest.java <vector file> [<vector file> ...]
//
// Vector line:  name | hex bytes | setup | expected disassembly ('-' skips) | expectations | langs
//   setup/expectations: R0..R15, SP, PSW, FPSW, INTB, ... =v ; flags C Z S O =0/1 ;
//   mem8|mem16|mem32[addr]=v (program byte order) ; PC=@+off or PC=abs ;
//   expectation-only: nostore (no memory written), nobranch (no BRANCH/CBRANCH/BRANCHIND in p-code),
//   noemu (decode + nobranch only; for behaviour the emulator cannot model, e.g. divide by zero)
//   langs: both (default) | le | be
// Memory: the scratch image is 64 KiB of zeros at 0. Vectors use 0x2000-0x3FFF for data; code slots
// start at 0x4000 (0x20 bytes each), so a run holds at most 1536 vectors per language.
//@category Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class RxVectorTest extends GhidraScript {

    private static final long LOAD_BASE = 0x4000;   // above the 0x2000-0x3FFF data area
    private static final long IMAGE_END = 0x10000;
    private static final long SLOT = 0x20;
    private static final String[] FLAGS = { "C", "Z", "S", "O" };   // PSW bits 0..3

    private int pass, fail;
    private String lang;

    @Override
    public void run() throws Exception {
        boolean be = currentProgram.getLanguage().isBigEndian();
        lang = be ? "be" : "le";
        int index = 0;
        for (String path : getScriptArgs()) {
            File f = new File(path);
            List<String[]> vectors = parse(f);
            for (String[] v : vectors) {
                String id = f.getName() + ":" + v[0];
                String langs = v.length > 5 && !v[5].isEmpty() ? v[5] : "both";
                if (!langs.equals("both") && !langs.equals(lang)) continue;
                long addr = LOAD_BASE + SLOT * (index++);
                if (addr + SLOT > IMAGE_END) {
                    report(false, id, "out of code slots (max " + (IMAGE_END - LOAD_BASE) / SLOT + " vectors per run)");
                    continue;
                }
                try {
                    String err = runVector(v, addr);
                    report(err == null, id, err == null ? "" : err);
                }
                catch (Throwable t) {
                    report(false, id, "exception: " + t);
                }
            }
        }
        for (String[] check : structuralChecks()) report(check[1] == null, "structure:" + check[0], check[1] == null ? "" : check[1]);
        println("RXTEST SUMMARY " + lang + " pass=" + pass + " fail=" + fail);
    }

    /** Structural (non-vector) checks; each entry is {name, error-or-null}. Extended by later tasks. */
    private List<String[]> structuralChecks() {
        List<String[]> out = new ArrayList<>();
        out.add(new String[] { "layout", checkLayout() });
        out.add(new String[] { "cspec", checkCspec() });
        return out;
    }

    /** Renesas RX ABI: arguments in R1-R4 (R15 is the struct-return pointer, not an argument);
     *  callers remove stack arguments, so every prototype pops only the return address. */
    private String checkCspec() {
        StringBuilder err = new StringBuilder();
        for (ghidra.program.model.lang.PrototypeModel pm : currentProgram.getCompilerSpec().getCallingConventions()) {
            if (pm.getExtrapop() != 4) err.append(pm.getName()).append(" extrapop=").append(pm.getExtrapop()).append("; ");
            List<String> regs = new ArrayList<>();
            for (ghidra.program.model.listing.VariableStorage vs : pm.getPotentialInputRegisterStorage(currentProgram))
                regs.add(vs.getRegister().getName());
            if (regs.contains("R15")) err.append(pm.getName()).append(" takes R15 as an argument; ");
            if (pm.getName().equals("__fastcall") && !regs.equals(List.of("R1", "R2", "R3", "R4")))
                err.append("__fastcall inputs ").append(regs).append("; ");
        }
        return err.length() == 0 ? null : err.toString();
    }

    /** Base registers must not overlap, and the core register offsets must stay stable (old projects). */
    private String checkLayout() {
        String[] core = { "SP", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12",
            "R13", "R14", "R15", "ISP", "USP", "INTB", "PC", "PSW", "BPC", "BPSW", "FINTV", "FPSW", "EXTB" };
        StringBuilder err = new StringBuilder();
        for (int i = 0; i < core.length; i++) {
            ghidra.program.model.lang.Register r = currentProgram.getLanguage().getRegister(core[i]);
            if (r == null) err.append(core[i]).append(" missing; ");
            else if (!r.isBaseRegister())
                err.append(core[i]).append(" is part of ").append(r.getBaseRegister().getName()).append("; ");
            else if (r.getOffset() != 4L * i || r.getMinimumByteSize() != 4)
                err.append(core[i]).append(" at 0x").append(Long.toHexString(r.getOffset())).append("; ");
        }
        List<ghidra.program.model.lang.Register> base = new ArrayList<>();
        for (ghidra.program.model.lang.Register r : currentProgram.getLanguage().getRegisters())
            if (r.isBaseRegister() && !r.isProcessorContext()) base.add(r);
        for (int i = 0; i < base.size(); i++)
            for (int j = i + 1; j < base.size(); j++) {
                ghidra.program.model.lang.Register a = base.get(i), b = base.get(j);
                long a0 = a.getOffset(), a1 = a0 + a.getMinimumByteSize();
                long b0 = b.getOffset(), b1 = b0 + b.getMinimumByteSize();
                if (a.getAddressSpace().equals(b.getAddressSpace()) && a0 < b1 && b0 < a1)
                    err.append(a.getName()).append(" overlaps ").append(b.getName()).append("; ");
            }
        return err.length() == 0 ? null : err.toString();
    }

    private void report(boolean ok, String id, String detail) {
        if (ok) pass++; else fail++;
        println("RXTEST " + (ok ? "PASS" : "FAIL") + " " + lang + " " + id + (detail.isEmpty() ? "" : " " + detail));
    }

    private List<String[]> parse(File f) throws Exception {
        List<String[]> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = r.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                String[] parts = t.split("\\|", -1);
                for (int i = 0; i < parts.length; i++) parts[i] = parts[i].trim();
                if (parts.length < 5) throw new IllegalArgumentException(f + ": malformed vector: " + line);
                out.add(parts);
            }
        }
        return out;
    }

    private String runVector(String[] v, long addrOff) throws Exception {
        Address addr = toAddr(addrOff);
        byte[] code = hex(v[1]);
        clearListing(addr, addr.add(SLOT - 1));
        setBytes(addr, code);
        disassemble(addr);
        Instruction insn = getInstructionAt(addr);
        if (insn == null) return "no instruction decoded";
        if (insn.getLength() != code.length)
            return "length " + insn.getLength() + " != " + code.length + " (" + insn + ")";
        if (!v[3].equals("-") && !insn.toString().equals(v[3]))
            return "disasm '" + insn + "' != '" + v[3] + "'";

        if (tokens(v[4]).contains("noemu")) {          // decode-only vector: static checks, no emulation
            for (String kv : tokens(v[4])) {
                if (kv.equals("noemu")) continue;
                if (!kv.equals("nobranch")) return "noemu vectors may only check nobranch, not " + kv;
                String e = check(null, insn, kv, addrOff);
                if (e != null) return e + " [" + insn + "]";
            }
            return null;
        }
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            for (String kv : tokens(v[2])) apply(emu, kv);
            emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(addrOff));
            emu.enableMemoryWriteTracking(true);
            if (!emu.step(monitor)) return "emulation failed: " + emu.getLastError();
            StringBuilder errs = new StringBuilder();
            for (String kv : tokens(v[4])) {
                String e = check(emu, insn, kv, addrOff);
                if (e != null) errs.append(e).append("; ");
            }
            return errs.length() == 0 ? null : errs.toString() + "[" + insn + "]";
        }
        finally {
            emu.dispose();
        }
    }

    private static List<String> tokens(String s) {
        List<String> out = new ArrayList<>();
        for (String t : s.trim().split("\\s+")) if (!t.isEmpty()) out.add(t);
        return out;
    }

    private static long num(String s) {
        s = s.trim();
        boolean neg = s.startsWith("-");
        if (neg) s = s.substring(1);
        long v = s.toLowerCase().startsWith("0x") ? Long.parseUnsignedLong(s.substring(2), 16) : Long.parseLong(s);
        return neg ? -v : v;
    }

    private static byte[] hex(String s) {
        String[] p = s.trim().split("\\s+");
        byte[] b = new byte[p.length];
        for (int i = 0; i < p.length; i++) b[i] = (byte) Integer.parseInt(p[i], 16);
        return b;
    }

    private int flagBit(String name) {
        for (int i = 0; i < FLAGS.length; i++) if (FLAGS[i].equals(name)) return i;
        return -1;
    }

    private byte[] memBytes(int bits, long value) {
        int n = bits / 8;
        byte[] b = new byte[n];
        boolean be = currentProgram.getLanguage().isBigEndian();
        for (int i = 0; i < n; i++) {
            byte x = (byte) (value >>> (8 * i));
            b[be ? n - 1 - i : i] = x;
        }
        return b;
    }

    private long memValue(byte[] b) {
        boolean be = currentProgram.getLanguage().isBigEndian();
        long v = 0;
        for (int i = 0; i < b.length; i++) {
            int idx = be ? i : b.length - 1 - i;
            v = (v << 8) | (b[idx] & 0xFF);
        }
        return v;
    }

    private void apply(EmulatorHelper emu, String kv) {
        String[] p = kv.split("=", 2);
        String key = p[0];
        long value = num(p[1]);
        int fb = flagBit(key);
        if (fb >= 0) {
            long psw = emu.readRegister("PSW").longValue();
            psw = value != 0 ? psw | (1L << fb) : psw & ~(1L << fb);
            emu.writeRegister("PSW", BigInteger.valueOf(psw));
        }
        else if (key.startsWith("mem")) {
            int bits = Integer.parseInt(key.substring(3, key.indexOf('[')));
            long a = num(key.substring(key.indexOf('[') + 1, key.indexOf(']')));
            emu.writeMemory(toAddr(a), memBytes(bits, value));
        }
        else {
            emu.writeRegister(key, BigInteger.valueOf(value & 0xFFFFFFFFL));
        }
    }

    private String check(EmulatorHelper emu, Instruction insn, String kv, long base) throws Exception {
        if (kv.equals("nostore")) {
            StringBuilder written = new StringBuilder();
            for (ghidra.program.model.address.AddressRange r : emu.getTrackedMemoryWriteSet())
                if (r.getAddressSpace().isLoadedMemorySpace()) written.append(r).append(' ');
            return written.length() == 0 ? null : "memory written at " + written.toString().trim();
        }
        if (kv.equals("nobranch")) {
            for (PcodeOp op : insn.getPcode()) {
                int c = op.getOpcode();
                if (c == PcodeOp.BRANCH || c == PcodeOp.CBRANCH || c == PcodeOp.BRANCHIND)
                    return "p-code contains " + op.getMnemonic();
            }
            return null;
        }
        String[] p = kv.split("=", 2);
        String key = p[0];
        long want;
        long got;
        if (key.equals("PC")) {
            want = p[1].startsWith("@") ? base + num(p[1].substring(1).replace("+", "")) : num(p[1]);
            got = emu.getExecutionAddress().getOffset();
        }
        else if (flagBit(key) >= 0) {
            want = num(p[1]);
            got = (emu.readRegister("PSW").longValue() >> flagBit(key)) & 1;
        }
        else if (key.startsWith("mem")) {
            int bits = Integer.parseInt(key.substring(3, key.indexOf('[')));
            long a = num(key.substring(key.indexOf('[') + 1, key.indexOf(']')));
            want = num(p[1]) & ((bits == 64) ? -1L : (1L << bits) - 1);
            got = memValue(emu.readMemory(toAddr(a), bits / 8));
        }
        else {
            want = num(p[1]) & 0xFFFFFFFFL;
            got = emu.readRegister(key).longValue() & 0xFFFFFFFFL;
        }
        if ((want & 0xFFFFFFFFL) == (got & 0xFFFFFFFFL)) return null;
        return key + "=0x" + Long.toHexString(got) + " (want 0x" + Long.toHexString(want) + ")";
    }
}
