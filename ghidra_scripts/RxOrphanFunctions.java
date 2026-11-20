// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
// Creates functions for disassembled code that analysis left outside any function
// (typically reached only through tail jumps or function-pointer tables), then repeats
// until nothing changes. Run after auto-analysis.
//@category RX
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class RxOrphanFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing L = currentProgram.getListing();
        int total = 0;
        for (int pass = 0; pass < 5; pass++) {
            int made = 0;
            Instruction prev = null;
            for (Instruction i : L.getInstructions(true)) {
                monitor.checkCancelled();
                Address a = i.getAddress();
                boolean orphan = getFunctionContaining(a) == null;
                // start of an orphan run: previous instruction doesn't fall through into it
                boolean start = prev == null || !prev.getMaxAddress().add(1).equals(a)
                                || prev.getFallThrough() == null || getFunctionContaining(prev.getAddress()) != null;
                if (orphan && start) {
                    if (createFunction(a, null) != null) made++;
                }
                prev = i;
            }
            total += made;
            if (made == 0) break;
        }
        println("orphan code: created " + total + " functions");
    }
}
