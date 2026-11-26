// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
// Used by tools/test_release.sh: reports whether the current program was loaded by the RX62T loader and
// whether the RX62T analyzer is registered, as "RXRELEASE loader <format>" and "RXRELEASE analyzer yes|no".
//@category Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class RxReleaseCheck extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("RXRELEASE loader " + currentProgram.getExecutableFormat());
        boolean analyzer = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).getOptionNames()
                .contains("RX62T Platform Setup");
        println("RXRELEASE analyzer " + (analyzer ? "yes" : "no"));
    }
}
