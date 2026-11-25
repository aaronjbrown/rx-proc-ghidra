// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
// Undoes the "locked (void)" signatures that RxFixSignatures leaves behind when it ran before
// "Decompiler Parameter ID" had stored parameters (this happens mainly in the GUI, where the two can
// overlap).
//
// For every function whose signature source is ANALYSIS and that has no stored parameters, the
// signature source is set back to DEFAULT, so the decompiler infers parameters and returns again.
// Functions with USER_DEFINED or IMPORTED signatures, or with parameters already stored, are left alone.
//
// Afterwards: run Analysis > One Shot > Decompiler Parameter ID to store the inferred parameters, then
// run RxFixSignatures again.
// Programs whose language is not an rx62t language are refused and left unchanged.
//@category RX
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class RxUnlockSignatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        String lang = currentProgram.getLanguageID().getIdAsString();
        if (!lang.startsWith("rx62t")) {
            println("RxUnlockSignatures: language '" + lang + "' is not an rx62t language; nothing changed.");
            return;
        }
        int unlocked = 0, skipped = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isThunk() || f.isExternal()) continue;
            if (f.getSignatureSource() == SourceType.ANALYSIS && f.getParameterCount() == 0) {
                f.setSignatureSource(SourceType.DEFAULT);
                unlocked++;
            } else {
                skipped++;
            }
        }
        println("Unlocked " + unlocked + " signatures (set source to DEFAULT); left " + skipped + " unchanged.");
    }
}
