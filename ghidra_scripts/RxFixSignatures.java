// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
// Tidies function signatures of an RX program after "Decompiler Parameter ID" has run:
//  1. Any function still on the "unknown" calling convention gets the cspec
//     default (__fastcall: args R1-R4, return R1), so storage can be assigned.
//  2. Functions whose return is still plain "undefined" with no storage
//     (Parameter ID found no return value) are set to void, which removes the
//     "undefined <UNASSIGNED> <RETURN>" lines. User-defined signatures are left alone.
// Programs whose language is not an rx62t language are refused and left unchanged.
//@category RX
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

public class RxFixSignatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        String lang = currentProgram.getLanguageID().getIdAsString();
        if (!lang.startsWith("rx62t")) {
            println("RxFixSignatures: language '" + lang + "' is not an rx62t language; nothing changed.");
            return;
        }
        String cc = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        int ccFixed = 0, voided = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isThunk() || f.isExternal() || f.getSignatureSource() == SourceType.USER_DEFINED) continue;
            if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(f.getCallingConventionName())) {
                f.setCallingConvention(cc);
                ccFixed++;
            }
            Parameter r = f.getReturn();
            if (r.getVariableStorage().isUnassignedStorage() && r.getDataType() instanceof DefaultDataType) {
                f.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                voided++;
            }
        }
        println("Calling convention '" + cc + "' set on " + ccFixed + " functions; " + voided + " returns set to void.");
    }
}
