// Writes Ghidra's decompilation of functions to <outdir>/<address>.c
// Usage (post-script): -postScript Decompile.java <outdir> [address...]
// With no addresses, every function is decompiled.
// @category decomp

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class Decompile extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args[0]);
		out.mkdirs();

		List<Function> funcs = new ArrayList<>();
		if (args.length > 1) {
			for (int i = 1; i < args.length; i++) {
				String addr = args[i].replaceFirst("^0[xX]", "");
				Function f = getFunctionAt(toAddr(addr));
				if (f == null) {
					printerr("REPORT: no function at " + args[i]);
				} else {
					funcs.add(f);
				}
			}
		} else {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (!f.isThunk() && !f.isExternal()) {
					funcs.add(f);
				}
			}
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int failed = 0;
		for (Function f : funcs) {
			if (monitor.isCancelled()) {
				break;
			}
			long addr = f.getEntryPoint().getOffset();
			DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
			try (PrintWriter w = new PrintWriter(new File(out, String.format("%08x.c", addr)), "UTF-8")) {
				w.printf("// %s at 0x%08x, %d bytes%n", f.getName(), addr, f.getBody().getNumAddresses());
				if (r.decompileCompleted()) {
					w.print(r.getDecompiledFunction().getC());
				} else {
					w.println("// decompilation failed: " + r.getErrorMessage());
					failed++;
				}
			}
		}
		decompiler.dispose();
		println(String.format("REPORT: decompiled %d functions to %s, %d failed", funcs.size() - failed, out, failed));
	}
}
