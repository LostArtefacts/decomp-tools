// Writes every function as CSV: address,size,name,callers,callees
// Usage (post-script): -postScript ExportFunctions.java <out.csv>
// @category decomp

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class ExportFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String out = getScriptArgs()[0];
		try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
			w.println("address,size,name,callers,callees");
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.isThunk() || f.isExternal()) {
					continue;
				}
				w.printf("0x%08x,%d,%s,%d,%d%n",
					f.getEntryPoint().getOffset(),
					f.getBody().getNumAddresses(),
					f.getName(),
					f.getCallingFunctions(TaskMonitor.DUMMY).size(),
					f.getCalledFunctions(TaskMonitor.DUMMY).size());
			}
		}
	}
}
