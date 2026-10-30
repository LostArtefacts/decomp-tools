// Teaches Ghidra Watcom's register calling convention.
// As a pre-script without arguments: adds the __watcall prototype.
// As a post-script with <functions.csv>: creates a function at each
// address of the list and gives every function __watcall.
// @category decomp

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class Watcom extends GhidraScript {
	static final String WATCALL =
		"<prototype name=\"__watcall\" extrapop=\"unknown\" stackshift=\"4\">\n" +
		"  <input>\n" +
		"    <pentry minsize=\"1\" maxsize=\"4\"><register name=\"EAX\"/></pentry>\n" +
		"    <pentry minsize=\"1\" maxsize=\"4\"><register name=\"EDX\"/></pentry>\n" +
		"    <pentry minsize=\"1\" maxsize=\"4\"><register name=\"EBX\"/></pentry>\n" +
		"    <pentry minsize=\"1\" maxsize=\"4\"><register name=\"ECX\"/></pentry>\n" +
		"    <pentry minsize=\"1\" maxsize=\"500\" align=\"4\"><addr offset=\"4\" space=\"stack\"/></pentry>\n" +
		"  </input>\n" +
		"  <output>\n" +
		"    <pentry minsize=\"4\" maxsize=\"10\" metatype=\"float\"><register name=\"ST0\"/></pentry>\n" +
		"    <pentry minsize=\"1\" maxsize=\"4\"><register name=\"EAX\"/></pentry>\n" +
		"    <pentry minsize=\"5\" maxsize=\"8\"><addr space=\"join\" piece1=\"EDX\" piece2=\"EAX\"/></pentry>\n" +
		"  </output>\n" +
		"  <unaffected>\n" +
		"    <register name=\"EBX\"/><register name=\"ECX\"/><register name=\"EDX\"/>\n" +
		"    <register name=\"ESI\"/><register name=\"EDI\"/><register name=\"EBP\"/>\n" +
		"    <register name=\"ESP\"/><register name=\"DF\"/>\n" +
		"  </unaffected>\n" +
		"</prototype>\n";

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			new SpecExtension(currentProgram).addReplaceCompilerSpecExtension(WATCALL, monitor);
			println("REPORT: added __watcall");
			return;
		}
		int added = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			r.readLine();
			for (String line; (line = r.readLine()) != null;) {
				Address a = toAddr(line.split(",")[0].replaceFirst("^0[xX]", ""));
				if (getFunctionAt(a) != null) {
					continue;
				}
				disassemble(a);
				if (new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) {
					added++;
				}
			}
		}
		println("REPORT: added " + added + " functions from " + args[0]);
		int n = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.isThunk() && !f.isExternal()) {
				f.setCallingConvention("__watcall");
				n++;
			}
		}
		println("REPORT: " + n + " functions use __watcall");
	}
}
