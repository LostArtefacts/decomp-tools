// Creates a function at every address of a symbols.csv that lies in
// executable memory and has none yet: functions that are only reached
// through pointer tables, which the analysis misses.
// Usage (post-script, before ExportFunctions): -postScript CreateFunctions.java <symbols.csv>
// @category decomp

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;

public class CreateFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int created = 0, failed = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(getScriptArgs()[0]))) {
			r.readLine();
			for (String line; (line = r.readLine()) != null;) {
				String field = line.split(",", 2)[0].replaceFirst("^0[xX]", "");
				if (field.isEmpty()) {
					continue;
				}
				Address addr = toAddr(field);
				MemoryBlock block = currentProgram.getMemory().getBlock(addr);
				if (block == null || !block.isExecute() || getFunctionAt(addr) != null) {
					continue;
				}
				if (getInstructionAt(addr) == null) {
					new DisassembleCommand(new AddressSet(addr), null, true).applyTo(currentProgram, monitor);
				}
				if (new CreateFunctionCmd(addr).applyTo(currentProgram, monitor)) {
					created++;
				} else {
					printerr("REPORT: no function at " + addr);
					failed++;
				}
			}
		}
		println(String.format("REPORT: created %d functions from symbols.csv, %d failed", created, failed));
	}
}
