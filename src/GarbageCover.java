//Basic mGBA code coverage visualizer for Ghidra
//@author svieg
//@category coverage.gba
//@keybinding
//@menupath
//@toolbar

import java.awt.Color;
import java.io.File;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;

public class GarbageCover extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File coverage_file = askFile("Select Coverage File", "Please select a mGBA coverage file.");
		
	}
	public boolean setInstructionBackgroundColor(long addr, Color color) {
		
		Address ba;
		PluginTool tool;
		// TODO: create FlatProgramAPI instance in init
		FlatProgramAPI flat_api = new FlatProgramAPI(this.currentProgram);
		ColorizingService colorService = tool.getService(ColorizingService.class);
		
		if (colorService == null) {
			return false;
		}
		
		ba = FlatProgramAPI.toAddr(addr);
		
		colorService.setBackgroundColor(ba, ba, color);
		
		return true;
	}
}
