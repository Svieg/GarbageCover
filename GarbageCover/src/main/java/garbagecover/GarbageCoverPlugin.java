/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * Additional IP: Hugo Genesse
 */
package garbagecover;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = GarbageCoverPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "GBA code coverage viewer for Ghidra.",
	description = "GBA code coverage viewer for Ghidra\n"
			+ "\n"
			+ "Code coverage format is based on the mGBA fork SiD3W4y/mgba."
)
//@formatter:on
public class GarbageCoverPlugin extends ProgramPlugin {

	GarbageCoverProvider provider;
	private FlatProgramAPI flatApi;
	private ColorizingService colorService;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GarbageCoverPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		provider = new GarbageCoverProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
        colorService = tool.getService(ColorizingService.class);
		// TODO: Acquire services if necessary
	}
	
	@Override
	public void programActivated(Program program) {
		super.programActivated(program);
		
		flatApi = new FlatProgramAPI(this.currentProgram);
	}
	
    public boolean setInstructionBackgroundColor(long addr, Color color) {

        Address ba;
        // TODO: create FlatProgramAPI instance in init


        if (colorService == null) {
                return false;
        }
        if (flatApi == null) {
        	return false;
        }
        ba = flatApi.toAddr(addr);

        colorService.setBackgroundColor(ba, ba, color);

        return true;
}


	private static class GarbageCoverProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public GarbageCoverProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
			//setInstructionBackgroundColor()
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
