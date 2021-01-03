package garbagecover;

import ghidra.framework.plugintool.util.PluginPackage;

public class GarbageCoverPluginPackage extends PluginPackage {

    public static final String NAME="garbagecover";
    
    public GarbageCoverPluginPackage() {
        super(NAME, null, "garbagecover plugin package");
    }
}
