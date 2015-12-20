package net.floodlightcontroller.conflictdetector;

import java.util.Map;

import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface getStoreFlowTableEntryService extends IFloodlightService{
	public Map<String,String> getStoreTableEntry();
}
