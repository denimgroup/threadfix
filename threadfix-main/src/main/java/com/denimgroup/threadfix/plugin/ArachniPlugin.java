package com.denimgroup.threadfix.plugin;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.service.channel.ChannelImporter;

@PluginImplementation
public class ArachniPlugin implements ScannerPlugin {
	
	@Override
	public double getVersion() {
		return 1.23;
	}

	@Override
	public String getId() {
		return ChannelType.ARACHNI;
	}

	@Override
	public ChannelImporter getChannelImporter() {
		return new ArachniChannelImporter(new ScannerUtils());
	}

}
