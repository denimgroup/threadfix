package com.denimgroup.threadfix.plugin;

import net.xeoh.plugins.base.Plugin;

import com.denimgroup.threadfix.service.channel.ChannelImporter;

public interface ScannerPlugin extends Plugin {

	double getVersion();
	
	String getId();
	
	ChannelImporter getChannelImporter();
	
}
