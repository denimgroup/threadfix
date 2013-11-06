package com.denimgroup.threadfix.plugin;

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import net.xeoh.plugins.base.PluginManager;
import net.xeoh.plugins.base.impl.PluginManagerFactory;
import net.xeoh.plugins.base.util.PluginManagerUtil;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.service.channel.ChannelImporter;

public class ScannerPluginManager {
	
	private boolean initialized = false;
	
	private Map<String, ScannerPlugin> pluginMap = new HashMap<>();
	
	public static ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

		if (applicationChannel == null || applicationChannel.getChannelType() == null
				|| applicationChannel.getChannelType().getName() == null
				|| applicationChannel.getChannelType().getName().trim().equals("")) {
			return null;
		}

		String channelName = applicationChannel.getChannelType().getName();
		
		if (!INSTANCE.initialized) {
			INSTANCE.initialize();
		}
		
		ChannelImporter channelImporter = INSTANCE.getChannelImporter(channelName);
		
		return channelImporter;
	}
	
	private static ScannerPluginManager INSTANCE = new ScannerPluginManager();
	
	private ChannelImporter getChannelImporter(String scannerName) {
		ChannelImporter result = null;
		
		if (pluginMap.containsKey(scannerName)) {
			result = pluginMap.get(scannerName).getChannelImporter();
		}
		
		return result;
	}
	
	private void initialize() {
		buildMap();
		initialized = true;
	}
	
	private void buildMap() {
		PluginManager pm = PluginManagerFactory.createPluginManager();
		
		pm.addPluginsFrom(new File("/Users/mac/Documents/Git/threadfix/threadfix/threadfix-main/util/build").toURI());
		
		Collection<ScannerPlugin> plugins =
				new PluginManagerUtil(pm).getPlugins(ScannerPlugin.class);
		
		for (ScannerPlugin plugin : plugins) {
			if (plugin != null) {
				String name = plugin.getId();
				if (name != null &&
						(pluginMap.get(name) == null ||
						pluginMap.get(name).getVersion() < plugin.getVersion())) {
					pluginMap.put(name, plugin);
				}
			}
		}
	}
}
