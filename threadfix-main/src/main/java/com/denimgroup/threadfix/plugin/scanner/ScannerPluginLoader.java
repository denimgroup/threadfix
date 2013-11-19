package com.denimgroup.threadfix.plugin.scanner;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collection;

import net.xeoh.plugins.base.PluginManager;
import net.xeoh.plugins.base.impl.PluginManagerFactory;
import net.xeoh.plugins.base.util.PluginManagerUtil;

import com.denimgroup.threadfix.plugin.scanner.service.ScanTypeCalculationService;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ChannelImporter;

public class ScannerPluginLoader {
	
	private static PluginManagerUtil INSTANCE = getInstance();
	
	private static PluginManagerUtil getInstance() {
		PluginManager pm = PluginManagerFactory.createPluginManager();

		try {
            URL url = ScannerPluginLoader.class.getClassLoader()
                    .getResource("scanners.jar");

            if (url != null) {
			    pm.addPluginsFrom(url.toURI());
            }
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return new PluginManagerUtil(pm);
	}
	
	public static Collection<? extends ChannelImporter> getScannerPlugins() {
		return INSTANCE.getPlugins(ChannelImporter.class);
	}
	
	public static ScanTypeCalculationService getScanTypeCalculationServiceImpl() {
		return INSTANCE.getPlugin(ScanTypeCalculationService.class);
	}
	
}
