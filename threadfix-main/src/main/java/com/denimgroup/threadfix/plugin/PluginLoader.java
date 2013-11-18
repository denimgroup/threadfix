package com.denimgroup.threadfix.plugin;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collection;

import net.xeoh.plugins.base.Plugin;
import net.xeoh.plugins.base.PluginManager;
import net.xeoh.plugins.base.impl.PluginManagerFactory;
import net.xeoh.plugins.base.util.PluginManagerUtil;

public class PluginLoader {
	
	private static PluginManagerUtil INSTANCE = getInstance();
	
	private static PluginManagerUtil getInstance() {
		PluginManager pm = PluginManagerFactory.createPluginManager();
		
		try {
			if(PluginLoader.class.getClassLoader().getResource("enterprise.jar")==null){
				return null;
			}

            URL url = PluginLoader.class.getClassLoader().getResource("enterprise.jar");

            if (url != null) {
                pm.addPluginsFrom(url.toURI());
            }
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		
		return new PluginManagerUtil(pm);
	}
	
	public static <T extends Plugin> T getMostRecentPlugin(Class<T> targetClass) {
		if(INSTANCE == null){
			return null;
		}
		Collection<T> plugins = INSTANCE.getPlugins(targetClass);
		
		T returnPlugin = null;
		
		for (T plugin : plugins) {
			if (plugin != null) {
				returnPlugin = plugin;
				break;
			}
		}
		
		return returnPlugin;
	}

}
