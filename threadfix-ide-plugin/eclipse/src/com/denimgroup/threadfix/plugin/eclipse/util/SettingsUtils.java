package com.denimgroup.threadfix.plugin.eclipse.util;

import org.eclipse.core.runtime.preferences.ConfigurationScope;
import org.eclipse.core.runtime.preferences.IEclipsePreferences;
import org.osgi.service.prefs.BackingStoreException;

public class SettingsUtils {
	
	private final static String 
		URL_KEY = "url", 
		API_KEY = "apiKey",
		PACKAGE_NAME = "com.denimgroup.threadfix.plugin.eclipse";
	
	public static void save(String url, String apiKey) {
		try {
			IEclipsePreferences prefs = getPreferences();
			
			prefs.put(API_KEY, apiKey);
			prefs.put(URL_KEY, url);
			
			prefs.flush();
		} catch (BackingStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static String getUrl() {
		return getPreferences().get(URL_KEY, "");
	}
	
	public static String getApiKey() {
		return getPreferences().get(API_KEY, "");
	}
	
	private static IEclipsePreferences getPreferences() {
		return ConfigurationScope.INSTANCE.getNode(PACKAGE_NAME);
	}
}
