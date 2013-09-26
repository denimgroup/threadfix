package com.denimgroup.threadfix.plugin.eclipse.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.core.runtime.preferences.ConfigurationScope;
import org.eclipse.core.runtime.preferences.IEclipsePreferences;
import org.osgi.service.prefs.BackingStoreException;

public class SettingsUtils {
	
	private final static String 
		URL_KEY = "url", 
		API_KEY = "apiKey", 
		APPLICATIONS = "applications", 
		PACKAGE_NAME = "com.denimgroup.threadfix.plugin.eclipse";
	
	public static void saveThreadFixInfo(String url, String apiKey) {
		try {
			IEclipsePreferences prefs = getPreferences();
			
			prefs.put(API_KEY, apiKey);
			prefs.put(URL_KEY, url);
			
			prefs.flush();
		} catch (BackingStoreException e) {
			e.printStackTrace();
		}
	}
	
	public static void saveApplicationInfo(Set<String> configuredApplications) {
		try {
			IEclipsePreferences prefs = getPreferences();
			
			prefs.put(APPLICATIONS, setToCSVString(configuredApplications));
			
			prefs.flush();
		} catch (BackingStoreException e) {
			e.printStackTrace();
		}
	}
	
	private static String setToCSVString(Set<String> input) {
		StringBuilder builder = new StringBuilder();
		
		for (String string : input) {
			builder.append(string).append(",");
		}
		
		if (builder.length() > 0) {
			// kill last comma
			builder.setLength(builder.length() - 1);
		}
	
		return builder.toString();
	}
	
	private static Set<String> csvStringToSet(String input) {
		if (input == null || input.trim().isEmpty()) {
			return new HashSet<String>();
		} else {
			return new HashSet<String>(Arrays.asList(input.split(",")));
		}
	}
	
	public static String getUrl() {
		return getPreferences().get(URL_KEY, "");
	}
	
	public static String getApiKey() {
		return getPreferences().get(API_KEY, "");
	}
	
	public static Set<String> getConfiguredApplications() {
		return csvStringToSet(getPreferences().get(APPLICATIONS, ""));
	}
	
	private static IEclipsePreferences getPreferences() {
		return ConfigurationScope.INSTANCE.getNode(PACKAGE_NAME);
	}
}
