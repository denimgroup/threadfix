////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.plugin.eclipse.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.core.runtime.preferences.ConfigurationScope;
import org.eclipse.core.runtime.preferences.IEclipsePreferences;
import org.osgi.service.prefs.BackingStoreException;

import com.denimgroup.threadfix.properties.PropertiesManager;

public class EclipsePropertiesManager extends PropertiesManager {
	
	public static final EclipsePropertiesManager INSTANCE = new EclipsePropertiesManager();
	
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
	
	@Override
	public String getUrl() {
		return getUrlStatic();
	}
	
	@Override
	public String getKey() {
		return getKeyStatic();
	}
	
	public static String getUrlStatic() {
		return getPreferences().get(URL_KEY, "");
	}
	
	public static String getKeyStatic() {
		return getPreferences().get(API_KEY, "");
	}
	
	public static Set<String> getConfiguredApplications() {
		return csvStringToSet(getPreferences().get(APPLICATIONS, ""));
	}
	
	private static IEclipsePreferences getPreferences() {
		return ConfigurationScope.INSTANCE.getNode(PACKAGE_NAME);
	}
}
