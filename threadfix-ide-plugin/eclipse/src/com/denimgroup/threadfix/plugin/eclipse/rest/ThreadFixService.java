package com.denimgroup.threadfix.plugin.eclipse.rest;

import java.util.HashMap;
import java.util.Map;

public class ThreadFixService {

	public static Map<String, String> getApplications() {
		String csvString = getApplicationCSV();
		
		Map<String, String> map = new HashMap<>();
		
		String[] lines = csvString.split("\n");
		
		for (String line : lines) {
			String[] components = line.split(",");
			if (components.length == 2) {
				map.put(components[0], components[1]);
			}
		}
		
		return map;
	}
	
	private static String getApplicationCSV() {
		return RestUtils.getFromSettings().getApplications();
	}

}
