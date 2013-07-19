package com.denimgroup.threadfix.service.scans;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SimpleVulnCollectionParser {
	
	private SimpleVulnCollectionParser() {}

	public static List<SimpleVuln> parseVulnsFromMergeCSV(WebApplication application) throws IOException {
		List<SimpleVuln> appScanMerges = new ArrayList<>();
		
		int count = 0;
		
		File testFile = application.getMergeCsvFile();
		
		BufferedReader reader = new BufferedReader(new FileReader(testFile));
		
		while (reader.ready()) {
			count ++;
			String lineContents = reader.readLine();
			String[] splitContents = lineContents.split(",");
			if (splitContents.length != 7) {
				System.out.println("line " + 
						count + 
						" has a problem - " + 
						splitContents.length + 
						" parts instead of 7.");
				System.out.println(lineContents);
			} else {
				appScanMerges.add(SimpleVuln.buildSimpleVuln(splitContents, count));
			}
		}
		
		reader.close();
		return appScanMerges;
	}
	
	public static List<SimpleVuln> parseVulnsFromJSON(String applicationJSON) throws JSONException {
		assertTrue(applicationJSON != null);
		
		JSONArray vulns = new JSONObject(applicationJSON).getJSONArray("vulnerabilities");
		
		assertTrue(vulns != null);
		
		List<SimpleVuln> result = new ArrayList<>();
		
		for (int i = 0; i < vulns.length(); i ++) {
			SimpleVuln vuln = new SimpleVuln(vulns.getJSONObject(i));
			
			if (vuln.getAppscanIdsToMatch() != null) {
				result.add(vuln);
			}
		}
		
		return result;
	}
	
}
