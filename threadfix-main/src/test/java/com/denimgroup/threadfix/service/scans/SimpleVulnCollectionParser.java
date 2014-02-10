////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
