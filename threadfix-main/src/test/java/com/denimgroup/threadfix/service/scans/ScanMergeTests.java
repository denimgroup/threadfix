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

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.webservices.tests.BaseRestIT;
import org.json.JSONException;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public class ScanMergeTests extends BaseRestIT {
	
	public static final boolean debug = true;
	
	static final ThreadFixRestClient GOOD_CLIENT = getGoodClient();

	@Test
	@Ignore
	public void testWavsepMerge() throws IOException, JSONException {
		testApplicationWithVariations(FrameworkType.JSP, WebApplication.WAVSEP);
	}
	
	@Test
	@Ignore
	public void testBodgeItMerge() throws IOException, JSONException {
		testApplicationWithVariations(FrameworkType.JSP, WebApplication.BODGEIT);
	}
	
	@Test
	@Ignore
	public void testPetClinicMerge() throws IOException, JSONException {
		testApplicationWithVariations(FrameworkType.SPRING_MVC, WebApplication.PETCLINIC);
	}

	private void testApplicationWithVariations(FrameworkType frameworkType, WebApplication application) throws JSONException, IOException {
		debug("Starting " + application.getName() + " tests.");
		
		FileWriter csvWriter = null, textWriter = null;
		try {
			csvWriter = new FileWriter(
					new File("C:\\test\\SBIR\\testoutput" + application.getName() + ".csv"));
			
			textWriter = new FileWriter(
					new File("C:\\test\\SBIR\\testoutput" + application.getName() + ".txt"));
			
			csvWriter.write("framework,source code access,vuln type strategy, total, correctly merged, correct path, correct param, correctCWE\n");
			
			// set up application
			// we pass in the type because we don't want to do a spring mvc run on a jsp app, for instance.
			for (FrameworkType type : new FrameworkType[] { FrameworkType.NONE, FrameworkType.DETECT, frameworkType }) {
				for (SourceCodeAccessLevel sourceCodeAccessLevel : SourceCodeAccessLevel.values()) {
					testApplication(application, type, sourceCodeAccessLevel, csvWriter, textWriter);
				}
			}
		} finally {
			if (csvWriter != null) {
				csvWriter.close();
			}
			
			if (textWriter != null) {
				textWriter.close();
			}
		}
	}
	
	private void testApplication(WebApplication application,
			FrameworkType frameworkType,
			SourceCodeAccessLevel sourceCodeAccessLevel,
			Writer csvWriter, Writer textWriter) throws JSONException, IOException {
		
		Integer appId = setupApplication(application, frameworkType);

//		String jsonToLookAt = GOOD_CLIENT.searchForApplicationById(appId.toString());
//
//		// Parsing / analysis
//
//		debug("Reading in manual merge results from JSON output.");
//		List<SimpleVuln> jsonResults = SimpleVulnCollectionParser.parseVulnsFromJSON(jsonToLookAt);
//
//		debug("Reading in manual merge results from CSV file.");
//		List<SimpleVuln> csvResults  = SimpleVulnCollectionParser.parseVulnsFromMergeCSV(application);
//
//		TestResult result = TestResult.compareResults(csvResults, jsonResults);
//
//		csvWriter.write(frameworkType + "," + sourceCodeAccessLevel);
//		csvWriter.write(result.getCsvLine() + "\n");
//
//		textWriter.write(frameworkType + "," + sourceCodeAccessLevel + "\n");
//		textWriter.write(result.toString());
//
//		if (result.hasMissing()) {
//			System.out.println("We have more than 0 missing. " +
//					"This means we need a better method of building the hash " +
//					"or that native ID generation is incorrect.");
//		}
	}
	
	private Integer setupApplication(WebApplication application, FrameworkType frameworkType) {
		debug("Creating new application and uploading scans.");
		
////		Integer teamId = getId(getJSONObject(GOOD_CLIENT.createTeam(
////				application.getName() + "-" + frameworkType
////				)));
////		Integer appId  = getId(getJSONObject(GOOD_CLIENT.createApplication(
////			teamId.toString(),
////			application.getName() + getRandomString(10),
////			null)));
//
//		GOOD_CLIENT.setParameters(appId.toString(),
//				frameworkType.toString(),
//				application.getUrl());
//
//		uploadScans(appId, application.getFPRPath(), application.getAppscanXMLPath());
//
//		debug("Application is at " + BASE_URL.replaceAll("/rest","") +
//				"/organizations/" + teamId + "/applications/" + appId);
//
		return 1;
	}
	
	private void uploadScans(Integer appId, String... scanPaths) {
		for (String scanPath : scanPaths) {
			debug("Uploading " + scanPath + " to application with ID " + appId);
//
//			String response = GOOD_CLIENT.uploadScan(appId.toString(), scanPath);
//
//			assertTrue(response != null);
//			assertTrue(getJSONObject(response) != null);
		}
	}
	
	public void debug(String message) {
		if (debug) {
			System.out.println(message);
		}
	}
}
