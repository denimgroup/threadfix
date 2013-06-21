package com.denimgroup.threadfix.service.scans;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Ignore;
import org.junit.Test;

import com.denimgroup.threadfix.webservices.tests.BaseRestTest;
import com.denimgroup.threadfix.webservices.tests.ThreadFixRestClient;

public class ScanMergeTests extends BaseRestTest {
	
	public static final boolean debug = true;
	
	static final ThreadFixRestClient GOOD_CLIENT = getGoodClient();

	@Ignore
	@Test
	public void testWavsepMerge() throws IOException, JSONException {
		testApplication(WebApplication.WAVSEP, 1);
	}
	
	@Ignore
	@Test
	public void testBodgeItMerge() throws IOException, JSONException {
		testApplication(WebApplication.BODGEIT, 2);
	}
	
	@Test
	public void testPetClinicMerge() throws IOException, JSONException {
		testApplication(WebApplication.PETCLINIC, 3);
	}
	
	public void testApplication(WebApplication application) throws JSONException, IOException {
		testApplication(application, null);
	}
	
	private void testApplication(WebApplication application, Integer id) throws JSONException, IOException {
		debug("Starting " + application.getName() + " tests.");
		
		// set up application
		
		Integer appId = id;
		
		if (appId == null) {
			appId = setupApplication(application);
		}
	
		String jsonToLookAt = GOOD_CLIENT.searchForApplicationById(appId.toString());
		
		// Parsing / analysis
		
		List<SimpleVuln> results = parseVulnsFromJSON(jsonToLookAt);
		
		List<SimpleVuln> target = getTarget(application);
		
		compareResults(results, target);
	}
	
	// First draft will only compare the appscan results and which findings they merge to.
	private void compareResults(List<SimpleVuln> results, List<SimpleVuln> target) {
		debug("Comparing results from ThreadFix and manual merge.");
		
		Map<String, SimpleVuln> resultMap = new HashMap<>();
		
		for (SimpleVuln vuln : results) {
			if (vuln.getAppscanNativeIds() != null) {
				for (String nativeId : vuln.getAppscanNativeIds()) {
					resultMap.put(nativeId, vuln);
				}
			}
		}
		
		TestResult matchResults = new TestResult();
		
		for (SimpleVuln targetVuln : target) {
			for (String nativeId : targetVuln.getAppscanNativeIds()) {
				if (resultMap.containsKey(nativeId)) {
					SimpleVuln result = resultMap.get(nativeId);
					matchResults.analyze(targetVuln, result);
				} else {
					matchResults.addMissing(targetVuln);
				}
			}
		}
		
		System.out.println(matchResults);
		
		if (matchResults.hasMissing()) {
			System.out.println("We have more than 0 missing. " +
					"This means we need a better method of building the hash " +
					"or that native ID generation is incorrect.");
		}
	}
	
	private Integer setupApplication(WebApplication application) {
		debug("Creating new application and uploading scans.");
		
		Integer teamId = getId(getJSONObject(GOOD_CLIENT.createTeam(getRandomString(23))));
		Integer appId  = getId(getJSONObject(GOOD_CLIENT.createApplication(
			teamId.toString(), 
			application.getName() + getRandomString(10), 
			application.getUrl())));
		
		uploadScans(appId, application.getFPRPath(), application.getAppscanXMLPath());

		debug("Application is at " + BASE_URL.replaceAll("/rest","") + 
				"/organizations/" + teamId + "/applications/" + appId);
		
		return appId;
	}
	
	private void uploadScans(Integer appId, String... scanPaths) {
		for (String scanPath : scanPaths) {
			debug("Uploading " + scanPath + " to application with ID " + appId);
			
			String response = GOOD_CLIENT.uploadScan(appId.toString(), scanPath);
			
			assertTrue(response != null);
			assertTrue(getJSONObject(response) != null);
		}
	}
	
	private List<SimpleVuln> getTarget(WebApplication application) throws IOException {
		debug("Reading in manual merge results from CSV file.");
		
		List<SimpleVuln> appScanMerges = new ArrayList<>();
		
		int count = 0;
		
		File testFile = application.getMergeCsvFile();
		
		BufferedReader reader = new BufferedReader(new FileReader(testFile));
		
		while (reader.ready()) {
			count ++;
			String lineContents = reader.readLine();
			String[] splitContents = lineContents.split(",");
			if (splitContents.length != 6) {
				System.out.println("line " + 
						count + 
						" has a problem - " + 
						splitContents.length + 
						" parts instead of 6.");
				System.out.println(lineContents);
			} else {
				appScanMerges.add(SimpleVuln.buildSimpleVuln(splitContents));
			}
		}
		
		reader.close();
		return appScanMerges;
	}
	
	private List<SimpleVuln> parseVulnsFromJSON(String applicationJSON) throws JSONException {
		debug("Parsing vulnerabilities from resulting JSON.");
		
		assertTrue(applicationJSON != null);
		
		JSONArray vulns = new JSONObject(applicationJSON).getJSONArray("vulnerabilities");
		
		assertTrue(vulns != null);
		
		List<SimpleVuln> result = new ArrayList<>();
		
		for (int i = 0; i < vulns.length(); i ++) {
			SimpleVuln vuln = new SimpleVuln(vulns.getJSONObject(i));
			
			if (vuln.getAppscanNativeIds() != null) {
				result.add(vuln);
			}
		}
		
		return result;
	}
	
	public void debug(String message) {
		if (debug) {
			System.out.println(message);
		}
	}
}
