package com.denimgroup.threadfix.service.scans;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.List;

import org.json.JSONException;
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
		
		debug("Reading in manual merge results from JSON output.");
		List<SimpleVuln> jsonResults = SimpleVulnCollectionParser.parseVulnsFromJSON(jsonToLookAt);
		
		debug("Reading in manual merge results from CSV file.");
		List<SimpleVuln> csvResults  = SimpleVulnCollectionParser.parseVulnsFromMergeCSV(application);
		
		TestResult result = TestResult.compareResults(csvResults, jsonResults);
		
		System.out.println(result);
		
		if (result.hasMissing()) {
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
	
	public void debug(String message) {
		if (debug) {
			System.out.println(message);
		}
	}
}
