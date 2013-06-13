package com.denimgroup.threadfix.service.scans;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.denimgroup.threadfix.webservices.tests.BaseRestTest;
import com.denimgroup.threadfix.webservices.tests.ThreadFixRestClient;

public class ScanMergeTests extends BaseRestTest {
	
	private String wavsepUrl = "http://satgit2.denimgroup.com/sbir/wavsep.git";
	
	@Test
	public void testJSPMerge() throws IOException, JSONException {
		
		// set up application
		
		ThreadFixRestClient goodClient = new ThreadFixRestClient();
		goodClient.setKey(GOOD_API_KEY);
		goodClient.setUrl(BASE_URL);
		
		Integer appId = 6;//setupApplication("petclinic", goodClient);
	
		String jsonToLookAt = goodClient.searchForApplicationById(appId.toString());
		
		assertTrue(jsonToLookAt != null);
		
		// Parsing / analysis
		
		JSONArray vulns = new JSONObject(jsonToLookAt).getJSONArray("vulnerabilities");
		
		List<SimpleVuln> result = new ArrayList<>();
		
		for (int i = 0; i < vulns.length(); i ++) {
			SimpleVuln vuln = new SimpleVuln(vulns.getJSONObject(i));
			
			if (vuln.getAppscanNativeIds() != null) {
				result.add(vuln);
			}
			
		}
		
		List<SimpleVuln> target = getTarget("petclinic");
		
		compareResults(result, target);
	}
	
	// First draft will only compare the appscan results and which findings they merge to.
	public void compareResults(List<SimpleVuln> results, List<SimpleVuln> target) {
		Map<String, SimpleVuln> appScanSimpleVulnMap = new HashMap<>();
		
		for (SimpleVuln vuln : results) {
			if (vuln.getAppscanNativeIds() != null) {
				for (String nativeId : vuln.getAppscanNativeIds()) {
					appScanSimpleVulnMap.put(nativeId, vuln);
				}
			}
		}
		
		int correctNoMatch = 0, correctMatch = 0, wrong = 0, missing = 0;
		
		for (SimpleVuln vuln : target) {
			for (String nativeId : vuln.getAppscanNativeIds()) {
				if (appScanSimpleVulnMap.containsKey(nativeId)) {
					SimpleVuln targetVuln = appScanSimpleVulnMap.get(nativeId);
					
					String targetVulnFortifyId = getFortifyParameter(targetVuln);
					String vulnFortifyId = getFortifyParameter(vuln);
					
					boolean targetVulnEmptyFortify = targetVulnFortifyId == null;
					boolean vulnEmptyFortify = vulnFortifyId == null;
					
					if (targetVulnEmptyFortify && vulnEmptyFortify) {
						correctNoMatch += 1;
					} else if (!targetVulnEmptyFortify && !vulnEmptyFortify &&
							vulnFortifyId.equals(targetVulnFortifyId)) {
						correctMatch += 1;
					} else {
						wrong += 1;
					}
				} else { 
					missing += 1;
				}
			}
		}
		
		System.out.println("Total              : " + (correctNoMatch + correctMatch + wrong + missing));
		System.out.println("Correct With Match : " + correctMatch);
		System.out.println("Correct No Match   : " + correctNoMatch);
		System.out.println("Wrong              : " + wrong);
		System.out.println("Missing            : " + missing);
		
		if (missing > 0) {
			System.out.println("We have more than 0 missing. " +
					"This means we need a better method of building the hash.");
		}
	}
	
	public String getFortifyParameter(SimpleVuln vuln) {
		if (vuln == null || vuln.getFortifyNativeIds() == null || vuln.getFortifyNativeIds().isEmpty()) {
			return null;
		}
		
		if (vuln.getFortifyNativeIds().size() > 1) {
			System.out.println("More than one Fortify finding for " + vuln + 
					". This extraction might not be accurate.");
		}
		
		for (String nativeId : vuln.getFortifyNativeIds()) {
			if (nativeId != null && !nativeId.isEmpty() && !nativeId.equals("null")) {
				return nativeId;
			}
		}
		
		return null;
	}
	
	public Integer setupApplication(String applicationName, ThreadFixRestClient goodClient) {
		Integer teamId = getId(getJSONObject(goodClient.createTeam(getRandomString(23))));
		Integer appId  = getId(getJSONObject(goodClient.createApplication(
				teamId.toString(), getRandomString(23), wavsepUrl)));

		File testFile = getFPR(applicationName);

		String response = goodClient.uploadScan(appId.toString(), testFile.getAbsolutePath());
		
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		testFile = getAppscanXML(applicationName);
		
		String response2 = goodClient.uploadScan(appId.toString(), testFile.getAbsolutePath());
		
		assertTrue(response2 != null);
		assertTrue(getJSONObject(response2) != null);
		
		System.out.println("Application is at " + BASE_URL.replaceAll("/rest","") + 
				"/organizations/" + teamId + "/applications/" + appId);
		
		return appId;
	}
	
	public File getFPR(String applicationName) {
		return getResource("/SBIR/" + applicationName + ".fpr");
	}
	
	public File getAppscanXML(String applicationName) {
		return getResource("/SBIR/" + applicationName + ".xml");
	}
	
	public File getResource(String path) {
		URL url = this.getClass().getResource(path);
		return new File(url.getFile());
	}
	
	public List<SimpleVuln> getTarget(String applicationName) throws IOException {
		List<SimpleVuln> appScanMerges = new ArrayList<>();
		
		int count = 0;
		
		URL url = this.getClass().getResource("/SBIR/" + applicationName + "-merge.csv");
		
		File testFile = new File(url.getFile());
		
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
	
}
