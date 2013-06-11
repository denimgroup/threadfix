package com.denimgroup.threadfix.service.scans;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.webservices.tests.BaseRestTest;
import com.denimgroup.threadfix.webservices.tests.ThreadFixRestClient;

public class ScanMergeTests extends BaseRestTest {
	
	private String wavsepFPRPath = "/SBIR/wavsep.fpr";
	private String wavsepAppscanPath = "/SBIR/wavsep.xml";
	
	private String wavsepUrl = "http://satgit2.denimgroup.com/sbir/wavsep.git";
	
	@Test
	public void testJSPMerge() throws IOException, JSONException {
		ThreadFixRestClient goodClient = new ThreadFixRestClient();
		goodClient.setKey(GOOD_API_KEY);
		goodClient.setUrl(BASE_URL);

		Integer teamId = getId(getJSONObject(goodClient.createTeam(getRandomString(23))));
		Integer appId  = getId(getJSONObject(goodClient.createApplication(
				teamId.toString(), getRandomString(23), wavsepUrl)));

		URL url = this.getClass().getResource(wavsepFPRPath);
		
		File testFile = new File(url.getFile());

		String response = goodClient.uploadScan(appId.toString(), testFile.getAbsolutePath());
		
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		url = this.getClass().getResource(wavsepAppscanPath);
		
		testFile = new File(url.getFile());
		
		String response2 = goodClient.uploadScan(appId.toString(), testFile.getAbsolutePath());
		
		assertTrue(response2 != null);
		assertTrue(getJSONObject(response2) != null);
		
		System.out.println("Application is at " + BASE_URL.replaceAll("/rest","") + 
				"/organizations/" + teamId + "/applications/" + appId);
	
		String jsonToLookAt = goodClient.searchForApplicationById(appId.toString());
		
		assertTrue(jsonToLookAt != null);
		
		Map<String, Set<SimpleVuln>> pathMap = new HashMap<>(), paramMap = new HashMap<>();
		
		JSONObject applicationObject = new JSONObject(jsonToLookAt);
		
		JSONArray vulns = applicationObject.getJSONArray("vulnerabilities");
		
		List<SimpleVuln> appscan = new ArrayList<>(), both = new ArrayList<>(), 
				fortify = new ArrayList<>(), neither = new ArrayList<>(),
				all = new ArrayList<>();
		
		int xss = 0, sqli = 0, other = 0;
		
		for (int i = 0; i < vulns.length(); i ++) {
			JSONObject vulnerability = vulns.getJSONObject(i);
			
			String path = null, parameter = null;
			JSONObject surfaceLocation = vulnerability.getJSONObject("surfaceLocation");
			if (surfaceLocation != null) {
				if (surfaceLocation.has("path")) {
					path = surfaceLocation.getString("path");
				}
				
				if (surfaceLocation.has("parameter")) {
					parameter = surfaceLocation.getString("parameter");
				}
			}
			
			JSONArray findings = vulnerability.getJSONArray("findings");
			
			boolean hasAppscan = false, hasFortify = false;
			
			String vulnName = vulnerability.getJSONObject("genericVulnerability").getString("name");
			
			for (int j = 0; j < findings.length(); j ++) {
				JSONObject finding = findings.getJSONObject(j);
				
				JSONObject channelVuln = finding.getJSONObject("channelVulnerability");
				if (channelVuln != null && channelVuln.has("channelType")) {
					JSONObject channelType = channelVuln.getJSONObject("channelType");
					String name = channelType.getString("name");
					
					switch (name) {
						case ChannelType.APPSCAN_DYNAMIC : hasAppscan = true; break;
						case ChannelType.FORTIFY         : hasFortify = true; break;
					}
				}
			}
			
			SimpleVuln vuln = new SimpleVuln(path, parameter, vulnName);
			all.add(vuln);
			if (path != null) {
				if (!pathMap.containsKey(path)) {
					pathMap.put(path, new HashSet<SimpleVuln>());
				}
				pathMap.get(path).add(vuln);
			}
			
			if (parameter != null) {
				if (!paramMap.containsKey(parameter)) {
					paramMap.put(parameter, new HashSet<SimpleVuln>());
				}
				paramMap.get(parameter).add(vuln);
			}
			
			if (hasAppscan && hasFortify) {
				both.add(vuln);
			} else if (hasAppscan) {
				appscan.add(vuln);
			} else if (hasFortify) {
				fortify.add(vuln);
			} else {
				neither.add(vuln);
			}
			
		}
		
		System.out.println("Vulnerability Finding Channel Breakdown");
		System.out.println("Both         : " + both.size());
		System.out.println("Appscan only : " + appscan.size());
		System.out.println("Fortify only : " + fortify.size());
		System.out.println("Neither      : " + neither.size());
		System.out.println();
		System.out.println("Appscan only vulnerability type breakdown");
		sortAndPrint(appscan);
		System.out.println();
		
		int nearMerges = 0;
		for (SimpleVuln vuln : appscan) {
			
			Set<SimpleVuln> pathResults = pathMap.get(vuln.getPath()),
				paramResults = paramMap.get(vuln.getParameter());
			
			
			if (pathResults != null && paramResults != null) {
				Set<SimpleVuln> results = new HashSet<SimpleVuln>(pathResults);
				results.retainAll(paramResults);
				results.remove(vuln);
				
				
				if (results.size() > 0) {
					// here results should have all the matching stuffs
					nearMerges++;
				}
			}
		}
		
		System.out.println(nearMerges + " vulnerabilities have path + param matches.");
	}
	
	public void sortAndPrint(List<SimpleVuln> vulns) {
		Map<String, Integer> countMap = new HashMap<>();
		
		for (SimpleVuln vuln : vulns) {
			if (!countMap.containsKey(vuln.genericVuln)) {
				countMap.put(vuln.genericVuln, 0);
			}
			
			countMap.put(vuln.genericVuln, countMap.get(vuln.genericVuln) + 1);
		}
		
		for (String key : new TreeSet<String>(countMap.keySet())) {
			System.out.println(key + " => " + countMap.get(key));
		}
	}
		
	class SimpleVuln {
		private String path, parameter, genericVuln;
		
		public SimpleVuln(String path, String parameter, String genericVuln) {
			this.path = path;
			this.parameter = parameter;
			this.genericVuln = genericVuln;
			
			if (path == null) {
				this.path = "";
			}
			if (parameter == null) {
				this.parameter = "";
			}
			if (genericVuln == null) {
				this.genericVuln = "";
			}
		}
		
		public String getPath() {
			return path;
		}

		public String getParameter() {
			return parameter;
		}

		public String getGenericVuln() {
			return genericVuln;
		}
		
		public String toString() {
			return "{ " + genericVuln + ", " + path + ", " + parameter + " }";
		}
		
		public boolean equals(Object other) {
			if (other == null || !(other instanceof SimpleVuln)) {
				return false;
			}
			
			SimpleVuln otherVuln = (SimpleVuln) other;
			
			return this.hashCode() == otherVuln.hashCode();
		}
		
		public int hashCode() {
			return (path + "-" + parameter + "-" + genericVuln).hashCode();
		}
	}
	
}
