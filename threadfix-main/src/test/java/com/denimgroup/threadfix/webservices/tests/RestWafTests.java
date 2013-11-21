package com.denimgroup.threadfix.webservices.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URL;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.webapp.controller.ApplicationRestController;
import com.denimgroup.threadfix.webapp.controller.RestController;
import com.denimgroup.threadfix.webapp.controller.WafRestController;

public class RestWafTests extends BaseRestTest {

	@Test
	public void indexTest() {
		String indexUrl = BASE_URL + "/wafs?apiKey=" + GOOD_API_KEY;

		String response = httpGet(indexUrl);
		assertTrue(response != null);

		JSONArray wafListing = getJSONArray(response);
		assertTrue(wafListing != null);

		// Bad Key
		indexUrl = BASE_URL + "/teams/?apiKey=" + BAD_API_KEY;
		assertTrue(httpGet(indexUrl).equals(RestController.API_KEY_NOT_FOUND_ERROR));
	}

	/**
	 * Needs more testing
	 */
	@Test
	public void detailTest() {
		String wafDetailUrl = BASE_URL + "/wafs/1?apiKey=" + GOOD_API_KEY;

		if (httpGet(wafDetailUrl).equals(WafRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/wafs/new", 
					new String[] { "apiKey", "name", "type" },
					new String[] { GOOD_API_KEY, getRandomString(20), "mod_security" });
		}
		
		String response = httpGet(wafDetailUrl);
		
		assertTrue(!response.equals(WafRestController.LOOKUP_FAILED));
		assertTrue(getJSONObject(response) != null);
		
		// TODO ensure the structure once that's locked down.
		
		// Bad Key
		wafDetailUrl = BASE_URL + "/teams/?apiKey=" + BAD_API_KEY;
		assertTrue(httpGet(wafDetailUrl).equals(RestController.API_KEY_NOT_FOUND_ERROR));
	}
	
	@Test
	public void creationTest() {
		
		// valid test
		String response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(20), "mod_security" });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		// TODO more testing on the validity of the JSON object
		
		// parameter testing
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// long name
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(2000), "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));

		// empty string name
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));

		//whitespace name
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "   \t\t\t", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		//empty type
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(19), "" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// wrong type
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(19), "this isn't correct" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing name
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "type" },
				new String[] { GOOD_API_KEY, "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing type
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name" },
				new String[] { GOOD_API_KEY, getRandomString(20) });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing both
		response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey" },
				new String[] { GOOD_API_KEY });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
	}
	
	// TODO boundary testing - this is only positive validation.
	@Test
	public void linkWafToApplicationTests() {
		
		String wafName = getRandomString(20);
		// valid test
		String response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, wafName, "mod_security" });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer wafId = getId(getJSONObject(response));
		String appCreationURL = BASE_URL + "/teams/1/applications/new";
		// Test valid input
		String applicationName = getRandomString(20);
		response = httpPost(appCreationURL,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, applicationName,
						"http://acceptable.url.com" });

		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer appId = getId(getJSONObject(response));
		
		String linkURL = BASE_URL + "/teams/1/applications/" + appId + "/setWaf";
		
		response = httpPost(linkURL,
							new String[] {"apiKey", "wafId"},
							new String[] {GOOD_API_KEY, String.valueOf(wafId)} );
		assertTrue(response != null);
		assertTrue(!response.equals(ApplicationRestController.SET_WAF_FAILED));
		assertTrue(getJSONObject(response) != null);
		
		try {
			JSONObject app = getJSONObject(response);
			log.debug(app);
			assertTrue(app.get("waf") != null);
			assertTrue(getId((JSONObject)app.get("waf")) == wafId);
		} 
		catch (JSONException e)
		{
			assertTrue(false);
		}
	}
	
	// TODO boundary testing - this is only positive validation.
	@Test
	public void uploadLogTests() {
		String wafName = getRandomString(20);
		// valid test
		String response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, wafName, "mod_security" });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer wafId = getId(getJSONObject(response));
		String appCreationURL = BASE_URL + "/teams/1/applications/new";
		// Test valid input
		String applicationName = getRandomString(20);
		response = httpPost(appCreationURL,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, applicationName,
						"http://acceptable.url.com" });

		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer appId = getId(getJSONObject(response));
		
		String linkURL = BASE_URL + "/teams/1/applications/" + appId + "/setWaf";
		
		response = httpPost(linkURL,
							new String[] {"apiKey", "wafId"},
							new String[] {GOOD_API_KEY, String.valueOf(wafId)} );
		assertTrue(response != null);
		assertTrue(!response.equals(ApplicationRestController.SET_WAF_FAILED));
		assertTrue(getJSONObject(response) != null);
		
		try {
			JSONObject app = getJSONObject(response);
			log.debug(app);
			assertTrue(app.get("waf") != null);
			assertTrue(getId((JSONObject)app.get("waf")) == wafId);
		} 
		catch (JSONException e)
		{
			assertTrue(false);
		}
		
		String addChannelURL = BASE_URL + "/teams/" + 1 + "/applications/" + appId
									+ "/addChannel";

		// add skipfish / w3af
		response = httpPost(addChannelURL,
				new String[] { "apiKey", "channelName" }, new String[] {
						GOOD_API_KEY, "w3af" });
		String w3afId = getId(getJSONObject(response)).toString();
		
		response = httpPost(addChannelURL,
				new String[] { "apiKey", "channelName" }, new String[] {
						GOOD_API_KEY, "Skipfish" });
		String skipfishId = getId(getJSONObject(response)).toString();
		
		URL url = this.getClass().getResource(
				"/SupportingFiles/Dynamic/w3af/w3af-demo-site.xml");
		File testFile = new File(url.getFile());
		String result = httpPostFile(BASE_URL + "/teams/1/applications/" + appId + "/upload", 
				testFile,
				new String[] { "apiKey",     "channelId" },
				new String[] {  GOOD_API_KEY, w3afId });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		url = this.getClass().getResource(
				"/SupportingFiles/Dynamic/Skipfish/skipfish-demo-site.zip");
		testFile = new File(url.getFile());
		result = httpPostFile(BASE_URL + "/teams/1/applications/" + appId + "/upload", 
				testFile,
				new String[] { "apiKey",     "channelId" },
				new String[] {  GOOD_API_KEY, skipfishId });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		result = httpGet(BASE_URL + "/wafs/" + wafId + "/rules" +
				"?apiKey=" + GOOD_API_KEY);
		
		assertTrue(result != null);
		
		// upload mod_security log
		url = this.getClass().getResource(
				"/SupportingFiles/Realtime/ModSecurity/mod-security-log.txt");
		testFile = new File(url.getFile());
		result = httpPostFile(BASE_URL + "/wafs/" + wafId + "/uploadLog", 
				testFile,
				new String[] { "apiKey" },
				new String[] {  GOOD_API_KEY });
		
		assertTrue(getJSONArray(result) != null);
		assertTrue(getJSONArray(result).length() != 0);
		
	}
	
	// TODO boundary testing - this is only positive validation.
	@Test
	public void getRulesTests() {
		String wafName = getRandomString(20);
		// valid test
		String response = httpPost(BASE_URL + "/wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, wafName, "mod_security" });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer wafId = getId(getJSONObject(response));
		String appCreationURL = BASE_URL + "/teams/1/applications/new";
		// Test valid input
		String applicationName = getRandomString(20);
		response = httpPost(appCreationURL,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, applicationName,
						"http://acceptable.url.com" });

		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		Integer appId = getId(getJSONObject(response));
		
		String linkURL = BASE_URL + "/teams/1/applications/" + appId + "/setWaf";
		
		response = httpPost(linkURL,
							new String[] {"apiKey", "wafId"},
							new String[] {GOOD_API_KEY, String.valueOf(wafId)} );
		assertTrue(response != null);
		assertTrue(!response.equals(ApplicationRestController.SET_WAF_FAILED));
		assertTrue(getJSONObject(response) != null);
		
		try {
			JSONObject app = getJSONObject(response);
			log.debug(app);
			assertTrue(app.get("waf") != null);
			assertTrue(getId((JSONObject)app.get("waf")) == wafId);
		} 
		catch (JSONException e)
		{
			assertTrue(false);
		}
		
		String addChannelURL = BASE_URL + "/teams/" + 1 + "/applications/" + appId
									+ "/addChannel";

		// add skipfish / w3af
		response = httpPost(addChannelURL,
				new String[] { "apiKey", "channelName" }, new String[] {
						GOOD_API_KEY, "w3af" });
		String w3afId = getId(getJSONObject(response)).toString();
		
		response = httpPost(addChannelURL,
				new String[] { "apiKey", "channelName" }, new String[] {
						GOOD_API_KEY, "Skipfish" });
		String skipfishId = getId(getJSONObject(response)).toString();
		
		URL url = this.getClass().getResource(
				"/SupportingFiles/Dynamic/w3af/w3af-demo-site.xml");
		File testFile = new File(url.getFile());
		String result = httpPostFile(BASE_URL + "/teams/1/applications/" + appId + "/upload", 
				testFile,
				new String[] { "apiKey",     "channelId" },
				new String[] {  GOOD_API_KEY, w3afId });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		url = this.getClass().getResource(
				"/SupportingFiles/Dynamic/Skipfish/skipfish-demo-site.zip");
		testFile = new File(url.getFile());
		result = httpPostFile(BASE_URL + "/teams/1/applications/" + appId + "/upload", 
				testFile,
				new String[] { "apiKey",     "channelId" },
				new String[] {  GOOD_API_KEY, skipfishId });
		
		result = httpGet(BASE_URL + "/wafs/" + wafId + "/rules" +
				"?apiKey=" + GOOD_API_KEY);
		
		assertTrue(result != null);
	}
	
	/**
	 * Test restricted URLs using ThreadFixRestClient. This test will need
	 * to be updated if the permissions change or any methods are added.
	 */
	@Test
	public void testRestrictedMethods() {
        ThreadFixRestClient goodClient = new ThreadFixRestClientImpl();
		goodClient.setKey(GOOD_API_KEY);
		goodClient.setUrl(BASE_URL);

        ThreadFixRestClient restrictedClient = new ThreadFixRestClientImpl();
		restrictedClient.setKey(RESTRICTED_API_KEY);
		restrictedClient.setUrl(BASE_URL);
		
		String response = httpGet(BASE_URL + "/wafs?apiKey=" + GOOD_API_KEY);
		assertFalse(RESTRICTED_URL_RETURNED,
				response.equals(RestController.RESTRICTED_URL_ERROR));
		
		String wafName = getRandomString(16);
		String initialResult = goodClient.createWaf(wafName, WafType.MOD_SECURITY);
		
		assertTrue("Bad response from waf creation", initialResult != null);
		
		String wafId = getId(getJSONObject(initialResult))
							.toString();
		
		String result = restrictedClient.searchForWafById(wafId);
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = restrictedClient.searchForWafByName(wafName);
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = restrictedClient.getRules(wafId);
		assertTrue(RESTRICTED_URL_NOT_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		URL url = this.getClass().getResource(
				"/SupportingFiles/Realtime/ModSecurity/mod-security-log.txt");
		File testFile = new File(url.getFile());
		result = httpPostFile(BASE_URL + "/wafs/" + wafId + "/uploadLog", 
				testFile,
				new String[] { "apiKey" },
				new String[] {  RESTRICTED_API_KEY });
		
	}

}
