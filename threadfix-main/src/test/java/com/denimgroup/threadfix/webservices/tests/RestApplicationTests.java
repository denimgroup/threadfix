package com.denimgroup.threadfix.webservices.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URL;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.webapp.controller.ApplicationRestController;
import com.denimgroup.threadfix.webapp.controller.OrganizationRestController;
import com.denimgroup.threadfix.webapp.controller.RestController;

/**
 * Test the methods in ApplicationRestController 
 * Could use more work / tests
 * 
 * @author mcollins
 * 
 */
public class RestApplicationTests extends BaseRestTest {

	String[] channels = { ScannerType.APPSCAN_DYNAMIC.getFullName(), 
			ScannerType.ARACHNI.getFullName(),
			ScannerType.BURPSUITE.getFullName(), 
			ScannerType.CAT_NET.getFullName(), 
			ScannerType.FINDBUGS.getFullName(),
			ScannerType.NESSUS.getFullName(), 
			ScannerType.NETSPARKER.getFullName(), 
			ScannerType.SKIPFISH.getFullName(),
			ScannerType.VERACODE.getFullName(), 
			ScannerType.W3AF.getFullName(), 
			ScannerType.WEBINSPECT.getFullName(),
			ScannerType.ZAPROXY.getFullName() };

	@Test
	public void creationTests() {
		String creationUrl = BASE_URL + "/teams/1/applications/new";
		String getTeamUrl = BASE_URL + "/teams/1?apiKey=" + GOOD_API_KEY;

		// Bad key
		assertTrue(httpPost(
				creationUrl,
				new String[] { "apiKey", "name", "url" },
				new String[] { BAD_API_KEY, getRandomString(20),
						"http://normal.url.com" }).equals(
				RestController.API_KEY_NOT_FOUND_ERROR));

		if (httpGet(getTeamUrl)
				.equals(OrganizationRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/teams/new",
					new String[] { "apiKey", "name" }, new String[] {
							GOOD_API_KEY, getRandomString(10) });
		}
		if (httpGet(getTeamUrl)
				.equals(OrganizationRestController.LOOKUP_FAILED)) {
			assertTrue(false);
		}

		// test name param
		String response = httpPost(creationUrl, new String[] { "apiKey",
				"name", "url" }, new String[] { GOOD_API_KEY,
				getRandomString(2000), "http://normal.url.com" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, "", "http://normal.url.com" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, "   	\t\t\t", "http://normal.url.com" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl, new String[] { "apiKey", "url" },
				new String[] { GOOD_API_KEY, "http://normal.url.com" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		// test url param
		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, getRandomString(20),
						"http://" + getRandomString(2000) });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, getRandomString(20), "" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, getRandomString(20), "   \t\t\t\t" });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		response = httpPost(creationUrl, new String[] { "apiKey", "name" },
				new String[] { GOOD_API_KEY, getRandomString(20) });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		// URL format
		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" },
				new String[] { GOOD_API_KEY, getRandomString(20),
						getRandomString(20) });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		// Test both missing
		response = httpPost(creationUrl, new String[] { "apiKey" },
				new String[] { GOOD_API_KEY });
		assertTrue(response.equals(ApplicationRestController.CREATION_FAILED));

		// Test valid input
		String applicationName = getRandomString(20);
		response = httpPost(creationUrl,
				new String[] { "apiKey", "name", "url" }, new String[] {
						GOOD_API_KEY, applicationName,
						"http://acceptable.url.com" });

		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		try {
			assertTrue(getJSONObject(response).get("name").equals(
					applicationName));
		} catch (JSONException e) {
			log.warn("The JSON coming back did not have a name parameter or was not parsed correctly.");
			assertTrue(false);
		}
	}

	@Test
	public void lookupTests() {
		String baseLookupUrl = BASE_URL + "/teams/1/applications/";
		String apiKeySegment = "?apiKey=";
		String lookupUrl = baseLookupUrl + "1" + apiKeySegment + GOOD_API_KEY;

		// Bad Key
		String error = httpGet(baseLookupUrl + "1" + apiKeySegment
				+ BAD_API_KEY);
		assertTrue(error.equals(RestController.API_KEY_NOT_FOUND_ERROR));

		// If we're in an empty database, we may have to create some objects
		// first
		String teamLookupUrl = BASE_URL + "/teams/1" + apiKeySegment
				+ GOOD_API_KEY;
		if (httpGet(teamLookupUrl).equals(
				OrganizationRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/teams/new",
					new String[] { "apiKey", "name" }, new String[] {
							GOOD_API_KEY, "Normal Team Name" });
		}

		if (httpGet(lookupUrl).equals(ApplicationRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/teams/1/new", new String[] { "apiKey",
					"name", "url" }, new String[] { GOOD_API_KEY,
					getRandomString(20), "http://normal.url.com" });
		}

		// Now we should have objects.
		String response = httpGet(lookupUrl);
		assertTrue(response != null);

		JSONObject resultObject = getJSONObject(response);
		assertTrue(resultObject != null);

		// TODO more testing on the object to ensure that it is in fact an
		// application.

		// Bad ID
		String badLookupUrl = baseLookupUrl + "100000000" + apiKeySegment
				+ GOOD_API_KEY;
		assertTrue(httpGet(badLookupUrl).equals(
				ApplicationRestController.LOOKUP_FAILED));
	}

	@Test
	public void addChannelTests() {
		Integer teamId = getId(getJSONObject(httpPost(BASE_URL + "/teams/new",
				new String[] { "apiKey", "name" }, new String[] { GOOD_API_KEY,
						getRandomString(21) })));
		Integer appId = getId(getJSONObject(httpPost(BASE_URL + "/teams/"
				+ teamId + "/applications/new", new String[] { "apiKey",
				"name", "url" }, new String[] { GOOD_API_KEY,
				getRandomString(22), "http://normal.url.com" })));

		String url = BASE_URL + "/teams/" + teamId + "/applications/" + appId
				+ "/addChannel";

		// bad Key
		String response = httpPost(url,
				new String[] { "apiKey", "channelName" }, new String[] {
						BAD_API_KEY, "Arachni" });
		assertTrue(response.equals(RestController.API_KEY_NOT_FOUND_ERROR));

		// bad channel name
		response = httpPost(url, new String[] { "apiKey", "channelName" },
				new String[] { GOOD_API_KEY, "THIS IS NOT A CHANNEL" });
		assertTrue(response
				.equals(ApplicationRestController.ADD_CHANNEL_FAILED));

		// empty string
		response = httpPost(url, new String[] { "apiKey", "channelName" },
				new String[] { GOOD_API_KEY, "" });
		assertTrue(response
				.equals(ApplicationRestController.ADD_CHANNEL_FAILED));

		// whitespace
		response = httpPost(url, new String[] { "apiKey", "channelName" },
				new String[] { GOOD_API_KEY, "   \t\t\t" });
		assertTrue(response
				.equals(ApplicationRestController.ADD_CHANNEL_FAILED));

		// missing param
		response = httpPost(url, new String[] { "apiKey" },
				new String[] { GOOD_API_KEY });
		assertTrue(response
				.equals(ApplicationRestController.ADD_CHANNEL_FAILED));

		// bad app ID
		String badUrl = BASE_URL + "/teams/" + teamId
				+ "/applications/1000000/addChannel";
		response = httpPost(badUrl, new String[] { "apiKey", "channelName" },
				new String[] { GOOD_API_KEY, "Arachni" });
		assertTrue(response
				.equals(ApplicationRestController.ADD_CHANNEL_FAILED));

		// add each valid channel type

		for (String channelName : channels) {
			response = httpPost(url, new String[] { "apiKey", "channelName" },
					new String[] { GOOD_API_KEY, channelName });
			assertTrue(response != null);
			assertTrue(getJSONObject(response) != null);

			String jsonChannelType;
			try {
				jsonChannelType = getJSONObject(response).getJSONObject(
						"channelType").getString("name");
				assertTrue(jsonChannelType.equals(channelName));
			} catch (JSONException e) {
				log.warn("Error trying to parse out the channel type name.");
				assertTrue(false);
			}
		}
	}

	@Test
	public void addWafTests() {
		Integer teamId = getId(getJSONObject(httpPost(BASE_URL + "/teams/new",
				new String[] { "apiKey", "name" }, new String[] { GOOD_API_KEY,
						getRandomString(21) })));
		Integer appId = getId(getJSONObject(httpPost(BASE_URL + "/teams/"
				+ teamId + "/applications/new", new String[] { "apiKey",
				"name", "url" }, new String[] { GOOD_API_KEY,
				getRandomString(22), "http://normal.url.com" })));
		Integer wafId = getId(getJSONObject(httpPost(BASE_URL + "/wafs/new",
				new String[] { "apiKey", "name", "type" }, new String[] {
						GOOD_API_KEY, getRandomString(22), "mod_security" })));
		String addWafUrl = BASE_URL + "/teams/" + teamId + "/applications/"
				+ appId + "/setWaf";
		String[] paramArray = new String[] { "apiKey", "wafId" };

		// bad key
		String response = httpPost(addWafUrl, paramArray, new String[] {
				BAD_API_KEY, String.valueOf(wafId) });
		assertTrue(response.equals(RestController.API_KEY_NOT_FOUND_ERROR));

		// waf ID testing

		// string
		response = httpPost(addWafUrl, paramArray, new String[] { GOOD_API_KEY,
				"string key" });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// empty
		response = httpPost(addWafUrl, paramArray, new String[] { GOOD_API_KEY,
				"" });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// negative number
		response = httpPost(addWafUrl, paramArray, new String[] { GOOD_API_KEY,
				"-1" });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// invalid WAF ID
		response = httpPost(addWafUrl, paramArray, new String[] { GOOD_API_KEY,
				"100000" });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// Missing
		response = httpPost(addWafUrl, new String[] { "apiKey" },
				new String[] { GOOD_API_KEY });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// invalid App ID
		String badWafUrl = BASE_URL + "/teams/" + teamId
				+ "/applications/1235632/setWaf";
		response = httpPost(badWafUrl, paramArray, new String[] { GOOD_API_KEY,
				String.valueOf(wafId) });
		assertTrue(response.equals(ApplicationRestController.SET_WAF_FAILED));

		// test valid
		response = httpPost(addWafUrl, paramArray, new String[] { GOOD_API_KEY,
				String.valueOf(wafId) });
		assertTrue(response != null);

		// TODO make the return more meaningful and test it here
	}

	/**
	 * TODO add more to this
	 * Very basic test, we just create a team, app, channel, and upload a scan to it.
	 */
	@Test
	public void uploadScanTests() {

        ThreadFixRestClient goodClient = new ThreadFixRestClientImpl();
		goodClient.setKey(GOOD_API_KEY);
		goodClient.setUrl(BASE_URL);

		Integer teamId = getId(getJSONObject(goodClient.createTeam(getRandomString(23))));
		Integer appId = getId(getJSONObject(goodClient.createApplication(
				teamId.toString(), getRandomString(23), "http://normal.url.com")));

		URL url = this.getClass().getResource(
				"/SupportingFiles/Dynamic/Arachni/php-demo.xml");
		File testFile = new File(url.getFile());

		String response = goodClient.uploadScan(appId.toString(), testFile.getAbsolutePath());
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
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
		
		Integer teamId = getId(getJSONObject(goodClient.createTeam(getRandomString(23))));
		
		String result = restrictedClient.createApplication(teamId.toString(), 
				getRandomString(15), "http://notimportant.com");
		assertTrue(RESTRICTED_URL_NOT_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		String appName = getRandomString(15);
		String appId = getId(getJSONObject(goodClient.createApplication(teamId.toString(), 
				appName, "http://notimportant.com"))).toString();
		
		String wafId = getId(getJSONObject(goodClient.createWaf(getRandomString(16), WafType.MOD_SECURITY)))
							.toString();
		
		result = restrictedClient.searchForApplicationById(appId.toString());
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = restrictedClient.searchForApplicationByName(appName, teamId.toString());
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = restrictedClient.addWaf(appId, wafId);
		assertTrue(RESTRICTED_URL_NOT_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
	}
}
