package com.denimgroup.threadfix.webservices.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.denimgroup.threadfix.webapp.controller.OrganizationRestController;
import com.denimgroup.threadfix.webapp.controller.RestController;

/**
 * Tests the OrganizationRestController methods.
 * Still in progress / could use more tests.
 * @author mcollins
 *
 */
public class RestOrganizationTests extends BaseRestTest {
	
	@Test
	public void indexTests() {
		String teamsUrl = BASE_URL + "/teams/?apiKey=" + GOOD_API_KEY;
		
		String response = httpGet(teamsUrl);
		assertTrue(response != null);
		
		JSONArray teamListing = getJSONArray(response);
		assertTrue(teamListing != null);
		
		// TODO more tests on the actual content
		
		// Bad Key
		teamsUrl = BASE_URL + "/teams/?apiKey=" + BAD_API_KEY;
		assertTrue(httpGet(teamsUrl).equals(RestController.API_KEY_NOT_FOUND_ERROR));
	}
	
	@Test
	public void creationTests() {
		String creationUrl = BASE_URL + "/teams/new";
		
		// Bad Key
		String error = httpPost(creationUrl, new String[] {"apiKey", "name"}, 
							new String[] {BAD_API_KEY, "Normal Team Name"});
		assertTrue(error.equals(RestController.API_KEY_NOT_FOUND_ERROR));
		
		String response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, getRandomString(2000)});
		assertTrue(response.equals(OrganizationRestController.CREATION_FAILED));
		
		response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, ""});
		assertTrue(response.equals(OrganizationRestController.CREATION_FAILED));
		
		response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, "   			"});
		assertTrue(response.equals(OrganizationRestController.CREATION_FAILED));
		
		// If this test is failing, make sure that this text is still present in the controller.
		String nameError = "\"name\" parameter was not present, new Team creation failed.";
		response = httpPost(creationUrl, new String[] {"apiKey"}, new String[] {GOOD_API_KEY});
		assertTrue(response.equals(nameError));
		
		String newOrgName = getRandomString(10);
		response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, newOrgName});
		assertTrue(response != null);
		JSONObject resultObject = getJSONObject(response);
		assertTrue(resultObject != null);
		try {
			assertTrue(resultObject.get("name").equals(newOrgName));
		} catch (JSONException e) {
			assertTrue(false);
		}
	}
	
	@Test
	public void lookupTests() {
		String baseLookupUrl = BASE_URL + "/teams/";
		String apiKeySegment = "?apiKey=";
		String lookupUrl = baseLookupUrl + "1" + apiKeySegment + GOOD_API_KEY;
		
		// Bad Key
		String error = httpGet(baseLookupUrl + "1" + apiKeySegment + BAD_API_KEY);
		assertTrue(error.equals(RestController.API_KEY_NOT_FOUND_ERROR));
		
		if (httpGet(lookupUrl).equals(OrganizationRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/teams/new", 
					new String[] {"apiKey", "name"}, 
					new String[] {GOOD_API_KEY, "Normal Team Name"});
		}
		
		String orgString = httpGet(lookupUrl);
		
		assertTrue(orgString != null);
		
		if (orgString.equals(OrganizationRestController.LOOKUP_FAILED)) {
			assertTrue(false);
		}
		
		assertTrue(getJSONObject(orgString) != null);
		// TODO more testing on the returned JSON object
		
		// Bad ID
		String badLookupUrl = baseLookupUrl + "100000000" + apiKeySegment + GOOD_API_KEY;
		assertTrue(httpGet(badLookupUrl).equals(OrganizationRestController.LOOKUP_FAILED));
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
		
		String teamName = getRandomString(23);
		Integer teamId = getId(getJSONObject(goodClient.createTeam(teamName)));

		String result = restrictedClient.createTeam(getRandomString(15));
		assertTrue(RESTRICTED_URL_NOT_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));

		result = restrictedClient.searchForTeamById(teamId.toString());
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = restrictedClient.searchForTeamByName(teamName);
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
		result = httpGet(BASE_URL + "/teams/?apiKey=" + RESTRICTED_API_KEY);
		assertFalse(RESTRICTED_URL_RETURNED,
				result.equals(RestController.RESTRICTED_URL_ERROR));
		
	}
}
