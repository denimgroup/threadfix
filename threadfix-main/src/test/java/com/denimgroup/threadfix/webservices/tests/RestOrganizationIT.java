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

package com.denimgroup.threadfix.webservices.tests;

import com.denimgroup.threadfix.WebServiceTests;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.webapp.controller.rest.TFRestController;
import com.denimgroup.threadfix.webapp.controller.rest.TeamRestController;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

/**
 * Tests the OrganizationRestController methods.
 * Still in progress / could use more tests.
 * @author mcollins
 *
 */
@Category(WebServiceTests.class)
public class RestOrganizationIT extends BaseRestIT {
	
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
		assertTrue(httpGet(teamsUrl).equals(TFRestController.API_KEY_NOT_FOUND_ERROR));
	}
	
	@Test
	public void creationTests() {
		String creationUrl = BASE_URL + "/teams/new";
		
		// Bad Key
		String error = httpPost(creationUrl, new String[] {"apiKey", "name"}, 
							new String[] {BAD_API_KEY, "Normal Team Name"});
		assertTrue(error.equals(TFRestController.API_KEY_NOT_FOUND_ERROR));
		
		String response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, getRandomString(2000)});
		assertTrue(response.equals(TeamRestController.CREATION_FAILED));
		
		response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, ""});
		assertTrue(response.equals(TeamRestController.CREATION_FAILED));
		
		response = httpPost(creationUrl, new String[] {"apiKey", "name"}, new String[] {GOOD_API_KEY, "   			"});
		assertTrue(response.equals(TeamRestController.CREATION_FAILED));
		
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
		assertTrue(error.equals(TFRestController.API_KEY_NOT_FOUND_ERROR));
		
		if (httpGet(lookupUrl).equals(TeamRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "/teams/new", 
					new String[] {"apiKey", "name"}, 
					new String[] {GOOD_API_KEY, "Normal Team Name"});
		}
		
		String orgString = httpGet(lookupUrl);
		
		assertTrue(orgString != null);
		if (orgString.equals(TeamRestController.LOOKUP_FAILED)) {
			assertTrue(false);
		}
		
		assertTrue(getJSONObject(orgString) != null);
		// TODO more testing on the returned JSON object
		
		// Bad ID
		String badLookupUrl = baseLookupUrl + "100000000" + apiKeySegment + GOOD_API_KEY;
		assertTrue(httpGet(badLookupUrl).equals(TeamRestController.LOOKUP_FAILED));
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
		
//		String teamName = getRandomString(23);
//		Integer teamId = getId(getJSONObject(goodClient.createTeam(teamName)));
//
//		String result = restrictedClient.createTeam(getRandomString(15));
//		assertTrue(RESTRICTED_URL_NOT_RETURNED,
//				result.equals(RestController.RESTRICTED_URL_ERROR));
//
//		result = restrictedClient.searchForTeamById(teamId.toString());
//		assertFalse(RESTRICTED_URL_RETURNED,
//				result.equals(RestController.RESTRICTED_URL_ERROR));
//
//		result = restrictedClient.searchForTeamByName(teamName);
//		assertFalse(RESTRICTED_URL_RETURNED,
//				result.equals(RestController.RESTRICTED_URL_ERROR));
//
//		result = httpGet(BASE_URL + "/teams/?apiKey=" + RESTRICTED_API_KEY);
//		assertFalse(RESTRICTED_URL_RETURNED,
//				result.equals(RestController.RESTRICTED_URL_ERROR));
		
	}
}
