package com.denimgroup.threadfix.webservices.tests;

import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.junit.Test;

import com.denimgroup.threadfix.webapp.controller.RestController;
import com.denimgroup.threadfix.webapp.controller.WafRestController;

public class RestWafTests extends BaseRestTest {
	
//	public static void main(String[] args) {
//		httpPost("https://qualysapi.qualys.com/api/2.0/fo/report")
//	}

	@Test
	public void indexTest() {
		String indexUrl = BASE_URL + "wafs?apiKey=" + GOOD_API_KEY;

		String response = httpGet(indexUrl);
		assertTrue(response != null);

		JSONArray wafListing = getJSONArray(response);
		assertTrue(wafListing != null);

		// TODO more tests on the actual content
//		
//		Request:
//			curl -u "USERNAME:PASSWORD"
//			"https://qualysapi.qualys.com/qps/rest/3.0/download/was/wasscan/

		// Bad Key
		indexUrl = BASE_URL + "/teams/?apiKey=" + BAD_API_KEY;
		assertTrue(httpGet(indexUrl).equals(RestController.API_KEY_ERROR));
	}

	/**
	 * Needs more testing
	 */
	@Test
	public void detailTest() {
		String wafDetailUrl = BASE_URL + "wafs/1?apiKey=" + GOOD_API_KEY;

		if (httpGet(wafDetailUrl).equals(WafRestController.LOOKUP_FAILED)) {
			httpPost(BASE_URL + "wafs/new", 
					new String[] { "apiKey", "name", "type" },
					new String[] { GOOD_API_KEY, getRandomString(20), "mod_security" });
		}
		
		String response = httpGet(wafDetailUrl);
		
		assertTrue(!response.equals(WafRestController.LOOKUP_FAILED));
		assertTrue(getJSONObject(response) != null);
		
		// TODO ensure the structure once that's locked down.
		
		// Bad Key
		wafDetailUrl = BASE_URL + "/teams/?apiKey=" + BAD_API_KEY;
		assertTrue(httpGet(wafDetailUrl).equals(RestController.API_KEY_ERROR));
	}
	
	@Test
	public void creationTest() {
		
		// valid test
		String response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(20), "mod_security" });
		assertTrue(response != null);
		assertTrue(getJSONObject(response) != null);
		
		// TODO more testing on the validity of the JSON object
		
		// parameter testing
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// long name
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(2000), "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));

		// empty string name
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));

		//whitespace name
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, "   \t\t\t", "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		//empty type
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(19), "" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// wrong type
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name", "type" },
				new String[] { GOOD_API_KEY, getRandomString(19), "this isn't correct" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing name
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "type" },
				new String[] { GOOD_API_KEY, "mod_security" });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing type
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey", "name" },
				new String[] { GOOD_API_KEY, getRandomString(20) });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
		
		// missing both
		response = httpPost(BASE_URL + "wafs/new", 
				new String[] { "apiKey" },
				new String[] { GOOD_API_KEY });
		assertTrue(response.equals(WafRestController.CREATION_FAILED));
	}
	
	@Test
	public void uploadLogTests() {
		// stub
	}
	
	@Test
	public void getRulesTests() {
		// stub
	}

}
