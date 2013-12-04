package com.denimgroup.threadfix.webservices.tests;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import org.junit.Test;

import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.webapp.controller.AddFindingRestController;

public class RestManualFindingTests extends BaseRestTest {

	/**
	 * The philosophy here is that only the vuln type and description fields are 
	 * required and the rest can be omitted. We can take another look later.
	 */
	@Test
	public void testManualFinding() {
        ThreadFixRestClient goodClient = new ThreadFixRestClientImpl();
		goodClient.setKey(GOOD_API_KEY);
		goodClient.setUrl(BASE_URL);
		
		String sqlInjection = "Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')";
		
		String teamResult = goodClient.createTeam("Manual Finding Team " + getRandomString(5));
		Integer teamId = getId(getJSONObject(teamResult));
		
		String appResult = goodClient.createApplication(teamId.toString(), getRandomString(20), "http://" );
		String appId = getId(getJSONObject(appResult)).toString();
		
		String result = null;
		
		// Base
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"1", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		
		//Finding.LONG_DESCRIPTION_LENGTH;
		//Finding.NATIVE_ID_LENGTH;
		//Finding.SOURCE_FILE_LOCATION_LENGTH;
		
		/////////////////////////////////////////////////////////////////
		// TEST COMMON FIELDS
		/////////////////////////////////////////////////////////////////
		
			// ID
		
		// Null
//		result = goodClient.addDynamicFinding(null, 
//				sqlInjection, 
//				"1", "test", "param", 
//				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
//		
//		// ID of 0
//		result = goodClient.addDynamicFinding("0", 
//				sqlInjection, 
//				"1", "test", "param", 
//				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
//		
//		// Big ID
//		result = goodClient.addDynamicFinding("2362346", 
//				sqlInjection, 
//				"1", "test", "param", 
//				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
//		
//		// Non-numeric
//		result = goodClient.addDynamicFinding("adrheranhaern", 
//				sqlInjection, 
//				"1", "test", "param", 
//				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
//		
//		// whitespace
//		result = goodClient.addDynamicFinding("%20", 
//				sqlInjection, 
//				"1", "test", "param", 
//				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		
			// vuln type TODO add ID lookup
			// TODO more testing
		
		// Null
		result = goodClient.addDynamicFinding(appId, 
				null, 
			"1", "test", "param", 
			"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		
		assert(result.equals(AddFindingRestController.INVALID_VULN_NAME));
		
		// whitespace
		result = goodClient.addDynamicFinding(appId, 
				"   \t\t\t 	    ", 
				"1", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		
		assert(result.equals(AddFindingRestController.INVALID_VULN_NAME));
		
		// Invalid
		result = goodClient.addDynamicFinding(appId, 
				"This is not a vuln type", 
				"1", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		
		assert(result.equals(AddFindingRestController.INVALID_VULN_NAME));
		
			// severity ID
		
		// Null
		result = goodClient.addDynamicFinding(appId, 
			sqlInjection, 
			null, "test", "param", 
			"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		// 0
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"0", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		// Big
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"13461", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		//non-numeric
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"awegwe", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		//whitespace
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"   ", "test", "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
			// Native ID - optional field, should be ok except for length limit
		
		// Null
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"1", null, "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		//too long
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"1", getRandomString(Finding.NATIVE_ID_LENGTH + 2), "param", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
			// SurfaceLocation param
		
		// null
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"1", "test", null, 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		// long
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, 
				"1", "test", getRandomString(SurfaceLocation.PARAMETER_LENGTH + 2), 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
		//whitespace
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"This is a test", "http://test.vuln.com/this_is_the_path", "also path");
		assert(getId(getJSONObject(result)) != null);
		
			// long description
		
		// null
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				null, "http://test.vuln.com/this_is_the_path", "also path");
		assert(result.equals(AddFindingRestController.INVALID_DESCRIPTION));
		
		// long
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				getRandomString(Finding.LONG_DESCRIPTION_LENGTH + 2), 
				"http://test.vuln.com/this_is_the_path", "also path");
		assert(result.equals(AddFindingRestController.INVALID_DESCRIPTION));
		
		// whitespace
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"   \t\t\t\t   ", 
				"http://test.vuln.com/this_is_the_path", "also path");
		assert(result.equals(AddFindingRestController.INVALID_DESCRIPTION));
		
		//////////////////////////////////////
		// Dynamic only stuff
		//////////////////////////////////////
		
			//URL
		
		// null
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", null, "also path");
		assert(getId(getJSONObject(result)) != null);
		
		// nonsense
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", getRandomString(20), "also path");
		assert(getId(getJSONObject(result)) != null);
		
		// too long host
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", 
				"http://" + getRandomString(SurfaceLocation.HOST_LENGTH+2), null);
		assert(getId(getJSONObject(result)) != null);
		
		// too long query
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", 
				"http://w.com/e?a=" + getRandomString(SurfaceLocation.QUERY_LENGTH), null);
		assert(getId(getJSONObject(result)) != null);
		
		// too long path
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", 
				"http://w.com/" + getRandomString(SurfaceLocation.PATH_LENGTH), null);
		assert(getId(getJSONObject(result)) != null);
		
		// too long path
		result = goodClient.addDynamicFinding(appId, 
				sqlInjection, "1", "test", "   \t\t\t\t   ", 
				"Test Description", 
				"http://w.com/", getRandomString(SurfaceLocation.PATH_LENGTH));
		assert(getId(getJSONObject(result)) != null);
		
		//////////////////////////////////////
		// Static only stuff
		//////////////////////////////////////
		
		// BASE
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "3", 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
			// File Location 
			// TODO come up with more to put here
		
		// Null
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", null, "3", 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
			// Line Text
			// TODO come up with more to put here
		
		// Null
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "3", 
				null, "12");
		assert(getId(getJSONObject(result)) != null);
		
			// Column #
		
		// Null
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", null, 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
		// high
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "3333333333333333333", 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
		//non-numeric
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "sdfh", 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
		// whitespace
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "    \t\t\t    ", 
				"String toPrint = request.getParameter(\"password\")", "12");
		assert(getId(getJSONObject(result)) != null);
		
			// Line #
		
		// Null
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "3", 
				"String toPrint = request.getParameter(\"password\")", null);
		assert(getId(getJSONObject(result)) != null);
		
		// high
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "3", 
				"String toPrint = request.getParameter(\"password\")", "348957290138475");
		assert(getId(getJSONObject(result)) != null);
		
		//non-numeric
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "12", 
				"String toPrint = request.getParameter(\"password\")", "wefaenber");
		assert(getId(getJSONObject(result)) != null);
		
		// whitespace
		goodClient.addStaticFinding(appId, 
				sqlInjection, "1", "test", "param", 
				"Test Description", "C:\\Documents\\file.java", "12", 
				"String toPrint = request.getParameter(\"password\")", "    \t\t\t\t    ");
		assert(getId(getJSONObject(result)) != null);
	}
}
