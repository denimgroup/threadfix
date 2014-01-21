package com.denimgroup.threadfix.remote.response;

import com.denimgroup.threadfix.data.entities.Application;
import org.junit.Test;

import java.util.List;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

public class ResponseParserTests {

    @Test
    public void testBasicParsing() {
        //String
    }

    @Test
    public void testAppInfoParsing() {
        String testString = "{\"object\":[{\"applicationId\":\"1\",\"organizationName\":\"test\",\"applicationName\":\"test\"},{\"applicationId\":\"2\",\"organizationName\":\"test\",\"applicationName\":\"test2\"},{\"applicationId\":\"3\",\"organizationName\":\"team2\",\"applicationName\":\"testteam2\"}],\"message\":null,\"success\":true}";

        RestResponse<Application.Info[]> response = ResponseParser.getRestResponse(testString, 200, Application.Info[].class);

        assertFalse("Response was null.", response == null);

        assertTrue("Wrong number of objects was parsed. " + response.object.length +
                " instead of 3.", response.object.length == 3);
        assertTrue("App ID was " + response.object[0].applicationId + " instead of 1",
                response.object[0].applicationId.equals("1"));
        assertTrue("Response's organizationName was " + response.object[0].organizationName +
                " instead of test.", response.object[0].organizationName.equals("test"));
        assertTrue("Response's applicationName was " + response.object[0].applicationName +
                " instead of test.", response.object[0].applicationName.equals("test"));
        assertTrue("response.success was false.", response.success);
    }

    @Test
    public void testStringObjectParsing() {
        String testString = "{\"object\":\"This is some test text.\",\"message\":null,\"success\":true}";
        String objectString = "\"This is some test text.\"";

        RestResponse<String> response = ResponseParser.getRestResponse(testString, 200, String.class);

        assertFalse("Response was null.", response == null);

        assertTrue("Response string was null.", response.object != null);

        assertTrue("Response had a bad String value.", response.object.equals(objectString));
    }

    @Test
    public void testParseAnythingAsStringParsing() {
        String testString = "{\"object\":[{\"applicationId\":\"1\",\"organizationName\":\"test\",\"applicationName\":\"test\"},{\"applicationId\":\"2\",\"organizationName\":\"test\",\"applicationName\":\"test2\"},{\"applicationId\":\"3\",\"organizationName\":\"team2\",\"applicationName\":\"testteam2\"}],\"message\":null,\"success\":true}";
        String objectString = "[{\"applicationId\":\"1\",\"organizationName\":\"test\",\"applicationName\":\"test\"},{\"applicationId\":\"2\",\"organizationName\":\"test\",\"applicationName\":\"test2\"},{\"applicationId\":\"3\",\"organizationName\":\"team2\",\"applicationName\":\"testteam2\"}]";
        RestResponse response = ResponseParser.getRestResponse(testString, 200, RestResponse.class);

        assertFalse("Response was null.", response == null);

        assertTrue("Response string was null.", response.getObjectAsJsonString() != null);

        assertTrue("Response had a bad String value.", response.getObjectAsJsonString().equals(objectString));
    }

}
