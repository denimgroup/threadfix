package com.denimgroup.threadfix.cli;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.util.Properties;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 2:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class HttpRestUtilsTests extends TestCase {

    private static final int APPLICATION_ID = 1;
    private static final String FILE_PATH = "C:\\Users\\stran\\Desktop\\CLIJTest\\export.xml";

    /**
     * !!!!!!! ATTENTION: Before running these testcases, please making sure:
     *      + ThreadFix server is running with API_KEY
     *      + There APPLICATION_ID in ThreadFix server, and not yet any scans are imported
     *      +  There is correct xml scan result FILE_PATH
     */

    @Test
    public void testHttpPostFile() {
        HttpRestUtils utils = new HttpRestUtils();

        String ret = utils.httpPostFile(UtilTest.URL + "/applications/" + APPLICATION_ID + "/upload",
                FILE_PATH,
                new String[] { "apiKey"       },
                new String[] {  UtilTest.API_KEY });

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testHttpPost() {
        HttpRestUtils utils = new HttpRestUtils();
        String ret = utils.httpPost(UtilTest.URL + "/applications/" + APPLICATION_ID + "/addUrl",
                new String[] { "apiKey",       "url" },
                new String[] {  UtilTest.API_KEY,  UtilTest.URL});

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testHttpGet() {
        HttpRestUtils utils = new HttpRestUtils();
        String ret = utils.httpGet(UtilTest.URL + "/applications/" + APPLICATION_ID +
                "?apiKey=" + UtilTest.API_KEY);

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testGetJSONObject() {
        HttpRestUtils utils = new HttpRestUtils();
        String responseContents = "{\"id\": \"1\", \"label\": \"One\"}";
        assertNotNull(utils.getJSONObject(responseContents));
    }

    @Test
    public void testGetId() {
        HttpRestUtils utils = new HttpRestUtils();
        JSONObject obj = new JSONObject();
        try {
            obj.put("id", 1);
            obj.put("label", "One");
            int id = utils.getId(obj);
            assertEquals(1, id);
        } catch (JSONException e) {
            Assert.fail();
        }
    }

    @Test
    public void testGetString() {
        HttpRestUtils utils = new HttpRestUtils();
        JSONObject obj = new JSONObject();
        try {
            obj.put("id", 1);
            obj.put("label", "One");
            String label = utils.getString(obj, "label");
            assertEquals("One", label);
        } catch (JSONException e) {
            Assert.fail();
        }
    }

    @Test
    public void testGetJSONArray() {
        HttpRestUtils utils = new HttpRestUtils();
        String responseContents = "[\"msg 1\",\"msg 2\",\"msg 3\"]";
        assertNotNull(utils.getJSONArray(responseContents));
    }

    @Test
    public void testSetUrl() {
        HttpRestUtils utils = new HttpRestUtils();
        utils.setUrl(UtilTest.URL);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(UtilTest.URL, properties.getString("url"));
        } catch (ConfigurationException e) {
            Assert.fail();
        }
    }

    @Test
    public void testSetKey() {
        HttpRestUtils utils = new HttpRestUtils();
        utils.setKey(UtilTest.API_KEY);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(UtilTest.API_KEY, properties.getString("key"));
        } catch (ConfigurationException e) {
            Assert.fail();
        }
    }

    @Test
    public void testGetUrl() {
        HttpRestUtils utils = new HttpRestUtils();
        assertEquals(UtilTest.URL, utils.getUrl());
    }

    @Test
    public void testGetKey() {
        HttpRestUtils utils = new HttpRestUtils();
        assertEquals(UtilTest.API_KEY, utils.getKey());
    }
}
