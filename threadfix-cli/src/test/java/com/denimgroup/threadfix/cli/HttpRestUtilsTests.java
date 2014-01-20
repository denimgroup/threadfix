package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.HttpRestUtils;
import junit.framework.Assert;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 2:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class HttpRestUtilsTests {

    private static final int APPLICATION_ID = 1;
    private static final String FILE_PATH = "C:\\Users\\stran\\Desktop\\CLIJTest\\export.xml";

    /**
     * !!!!!!! ATTENTION: Before running these test cases, please making sure:
     *      + ThreadFix server is running with API_KEY
     *      + There APPLICATION_ID in ThreadFix server, and not yet any scans are imported
     *      +  There is correct xml scan result FILE_PATH
     */

    @Test
    public void testHttpPostFile() {
        String ret = HttpRestUtils.httpPostFile(UtilTest.URL + "/applications/" + APPLICATION_ID + "/upload",
                FILE_PATH,
                new String[] { "apiKey"       },
                new String[] {  UtilTest.API_KEY });

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testHttpPost() {
        String ret = HttpRestUtils.httpPost(UtilTest.URL + "/applications/" + APPLICATION_ID + "/addUrl",
                new String[] { "apiKey",       "url" },
                new String[] {  UtilTest.API_KEY,  UtilTest.URL});

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testHttpGet() {
        String ret = HttpRestUtils.httpGet(UtilTest.URL + "/applications/" + APPLICATION_ID +
                "?apiKey=" + UtilTest.API_KEY);

        assertNotNull(UtilTest.getJSONObject(ret));
    }

    @Test
    public void testSetUrl() {
        PropertiesManager utils = PropertiesManager.getInstance();
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
        PropertiesManager utils = PropertiesManager.getInstance();
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
        PropertiesManager utils = PropertiesManager.getInstance();
        assertEquals(UtilTest.URL, utils.getUrl());
    }

    @Test
    public void testGetKey() {
        PropertiesManager utils = PropertiesManager.getInstance();
        assertEquals(UtilTest.API_KEY, utils.getKey());
    }
}
