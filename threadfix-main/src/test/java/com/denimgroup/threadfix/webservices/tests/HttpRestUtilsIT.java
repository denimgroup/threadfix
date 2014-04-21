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
import com.denimgroup.threadfix.properties.PropertiesManager;
import junit.framework.Assert;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static junit.framework.Assert.assertEquals;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 2:45 PM
 * To change this template use File | Settings | File Templates.
 */
@Category(WebServiceTests.class)
public class HttpRestUtilsIT {

    private static final int APPLICATION_ID = 1;
    private static final String FILE_PATH = "C:\\Users\\stran\\Desktop\\CLIJTest\\export.xml";

    /**
     * !!!!!!! ATTENTION: Before running these test cases, please making sure:
     *      + ThreadFix server is running with API_KEY
     *      + There APPLICATION_ID in ThreadFix server, and not yet any scans are imported
     *      +  There is correct xml scan result FILE_PATH
     */
//
//    @Test
//    public void testHttpPostFile() {
//        String ret = TestUtils.getRestUtils().httpPostFile(TestUtils.URL + "/applications/" + APPLICATION_ID + "/upload",
//                FILE_PATH,
//                new String[] {  },
//                new String[] {  });
//
//        assertNotNull(TestUtils.getJSONObject(ret));
//    }
//
//    @Test
//    public void testHttpPost() {
//        String ret = TestUtils.getRestUtils().httpPost(TestUtils.URL + "/applications/" + APPLICATION_ID + "/addUrl",
//                new String[] { "apiKey",       "url" },
//                new String[] {  TestUtils.API_KEY,  TestUtils.URL});
//
//        assertNotNull(TestUtils.getJSONObject(ret));
//    }
//
//    @Test
//    public void testHttpGet() {
//        String ret = TestUtils.getRestUtils().httpGet(TestUtils.URL + "/applications/" + APPLICATION_ID +
//                "?apiKey=" + TestUtils.API_KEY);
//
//        assertNotNull(TestUtils.getJSONObject(ret));
//    }

    @Test
    public void testSetUrl() {
        PropertiesManager utils = new PropertiesManager();
        utils.setUrl(TestUtils.URL);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(TestUtils.URL, properties.getString("url"));
        } catch (ConfigurationException e) {
            Assert.fail();
        }
    }

    @Test
    public void testSetKey() {
        PropertiesManager utils = new PropertiesManager();
        utils.setKey(TestUtils.API_KEY);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(TestUtils.API_KEY, properties.getString("key"));
        } catch (ConfigurationException e) {
            Assert.fail();
        }
    }

    @Test
    public void testGetUrl() {
        PropertiesManager utils = new PropertiesManager();
        assertEquals(TestUtils.URL, utils.getUrl());
    }

    @Test
    public void testGetKey() {
        PropertiesManager utils = new PropertiesManager();
        assertEquals(TestUtils.API_KEY, utils.getKey());
    }
}
