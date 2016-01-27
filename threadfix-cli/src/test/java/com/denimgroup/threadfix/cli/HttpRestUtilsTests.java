////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.properties.PropertiesManager;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 2:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class HttpRestUtilsTests {

    @Test
    public void testSetUrl() {
        PropertiesManager utils = new PropertiesManager();
        utils.setUrl(TestPropertiesManager.URL);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(TestPropertiesManager.URL, properties.getString("url"));
        } catch (ConfigurationException e) {
            assertFalse(true);
        }
    }

    @Test
    public void testSetKey() {
        PropertiesManager utils = new PropertiesManager();
        utils.setKey(TestPropertiesManager.API_KEY);
        try {
            Configuration properties = new PropertiesConfiguration("threadfix.properties");
            assertEquals(TestPropertiesManager.API_KEY, properties.getString("key"));
        } catch (ConfigurationException e) {
            assertFalse(true);
        }
    }

}
