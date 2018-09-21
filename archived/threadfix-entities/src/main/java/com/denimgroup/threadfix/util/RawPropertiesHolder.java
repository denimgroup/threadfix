////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Created by mcollins on 4/10/15.
 */
public class RawPropertiesHolder {

    // Prevent Instantiation
    private RawPropertiesHolder(){}

    private static final SanitizedLogger LOG = new SanitizedLogger(RawPropertiesHolder.class);

    private static Properties PROPERTIES = new Properties();

    static {
        loadProperties();
    }

    private static void loadProperties() {
        InputStream resourceAsStream =
                RawPropertiesHolder.class
                        .getClassLoader()
                        .getResourceAsStream("custom.properties");

        if (resourceAsStream == null) {
            LOG.info("custom.properties not found, using default settings.");
        } else try {
            PROPERTIES.load(resourceAsStream);
        } catch (IOException e) {
            LOG.error("Got IOException loading properties from custom.properties");
        }
    }

    public static String getProperty(String key) {
        return PROPERTIES.getProperty(key);
    }
}
