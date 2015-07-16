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

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.jar.Attributes;
import java.io.InputStream;
import java.util.jar.Manifest;

public class TFManifestProperties implements ServletContextListener {
    private static final SanitizedLogger log = new SanitizedLogger(TFManifestProperties.class);

    public static Attributes TF_ATTRIBUTES = null;

    public static String MANIFEST_GIT_COMMIT = null;
    public static String MANIFEST_BUILD_NUMBER = null;
    public static Date MANIFEST_BUILD_DATE = Calendar.getInstance().getTime();

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        try {
            InputStream inputStream = servletContextEvent.getServletContext().getResourceAsStream("/META-INF/MANIFEST.MF");

            Manifest manifest = new Manifest(inputStream);
            TF_ATTRIBUTES = manifest.getMainAttributes();

            String version = TF_ATTRIBUTES.getValue("Implementation-Version");
            String date = TF_ATTRIBUTES.getValue("Implementation-Build-Date");
            MANIFEST_GIT_COMMIT = TF_ATTRIBUTES.getValue("Implementation-Build");

            if(date != null) {
                SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                try {
                    MANIFEST_BUILD_DATE = dt.parse(date);
                } catch (ParseException e) {
                    log.debug("Exception thrown parsing build date from MANIFEST.mf file.");
                }
            }

            // build fake git commit # for dev env
            MANIFEST_GIT_COMMIT = (MANIFEST_GIT_COMMIT != null) ? MANIFEST_GIT_COMMIT : Integer.toString(new Random().nextInt(10000000));
            log.info("Git commit was set to: " + MANIFEST_GIT_COMMIT);

            if (version != null){
                MANIFEST_BUILD_NUMBER = version + "-" + MANIFEST_GIT_COMMIT;
                log.info("Application version set to: " + MANIFEST_BUILD_NUMBER);
            }

        } catch (IOException e) {
            log.error("I/O Exception reading manifest: " + e.getMessage());
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        TF_ATTRIBUTES = null;
    }
}
