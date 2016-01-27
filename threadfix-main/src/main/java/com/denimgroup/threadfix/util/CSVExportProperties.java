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
package com.denimgroup.threadfix.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.util.RawPropertiesHolder.getProperty;

/**
 * Created by mcollins on 4/10/15.
 */
public class CSVExportProperties {

    private static final SanitizedLogger LOG = new SanitizedLogger(CSVExportProperties.class);

    private static final String
            HEADERS_REGEX = " *, *",
            PROPERTY_NAME = "csvExportFields";

    public static final String
            UNIQUE_ID               = "Unique ID",
            CWE_ID                  = "CWE ID",
            CWE_NAME                = "CWE Name",
            PATH                    = "Path",
            PARAMETER               = "Parameter",
            SEVERITY                = "Severity",
            OPEN_DATE               = "Open Date",
            DESCRIPTION             = "Description",
            DEFECT_ID               = "Defect ID",
            APPLICATION_NAME        = "Application Name",
            TEAM_NAME               = "Team Name",
            PAYLOAD                 = "Payload",
            ATTACK_SURFACE_PATH     = "Attack Surface Path",
            ATTACK_STRING           = "Attack String",
            ATTACK_REQUEST          = "Attack Request",
            ATTACK_RESPONSE         = "AttackResponse",
            SCANNER_DETAIL          = "Scanner Detail",
            SCANNER_RECOMMENDATION  = "Scanner Recommendation";

    private static List<String> DEFAULT_HEADERS_LIST = list(
            UNIQUE_ID,
            CWE_ID,
            CWE_NAME,
            PATH,
            PARAMETER,
            SEVERITY,
            OPEN_DATE,
            DESCRIPTION,
            DEFECT_ID,
            APPLICATION_NAME,
            TEAM_NAME,
            PAYLOAD,
            ATTACK_SURFACE_PATH,
            ATTACK_STRING,
            ATTACK_REQUEST,
            ATTACK_RESPONSE,
            SCANNER_DETAIL,
            SCANNER_RECOMMENDATION
    );

    private static Set<String> VALID_HEADERS_SET = setFrom(DEFAULT_HEADERS_LIST);

    private CSVExportProperties() {}

    private static List<String> HEADERS = list();

    static {
        loadProperties();
    }

    private static void loadProperties() {
        String headers = getProperty(PROPERTY_NAME);
        if (headers == null || headers.trim().equals("")) {
            HEADERS = DEFAULT_HEADERS_LIST;

        } else {
            LOG.info("Got headers configuration from custom.properties.");

            HEADERS = list(headers.split(HEADERS_REGEX));

            List<String> toRemove = list();
            for (String header : HEADERS) {
                if (!VALID_HEADERS_SET.contains(header)) {
                    LOG.error("Removing invalid header " + header);
                    toRemove.add(header);
                }
            }

            // this avoids ConcurrentModificationException
            HEADERS.removeAll(toRemove);
        }
    }

    public static List<String> getCSVExportHeaderList() {
        return HEADERS;
    }

    public static String getCSVExportHeaderString() {
        return join(", ", HEADERS) + "\n";
    }
}
