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
package com.denimgroup.threadfix.importer.date;

import org.junit.Test;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mac on 10/13/14.
 */
public class DateParsingTests {

    // TODO extend to all test files that we have

    @Test
    public void testZapDateParsing() {

        Map<String, Long> map = map(
                "/Dynamic/ZAP/TestSiteZAP.xml", 1367942139000L,
                "/Dynamic/ZAP/zap2.2.xml", 1380556038000L,
                "/Dynamic/ZAP/zaproxy-normal.xml", 1316813501000L,
                "/Dynamic/ZAP/ZAPScanOfThreadFix_2_1.xml", 1367962195000L);

        for (Map.Entry<String, Long> entry : map.entrySet()) {
            ScanDateParsingChecker.compare(entry.getKey(), entry.getValue());
        }
    }

}
