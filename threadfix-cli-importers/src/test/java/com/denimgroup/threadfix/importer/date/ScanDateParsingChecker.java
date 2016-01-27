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
package com.denimgroup.threadfix.importer.date;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.util.ScanParser;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by mac on 10/13/14.
 */
@Component
public class ScanDateParsingChecker {

    @Autowired
    ScanParser scanParser;

    SimpleDateFormat format = new SimpleDateFormat("dd-MM-yy:HH:mm:SS Z");

    public static void compare(String filePath, Long expectedDate) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(ScanDateParsingChecker.class).checkDate(filePath, expectedDate);
    }

    public void checkDate(String filePath, Long expectedDate) {

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(expectedDate));

        ScanCheckResultBean scanCheckResultBean = scanParser.testScan(ScanLocationManager.getRoot() + filePath);
        Calendar testDate = scanCheckResultBean.getTestDate();

        assert testDate != null : "Test date was null for file path " + filePath;

        assert testDate.equals(calendar) :
                "Parsing returned " + getString(testDate) +
                        " but was expecting " + getString(calendar) +
                        " for file " + filePath;

        Scan scan = scanParser.getScan(ScanLocationManager.getRoot() + filePath);
        assert scan.getImportTime().equals(calendar) :
                "Parsing returned " + getString(scan.getImportTime()) +
                        " but was expecting " + getString(calendar) +
                        " for file " + filePath;
    }

    private String getString(Calendar calendar) {
        return format.format(calendar.getTime());
    }

}
