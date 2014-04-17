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
package com.denimgroup.threadfix.service.enterprise;

import java.io.IOException;
import java.io.StringReader;
import java.util.Calendar;
import java.util.Properties;

/**
 * Created by mac on 4/16/14.
 */
public class LicenseInformation {

    private final static String NUMBER_APPLICATIONS_KEY = "numberApplications",
            TARGET_DATE_KEY = "targetDate";

    public Calendar getTargetDate() {
        return targetDate;
    }

    public int getNumberApplications() {
        return numberApplications;
    }

    private final Calendar targetDate;
    private final int numberApplications;

    private LicenseInformation(int numberApplications, Calendar targetDate) {
        this.targetDate = targetDate;
        this.numberApplications = numberApplications;
    }

    public static Option<LicenseInformation> getInformation(String propertiesBlock) {
        assert propertiesBlock != null;

        Option<LicenseInformation> licenseInformation = Option.failure();

        try {
            Properties properties = new Properties();
            properties.load(new StringReader(propertiesBlock));

            String numApplicationsString = properties.getProperty(NUMBER_APPLICATIONS_KEY),
                    targetDateString = properties.getProperty(TARGET_DATE_KEY);

            if (numApplicationsString.matches("^[0-9]+$") &&
                    targetDateString.matches("^[0-9]+$")) {

                Calendar targetDate = Calendar.getInstance();
                targetDate.setTimeInMillis(Long.valueOf(targetDateString));

                licenseInformation = Option.success(new LicenseInformation(
                        Integer.valueOf(numApplicationsString),
                        targetDate));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return licenseInformation;
    }


}
