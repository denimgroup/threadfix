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

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Calendar;

/**
 * Created by mac on 4/16/14.
 */
public class LicenseReader {

    private static final SanitizedLogger log = new SanitizedLogger(LicenseReader.class);

    public static boolean isLicenseExpired() {

        Option<LicenseInformation> information = getLicenseInformationWithSignatureCheck();

        if (information.isValid()) {
            Calendar now = Calendar.getInstance(),
                    target = information.getValue().getTargetDate();

            if (now.before(target)) {
                log.info("ThreadFix license has expired.");
                return true;
            } else {
                log.info("ThreadFix license hasn't expired.");
                return false;
            }
        } else {
            log.info("ThreadFix license was invalid but not because it expired.");
            return false;
        }
    }

    public static Option<LicenseInformation> getLicenseInformation() {
        Option<LicenseInformation> returnValue = getLicenseInformationWithSignatureCheck();

        if (returnValue.isValid()) {
            Calendar now = Calendar.getInstance(),
                    target = returnValue.getValue().getTargetDate();

            if (now.before(target)) {
                log.info("ThreadFix license hasn't expired.");
            } else {
                log.info("ThreadFix license has expired.");

                returnValue = Option.failure();
            }
        }

        return returnValue;
    }

    public static Option<LicenseInformation> getLicenseInformationWithSignatureCheck() {
        Option<LicenseInformation> returnValue = Option.failure();
        try (InputStream stream = LicenseReader.class.getResourceAsStream("/threadfix.license")) {

            if (stream != null) {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream));

                String propertiesBlock = bufferedReader.readLine() + "\n" + bufferedReader.readLine() + "\n" + bufferedReader.readLine() + "\n";

                String signature = bufferedReader.readLine();

                if (LicenseVerifier.isValid(propertiesBlock, signature)) {
                    returnValue = LicenseInformation.getInformation(propertiesBlock);
                }

                if (returnValue.isValid()) {
                    log.info("threadfix.license signature was valid.");

                } else {
                    log.error("threadfix.license was found but has an invalid signature.");
                }
            }

        } catch (IOException e) {
            log.error("threadfix.license not found. License check failed.");
        }

        return returnValue;
    }

}
