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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ApplicationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by mac on 4/17/14.
 */
@Service
public class LicenseServiceImpl implements LicenseService {

    @Autowired
    ApplicationService applicationService;

    private static final SanitizedLogger log = new SanitizedLogger(LicenseServiceImpl.class);

    @Override
    public boolean canAddApps() {
        boolean returnValue = true;

        if (EnterpriseTest.isEnterprise()) {
            returnValue = false;

            Option<LicenseInformation> information = LicenseReader.getLicenseInformation();

            if (information.isValid()) {
                List<Application> applications = applicationService.loadAllActive();

                returnValue = applications.size() < information.getValue().getNumberApplications();

            } else {
                log.error("Shouldn't have gotten here.");
            }
        }

        return returnValue;
    }

    @Override
    public int getAppLimit() {
        int returnValue = 50;

        if (EnterpriseTest.isEnterprise()) {
            Option<LicenseInformation> information = LicenseReader.getLicenseInformation();

            if (information.isValid()) {

                returnValue = information.getValue().getNumberApplications();

            } else {
                log.error("Shouldn't have gotten here.");
            }
        }

        return returnValue;
    }

}
