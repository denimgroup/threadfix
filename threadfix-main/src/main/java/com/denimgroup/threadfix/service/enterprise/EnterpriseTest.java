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

package com.denimgroup.threadfix.service.enterprise;

import com.denimgroup.threadfix.service.LdapService;
import com.denimgroup.threadfix.service.LicenseService;
import com.denimgroup.threadfix.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

public class EnterpriseTest extends SpringBeanAutowiringSupport {

    public static final String ENTERPRISE_FEATURE_ERROR =
            "This feature is not enabled in the community edition of ThreadFix.";

    @Autowired(required = false)
    LdapService ldapService;

    @Autowired(required = false)
    PermissionService permissionService;

    @Autowired(required = false)
    LicenseService licenseService;

    public static boolean isEnterprise() {
        EnterpriseTest enterpriseTest = new EnterpriseTest();

        return enterpriseTest.ldapService != null && enterpriseTest.permissionService != null &&
                enterpriseTest.licenseService != null;
    }

    public static boolean hasValidLicense() {

        EnterpriseTest enterpriseTest = new EnterpriseTest();

        return enterpriseTest.licenseService != null && enterpriseTest.licenseService.hasValidLicense();
    }

    public static boolean isLicenseExpired() {
        EnterpriseTest enterpriseTest = new EnterpriseTest();

        return enterpriseTest.licenseService == null || enterpriseTest.licenseService.isLicenseExpired();
    }
}
