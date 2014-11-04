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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.FilterPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.NoSuchElementException;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class CWEUpdateIT extends BaseIT {

    @Test
    public void testCWEUpdate() {
        String vulnerabilityType = "Improper Authorization in Handler for Custom URL Scheme";
        String severity = "High";

        FilterPage globalFilterPage = loginPage.defaultLogin()
                .clickManageFiltersLink()
                .clickCreateNewFilter()
                .addVulnerabilityFilter(vulnerabilityType, severity);

        assertTrue("Could not find the vulnerability.", globalFilterPage.isVulnerabilityTypeFound());
        assertTrue("Success message not present.", globalFilterPage.isSuccessMessagePresent());

        try {
            globalFilterPage.deleteFilter()
                    .closeSuccessNotification()
                    .clickOrganizationHeaderLink();
        } catch (NoSuchElementException e) {
            System.out.println("There was not a global vulnerability filter set.");
        }
    }
}
