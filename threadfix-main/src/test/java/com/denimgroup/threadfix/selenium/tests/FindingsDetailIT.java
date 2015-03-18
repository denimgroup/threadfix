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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class FindingsDetailIT extends BaseDataTest{

    private FindingDetailPage findingDetailPage;

    @Before
    public void initialize() {
        initializeTeamAndAppWithIbmScan();

        findingDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab()
                .clickViewScan()
                .clickViewFinding();
    }

    @Test
    public void testVulnerabilityNavigation() {
        VulnerabilityDetailPage vulnerabilityDetailPage = findingDetailPage.clickViewVulnerability();

        assertTrue("Vulnerability Details Page is not Available",
                vulnerabilityDetailPage.isToggleMoreInfoButtonAvailable());
    }

    @Test
    public void testCheckMergeWithOtherFindingsButton() {
        MergeFindingPage mergeFindingPage = findingDetailPage.clickMergeWithOtherFindings();

        assertTrue("Vulnerability Details Page is not Available",
                mergeFindingPage.isMergeFindingPagePresent());
    }

    @Test
    public void testMergeSameVariableOrLocation() {
        MergeFindingPage mergeFindingPage = findingDetailPage.clickMergeWithOtherFindings();

        VulnerabilityDetailPage vulnerabilityDetailPage = mergeFindingPage.setVariableOrLocation()
                .clickSubmitMergeButton();

        ApplicationDetailPage applicationDetailPage = vulnerabilityDetailPage.clickApplicationLink(appName);

        assertTrue("Merge wasn't added", applicationDetailPage.isVulnerabilityCountCorrect("Critical", "9"));
    }

}
