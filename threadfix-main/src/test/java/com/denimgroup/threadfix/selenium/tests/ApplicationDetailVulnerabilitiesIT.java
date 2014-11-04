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
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.VulnerabilityDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static junit.framework.Assert.assertFalse;
import static junit.framework.TestCase.assertTrue;

@Category(CommunityTests.class)
public class ApplicationDetailVulnerabilitiesIT extends BaseDataTest{
    private ApplicationDetailPage applicationDetailPage;

    @Before
    public void initialize() {
        initializeTeamAndAppWithIBMScan();

        applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
    }

    @Test
    public void markSingleVulnerabilityClosedTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should only be 9 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "9"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "44"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "44"));
    }

    @Test
    public void reopenSingleVulnerabilityTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("There should only be 1 critical vulnerability shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickOpenVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should be no closed vulnerabilities.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.toggleStatusFilter("Closed")
                .toggleStatusFilter("Open");

        assertTrue("There should be 10 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "45"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "45"));
    }

    @Test
    public void markMultipleVulnerabilitiesClosedTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should only be 5 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "40"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "40"));

    }

    @Test
    public void reopenMultipleVulnerabilitiesTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("There should only be 5 critical vulnerability shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickOpenVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should not be any closed vulnerabilities.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.toggleSeverityFilter("Closed")
                .toggleStatusFilter("Open");

        assertTrue("There should be 10 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "45"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "45"));
    }

    @Test
    public void markSingleVulnerabilityFalsePositiveTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        assertTrue("There should only be 9 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "9"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "44"));
        assertTrue("The total number is not showing correctly", teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "44"));
    }

    @Test
    public void unMarkSingleVulnerabilityFalsePositiveTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("FalsePositive");

        assertTrue("There should only be 1 critical vulnerability shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickUnMarkFalsePositive()
                .sleepForResults();

        assertTrue("There should be no vulnerabilities marked false positive.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.toggleStatusFilter("FalsePositive")
                .toggleStatusFilter("Open");

        assertTrue("There should only be 10 vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "45"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "45"));
    }

    @Test
    public void markMultipleVulnerabilitiesFalsePositiveTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        assertTrue("There should only be 5 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "40"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "40"));
    }

    @Test
    public void unMarkMultipleVulnerabilitiesFalsePositiveTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("FalsePositive");

        assertTrue("There should only be 5 critical vulnerability shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickUnMarkFalsePositive()
                .sleepForResults();

        assertTrue("There should be no vulnerabilities marked false positive.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.toggleStatusFilter("FalsePositive")
                .toggleStatusFilter("Open");

        assertTrue("There should only be 10 vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The total number is not showing correctly", teamIndexPage.isTeamTotalNumberCorrect(teamName, "45"));
        assertTrue("The total number is not showing correctly",
                teamIndexPage.isApplicationTotalNumberCorrect(teamName,appName, "45"));
    }

    @Test
    public void viewMoreLinkTest() {
        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(getName())
                .clickModalSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickViewMoreVulnerabilityLink("Critical790");

        assertTrue("Vulnerability Detail Page navigation failed after click view more link of vulnerability.",
                vulnerabilityDetailPage.isToggleMoreInfoLinkPresent());
    }

    @Test
    public void addCommentToVulnerabilityTest() {
        String comment = getName();

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(comment)
                .clickModalSubmit();

        assertTrue("There should be 1 comment associated with this vulnerability.",
                applicationDetailPage.isCommentCountCorrect("Critical790", "1"));

        assertTrue("The comment was not preserved correctly.",
                applicationDetailPage.isCommentCorrect("0", comment));
    }

    //TODO fix bad navigation
    @Test
    public void vulnerabilityPaginationTestingAvailable() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        applicationDetailPage.refreshPage();

        applicationDetailPage.expandVulnerabilityByType("Low209");

        assertTrue("Pagination available", applicationDetailPage.isPaginationPresent("Low209"));
    }

    @Test
    public void vulnerabilityPaginationTestingUnavailable() {
        applicationDetailPage.expandVulnerabilityByType("Critical79");

        assertFalse("Pagination available", applicationDetailPage.isPaginationPresent("Critical79"));

    }
}
