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
import com.denimgroup.threadfix.selenium.pages.VulnerabilityDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static junit.framework.Assert.assertFalse;
import static junit.framework.TestCase.assertTrue;

@Category(CommunityTests.class)
public class ApplicationDetailVulnerabilitiesIT extends BaseIT{
    private String teamName;
    private String appName;

    @Before
    public void initialize() {
        teamName = getRandomString(8);
        appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
    }

    @Test
    public void markSingleVulnerabilityClosedTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should only be 9 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "9"));
    }

    @Test
    public void reopenSingleVulnerabilityTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

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
    }

    @Test
    public void markMultipleVulnerabilitiesClosedTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .sleepForResults();

        assertTrue("There should only be 5 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    @Test
    public void reopenMultipleVulnerabilitiesTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

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
    }

    @Test
    public void markSingleVulnerabilityFalsePositiveTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        assertTrue("There should only be 9 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "9"));
    }

    @Test
    public void unMarkSingleVulnerabilityFalsePositiveTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

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
    }

    @Test
    public void markMultipleVulnerabilitiesFalsePositiveTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilitiesByCategory("Critical79")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability()
                .sleepForResults();

        assertTrue("There should only be 5 critical vulnerabilities shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    @Test
    public void unMarkMultipleVulnerabilitiesFalsePositiveTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

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
    }

    @Test
    public void viewMoreLinkTest() {
        String comment = "This is a test.";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(comment)
                .clickModalSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickViewMoreVulnerabilityLink("Critical790");

        assertTrue("Vulnerability Detail Page navigation failed after click view more link of vulnerability.",
                vulnerabilityDetailPage.isToggleMoreInfoLinkPresent());
    }

    @Test
    public void addCommentToVulnerabilityTest() {
        String comment = "This is a test.";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

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

    @Test
    public void vulnerabilityPaginationTestingAvailable() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Low209");

        assertTrue("Pagination available", applicationDetailPage.isPaginationPresent("Low209"));
    }

    @Test
    public void vulnerabilityPaginationTestingunavailable() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79");

        assertFalse("Pagination available", applicationDetailPage.isPaginationPresent("Critical79"));

    }
}
