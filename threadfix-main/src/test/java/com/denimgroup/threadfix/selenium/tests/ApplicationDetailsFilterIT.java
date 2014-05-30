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
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationDetailsFilterIT extends BaseIT{
    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");

    static {
        if (API_KEY == null) {
            throw new RuntimeException("Please set API_KEY in run configuration.");
        }

        if (REST_URL == null) {
            throw new RuntimeException("Please set REST_URL in run configuration.");
        }
    }

    @Test
    public void testExpandCollapse() {
        int filtersExpandedControlSize;
        int filtersCollapsedControlSize;
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        filtersCollapsedControlSize = applicationDetailPage.getFilterDivHeight();
        applicationDetailPage = applicationDetailPage.toggleAll();

        filtersExpandedControlSize = applicationDetailPage.getFilterDivHeight();
        assertFalse("Filters were not expanded.", filtersCollapsedControlSize == filtersExpandedControlSize);

        applicationDetailPage = applicationDetailPage.toggleAll();
        assertFalse("Filters were not collapsed.",
                filtersCollapsedControlSize == applicationDetailPage.getFilterDivHeight());
    }

    @Test
    public void testClearFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String parameter = "username";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addParameterFilter(parameter)
                .toggleSeverityFilter("Critical")
                .toggleSeverityFilter("Medium");

        sleep(1000);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));

        applicationDetailPage = applicationDetailPage.toggleClear();

        assertTrue("Critical vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Critical"));
        assertTrue("Medium vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Medium"));
        assertTrue("Low vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Low"));
        assertTrue("Info vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Info"));
    }

    /* Saved Filters */
    @Test
    public void testSavedFilters() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";
        String parameter = "username";
        String newFilter = "Custom Filter";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner)
                .expandFieldControls()
                .addParameterFilter(parameter)
                .toggleSeverityFilter("Medium")
                .toggleSeverityFilter("Critical")
                .expandSavedFilters()
                .addSavedFilter(newFilter);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));

        applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .toggleClear()
                .expandSavedFilters()
                .loadSavedFilter(newFilter);

        assertTrue("Only 4 critical vulnerabilities should be shown. There was a problem loading saved filter.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown. There was a problem loading saved filter.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
    }

    /* Scanner and Merged */
    @Test
    public void testMergedFindingsFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandScannerAndMerged()
                .toggleTwoPlus();

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));

        applicationDetailPage = applicationDetailPage.toggleFourPlus();

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testScannerFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));
    }

    /* Field Controls */
    @Test
    public void testVulnerabilityTypeFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType);

        sleep(2000);

        assertTrue("Only 5 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    //TODO get rid of the extra clicks for the info shown when fix
    @Test
    public void testPathFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String path = "/demo/EvalInjection2.php";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        // Get rid of these when fix is issued.
        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addPathFilter(path);

        applicationDetailPage = applicationDetailPage.toggleSeverityFilter("Info")
                .toggleSeverityFilter("Info");

        assertTrue("Only 1 critical vulnerability should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));
        assertTrue("Only 1 info vulnerability should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "1"));
    }

    //TODO get rid of the extra clicks for the info shown when fix
    @Test
    public void testParameterFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String parameter = "username";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addParameterFilter(parameter);

        // Get rid of these when fix is issued.
        applicationDetailPage = applicationDetailPage.toggleSeverityFilter("Info")
                .toggleSeverityFilter("Info");

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
        assertTrue("Only 3 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "3"));
    }

    @Test
    public void testSeverityFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .toggleSeverityFilter("Critical")
                .toggleSeverityFilter("Low");

        assertTrue("Critical vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Critical"));
        assertTrue("Low vulnerabilities should be shown.",
                applicationDetailPage.isSeverityLevelShown("Low"));

        assertFalse("High vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("High"));
        assertFalse("Medium vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Medium"));
        assertFalse("Info vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Info"));
    }

    @Test
    public void testStatusFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());
    }

    /* Aging */
    @Test
    public void testAgingFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandAging()
                .toggleLessThan()
                .toggle90Days();

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        applicationDetailPage = applicationDetailPage.toggleOneWeek();
        sleep(1000);

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage = applicationDetailPage.toggleMoreThan();
        sleep(1000);

        assertTrue("Only 16 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "16"));
        assertTrue("Only 15 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "15"));
        assertTrue("Only 25 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "25"));
        assertTrue("Only 15 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "15"));

        applicationDetailPage = applicationDetailPage.toggle90Days();
        sleep(1000);

        assertTrue("Only 6 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "6"));
        assertTrue("Only 6 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("Only 4 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("Only 10 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "10"));
    }

    /* Date Range */
    //TODO Put on hold because of bugs and ids to check for 'No Results Found' better
    @Ignore
    @Test
    public void testDateFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandDateRange()
                .enterStartDate("14-June-2012")
                .expandFieldControls()
                .toggleStatusFilter("Open");

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        applicationDetailPage = applicationDetailPage.enterEndDate("15-June-2012")
                .toggleStatusFilter("Open");

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());

    }


}
