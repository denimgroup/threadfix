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

    //TODO check when ids are given to expand/collapse button
    @Test
    public void testExpandCollapse() {
        int filtersExpandedControlSize = 0;
        int filtersCollapsedControlSize = 0;
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
        applicationDetailPage = applicationDetailPage.clickExpandAllFilters();

        filtersExpandedControlSize = applicationDetailPage.getFilterDivHeight();
        assertFalse("Filters were not expanded.", filtersCollapsedControlSize == filtersExpandedControlSize);

        applicationDetailPage = applicationDetailPage.clickCollapseAllFilters();
        assertFalse("Filters were not collapsed.",
                filtersCollapsedControlSize == applicationDetailPage.getFilterDivHeight());
    }

    /* Field Controls */
    @Test
    public void testVulnerabilityTypeFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')";

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType);

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

        // Get rid of these when fix is issued.
        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addParameterFilter(parameter);

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

    //TODO maybe change this to check for the string 'No results found.' when ids allow
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

        assertFalse("Critical vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Critical"));
        assertFalse("High vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("High"));
        assertFalse("Medium vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Medium"));
        assertFalse("Low vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Low"));
        assertFalse("Info vulnerabilities should not be shown.",
                applicationDetailPage.isSeverityLevelShown("Info"));
    }
}
