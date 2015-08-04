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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationVulnerabilitiesFilterIT extends BaseDataTest{

    private ApplicationDetailPage applicationDetailPage;

    @Before
    public void initialNavigation() {
        initializeTeamAndAppWithIbmScan();

        applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
    }


    //===========================================================================================================
    // Filter Basics
    //===========================================================================================================

    @Test
    public void testExpandCollapseFilters() {
        int filtersExpandedSize;
        int filtersCollapsedSize;

        sleep(5500);

        filtersCollapsedSize = applicationDetailPage.getFilterDivHeight();
        applicationDetailPage = applicationDetailPage.toggleAllFilter();

        filtersExpandedSize = applicationDetailPage.getFilterDivHeight();
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        applicationDetailPage = applicationDetailPage.toggleAllFilter();
        int test = applicationDetailPage.getFilterDivHeight();
        assertTrue("Filters were not collapsed completely.", filtersCollapsedSize == test);
    }

    @Test
    public void testClearFilter() {
        String parameter = "username";

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

    //===========================================================================================================
    // Saved Filters
    //===========================================================================================================

    @Test
    public void testSavedFilterFieldValidation() {
        String tooLong = getRandomString(26);
        String goodLength = getRandomString(25);

        applicationDetailPage.expandSavedFilters()
                .addInvalidNameSavedFilter(tooLong);

        assertTrue("The name should be too long to save.", applicationDetailPage.isSaveFilterDisabled());

        applicationDetailPage.addSavedFilter(goodLength);

        assertTrue("Success message not present.", applicationDetailPage.isSavedFilterSuccessMessageDisplayed());

        applicationDetailPage.clickLoadFilters();

        assertTrue("Saved filter should be in list of saved filters.", applicationDetailPage.isSavedFilterPresent(goodLength));
    }

    @Test
    public void testDuplicateNameSavedFilter() {
        String filterName = getRandomString(8);

        applicationDetailPage.expandSavedFilters()
                .addSavedFilter(filterName);

        assertTrue("Success message not present.", applicationDetailPage.isSavedFilterSuccessMessageDisplayed());

        applicationDetailPage.clickLoadFilters()
                .clearSavedFilter()
                .clickFiltersTab()
                .addSavedFilterInvalid(filterName);

        assertTrue("Error message not displayed.", applicationDetailPage.isDuplicateNameErrorMessageDisplayed());
    }

    @Test
    public void testSavedFiltersUpdateResults() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";
        String parameter = "username";
        String newFilter = getName();

        applicationDetailPage.refreshPage();

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
                .clickLoadFilters()
                .loadSavedFilter(newFilter);

        assertTrue("Only 4 critical vulnerabilities should be shown. There was a problem loading saved filter.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown. There was a problem loading saved filter.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
    }

    //===========================================================================================================
    // Scanner and Merged Findings
    //===========================================================================================================

    @Test
    public void testMergedFindingsFilter() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        applicationDetailPage.refreshPage();

        applicationDetailPage = applicationDetailPage.expandScannerAndMerged()
                .toggleTwoPlus();

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));

        applicationDetailPage = applicationDetailPage.toggleFourPlus();

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testScannerFilter() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Security AppScan Standard";

        applicationDetailPage.refreshPage();

        applicationDetailPage = applicationDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));
    }

    //===========================================================================================================
    // Field Controls
    //===========================================================================================================

    @Test
    public void testVulnerabilityTypeFilter() {
        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation";

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType);

        sleep(2000);

        assertTrue("Only 5 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    @Test
    public void testPathFilter() {
        String path = "/demo/EvalInjection2.php";

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addPathFilter(path);

        assertTrue("Only 1 critical vulnerability should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));
        assertTrue("Only 1 info vulnerability should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "1"));
    }

    @Test
    public void testParameterFilter() {
        String parameter = "username";

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addParameterFilter(parameter);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
        assertTrue("Only 3 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "3"));
    }

    @Test
    public void testSeverityFilter() {
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

    //TODO check for open/closed/false positives and what not
    @Test
    public void testStatusFilter() {
        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());
    }

    //===========================================================================================================
    // Aging Filter
    //===========================================================================================================

    @Test
    public void testAgingFilter() {
       applicationDetailPage = applicationDetailPage.expandAging()
                .toggleLessThan()
                .toggle90Days();

        assertTrue("No vulnerabilities should be shown.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage = applicationDetailPage.toggleOneWeek();
        sleep(1000);

        assertTrue("No vulnerabilities should be shown.",
                applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage = applicationDetailPage.toggleMoreThan();
        sleep(1000);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 8 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        applicationDetailPage = applicationDetailPage.toggle90Days();
        sleep(1000);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 8 medium vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Info", "5"));
    }

    //===========================================================================================================
    // Date Range
    //===========================================================================================================

    //TODO when issue 1833 has been closed this test can be re-examined
    @Ignore
    @Test
    public void testDateFilter() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        applicationDetailPage.refreshPage();

        applicationDetailPage = applicationDetailPage.expandDateRange()
                .enterStartDate("14-June-2012");

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
