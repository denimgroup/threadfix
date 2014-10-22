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
        initializeTeamAndAppWithIBMScan();

        applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
    }

    @Test
    public void expandCollapseTest() {
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
    public void clearFilterTest() {
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

        //TODO Remove refresh after issue #663 is fixed in 2.2milestone2
        applicationDetailPage.refreshPage();

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
    public void duplicateNameSavedFilterTest() {
        String filterName = getRandomString(8);

        applicationDetailPage.expandSavedFilters()
                .addSavedFilter(filterName);

        assertTrue("Success message not present.", applicationDetailPage.isSavedFilterSuccessMessageDisplayed());

        applicationDetailPage.addSavedFilterInvalid(filterName);

        assertTrue("Error message not displayed.", applicationDetailPage.isDuplicateNameErrorMessageDisplayed());
    }

    @Test
    public void savedFiltersTest() {
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

    /* Scanner and Merged */
    @Test
    public void mergedFindingsFilterTest() {
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
    public void scannerFilterTest() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";

        applicationDetailPage.refreshPage();

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
    public void vulnerabilityTypeFilterTest() {
        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation";

        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType);

        sleep(2000);

        assertTrue("Only 5 critical vulnerabilities should be shown.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    //TODO get rid of the extra clicks for the info shown when fix
    @Test
    public void pathFilterTest() {
        String path = "/demo/EvalInjection2.php";

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
    public void parameterFilterTest() {
        String parameter = "username";

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
    public void severityFilterTest() {
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
    public void statusFilterTest() {
        applicationDetailPage = applicationDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("No Results Found should be displayed.", applicationDetailPage.areAllVulnerabilitiesHidden());
    }

    /* Aging */
    @Test
    public void agingFilterTest() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        applicationDetailPage.refreshPage();

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
    //TODO when issue 358 has been closed this test can be added back
    @Ignore
    @Test
    public void dateFilterTest() {
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
