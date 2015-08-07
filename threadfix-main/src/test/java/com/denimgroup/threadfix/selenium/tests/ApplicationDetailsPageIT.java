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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationDetailsPageIT extends BaseDataTest {

    private  DashboardPage dashboardPage;
    private ApplicationDetailPage applicationDetailPage;
    /*
    *   This test class is designed to test top layer functionality
    *   of Application Detail Page
    */

    public void initialize() {
        initializeTeamAndAppWithIbmScan();

        dashboardPage = loginPage.defaultLogin();

        applicationDetailPage = dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
    }

    @Test
    public void testNavigationHeader() {
        initialize();
        dashboardPage = applicationDetailPage.clickDashboardLink();
        assertTrue("Dashboard link is not present", dashboardPage.isDashboardMenuLinkPresent() );
        assertTrue("Dashboard link is not clickable", dashboardPage.isDashboardMenuLinkClickable());
        assertTrue("Application link is not present", dashboardPage.isApplicationMenuLinkPresent());
        assertTrue("Application link is not clickable", dashboardPage.isApplicationMenuLinkClickable());
        assertTrue("Scan link is not present", dashboardPage.isScansMenuLinkPresent());
        assertTrue("Scan link is not clickable", dashboardPage.isScansMenuLinkClickable());
        assertTrue("Report link is not present", dashboardPage.isReportsMenuLinkPresent());
        assertTrue("Report link is not clickable", dashboardPage.isReportsMenuLinkClickable());
        assertTrue("User link is not present", dashboardPage.isUsersMenuLinkPresent());
        assertTrue("User link is not clickable", dashboardPage.isUsersMenuLinkClickable());
        assertTrue("Config link is not present", dashboardPage.isConfigMenuLinkPresent());
        assertTrue("Config link is not clickable", dashboardPage.isConfigMenuLinkClickable());
        assertTrue("Logo link is not present", dashboardPage.isLogoPresent());
        assertTrue("Logo link is not clickable", dashboardPage.isLogoClickable());
    }

    @Test
    public void testUserDropdownElement() {
        initialize();
        dashboardPage = applicationDetailPage.clickDashboardLink();
        sleep(3000);
        dashboardPage.clickUserTab();
        sleep(2000);
        assertTrue("User tab is not dropped down", dashboardPage.isUserDropDownPresent());
        assertTrue("User change password link is not present", dashboardPage.isChangePasswordLinkPresent());
        assertTrue("User change password link is not clickable", dashboardPage.isChangePasswordMenuLinkClickable());
        assertTrue("Logout link is not present", dashboardPage.isLogoutLinkPresent());
        assertTrue("Logout link is not clickable", dashboardPage.isLogoutMenuLinkClickable() );
    }

    @Test
    public void testCogMenuElement() {
        //TODO: Update this test with new config menu links.
        initialize();
        dashboardPage = applicationDetailPage.clickDashboardLink();
        dashboardPage.clickConfigTab();
        assertTrue("Configuration tab is not dropped down", dashboardPage.isConfigDropDownPresent());
        assertTrue("API link is not present", dashboardPage.isApiKeysLinkPresent());
        assertTrue("API link is not clickable", dashboardPage.isApiKeysMenuLinkClickable());
        assertTrue("DefectTracker is not present" ,dashboardPage.isDefectTrackerLinkPresent());
        assertTrue("DefectTracker is not clickable", dashboardPage.isDefectTrackerMenuLinkClickable());
        assertTrue("Remote Providers is not present", dashboardPage.isRemoteProvidersLinkPresent());
        assertTrue("Remote Providers is not clickable", dashboardPage.isRemoteProvidersMenuLinkClickable());
        assertTrue("Scanner plugin link is not present", dashboardPage.isScansMenuLinkPresent());
        assertTrue("Scanner plugin link is not clickable", dashboardPage.isScansMenuLinkClickable());
        assertTrue("Waf link is not present", dashboardPage.isWafsLinkPresent());
        assertTrue("Waf link is not clickable", dashboardPage.isWafsMenuLinkClickable());
        assertTrue("Manage Users is not present", dashboardPage.isManageUsersLinkPresent());
        assertTrue("Manage Users is not clickable", dashboardPage.isManageUsersMenuLinkClickable());
        assertTrue("Customize ThreadFix Vulnerability Types Link is not present", dashboardPage.isCustomizeThreadFixVulnerabilityTypesLinkPresent());
        assertTrue("Customize ThreadFix Vulnerability Types Link is not clickable", dashboardPage.isCustomizeThreadFixVulnerabilityTypesLinkClickable());
        assertTrue("View Error Log is not present", dashboardPage.isLogsLinkPresent());
        assertTrue("View Error Log is not clickable", dashboardPage.isLogsMenuLinkClickable());
    }

    @Test
    public void testBreadCrumbNavigationLinks() {
        initialize();
        sleep(1000);
        assertTrue("BreadCrumb Application is not present", applicationDetailPage.isBreadcrumbPresent());
        assertTrue("BreadCrumb Application is not present", applicationDetailPage.isApplicationBreadcrumbPresent());
    }

    @Test
    public void testApplicationName() {
        initialize();
        assertTrue("Application Name is not present", applicationDetailPage.isApplicationNamePresent());
    }

    @Test
    public void testActionButton() {
        initialize();
        assertTrue("Action Button is not present", applicationDetailPage.isActionButtonPresent());
        assertTrue("Action Button is not Clickable", applicationDetailPage.isActionButtonClickable());
    }

    @Test
    public void testActionButtonDropdownContents() {
        //TODO: Update these dropdown elements.
        initialize();
        sleep(3000);
        applicationDetailPage.clickActionButton();
        sleep(1000);
        assertTrue("Edit Delete button is not present", applicationDetailPage.isEditDeletePresent());
        assertTrue("Edit Delete button is not clickable", applicationDetailPage.isEditDeleteClickable());
        assertTrue("Edit Vuln button is not present", applicationDetailPage.isEditVulnFiltersPresent());
        assertTrue("Edit Vuln button is not clickable", applicationDetailPage.isEditVulnFiltersClickable());
        assertTrue("Scan Upload button is not present", applicationDetailPage.isUploadScanPresent());
        assertTrue("Scan Upload button is not clickable", applicationDetailPage.isUploadScanClickable());
        assertTrue("Add Manual finding button is not present", applicationDetailPage.isAddManualFindingsPresent());
        assertTrue("Add Manual finding button is not clickable", applicationDetailPage.isAddManualFindingsClickable());
    }

    @Test
    public void testActionButtonEditDeleteButton() {
        initialize();
        sleep(2000);
        applicationDetailPage.clickEditDeleteBtn();
        applicationDetailPage.clickSourceInfo();
        assertTrue("Delete Button is not present", applicationDetailPage.isDeleteButtonPresent());
        assertTrue("Delete Button is not clickable", applicationDetailPage.isDeletebuttonClickable());
        assertTrue("App Name Input is not present.", applicationDetailPage.isNameInputPresent());
        assertTrue("URL input is not Present.", applicationDetailPage.isURLInputPresent());
        assertTrue("Unique ID is not present.", applicationDetailPage.isUniqueIDPresent());
        assertTrue("Team Selection is not present.", applicationDetailPage.isTeamSelectionPresent());
        assertTrue("Critical Selection is not present.", applicationDetailPage.isCritcalityPresent());
        assertTrue("Application Type is not present.", applicationDetailPage.isAppTypePresent());
        assertTrue("Source Code URL is not present.", applicationDetailPage.isSourceURLPresent());
        assertTrue("Source Code Folder is not present.", applicationDetailPage.isSourceFolderPresent());
        assertTrue("Defect Tracker add button is not present.", applicationDetailPage.isDefectTrackerAddPresent());
        assertTrue("Defect Tracker add button is not clickable.", applicationDetailPage.isDefectTrackerAddClickable());
        assertTrue("Waf add button is not present.", applicationDetailPage.isWAFAddButtonPresent());
        assertTrue("Waf add button is not clickable.", applicationDetailPage.isWAFAddButtonClickable());
    }

    @Test
    public void testActionButtonEditVulnerabilityFilters() {
        initialize();
        sleep(3000);
        applicationDetailPage.clickActionButton();
        sleep(2000);
        TeamAppCustomizeVulnerabilityTypesPage appCustomizeVulnerabilityTypesPage = applicationDetailPage.clickEditVulnerabilityFilters();
        sleep(1000);
        assertTrue("Did not navigate to FilterPage.", appCustomizeVulnerabilityTypesPage.isElementVisible("createNewKeyModalButton"));
    }

    @Test
    public void testActionButtonAddManualFinding() {
        initialize();
        applicationDetailPage.clickActionButton()
                .clickManualFindingButton();
        assertTrue("Dynamic Radio button is not present.", applicationDetailPage.isDynamicRadioPresent());
        assertTrue("Static Radio button is not present.", applicationDetailPage.isStaticRadioPresent());
        assertTrue("CWE input is not present", applicationDetailPage.isCWEInputPresent());
        assertTrue("Source URL is not present", applicationDetailPage.isURLDynamicSearchPresent());
        assertTrue("Parameter input is not present.", applicationDetailPage.isParameterPresent());
        assertTrue("Severity is not present.", applicationDetailPage.isSeverityPresent());
        assertTrue("Description Input is not present.", applicationDetailPage.isCveDescriptionInputPresent());
        assertTrue("Submit button is not present.", applicationDetailPage.isSubmitManualFindingPresent());
        assertTrue("Submit button is not clickable.", applicationDetailPage.isSubmitManualFindingClickable());
        assertTrue("Cancel button is not present.", applicationDetailPage.isManualFindingCloseButtonPresent());
        assertTrue("Cancel button is not clickable.", applicationDetailPage.isManualFindingCloseButtonClickable());
        applicationDetailPage.clickStaticRadioButton();
        assertTrue("Line Number Input is not present.", applicationDetailPage.isLineNumberInputPresent());
        assertTrue("Source File is not present.", applicationDetailPage.isURLStaticSearchPresent());
    }

    @Test
    public void testDefaultApplicationTypeValue() {
        initialize();
        applicationDetailPage.clickEditDeleteBtn();
        assertTrue("Application Type is not set to Detect.", applicationDetailPage.isAppTypeDetect());
    }

    @Test
    public void testViewMoreNavigation() {
        initializeTeamAndAppWithAppScanEnterpriseScan();

        ApplicationDetailPage applicationDetailPage1 = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        AnalyticsPage analyticsPage1 = applicationDetailPage1.clickViewMoreVulnerabilityTrending();

        assertTrue("View More Vulnerability Trending failed", analyticsPage1.isReportCorrect());

        ApplicationDetailPage applicationDetailPage2 = analyticsPage1.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        AnalyticsPage analyticsPage2 = applicationDetailPage2.clickViewMoreTopVulnerabilities();

        assertTrue("View More Top 10 failed", analyticsPage2.isReportCorrect());
    }

    //TODO look at this test
    @Test
    public void testScansTab() {
        initializeTeamAndApp();

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .uploadScanButton(teamName, appName)
                .uploadNewScan(ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"), teamName, appName);

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickApplicationName(teamName, appName)
                .clickScansTab();
        String[] scanValues = applicationDetailPage.getFirstScanInfo();

        ScanDetailPage scanDetailPage = applicationDetailPage.clickViewScan();
        String scanHeader = scanDetailPage.getScanHeader().toLowerCase();
        boolean vulnsMatch= scanDetailPage.toggleStatistics().isTotalVulnerabilitiesCorrect(scanValues[1]);
        boolean typeMatch = scanHeader.contains(scanValues[0].toLowerCase());
        boolean bothMatch = (vulnsMatch && typeMatch);
        assertTrue("Scan does not link correctly", bothMatch);
    }

    @Test
    public void testUploadFileToApplication() {
        initializeTeamAndApp();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName);

        applicationDetailPage.clickFilesTab()
                .clickAddFileButton()
                .uploadFile(ScanContents.getScanFilePath("Snort Log"));

        assertTrue("File was not uploaded successfully.",
                applicationDetailPage.isUploadedFilePresent("snort_log"));

    }

    @Test
    public void testCreateDefectTrackerViaAppDetailPage() {
        initializeTeamAndApp();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin().clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName);

        applicationDetailPage.clickEditDeleteBtn()
            .clickAddDefectTrackerButton();

        if (applicationDetailPage.getModalTitle().contains("Add")) {
            applicationDetailPage.clickCreateNewDefectTracker();
        }

        applicationDetailPage.setDefectTrackerName(getName())
            .setUrlInput(BUGZILLA_URL)
            .setDefectTrackerType("Bugzilla")
            .clickCreateDefectTracker()
            .setUsername(BUGZILLA_USERNAME)
            .setPassword(BUGZILLA_PASSWORD)
            .clickGetProductNames()
            .clickUpdateApplicationButton();

        assertTrue("Defect Tracker not added correctly", applicationDetailPage.isDefectTrackerAttached());
    }

    @Test
    public void testTop10VulnerabilitiesGraphIsPresent() {
        initialize();

        applicationDetailPage.waitForCWEBar(teamName, appName, "CWE20");

        assertTrue("Bar for vulnerability CWE-20 is missing", applicationDetailPage.isCWEBarPresent(teamName, appName, "CWE20"));
    }

    @Test
    public void testTop10VulnerabilitiesGraphUpdates() {
        initialize();

        applicationDetailPage.clickActionButton()
                .clickUploadScan()
                .uploadScan(ScanContents.getScanFilePath("Acunetix WVS"));

        applicationDetailPage.waitForCWEBar(teamName, appName, "CWE552");

        assertTrue("Bar for vulnerability CWE-20 is missing", applicationDetailPage.isCWEBarPresent(teamName, appName, "CWE20"));
        assertTrue("Bar for vulnerability CWE-552 is missing", applicationDetailPage.isCWEBarPresent(teamName, appName, "CWE552"));
    }

    @Test
    public void testTop10GraphNumberOfBars() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.getScanFilePath("Microsoft CAT.NET"));

        dashboardPage = loginPage.defaultLogin();

        applicationDetailPage = dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("The number of bars in the Top 10 report is not correct.", applicationDetailPage.isTop10BarCountCorrect(2));
    }

    @Test
    public void testTop10VulnerabilitiesGraphTipInfo() {
        initialize();
        String tipText = "Improper Input Validation (CWE 20): 10";
        String vulnerabilityBar = teamName + appName + "CWE20Bar";

        applicationDetailPage.hover(vulnerabilityBar);

        assertTrue("Information in tip was not correct.", applicationDetailPage.isTop10TipCorrect(tipText));
    }

    @Test
    public void testTop10VulnerabilitiesModalInfo() {
        initialize();
        String cweID = "20";
        String cweName = "Improper Input Validation";
        String severity = "Low";
        String quantity = "10";
        String vulnerabilityBar = teamName + appName + "CWE20Bar";

        applicationDetailPage.clickSVGElement(vulnerabilityBar);

        assertTrue("CWE ID was not correct.", applicationDetailPage.isVulnerabilitySummaryElementCorrect("cweId20", cweID));
        assertTrue("CWE name was not correct.", applicationDetailPage.isVulnerabilitySummaryElementCorrect("cweName20", cweName));
        assertTrue("Severity was not correct.", applicationDetailPage.isVulnerabilitySummaryElementCorrect("severity20", severity));
        assertTrue("Quantity was not correct.", applicationDetailPage.isVulnerabilitySummaryElementCorrect("quantity20", quantity));
    }

    @Test
    public void testVulnerabilitySummaryDetailFilter() {
        initialize();
        String vulnerabilityBar = teamName + appName + "CWE20Bar";

        applicationDetailPage.clickSVGElement(vulnerabilityBar)
                .clickModalSubmit();

        assertTrue("Only 10 low vulnerabilities should be shown.", applicationDetailPage.isVulnerabilityCountCorrect("Low", "10"));
    }

    @Test
    public void testTop10VulnerabilitiesGraphRespondsToScanDelete() {
        initialize();
        String vulnerabilityBar = teamName + appName + "CWE20Bar";

        applicationDetailPage.waitForElement(driver.findElement(By.id(vulnerabilityBar)));
        applicationDetailPage.clickScansTab().clickDeleteScanButton();

        assertTrue("Element bar not refreshed", driver.findElements(By.id(vulnerabilityBar)).isEmpty());
    }
}