package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.FilterPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;

import static org.junit.Assert.assertTrue;


public class ApplicationDetailsPageIT extends BaseIT {

    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");
	private  DashboardPage dashboardPage;
	private  String teamName = getRandomString(8);
	private  String appName = getRandomString(8);


	static {

        if (API_KEY == null) {
            throw new RuntimeException("Please set API_KEY in run configuration.");
        }

        if (REST_URL == null) {
            throw new RuntimeException("Please set REST_URL in run configuration.");
        }
    }

    /*
    *   This test class is designed to test top layer functionality
    *   of Application Detail Page
    */



    @Test
    public void testHeaderNavigation() {
        buildTeamAppandScan();
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
    public void testTabUserNavigation() {
        buildTeamAppandScan();
            dashboardPage.clickUserTab();
            assertTrue("User tab is not dropped down", dashboardPage.isUserDropDownPresent());
            assertTrue("User change password link is not present", dashboardPage.isChangePasswordLinkPresent());
            assertTrue("User change password link is not clickable", dashboardPage.isChangePasswordMenuLinkClickable());
            assertTrue("Toggle help is not present", dashboardPage.isToggleHelpLinkPresent());
            assertTrue("Toggle help is not clickable", dashboardPage.isToggleHelpMenuLinkClickable());
            assertTrue("Logout link is not present", dashboardPage.isLogoutLinkPresent());
            assertTrue("Logout link is not clickable", dashboardPage.isLogoutMenuLinkClickable() );
    }

    @Test
    public void testConfigTabNavigation() {
        buildTeamAppandScan();
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
        assertTrue("Manage Filters is not present", dashboardPage.isManageFiltersMenuLinkPresent());
        assertTrue("Manage Filters is not clickable", dashboardPage.isManageFiltersMenuLinkClickable());
        assertTrue("View Error Log is not present", dashboardPage.isLogsLinkPresent());
        assertTrue("View Error Log is not clickable", dashboardPage.isLogsMenuLinkClickable());
    }

    @Test
    public void  testBreadCrumbNavigation() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        assertTrue("BreadCrumb Application is not present", ap.isBreadcrumbPresent());
        assertTrue("BreadCrumb Application is not present", ap.isApplicationBreadcrumbPresent(teamName));
    }

    @Test
    public void testApplicationName() {
        ApplicationDetailPage ap =  buildTeamAppandScan();
        assertTrue("Application Name is not present", ap.isApplicationNamePresent());
    }

    @Test
    public void testActionButton() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        assertTrue("Action Button is not present", ap.isActionButtonPresent());
        assertTrue("Action Button is not Clickable", ap.isActionButtonClickable());
    }

    @Test
    public void testActionButtonContents() {
        ApplicationDetailPage ap =  buildTeamAppandScan();
        ap.clickActionButton();
        assertTrue("Edit Delete button is not present", ap.isEditDeletePresent());
        assertTrue("Edit De;ete button is not clickable", ap.isEditDeleteClickable());
        assertTrue("Edit Vuln button is not present", ap.isEditVulnFiltersPresent());
        assertTrue("Edit Vuln buton is not clickable", ap.isEditVulnFiltersClickable());
        assertTrue("Scan Upload button is not present", ap.isUploadScanPresent());
        assertTrue("Scan Upload button is not clickable", ap.isUploadScanClickable());
        assertTrue("Add Manual finding button is not present", ap.isAddManualFindingsPresent());
        assertTrue("Add Manual finding button is not clickable", ap.isAddManualFindingsClickable());
    }

    @Test
    public void testActionButtonEditDeleteButton() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        ap.clickEditDeleteBtn();
        assertTrue("Delete Button is not present", ap.isDeleteButtonPresent());
        assertTrue("Delete Button is not clickable", ap.isDeletebuttonClickable());
        assertTrue("App Name Input is not present.", ap.isNameInputPresent());
        assertTrue("URL input is not Present.", ap.isURLInputPresent());
        assertTrue("Unique ID is not present.", ap.isUniqueIDPresent());
        assertTrue("Team Selection is not present.", ap.isTeamSelectionPresent());
        assertTrue("Critical Selection is not present.", ap.isCritcalityPresent());
        assertTrue("Application Type is not present.", ap.isAppTypePresent());
        assertTrue("Source Code URL is not present.", ap.isSourceURLPresent());
        assertTrue("Source Code Folder is not present.", ap.isSourceFolderPresent());
        assertTrue("Defect Tracker add button is not present.", ap.isDefectTrackerAddPresent());
        assertTrue("Defect Tracker add button is not clickable.", ap.isDefectTrackerAddClickable());
        assertTrue("Waf add button is not present.", ap.isWAFAddButtonPresent());
        assertTrue("Waf add button is not clickable.", ap.isWAFAddButtonClickable());
        assertTrue("Save Changes button is not present.", ap.isSaveChangesButtonPresent());
        assertTrue("Save Changes button is not clickable.", ap.isSaveChangesButtonClickable());
    }

    @Test
    public void testActionButtonEditVulnFilter() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        ap.clickActionButton();
        FilterPage filterPage = ap.clickEditVulnerabilityFilters();
        assertTrue("Did not navigate to FilterPage.", filterPage.isCreateNewFilterPresent());
    }

    @Test
    public void testActionButtonUploadScan() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        ap.clickUploadScanLink();
        assertTrue("Did not generate upload scan dialog", ap.isSubmitScanLinkPresent(appName));
    }

    @Test
    public void testActionButtonAddManualFinding() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        ap.clickActionButton()
                .clickManualFindingButton();
        sleep(2000);
        assertTrue("Dynamic Radio button is not present.", ap.isDynamicRadioPresent());
        assertTrue("Static Radio button is not present.", ap.isStaticRadioPresent());
        assertTrue("CWE input is not present", ap.isCWEInputPresent());
        assertTrue("Source URL is not present", ap.isURLDynamicSearchPresent());
        assertTrue("Parameter input is not present.", ap.isParameterPresent());
        assertTrue("Severity is not present.", ap.isSeverityPresent());
        assertTrue("Description Input is not present.", ap.isDescriptionInputPresent());
        assertTrue("Submit button is not present.", ap.isSubmitManualFindingPresent());
        assertTrue("Submit button is not clickable.", ap.isSubmitManualFindingClickable());
        assertTrue("Cancel button is not present.", ap.isManualFindingCloseButtonPresent());
        assertTrue("Cancel button is not clickable.", ap.isManualFindingCloseButtonClickable());
        ap.clickStaticRadioButton();
        assertTrue("Line Number Input is not present.", ap.isLineNumberInputPresent());
        assertTrue("Source File is not present.", ap.isURLStaticSearchPresent());
    }

    //@Test
    public void testGraphsPresent() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
    }

    //@Test
    public void testVulnerabilityTab() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
    }

    //@Test
    public void testScansTab() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
    }

    //@Test
    public void testFilesTab() {
        buildTeamAppandScan();
        //assert goes here1
        //destroyTeamAppandScan();
    }

    //@Test
    public void testFooter() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
    }

    /*

    Helper methods to build and destroy Team information
    This will not be of use once preemptive data is setup
    with MySQL

    */


    public ApplicationDetailPage buildTeamAppandScan() {
        DatabaseUtils.createTeam(teamName);

        dashboardPage = loginPage.login("user", "password");


        dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication(teamName)
                .clickViewAppLink(appName, teamName)
                .clickUploadScanLink()
                .setFileInput(appName,ScanContents.SCAN_FILE_MAP.get("Skipfish"))
                .submitScan(appName);
        return new ApplicationDetailPage(driver);
    }
/*
    public void destroyTeamAppandScan() {

        dashboardPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton();
        dashboardPage.clickOrganizationHeaderLink()
                .logout();
    }
*/

}
