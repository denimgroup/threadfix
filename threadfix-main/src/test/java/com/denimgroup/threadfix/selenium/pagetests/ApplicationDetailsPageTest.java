package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.assertTrue;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseTest;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.*;

public class ApplicationDetailsPageTest extends BaseTest {
	
	private  DashboardPage dashboardPage;
	private  String teamName = getRandomString(8);
	private  String appName = getRandomString(8);


	static {

    }

    /*
    *   This test class is designed to test top layer functionality
    *
    *
    *
    * */



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
        //destroyTeamAppandScan();
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
        //destroyTeamAppandScan();
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
        //destroyTeamAppandScan();
    }

    @Test
    public void  testBreadCrumbNavigation() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        assertTrue("BreadCrumb Application is not present", ap.isBreadcrumbPresent());
        assertTrue("BreadCrumb Application is not present", ap.isApplicationBreadcrumbPresent(teamName));
        //destroyTeamAppandScan();
    }

    @Test
    public void testApplicationName() {
        ApplicationDetailPage ap =  buildTeamAppandScan();
        assertTrue("Application Name is not present", ap.isApplicationNamePresent());
        //destroyTeamAppandScan();
    }

    @Test
    public void testActionButton() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        assertTrue("Action Button is not present", ap.isActionButtonPresent());
        assertTrue("Action Button is not Clickable", ap.isActionButtonClickable());
        //destroyTeamAppandScan();
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
        //destroyTeamAppandScan();
    }

    @Test
    public void testActionButtonEditDeleteButton() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        ap.clickEditDeleteBtn();
        assertTrue("Delete Button is not present", ap.isDeleteButtonPresent());
        assertTrue("Delete Button is not clickable", ap.isDeletebuttonClickable());
        //destroyTeamAppandScan();
    }

    //@Test
    public void testActionButtonEditVulnFilter() {
        ApplicationDetailPage ap = buildTeamAppandScan();
        //assertTrue("Edit Vulnerabilty Filters page does not show", );
        //destroyTeamAppandScan();
    }

    //@Test
    public void testActionButtonUploadScan() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
    }

    //@Test
    public void testActionButtonAddManualFinding() {
        buildTeamAppandScan();
        //assert goes here
        //destroyTeamAppandScan();
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
                .expandTeamRowByIndex(teamName)
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
