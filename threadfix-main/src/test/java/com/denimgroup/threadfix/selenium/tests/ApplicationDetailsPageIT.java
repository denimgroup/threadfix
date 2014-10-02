package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.FilterPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationDetailsPageIT extends BaseIT {

    private  DashboardPage dashboardPage;
    private  String teamName = getName();
    private  String appName = getName();

    /*
    *   This test class is designed to test top layer functionality
    *   of Application Detail Page
    */

    @Test
    public void testHeaderNavigation() {
        initialize();
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
        initialize();
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
    public void testConfigTabNavigation() {
        initialize();
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
    public void testBreadCrumbNavigation() {
        ApplicationDetailPage applicationDetailPage = initialize();
        sleep(1000);
        assertTrue("BreadCrumb Application is not present", applicationDetailPage.isBreadcrumbPresent());
        assertTrue("BreadCrumb Application is not present", applicationDetailPage.isApplicationBreadcrumbPresent());
    }

    @Test
    public void testApplicationName() {
        ApplicationDetailPage applicationDetailPage = initialize();
        assertTrue("Application Name is not present", applicationDetailPage.isApplicationNamePresent());
    }

    @Test
    public void testActionButton() {
        ApplicationDetailPage applicationDetailPage = initialize();
        assertTrue("Action Button is not present", applicationDetailPage.isActionButtonPresent());
        assertTrue("Action Button is not Clickable", applicationDetailPage.isActionButtonClickable());
    }

    @Test
    public void testActionButtonContents() {
        ApplicationDetailPage applicationDetailPage =  initialize();
        sleep(3000);
        applicationDetailPage.clickActionButton();
        sleep(1000);
        assertTrue("Edit Delete button is not present", applicationDetailPage.isEditDeletePresent());
        assertTrue("Edit De;ete button is not clickable", applicationDetailPage.isEditDeleteClickable());
        assertTrue("Edit Vuln button is not present", applicationDetailPage.isEditVulnFiltersPresent());
        assertTrue("Edit Vuln buton is not clickable", applicationDetailPage.isEditVulnFiltersClickable());
        assertTrue("Scan Upload button is not present", applicationDetailPage.isUploadScanPresent());
        assertTrue("Scan Upload button is not clickable", applicationDetailPage.isUploadScanClickable());
        assertTrue("Add Manual finding button is not present", applicationDetailPage.isAddManualFindingsPresent());
        assertTrue("Add Manual finding button is not clickable", applicationDetailPage.isAddManualFindingsClickable());
    }

    @Test
    public void testActionButtonEditDeleteButton() {
        ApplicationDetailPage applicationDetailPage = initialize();
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
    public void testActionButtonEditVulnFilter() {
        ApplicationDetailPage applicationDetailPage = initialize();
        sleep(3000);
        applicationDetailPage.clickActionButton();
        sleep(2000);
        FilterPage filterPage = applicationDetailPage.clickEditVulnerabilityFilters();
        sleep(1000);
        assertTrue("Did not navigate to FilterPage.", filterPage.isElementVisible("createNewKeyModalButton"));
    }

    @Test
    public void testActionButtonAddManualFinding() {
        ApplicationDetailPage applicationDetailPage = initialize();
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
    public void testApplicationTypeDefect() {
        ApplicationDetailPage applicationDetailPage = initialize();
        applicationDetailPage.clickEditDeleteBtn();
        assertTrue("Application Type is not set to Detect.", applicationDetailPage.isAppTypeDetect());
    }

    public ApplicationDetailPage initialize() {
        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        dashboardPage = loginPage.login("user", "password");

        dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        return new ApplicationDetailPage(driver);
    }
}