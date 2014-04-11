package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;

import static org.junit.Assert.assertTrue;


public class TeamIndexPageIT extends BaseIT {

    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");
    private DashboardPage dashboardPage;
    private String teamName = getRandomString(8);
    private String appName = getRandomString(8);

    static {
        if (API_KEY == null) {
            throw new RuntimeException("Please set API_KEY in run configuration.");
        }

        if (REST_URL == null) {
            throw new RuntimeException("Please set REST_URL in run configuration.");
        }
    }

    @Test
    public void testTeamIndexHeaderNavigation() {
        setupDatabase();
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
    public void testTeamIndexTabUserNavigation() {
        setupDatabase();
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
    public void testTeamIndexConfigTabNavigation() {
        setupDatabase();
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
    public void testAddExpandCollapseButtons() {
        TeamIndexPage ti = setupDatabase();
        assertTrue("Add Team Button is notpresent", ti.isAddTeamBtnPresent());
        assertTrue("Add TeamB Button is not clickable", ti.isAddTeamBtnClickable());
        assertTrue("Expand All button is not present", ti.isExpandAllBtnPresent());
        assertTrue("Expand ALl button is not clickable", ti.isExpandAllBtnClickable());
        assertTrue("Collapse All button is not present", ti.isCollapseAllBtnPresent());
        assertTrue("Collapse All button is not clickable", ti.isCollapseAllBtnClickable());
    }

    public TeamIndexPage setupDatabase() {
        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        dashboardPage = loginPage.login("user", "password");

        dashboardPage.clickOrganizationHeaderLink();

        return new TeamIndexPage(driver);
    }
}
