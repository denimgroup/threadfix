package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class TeamIndexPageIT extends BaseDataTest {

    private DashboardPage dashboardPage;
    private String teamName = createTeam();
    private String appName = createApplication(teamName);

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
        sleep(1000);
        assertTrue("Add Team Button is not present", ti.isAddTeamBtnPresent());
        assertTrue("Add TeamB Button is not clickable", ti.isAddTeamBtnClickable());
        assertTrue("Expand All button is not present", ti.isExpandAllBtnPresent());
        assertTrue("Expand ALl button is not clickable", ti.isExpandAllBtnClickable());
        assertTrue("Collapse All button is not present", ti.isCollapseAllBtnPresent());
        assertTrue("Collapse All button is not clickable", ti.isCollapseAllBtnClickable());
    }

    public TeamIndexPage setupDatabase() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        
        dashboardPage = loginPage.defaultLogin();

        dashboardPage.clickOrganizationHeaderLink();

        return new TeamIndexPage(driver);
    }

    @Test
    public void isUploadScanButtonAvailableAfterUploading() {
        DatabaseUtils.uploadScan(teamName, appName,ScanContents.SCAN_FILE_MAP.get("Burp Suite"));

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("Upload Scan Button is not Available", teamIndexPage.isUploadScanButtonDisplay());
    }

    @Test
    public void testuploadSameScanTwice() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");


        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .uploadScanButton(teamName, appName)
                .uploadNewScan(newScan, teamName, appName);

        assertTrue("The first scan hasn't uploaded yet", teamIndexPage.isScanUploadedAlready(teamName, appName));
    }

    @Test
    public void testIsNamePreventScanUpload() {
        String teamName1 = getRandomString(6) + "2.0";

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createApplication(teamName1, appName);

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName1)
                .uploadScanButton(teamName1, appName)
                .uploadNewScan(newScan, teamName1, appName);

        assertTrue("The scan wasn't uploaded",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName1, appName, "Total", "45"));
    }

    @Test
    public void testUpdateOldScan() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .uploadScanButton(teamName, appName)
                .uploadNewScan(ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"), teamName, appName);

        int numOldVulns = Integer.parseInt(teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total"));

        teamIndexPage.uploadScanButton(teamName, appName)
                .uploadNewScan(ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"), teamName, appName);

        int numNewVulns = Integer.parseInt(teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total"));

        assertTrue("Update old scan failed", numNewVulns > numOldVulns);
    }

    @Test
    public void testReplaceNewScanWithOld() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .uploadScanButton(teamName, appName)
                .uploadNewScan(ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"), teamName, appName);

        int numOriginalVulns = Integer.parseInt(teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total"));

        teamIndexPage.uploadScanButton(teamName, appName)
                .uploadNewScan(ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"), teamName, appName);

        int numUpdatedVulns = Integer.parseInt(teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total"));

        assertTrue("Old scan replaced newer scan", numOriginalVulns == numUpdatedVulns);
    }

    @Test
    public void testTeamPieGraphNav() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        AnalyticsPage analyticsPage;
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("WebInspect"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);
        sleep(1000);

        for(int i = 0; i < 5; i++) {
            String numVulns = driver.findElement(By.id("num" + levels[i] + "Vulns" + teamName + "-" + appName))
                    .getText().trim();

            teamIndexPage.clickSVGElement(teamName + levels[i] + "Arc");

            analyticsPage = teamIndexPage.clickDetails();

            assertTrue("Navigation @ level " + levels[i] + " failed", analyticsPage.checkCorrectFilterLevel(levels[i]));
            assertTrue("Number of badge vulnerabilities at level " + levels[i] + "is incorrect",
                    analyticsPage.isVulnerabilityCountCorrect(levels[i],numVulns));

            teamIndexPage = analyticsPage.clickOrganizationHeaderLink()
                    .expandTeamRowByName(teamName);
            sleep(1000);
        }
    }

    @Test
    public void testTeamPieGraphTips() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("WebInspect"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        for(int i = 0; i < 5; i++) {
            teamIndexPage.hoverOverSVGElement(teamName + levels[i] + "Arc");
            sleep(2000);
            String numTip = driver.findElement(By.id("pointInTimeTip")).getText().split("\\s+")[1];

            assertTrue("Tip value at level " + levels[i] + " does not match badge",
                    driver.findElement(By.id("num" + levels[i] + "Vulns" + teamName + "-" + appName))
                            .getText().trim().equals(numTip));
        }
    }

    @Test
    public void testTeamPieGraphModalNum() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        AnalyticsPage analyticsPage;
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("WebInspect"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        for(int i = 0; i < 5; i++) {
            String numVulns = driver.findElement(By.id("num" + levels[i] + "Vulns" + teamName + "-" + appName))
                    .getText().trim();

            teamIndexPage.clickSVGElement(teamName + levels[i] + "Arc");

            assertTrue("Number of modal vulnerabilities does not match",
                    driver.findElement(By.id("header1")).getText().split("\\s+")[1].trim().equals(numVulns));

            analyticsPage = teamIndexPage.clickDetails();
            teamIndexPage = analyticsPage.clickOrganizationHeaderLink()
                    .expandTeamRowByName(teamName);
        }
    }
}