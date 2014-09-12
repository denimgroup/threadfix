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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class RemoteProvidersIT extends BaseIT {
	
	private static String SENTINEL_API_KEY = System.getProperty("WHITEHAT_KEY");
	private static String VERACODE_USER = System.getProperty("VERACODE_USERNAME");
	private static String VERACODE_PASSWORD = System.getProperty("VERACODE_PASSWORD");
	private static String QUALYS_USER = System.getProperty("QUALYS_USER");
	private static String QUALYS_PASS = System.getProperty("QUALYS_PASS");

    static {
        if (SENTINEL_API_KEY == null) {
            throw new RuntimeException("Please set WHITEHAT_KEY in run configuration.");
        }

        if (VERACODE_USER == null) {
            throw new RuntimeException("Please set VERACODE_USERNAME in run configuration.");
        }

        if (VERACODE_PASSWORD == null) {
            throw new RuntimeException("Please set VERACODE_PASSWORD in run configuration.");
        }

        if (QUALYS_USER == null) {
            throw new RuntimeException("Please set QUALYS_USER in run configuration.");
        }

        if (QUALYS_PASS == null) {
            throw new RuntimeException("Please set QUALYS_PASS in run configuration.");
        }
    }

	@Test
	public void navigationTest() {
		RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
									.clickRemoteProvidersLink();
		
		assertTrue("Remote Provider Page not found", remoteProvidersIndexPage.isTabPresent());
	}

    //TODO Add back when Qualys credentials are fixed
    @Ignore
    @Test
    public void configureQualysTest() {
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .saveQualys();

        assertTrue("Qualys was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider QualysGuard WAS"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearQualys();

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void invalidQualysTest(){
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureQualys()
                .setQualysUsername("No Such User")
                .setQualysPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.waitForErrorMessage();

        assertTrue("Failure message detailing why credentials were not accepted should have been displayed.",
                remoteProvidersIndexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
    }

	@Test
	public void configureWhiteHatTest() {
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat();

		assertTrue("WhiteHat Sentinel was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider WhiteHat Sentinel"));
		
		remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();
		
		assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
	}

	@Test
	public void invalidWhiteHatTest(){
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clearPreviousWhiteHat()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI("This should't Work!")
                .clickSubmitWait();

        remoteProvidersIndexPage.sleep(1000);

		assertTrue("Incorrect credentials accepted",
                remoteProvidersIndexPage.getErrorMessage().contains("Failure. Message was : undefined"));
	}

	@Test
	public void configureVeracodeTest() {
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureVeracode()
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveVera();

        assertTrue("Veracode was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider Veracode"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
	}
	
	@Test
	public void invalidVeracodeTest(){
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureVeracode()
                .setVeraUsername("No Such User")
                .setVeraPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.sleep(15000);
        String error = remoteProvidersIndexPage.getErrorMessage();
        System.out.println(error);
		assertTrue("Incorrect credentials accepted", error.contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
	}

    //TODO Add back when Qualys credentials are fixed
    @Ignore
    @Test
    public void editQualysMapping() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .saveQualys();

        remoteProvidersIndexPage.mapQualysToTeamAndApp(0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(3, 0, teamName, appName));

        remoteProvidersIndexPage.clearQualys();

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void editVeracodeMapping() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureVeracode()
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveVera();

        remoteProvidersIndexPage.mapVeracodeToTeamAndApp(0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(2, 0, teamName, appName));

        remoteProvidersIndexPage.clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    @Test
    public void editWhiteHatMapping() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat();

        remoteProvidersIndexPage.mapWhiteHatToTeamAndApp(0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(1, 0, teamName, appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    //TODO Update when new ids are added
    @Test
    public void importWhiteHatScan() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .mapWhiteHatToTeamAndApp(1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        remoteProvidersIndexPage.clickWhiteHatImportScan(1)
                .checkForAlert();

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void importVeracodeScan() {
        String teamName = "importVeracodeTeam" + getRandomString(3);
        String appName = "importVeracodeApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureVeracode()
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveVera()
                .mapVeracodeToTeamAndApp(0, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("Veracode"));

        remoteProvidersIndexPage.clickVeracodeImportScan(0)
                .checkForAlert();

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage.clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    @Test
    public void testVulnerabilityCountAfterImport() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password").clickRemoteProvidersLink();
        remoteProvidersIndexPage.clickConfigureWhiteHat();
        remoteProvidersIndexPage.setWhiteHatAPI(SENTINEL_API_KEY);
        remoteProvidersIndexPage.saveWhiteHat();

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));
        remoteProvidersIndexPage.mapWhiteHatToTeamAndApp(1, teamName, appName);

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickWhiteHatImportScan(1);
        sleep(40000);
        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().accept();

        assertFalse("The critical vulnerability count was not updated.",
                applicationDetailPage.isVulnerabilityCountNonZero("Critical"));
        assertFalse("The high vulnerability count was not updated.",
                applicationDetailPage.isVulnerabilityCountNonZero("High"));
        assertFalse("The medium vulnerability count was not updated.",
                applicationDetailPage.isVulnerabilityCountNonZero("Medium"));
        assertFalse("The low vulnerability count was not updated.",
                applicationDetailPage.isVulnerabilityCountNonZero("Low"));
        assertFalse("The info vulnerability count was not updated.",
                applicationDetailPage.isVulnerabilityCountNonZero("Info"));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("The vulnerability count was not updated.",
                teamIndexPage.getApplicationSpecificVulnerability(teamName, appName, "Total").equals("0"));

        remoteProvidersIndexPage = applicationDetailPage.clickRemoteProvidersLink();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testDeletedApplicationOnList() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        TeamDetailPage teamDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .clickDeleteLink();

        RemoteProvidersIndexPage remoteProvidersIndexPage = teamDetailPage.clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .clickEditWhiteHatButton(1)
                .selectTeamMapping(teamName);

        assertFalse("Application wasn't deleted", remoteProvidersIndexPage.isElementPresentInSelect("appSelect1",appName));

        remoteProvidersIndexPage.clickCloseButton()
               .clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testDeletedTeamOnList() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName);

        teamDetailPage.clickDeleteButton();

        assertTrue("Team Name wasn't deleted",
                teamDetailPage.successAlert().contains("Team" +  " " + teamName + " has been deleted successfully"));

        RemoteProvidersIndexPage remoteProvidersIndexPage = teamIndexPage.clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .clickEditWhiteHatButton(1);

        assertFalse("Team wasn't deleted", remoteProvidersIndexPage.isElementPresentInSelect("orgSelect1",teamName));

        remoteProvidersIndexPage.clickCloseButton()
                .clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void checkNumberUnderSeverity() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .mapWhiteHatToTeamAndApp(1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        remoteProvidersIndexPage.clickWhiteHatImportScan(1)
                .checkForAlert();

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickTeamLink(teamName);

        assertTrue("Number of Open Vulnerabilities is not correct", teamDetailPage.isNumberOfOpenVulnerabilityCorrect("14", 0));
        assertTrue("Number of Critical Vulnerability is not correct", teamDetailPage.isNumberOfCriticalCorrect("2", 0));
        assertTrue("Number of High Vulnerability is not correct", teamDetailPage.isNumberOfHighCorrect("8", 0));
        assertTrue("Number of Medium Vulnerability is not correct", teamDetailPage.isNumberOfMediumCorrect("4", 0));
        assertTrue("Number of Low Vulnerability is not correct", teamDetailPage.isNumberOfLowCorrect("0", 0));
        assertTrue("Number of Info Vulnerability is not correct", teamDetailPage.isNumberOfInfoCorrect("0", 0));

        remoteProvidersIndexPage = teamDetailPage.clickRemoteProvidersLink()
                                    .clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testTeamExistAfterDeleted() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .mapWhiteHatToTeamAndApp(1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickTeamLink(teamName);

        TeamIndexPage teamIndexPage = teamDetailPage.clickDeleteButton();

        teamIndexPage.clickRemoteProvidersLink();

        assertFalse("Application wasn't Deleted", remoteProvidersIndexPage.isTeamLinkPresent(appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testApplicationExistAfterDeleted(){
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat()
                .mapWhiteHatToTeamAndApp(1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickApplicationLink(appName);

        TeamDetailPage teamDetailPage  = applicationDetailPage.clickEditDeleteBtn()
                .clickDeleteLink();

        teamDetailPage.clickRemoteProvidersLink();

        assertFalse("Application wasn't Deleted", remoteProvidersIndexPage.isApplicationLinkPresent(appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    /*------------------------------ Scheduling ------------------------------*/

    @Test
    public void scheduledImportNavigationTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersSchedulePage remoteProvidersSchedulePage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickScheduleTab();

        assertTrue("Navigation to scheduled imports failed.",
                remoteProvidersSchedulePage.isNewImportButtonDisplayed());
    }

    //TODO when issue 524 is fixed finish test.
    @Ignore
    @Test
    public void scheduledDailyImportCreationTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersSchedulePage remoteProvidersSchedulePage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickScheduleTab();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Daily")
                .setHour(8)
                .setMinute(30)
                .setPeriodOfDay("PM")
                .clickModalSubmit();
    }

}
