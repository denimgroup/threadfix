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
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class RemoteProvidersIT extends BaseDataTest {
    private RemoteProvidersIndexPage remoteProvidersIndexPage;
    private RemoteProvidersSchedulePage remoteProvidersSchedulePage;
	
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

    @Before
    public void indexNavigation() {
        initializeTeamAndApp();
        remoteProvidersIndexPage = loginPage.defaultLogin()
                .clickRemoteProvidersLink();
    }

	@Test
	public void navigationTest() {
		assertTrue("Remote Provider Page not found", remoteProvidersIndexPage.isTabPresent());
	}

    @Test
    public void configureQualysTest() {
        remoteProvidersIndexPage.clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .saveQualys();

        assertTrue("Qualys was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider QualysGuard WAS"));
        assertTrue("Qualys configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(0,"Yes"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearQualys();

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
        assertTrue("Qualys configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(0, "No"));
    }

    @Test
    public void invalidQualysTest(){
        remoteProvidersIndexPage.clickConfigureQualys()
                .setQualysUsername("No Such User")
                .setQualysPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.waitForErrorMessage();

        assertTrue("Failure message detailing why credentials were not accepted should have been displayed.",
                remoteProvidersIndexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
    }

	@Test
	public void configureWhiteHatTest() {
        remoteProvidersIndexPage.clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat();

		assertTrue("WhiteHat Sentinel was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider WhiteHat Sentinel"));
        assertTrue("WhiteHat Sentinel configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(3, "Yes"));
		
		remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();
		
		assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
        assertTrue("WhiteHat Sentinel configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(3, "No"));
	}

	@Test
	public void invalidWhiteHatTest(){
        remoteProvidersIndexPage.clearPreviousWhiteHat()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI("This should't Work!")
                .clickSubmitWait();

        remoteProvidersIndexPage.sleep(1000);

		assertTrue("Incorrect credentials accepted",
                remoteProvidersIndexPage.getErrorMessage().contains("Failure. undefined"));
	}

	@Test
	public void configureVeracodeTest() {
        remoteProvidersIndexPage.clickConfigureVeracode()
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveVera();

        assertTrue("Veracode was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider Veracode"));
        assertTrue("Veracode configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(2, "Yes"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
        assertTrue("Veracode configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(2, "No"));
	}
	
	@Test
	public void invalidVeracodeTest(){
        remoteProvidersIndexPage.clickConfigureVeracode()
                .setVeraUsername("No Such User")
                .setVeraPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.sleep(15000);
        String error = remoteProvidersIndexPage.getErrorMessage();
        System.out.println(error);
		assertTrue("Incorrect credentials accepted", error.contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
	}

    @Test
    public void editQualysMapping() {
        remoteProvidersIndexPage.clickConfigureQualys()
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
        remoteProvidersIndexPage.clickConfigureVeracode()
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
        remoteProvidersIndexPage.clickConfigureWhiteHat()
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
        remoteProvidersIndexPage.clickConfigureWhiteHat()
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
        remoteProvidersIndexPage.clickConfigureVeracode()
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
    public void importQualysGuardScan() {
        remoteProvidersIndexPage.clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .setQualysPlatform(QUALYS_PLATFORM)
                .clickModalSubmitInvalid();

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS"));

        remoteProvidersIndexPage.clickEditMappingQualysButton(1)
                .selectTeamMapping(teamName)
                .selectAppMapping(appName)
                .clickUpdateMappings();

        remoteProvidersIndexPage.clickQualysGuardImportScan(1)
                .checkForAlert();

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearQualys();

        assertTrue("Qualys Guard configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void testVulnerabilityCountAfterImport() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        remoteProvidersIndexPage.clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat();

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));
        remoteProvidersIndexPage.mapWhiteHatToTeamAndApp(1, teamName, appName);

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickWhiteHatImportScan(1);
        applicationDetailPage.checkForAlert();

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
                teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total").equals("0"));

        remoteProvidersIndexPage = applicationDetailPage.clickRemoteProvidersLink();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testDeletedApplicationOnList() {
        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickOrganizationHeaderLink()
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
        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName);

        TeamIndexPage teamIndexPage = teamDetailPage.clickDeleteButton();

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
        remoteProvidersIndexPage.clickConfigureWhiteHat()
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
        remoteProvidersIndexPage.clickConfigureWhiteHat()
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
        remoteProvidersIndexPage.clickConfigureWhiteHat()
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

    public void navigateToSchedule() {
        remoteProvidersSchedulePage = remoteProvidersIndexPage.clickScheduleTab();
    }

    @Test
    public void scheduledImportNavigationTest() {
        navigateToSchedule();

        assertTrue("Navigation to scheduled imports failed.",
                remoteProvidersSchedulePage.isNewImportButtonDisplayed());
    }

    @Test
    public void scheduledDailyImportCreationTest() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Daily")
                .setHour(3)
                .setMinute(45)
                .setPeriodOfDay("PM")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", remoteProvidersSchedulePage.isNewSchedulePresent("_3_45_PM"));
    }

    @Test
    public void scheduledWeeklyImportCreationTest() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Weekly")
                .setHour(4)
                .setMinute(30)
                .setPeriodOfDay("AM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", remoteProvidersSchedulePage.isNewSchedulePresent("Sunday_4_30_AM"));
    }

    //TODO remove extra navigation when enhancement #618 is added
    @Test
    public void checkSameDailyScheduleConflict() {
        String frequency = "Daily";
        int hour = 9;
        int minutes = 30;
        String periodOfDay = "AM";

        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        remoteProvidersSchedulePage = remoteProvidersSchedulePage.clickOrganizationHeaderLink()
                .clickRemoteProvidersLink()
                .clickScheduleTab();

        assertTrue("New Schedule wasn't created", remoteProvidersSchedulePage.isNewSchedulePresent("_9_30_AM"));

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        assertTrue("Same Schedule was created",
                remoteProvidersSchedulePage.isErrorPresent("Another remote provider import is scheduled at that time/frequency"));
    }

    //TODO remove extra navigation when enhancement #618 is added
    @Test
    public void checkSameWeeklyScheduleConflict() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Weekly")
                .setHour(8)
                .setMinute(30)
                .setPeriodOfDay("PM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        remoteProvidersSchedulePage = remoteProvidersSchedulePage.clickOrganizationHeaderLink()
                .clickRemoteProvidersLink()
                .clickScheduleTab();

        assertTrue("New Schedule wasn't Created", remoteProvidersSchedulePage.isNewSchedulePresent("Sunday_8_30_PM"));

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Weekly")
                .setHour(8)
                .setMinute(30)
                .setPeriodOfDay("PM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("Same Schedule was Created",
                remoteProvidersSchedulePage.isErrorPresent("Another remote provider import is scheduled at that time/frequency"));
    }

    @Test
    public void deleteDailyRemoteProviderScheduling() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Daily")
                .setHour(7)
                .setMinute(15)
                .setPeriodOfDay("PM")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", remoteProvidersSchedulePage.isNewSchedulePresent("_7_15_PM"));

        remoteProvidersSchedulePage.clickDeleteDefectTrackerButton("_7_15_PM");

        assertFalse("The Schedule wasn't Deleted",
                remoteProvidersSchedulePage.isDeleteButtonPresent("_7_15_PM"));
    }

    @Test
    public void deleteWeeklyRemoteProviderScheduling() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Weekly")
                .setHour(11)
                .setMinute(30)
                .setPeriodOfDay("AM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created",
                remoteProvidersSchedulePage.isNewSchedulePresent("Sunday_11_30_AM"));

        remoteProvidersSchedulePage.clickDeleteDefectTrackerButton("Sunday_11_30_AM");

        assertFalse("The Schedule wasn't Deleted",
                remoteProvidersSchedulePage.isDeleteButtonPresent("Sunday_11_30_AM"));
    }

    @Test
    public void checkSuccessMessageLocation() {
        navigateToSchedule();

        remoteProvidersSchedulePage.clickScheduleNewImportButton()
                .setFrequency("Weekly")
                .setHour(11)
                .setMinute(30)
                .setPeriodOfDay("AM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created",
                remoteProvidersSchedulePage.isNewSchedulePresent("Sunday_11_30_AM"));

        remoteProvidersSchedulePage.clickDeleteDefectTrackerButton("Sunday_11_30_AM");

        assertFalse("The Schedule wasn't Deleted",
                remoteProvidersSchedulePage.isDeleteButtonPresent("Sunday_11_30_AM"));

        RemoteProvidersIndexPage remoteProvidersIndexPage = remoteProvidersSchedulePage.clickRemoteProvidersTab();

        assertFalse("success message is present",
                remoteProvidersIndexPage.isSuccessMessagePresent("Weekly Scheduled Remote Provider Import successfully deleted."));

    }

    @Test
    public void checkQualysEditNameModalHeader() {
        remoteProvidersIndexPage.clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .setQualysPlatform(QUALYS_PLATFORM)
                .clickModalSubmitInvalid();

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(),
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS"));

        remoteProvidersIndexPage.clickEditName("3","0");

        assertTrue("Modal does not contain app name",
                driver.findElement(By.id("myModalLabel")).getText().contains("PHP Demo site"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.closeModal().clearQualys();

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void checkVeracodeEditNameModalHeader() {
        remoteProvidersIndexPage.clickConfigureVeracode()
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveVera()
                .mapVeracodeToTeamAndApp(0, teamName, appName);

        remoteProvidersIndexPage.clickEditName("2","0");

        assertTrue("Modal does not contain app name",
                driver.findElement(By.id("myModalLabel")).getText().contains("Apache"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.closeModal().clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    @Test
    public void checkWhiteHatEditNameModalHeader() {
        remoteProvidersIndexPage.clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .saveWhiteHat();

        remoteProvidersIndexPage.clickEditName("1","0");

        assertTrue("Modal does not contain app name",
                driver.findElement(By.id("myModalLabel")).getText().contains("Demo Site BE"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.closeModal().clearWhiteHat();

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }
}
