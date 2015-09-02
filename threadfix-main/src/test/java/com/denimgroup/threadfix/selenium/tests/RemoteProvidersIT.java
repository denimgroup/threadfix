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

    private static final String CONTRAST = "Contrast";
    private static final String APPSCAN = "IBMSecurityAppScanEnterprise";
    private static final String QUALYS = "QualysGuardWAS";
    private static final String SONATYPE = "Sonatype";
    private static final String TRUSTWAVE = "TrustwaveHailstorm";
    private static final String VERACODE = "Veracode";
    private static final String WHITEHAT = "WhiteHatSentinel";
    private static final String WHITEHATSOURCE = "WhiteHatSentinelSource";
	
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
	public void testNavigation() {
		assertTrue("Remote Provider Page not found", remoteProvidersIndexPage.isTabPresent());
	}

    //===========================================================================================================
    // Contrast
    //===========================================================================================================

    @Test
    public void testConfigureContrast() {

        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(CONTRAST);

        remoteProvidersIndexPage.clickConfigure(CONTRAST)
                .setContrastUser(CONTRAST_USER)
                .setContrastAPI(CONTRAST_API_KEY)
                .setContrastService(CONTRAST_SERVICE_KEY)
                .saveConfiguration(CONTRAST);

        assertTrue("Contrast Sentinel was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider Contrast"));
        assertTrue("Contrast Sentinel configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(CONTRAST, "Yes"));

        //Runtime Fix
        remoteProvidersIndexPage.refreshPage();

        remoteProvidersIndexPage.clearConfiguration(CONTRAST);

        assertTrue("Contrast configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Contrast configuration was cleared successfully."));
        assertTrue("Contrast configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(CONTRAST, "No"));
    }

    @Test
    public void testUpdateContrastApplications() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(CONTRAST);

        remoteProvidersIndexPage.clickConfigure(CONTRAST)
                .setContrastUser(CONTRAST_USER)
                .setContrastAPI(CONTRAST_API_KEY)
                .setContrastService(CONTRAST_SERVICE_KEY)
                .saveConfiguration(CONTRAST);

        remoteProvidersIndexPage.clickEditMappingButton(CONTRAST, 0)
                .selectTeamMapping(teamName)
                .selectAppMapping(appName)
                .clickUpdateMappings();

        remoteProvidersIndexPage.clickImportScan(CONTRAST, 0)
                .checkForAlert();

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        //Runtime Fix
        remoteProvidersIndexPage.refreshPage();

        remoteProvidersIndexPage.clearConfiguration(CONTRAST);

        assertTrue("Contrast configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Contrast configuration was cleared successfully."));
        assertTrue("Contrast configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(CONTRAST, "No"));
    }

    @Test
    public void testEditContrastApplicationName() {
        String newName = getName();

        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(CONTRAST);

        remoteProvidersIndexPage.clickConfigure(CONTRAST)
                .setContrastUser(CONTRAST_USER)
                .setContrastAPI(CONTRAST_API_KEY)
                .setContrastService(CONTRAST_SERVICE_KEY)
                .saveConfiguration(CONTRAST);

        remoteProvidersIndexPage.clickEditName(CONTRAST,"0").setNewName(newName);

        assertTrue("Application name did not update properly",
                remoteProvidersIndexPage.getAppName(CONTRAST, "0").equals(newName));

        //Runtime Fix
        remoteProvidersIndexPage.refreshPage();

        remoteProvidersIndexPage.clearConfiguration(CONTRAST);
    }

    //===========================================================================================================
    // IBM Rational AppScan Enterprise
    //===========================================================================================================

    

    //===========================================================================================================
    // QualysGuard WAS
    //===========================================================================================================

    @Test
    public void testConfigureQualys() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(QUALYS);

        remoteProvidersIndexPage.clickConfigure(QUALYS)
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .saveConfiguration(QUALYS);

        assertTrue("Qualys was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider QualysGuard WAS"));
        assertTrue("Qualys configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(QUALYS,"Yes"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(QUALYS);

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
        assertTrue("Qualys configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(QUALYS, "No"));
    }

    @Test
    public void testInvalidQualys(){
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(QUALYS);

        remoteProvidersIndexPage.clickConfigure(QUALYS)
                .setQualysUsername("No Such User")
                .setQualysPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.waitForErrorMessage();

        assertTrue("Failure message detailing why credentials were not accepted should have been displayed.",
                remoteProvidersIndexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
    }

    @Test
    public void testEditQualysMapping() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(QUALYS);

        remoteProvidersIndexPage.clickConfigure(QUALYS)
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .saveConfiguration(QUALYS);

        remoteProvidersIndexPage.mapProviderToTeamAndApp(QUALYS, 0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(QUALYS, 0, teamName, appName));

        remoteProvidersIndexPage.clearConfiguration(QUALYS);

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void testImportQualysGuardScan() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(QUALYS);

        remoteProvidersIndexPage.clickConfigure(QUALYS)
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .setQualysPlatform(QUALYS_PLATFORM)
                .saveConfiguration(QUALYS);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS"));

        remoteProvidersIndexPage.clickEditMappingButton(QUALYS, 3)
                .selectTeamMapping(teamName)
                .selectAppMapping(appName)
                .clickUpdateMappings();

        remoteProvidersIndexPage.clickImportScan(QUALYS, 3)
                .checkForAlert(60);

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(QUALYS);

        assertTrue("Qualys Guard configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    @Test
    public void testQualysEditNameModalHeader() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(QUALYS);

        remoteProvidersIndexPage.clickConfigure(QUALYS)
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .setQualysPlatform(QUALYS_PLATFORM)
                .saveConfiguration(QUALYS);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(),
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS"));

        remoteProvidersIndexPage.clickEditName(QUALYS, "0");

        assertTrue("Modal does not contain app name", remoteProvidersIndexPage.getModalText().contains("PHP Demo site"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.closeModal().clearConfiguration(QUALYS);

        assertTrue("Qualys configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("QualysGuard WAS configuration was cleared successfully."));
    }

    //===========================================================================================================
    // Sonatype
    //===========================================================================================================



    //===========================================================================================================
    // Trustwave Hailstorm
    //===========================================================================================================



    //===========================================================================================================
    // Veracode
    //===========================================================================================================

    @Test
    public void testConfigureVeracode() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(VERACODE);

        remoteProvidersIndexPage.clickConfigure(VERACODE)
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveConfiguration(VERACODE);

        assertTrue("Veracode was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider Veracode"));
        assertTrue("Veracode configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(VERACODE, "Yes"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(VERACODE);

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
        assertTrue("Veracode configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(VERACODE, "No"));
    }

    @Test
    public void testInvalidVeracode(){
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(VERACODE);

        remoteProvidersIndexPage.clickConfigure(VERACODE)
                .setVeraUsername("No Such User")
                .setVeraPassword("Password Bad")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.sleep(15000);
        String error = remoteProvidersIndexPage.getErrorMessage();
        System.out.println(error);
        assertTrue("Incorrect credentials accepted", error.contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
    }

    @Test
    public void testEditVeracodeMapping() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(VERACODE);

        remoteProvidersIndexPage.clickConfigure(VERACODE)
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveConfiguration(VERACODE);

        remoteProvidersIndexPage.mapProviderToTeamAndApp(VERACODE, 0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(VERACODE, 0, teamName, appName));

        remoteProvidersIndexPage.clearConfiguration(VERACODE);

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    @Test
    public void testImportVeracodeScan() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(VERACODE);

        remoteProvidersIndexPage.clickConfigure(VERACODE)
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveConfiguration(VERACODE)
                .mapProviderToTeamAndApp(VERACODE, 0, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("Veracode"));

        remoteProvidersIndexPage.clickImportScan(VERACODE, 0)
                .checkForAlert(45);

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage.clearConfiguration(VERACODE);

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    @Test
    public void testVeracodeEditNameModalHeader() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(VERACODE);

        remoteProvidersIndexPage.clickConfigure(VERACODE)
                .setVeraUsername(VERACODE_USER)
                .setVeraPassword(VERACODE_PASSWORD)
                .saveConfiguration(VERACODE)
                .mapProviderToTeamAndApp(VERACODE, 0, teamName, appName);

        remoteProvidersIndexPage.clickEditName(VERACODE, "0");

        assertTrue("Modal does not contain app name", remoteProvidersIndexPage.getModalText().contains("Apache"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.closeModal().clearConfiguration(VERACODE);

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));
    }

    //===========================================================================================================
    // WhiteHat Sentinel
    //===========================================================================================================

    @Test
    public void testConfigureWhiteHat() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Successfully edited remote provider WhiteHat Sentinel"));
        assertTrue("WhiteHat Sentinel configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(WHITEHAT, "Yes"));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
        assertTrue("WhiteHat Sentinel configured message is not correct.",
                remoteProvidersIndexPage.checkConfigurationMessage(WHITEHAT, "No"));
    }

    @Test
    public void testInvalidWhiteHat(){
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI("ThisShouldNotWork")
                .clickModalSubmitInvalid();

        remoteProvidersIndexPage.sleep(1000);

        assertTrue("Incorrect credentials accepted",
                remoteProvidersIndexPage.getErrorMessage().contains("Failure. Unable to retrieve applications. WhiteHat response status:"));
    }

    @Test
    public void testEditWhiteHatMapping() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT);

        remoteProvidersIndexPage.mapProviderToTeamAndApp(WHITEHAT, 0, teamName, appName);

        assertTrue("Team was not mapped properly.", remoteProvidersIndexPage.isMappingCorrect(WHITEHAT, 0, teamName, appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testImportWhiteHatScan() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .mapProviderToTeamAndApp(WHITEHAT, 1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        remoteProvidersIndexPage.clickImportScan(WHITEHAT, 1)
                .checkForAlert(20);

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testCheckWhiteHatEditNameModalHeader() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT);

        remoteProvidersIndexPage.clickEditName(WHITEHAT, "0");

        //Runtime Fix
        sleep(5000);

        assertTrue("Modal does not contain app name", remoteProvidersIndexPage.getModalText().contains("DAST App"));

        remoteProvidersIndexPage.closeModal().clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    //===========================================================================================================
    // WhiteHat Sentinel Source
    //===========================================================================================================

    //===========================================================================================================
    // Other
    //===========================================================================================================

    @Test
    public void testVulnerabilityCountAfterImport() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));
        remoteProvidersIndexPage.mapProviderToTeamAndApp(WHITEHAT, 1, teamName, appName);

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickImportScan(WHITEHAT, 1);
        applicationDetailPage.checkForAlert(20);

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().accept();

        ApplicationDetailPage applicationDetailPage1 = new ApplicationDetailPage(driver);

        assertFalse("The critical vulnerability count was not updated.",
                applicationDetailPage1.isVulnerabilityCountNonZero("Critical"));
        assertFalse("The high vulnerability count was not updated.",
                applicationDetailPage1.isVulnerabilityCountNonZero("High"));
        assertFalse("The medium vulnerability count was not updated.",
                applicationDetailPage1.isVulnerabilityCountNonZero("Medium"));
        assertFalse("The low vulnerability count was not updated.",
                applicationDetailPage1.isVulnerabilityCountNonZero("Low"));
        assertFalse("The info vulnerability count was not updated.",
                applicationDetailPage1.isVulnerabilityCountNonZero("Info"));

        TeamIndexPage teamIndexPage = applicationDetailPage1.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("The vulnerability count was not updated.",
                teamIndexPage.getApplicationSpecificVulnerabilityCount(teamName, appName, "Total").equals("0"));

        remoteProvidersIndexPage = applicationDetailPage.clickRemoteProvidersLink();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testDeletedApplicationOnList() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        TeamDetailPage teamDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .clickDeleteLink();

        RemoteProvidersIndexPage remoteProvidersIndexPage = teamDetailPage.clickRemoteProvidersLink()
                .clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .clickEditMappingButton(WHITEHAT, 1);

        assertFalse("Application wasn't deleted", remoteProvidersIndexPage.isElementPresentInSelect("orgSelect1",teamName));

        remoteProvidersIndexPage.clickCloseButton()
               .clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testDeletedTeamOnList() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName);

        TeamIndexPage teamIndexPage = teamDetailPage.clickDeleteButton()
                .clickCloseNewTeamModal();

        assertTrue("Team Name wasn't deleted",
                teamDetailPage.successAlert().contains("Team" +  " " + teamName + " has been deleted successfully"));

        RemoteProvidersIndexPage remoteProvidersIndexPage = teamIndexPage.clickRemoteProvidersLink()
                .clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .clickEditMappingButton(WHITEHAT, 1);

        assertFalse("Team wasn't deleted", remoteProvidersIndexPage.isElementPresentInSelect("orgSelect1",teamName));

        remoteProvidersIndexPage.clickCloseButton()
                .clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testNumberUnderSeverity() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .mapProviderToTeamAndApp(WHITEHAT, 1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        remoteProvidersIndexPage.clickImportScan(WHITEHAT, 1)
                .checkForAlert(20);

        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().dismiss();

        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickTeamLink(teamName);

        sleep(10000);

        assertTrue("Number of Open Vulnerabilities is not correct", teamDetailPage.isNumberOfOpenVulnerabilityCorrect("50", 0));
        assertTrue("Number of Critical Vulnerability is not correct", teamDetailPage.isNumberOfCriticalCorrect("10", 0));
        assertTrue("Number of High Vulnerability is not correct", teamDetailPage.isNumberOfHighCorrect("11", 0));
        assertTrue("Number of Medium Vulnerability is not correct", teamDetailPage.isNumberOfMediumCorrect("27", 0));
        assertTrue("Number of Low Vulnerability is not correct", teamDetailPage.isNumberOfLowCorrect("1", 0));
        assertTrue("Number of Info Vulnerability is not correct", teamDetailPage.isNumberOfInfoCorrect("1", 0));

        remoteProvidersIndexPage = teamDetailPage.clickRemoteProvidersLink()
                                    .clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testTeamExistsAfterDeleted() {
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .mapProviderToTeamAndApp(WHITEHAT, 1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        TeamDetailPage teamDetailPage = remoteProvidersIndexPage.clickTeamLink(teamName);

        TeamIndexPage teamIndexPage = teamDetailPage.clickDeleteButton()
                .clickCloseNewTeamModal();

        teamIndexPage.clickRemoteProvidersLink();

        assertFalse("Application wasn't Deleted", remoteProvidersIndexPage.isTeamLinkPresent(appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    @Test
    public void testApplicationExistsAfterDeleted(){
        remoteProvidersIndexPage.ensureRemoteProviderConfigurationIsCleared(WHITEHAT);

        remoteProvidersIndexPage.clickConfigure(WHITEHAT)
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .selectWhiteHatImportStyle()
                .saveConfiguration(WHITEHAT)
                .mapProviderToTeamAndApp(WHITEHAT, 1, teamName, appName);

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickApplicationLink(appName);

        TeamDetailPage teamDetailPage  = applicationDetailPage.clickEditDeleteBtn()
                .clickDeleteLink();

        teamDetailPage.clickRemoteProvidersLink();

        assertFalse("Application wasn't Deleted", remoteProvidersIndexPage.isApplicationLinkPresent(appName));

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearConfiguration(WHITEHAT);

        assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
    }

    //===========================================================================================================
    // Scheduling
    //===========================================================================================================

    public void navigateToSchedule() {
        remoteProvidersSchedulePage = remoteProvidersIndexPage.clickScheduleTab();
    }

    @Test
    public void testScheduledImportNavigation() {
        navigateToSchedule();

        assertTrue("Navigation to scheduled imports failed.",
                remoteProvidersSchedulePage.isNewImportButtonDisplayed());
    }

    @Test
    public void testScheduledDailyImportCreation() {
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
    public void testScheduledWeeklyImportCreation() {
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
    public void testSameDailyScheduleConflict() {
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
    public void testSameWeeklyScheduleConflict() {
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
    public void testDeleteDailyRemoteProviderScheduling() {
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
    public void testDeleteWeeklyRemoteProviderScheduling() {
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
    public void testSuccessMessageLocation() {
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
}
