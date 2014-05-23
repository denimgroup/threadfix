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
import com.denimgroup.threadfix.selenium.pages.RemoteProvidersIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class RemoteProvidersIT extends BaseIT {
	
	private static String SENTINEL_API_KEY = System.getProperty("WHITEHAT_KEY");
	private static String VERACODE_USER = System.getProperty("VERACODE_USERNAME");
	private static String VERACODE_PASSWORD = System.getProperty("VERACODE_PASSWORD");
	private static String QUALYS_USER = System.getProperty("QUALYS_USER");
	private static String QUALYS_PASS = System.getProperty("QUALYS_PASS");

	@Test
	public void navigationTest() {
		String pageHeader = loginPage.login("user", "password")
									.clickRemoteProvidersLink()
									.getH2Tag();
		
		assertTrue("Remote Provider Page not found",pageHeader.contains("Remote Providers"));
	}

    //TODO WhiteHat Key seems to be invalid
    @Ignore
	@Test
	public void configureSentinel() {
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(SENTINEL_API_KEY)
                .clickSubmitWait();

		assertTrue("WhiteHat Sentinel was not configured properly",
                remoteProvidersIndexPage.successAlert().contains("Applications successfully updated"));
		
		remoteProvidersIndexPage = remoteProvidersIndexPage.clearWhiteHat();
		
		assertTrue("WhiteHat Sentinel configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
	}

	@Test
	public void invalidSentinel(){
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI("This should't Work!")
                .clickSubmitWait();

        remoteProvidersIndexPage.sleep(1000);

		assertTrue("Incorrect credentials accepted",
                remoteProvidersIndexPage.getErrorMessage().contains("Failure. Message was : undefined"));
	}

	@Test
	public void configureVeracode() {
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
	public void invalidVeracode(){
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
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

    //TODO need valid QualysGuard credentials
	@Ignore
	@Test
	public void configureQualys() {
        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickRemoteProvidersLink()
                .clickConfigureQualys()
                .setQualysUsername(QUALYS_USER)
                .setQualysPassword(QUALYS_PASS)
                .clickModalSubmit();
	}
	
	@Test
	public void invalidQualys(){
		RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickRemoteProvidersLink()
                .clickConfigureQualys()
                .setQualysUsername("No Such User")
                .setQualysPassword("Password Bad")
                .clickModalSubmitInvalid();
        sleep(15000);
        String error = remoteProvidersIndexPage.getErrorMessage();
		System.out.println(error);
		assertTrue("Expected failure", error.contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
	}

    @Test
    public void importWhiteHatScan() {
        String teamName = "importWhiteHatTeam" + getRandomString(3);
        String appName = "importWhiteHatApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password").clickRemoteProvidersLink();
        remoteProvidersIndexPage.clickConfigureWhiteHat();
        remoteProvidersIndexPage.setWhiteHatAPI(SENTINEL_API_KEY);
        remoteProvidersIndexPage.saveWhiteHat();

        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("WhiteHat Sentinel"));
        remoteProvidersIndexPage.mapWhiteHatToTeamAndApp(1, teamName, appName);

        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickWhiteHatImportScan(1);
        sleep(25000);
        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().accept();

        remoteProvidersIndexPage = applicationDetailPage.clickRemoteProvidersLink();

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

        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password").clickRemoteProvidersLink();
        remoteProvidersIndexPage.clickConfigureVeracode();
        remoteProvidersIndexPage.setVeraUsername(VERACODE_USER);
        remoteProvidersIndexPage.setVeraPassword(VERACODE_PASSWORD);
        remoteProvidersIndexPage.saveVera();
        remoteProvidersIndexPage.mapVeracodeToTeamAndApp(0, teamName, appName);
        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("Veracode"));
        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickVeracodeImportScan(0);
        sleep(20000);
        assertTrue(driver.switchTo().alert().getText().contains("ThreadFix imported scans successfully."));
        driver.switchTo().alert().accept();

        remoteProvidersIndexPage = applicationDetailPage.clickRemoteProvidersLink();

        remoteProvidersIndexPage = remoteProvidersIndexPage.clearVeraCode();

        assertTrue("Veracode configuration was not cleared properly",
                remoteProvidersIndexPage.successAlert().contains("Veracode configuration was cleared successfully."));

    }
//
//    @Test
//    public void invalidImportVeracodeScan() {
//        String teamName = "importVeracodeTeam" + getRandomString(3);
//        String appName = "importVeracodeApp" + getRandomString(3);
//
//        DatabaseUtils.createTeam(teamName);
//        DatabaseUtils.createApplication(teamName, appName);
//
//        RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password").clickRemoteProvidersLink();
//        remoteProvidersIndexPage.clickConfigureVeracode();
//        remoteProvidersIndexPage.setVeraUsername(VERACODE_USER);
//        remoteProvidersIndexPage.setVeraPassword(VERACODE_PASSWORD);
//        remoteProvidersIndexPage.saveVera();
//        remoteProvidersIndexPage.mapVeracodeToTeamAndApp(3, teamName, appName);
//        assertTrue("Success message was " + remoteProvidersIndexPage.successAlert(), remoteProvidersIndexPage.successAlert().contains("Veracode"));
//        ApplicationDetailPage applicationDetailPage = remoteProvidersIndexPage.clickVeracodeImportScan(3);
//        //assert error message displayed
//        assertTrue("Error was not displayed", driver.findElement(By.className("alert-danger")).isDisplayed());
//    }
}
