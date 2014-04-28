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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationIT extends BaseIT {

	@Test 
	public void testCreateBasicApplicationDisplayedTeamIndexPage() {
		String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
		String appName = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication();

        assertTrue("The application was not added properly.", teamIndexPage.isAppPresent(appName));
	}

    @Test
    public void testCreateBasicApplicationDisplayedApplicationDetailPage() {
        String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
        String appName = "testCreateBasicApplicationApp" + getRandomString(3);
        String urlText = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        //Create Team & Application
        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, urlText, "Low")
                .saveApplication();

        //Navigate to Application Detail Page
        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("The name was not preserved correctly on Application Detail Page.",
                applicationDetailPage.getNameText().contains(appName));
    }

    //Validation Test
	@Test 
	public void testCreateBasicApplicationValidation() {
        String teamName = "testCreateBasicApplicationValidationTeam" + getRandomString(3);
		String appName;
		String urlText = "htnotaurl.com";

		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.NAME_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputName = stringBuilder.toString();
		
		stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.URL_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputUrl = "http://" + stringBuilder.toString();
		
		String emptyError = "Name is required.";
        String notValidURl = "Not a valid URL";
		
		String emptyString = "";
		String whiteSpace = "     ";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

		//Team & Application set up...hopefully to be removed later
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, emptyString, emptyString, "Low")
                .saveApplicationInvalid();
		
		assertTrue("The correct error did not appear for the name field.",
                teamIndexPage.getNameErrorMessage().contains(emptyError));
		
		teamIndexPage = teamIndexPage.clickCloseAddAppModal(teamName)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, whiteSpace, whiteSpace, "Low")
                .saveApplicationInvalid();

		assertTrue("The correct error did not appear for the name field.",
                teamIndexPage.getNameErrorMessage().contains(emptyError));

		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains(notValidURl));
		
		// Test URL format
		teamIndexPage = teamIndexPage.clickCloseAddAppModal(teamName)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, "dummyApp", urlText, "Low")
                .saveApplicationInvalid();
		
		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains(notValidURl));

		// Test browser field length limits
        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickCloseAddAppModal(teamName)
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.addNewApplication(teamName, longInputName, longInputUrl, "Low")
				.saveApplication()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink("iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",teamName);

		assertTrue("The length limit was incorrect for name.",
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
		
		appName = applicationDetailPage.getNameText();
		
		// Test name duplication check
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "http://dummyurl", "Low")
                .saveApplicationInvalid();

        //Is this even a good?
		assertTrue("The duplicate message didn't appear correctly.", 
				teamIndexPage.getNameErrorMessage().contains("That name is already taken."));
	}

	@Test
	public void testEditBasicApplicationDisplayedApplicationDetailPage() {
		String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
		String appName1 = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText1 = "http://testurl.com";
		String appName2 = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText2 = "http://testurl.com352";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName1, urlText1, "Low")
				.saveApplication();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
				.clickViewAppLink(appName1, teamName);

		applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(appName2)
				.setUrlInput(urlText2)
				.clickUpdateApplicationButton();
		
		assertTrue("The name was not preserved correctly on Application Detail Page.",
                appName2.equals(applicationDetailPage.getNameText()));

        applicationDetailPage = applicationDetailPage.clickEditDeleteBtn();
	    assertTrue("The URL was not edited correctly.", applicationDetailPage.getUrlText().contains(urlText2));
	}

    @Test
    public void testEditBasicApplicationDisplayedTeamIndexPage() {
        String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
        String appName1 = "testCreateBasicApplicationApp" + getRandomString(3);
        String urlText1 = "http://testurl.com";
        String appName2 = "testCreateBasicApplicationApp" + getRandomString(3);
        String urlText2 = "http://testurl.com352";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName1, urlText1, "Low")
                .saveApplication();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName1, teamName);

        applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(appName2)
                .setUrlInput(urlText2)
                .clickUpdateApplicationButton();

        // ensure that the application is present in the organization's app table.
        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The edited application does not appear on Team Index Page.", teamIndexPage.isAppPresent(appName2));
    }

	//Validation Test
	@Test
	public void testEditBasicApplicationValidation() {
        String teamName = "testEditBasicApplicationValidationTeam" + getRandomString(3);
		String appName2 = "testApp23";
		String appName = "testApp17";
		String validUrlText = "http://test.com";
		String urlText = "htnotaurl.com";
		
		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.NAME_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputName = stringBuilder.toString();
		
		stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.URL_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputUrl = "http://" + stringBuilder.toString();
		
		String emptyError = "Name is required.";
		
		String emptyString = "";
		String whiteSpace = "     ";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();
		
		//set up an organization,
		//add an application for duplicate checking,
		//add an application for normal testing,
		// and Test a submission with no changes
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName2, validUrlText, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, validUrlText, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

		// Test blank input
		applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(emptyString)
                .setUrlInput(emptyString)
                .clickUpdateApplicationButtonInvalid();
		
		assertTrue("The correct error did not appear for the name field.", 
				applicationDetailPage.getNameError().equals(emptyError));
		
		// Test whitespace input
		applicationDetailPage = applicationDetailPage.setNameInput(whiteSpace)
                .setUrlInput(whiteSpace)
                .clickUpdateApplicationButtonInvalid();

		assertTrue("The correct error did not appear for the name field.",
                applicationDetailPage.getNameError().equals(emptyError));
		assertTrue("The correct error did not appear for the url field.",
				applicationDetailPage.getUrlError().equals("Not a valid URL"));
		
		// Test URL format
		applicationDetailPage = applicationDetailPage.setNameInput("dummyName")
                .setUrlInput(urlText)
                .clickUpdateApplicationButtonInvalid();

		assertTrue("The correct error did not appear for the url field.",
				applicationDetailPage.getUrlError().equals("Not a valid URL"));

		// Test name duplication check
		applicationDetailPage = applicationDetailPage.setNameInput(appName2)
                .setUrlInput("")
                .clickUpdateApplicationButtonInvalid();

		assertTrue("The duplicate message didn't appear correctly.", 
				applicationDetailPage.getNameError().equals("That name is already taken."));

		// Test browser field length limits
		applicationDetailPage = applicationDetailPage.setNameInput(longInputName)
                .setUrlInput(longInputUrl)
                .clickUpdateApplicationButton()
                .clickEditDeleteBtn();

        //Is this even good?
		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
	}

	@Test
	public void testAddWafAtApplicationCreationTimeAndDelete() {
		String wafName = "appCreateTimeWaf1";
		String type = "Snort";
		String teamName = "appCreateTimeWafOrg2";
		String appName = "appCreateTimeWafName2";
		String appUrl = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        WafIndexPage wafIndexPage = teamIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, type)
                .clickModalSubmit();

		// Add Application with WAF
        ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, appUrl, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName);

		// Check that it also appears on the WAF page.
        WafRulesPage wafDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickRules(wafName);
		
		assertTrue("The WAF was not added correctly.", 
				wafDetailPage.isTextPresentInApplicationsTableBody(appName));
		
		// Attempt to delete the WAF and ensure that it is a failure because the Application is still there
		// If the page goes elsewhere, this call will fail.
		wafIndexPage = wafDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickDeleteWaf(wafName);
		
		// Delete app and org and make sure the Application doesn't appear in the WAFs table.
		wafDetailPage = wafIndexPage.clickCloseWafModal(wafName)
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton()
                .clickWafsHeaderLink()
                .clickRules(wafName);
		
		assertFalse("The Application was not removed from the WAF correctly.", 
				wafDetailPage.isTextPresentInApplicationsTableBody(appName));
		
		loginPage = wafDetailPage.clickWafsHeaderLink().clickDeleteWaf(wafName).logout();
		
	}

	@Test
	public void testSwitchWafs() {
		//TODO
		String wafName1 = "firstWaf" + getRandomString(3);
		String wafName2 = "secondWaf" + getRandomString(3);
		String type1 = "Snort" ;
		String type2 = "mod_security";
		String teamName = "testSwitchWafs" + getRandomString(3);
		String appName = "switchWafApp" + getRandomString(3);
		String appUrl = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();
		
		//Create two WAFs
        WafIndexPage wafIndexPage = teamIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName1, type1)
                .clickCreateWaf();

                wafIndexPage.clickOrganizationHeaderLink();

        WafIndexPage wafIndexPage1 = teamIndexPage.clickWafsHeaderLink()
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName2, type2)
                .clickCreateWaf();

        //Create team & application
        teamIndexPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, appUrl, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        //Create second application
        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName,teamName)
                .clickEditDeleteBtn()
				.clickAddWaf()
				.addWaf(wafName1);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
				.clickEditWaf()
                .addWaf(wafName2)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn();
								
		assertTrue("The edit didn't change the application's WAF.",
                applicationDetailPage.getWafText().contains(wafName2));
	}

	@Test
	public void sameAppNameMultipleTeams(){
		String appName = getRandomString(8);
		String teamName1 = getRandomString(8);
		String teamName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        //Add an app with same name to both teams
        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName1)
				.addNewApplication(teamName1, appName, "", "Low")
				.saveApplication()
				.expandTeamRowByName(teamName2)
				.addNewApplication(teamName2, appName, "", "Low")
				.saveApplication()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName1)
				.clickViewAppLink(appName,teamName1);
		
		Boolean isAppInTeam1 = applicationDetailPage.getNameText().contains(appName);
		
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName2)
				.clickViewAppLink(appName, teamName2);
		
		Boolean isAppInTeam2  = applicationDetailPage.getNameText().contains(appName);

		assertTrue("Unable to add apps with the same name to different teams", isAppInTeam1 && isAppInTeam2);
	}

    @Test
    public void switchAppTeam() {
        String teamName1 = "switchAppTeam" + getRandomString(3);
        String teamName2 = "switchAppTeam" + getRandomString(3);
        String appName = "switchApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);
        DatabaseUtils.createApplication(teamName1, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.expandTeamRowByName(teamName1)
                .clickViewAppLink(appName, teamName1)
                .clickEditDeleteBtn()
                .setTeam(teamName2)
                .clickUpdateApplicationButton()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName1);

        Boolean appOnTeam1 = teamDetailPage.isAppPresent(appName);

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName2);

        Boolean appOnTeam2 = teamDetailPage.isAppPresent(appName);

        assertTrue("The application was not switched properly.", !appOnTeam1 && appOnTeam2);

    }

    @Ignore
    @Test
    public void testAddDynamicManualFinding() {
        String teamName = "Team" + getRandomString(5);
        String appName = "App" + getRandomString(5);
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "testPara";
        String desc = "Test description test";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage ap = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        ap.clickActionButton()
                .clickManualFindingButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setDescription(desc)
                .clickDynamicSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = ap.clickScansTab()
                .clickViewScan()
                .clickViewFinding(1)
                .clickViewVulnerability();

        //TODO requires ElementIDs on VulnerabililtyDetailPage
        assertTrue("Description was not present", vulnerabilityDetailPage.isTextPresentOnPage(desc) );
    }

    @Ignore
    @Test
    public void testEditDynamicManualFindings() {
        String teamName = "TeamName" + getRandomString(5);
        String appName = "AppName" + getRandomString(5);
        String cwe = "Improper Neutralization of Special Elements used in an SQL Command";
        String parameter = "testParameter";
        String desc = "Test Description: This is a test, this is only a test.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage ap = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        ap.clickActionButton()
                .clickManualFindingButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setDescription(desc)
                .clickDynamicSubmit();

        ap.clickScansTab()
                .clickViewScan()
                .clickViewFinding(1)
                .clickEditVulnerability();

        //TODO Bug in VulnerabilityDetailsPage, does not save changes.
        // Continue to finish building test when bug is fixed.

    }


    @Test
    public void deleteManualFindingScan() {
        String teamName = "TeamName" + getRandomString(5);
        String appName = "AppName" + getRandomString(5);
        String CWE = "89";
        String parameter = "Test_Parameter";
        String desc = "Test Description for deleting manual finding.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage ap = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        ap.clickActionButton()
                .clickManualFindingButton()
                .setCWE(CWE)
                .setParameter(parameter)
                .setDescription(desc)
                .clickDynamicSubmit();

        ap.clickScansTab()
            .clickDeleteScanButton();

        assertTrue("Manual Finding was not deleted correctly.", ap.isScanDeleted());

    }


    @Test
    public void deleteUploadedScan() {
        String teamName = "TeamName" + getRandomString(5);
        String appName = "AppName" + getRandomString(5);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage ap = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        ap.clickScansTab()
                .clickDeleteScanButton();

        assertTrue("Scan file was not deleted correctly.", ap.isScanDeleted());
    }

    public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
