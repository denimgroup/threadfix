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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;

public class ApplicationTests extends BaseTest {

	private RemoteWebDriver driver;
	private ApplicationDetailPage applicationDetailPage;
	private TeamIndexPage teamIndexPage;
	private WafIndexPage wafIndexPage;
	private WafRulesPage wafDetailPage;

	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver) super.getDriver();
	}

	@Test 
	public void testCreateBasicApplication() {
		String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
		String appName = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText = "http://testurl.com";
		
		teamIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink();

        //Create Team & Application
        teamIndexPage = teamIndexPage.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName);

        assertTrue("The organization was not preserved correctly.", teamIndexPage.teamAddedToTable(teamName));

        //Navigate to Application Detail Page
		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByIndex(teamName)
                .clickViewAppLink(appName, teamName);

		assertTrue("The name was not preserved correctly.", applicationDetailPage.getNameText().contains(appName));
		
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();
		
		//Cleanup
		teamIndexPage = teamIndexPage.expandTeamRowByIndex(teamName)
                .clickViewAppLink(appName, teamName)
                .clickDeleteLink()
                .clickDeleteButton();
	}

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
		
		String emptyError = "This field cannot be blank";
		
		String emptyString = "";
		String whiteSpace = "     ";
		
		//set up an organization
		
		teamIndexPage = loginPage.login("user", "password")
										.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(teamName)
										.addNewTeam()
										.expandTeamRowByIndex(teamName)
										.addNewApplication(teamName, emptyString, emptyString, "Low")
										.saveApplicationInvalid(teamName);
		
		assertTrue("The correct error did not appear for the name field.", 
				teamIndexPage.getNameErrorMessage().contains(emptyError));
		
		teamIndexPage = teamIndexPage.clickCloseAddAppModal(teamName)
									.clickOrganizationHeaderLink()
									.expandTeamRowByIndex(teamName)
									.addNewApplication(teamName, whiteSpace, whiteSpace, "Low")
									.saveApplicationInvalid(teamName);
		
		
		assertTrue("The correct error did not appear for the name field.", 
				teamIndexPage.getNameErrorMessage().contains(emptyError));
		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains("Not a valid URL"));
		
		// Test URL format
		teamIndexPage = teamIndexPage.clickCloseAddAppModal(teamName)
									.clickOrganizationHeaderLink()
									.expandTeamRowByIndex(teamName)
									.addNewApplication(teamName, "dummyApp", urlText, "Low")
									.saveApplicationInvalid(teamName);
		
		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains("Not a valid URL"));

		// Test browser field length limits
		applicationDetailPage = teamIndexPage
				.clickCloseAddAppModal(teamName)
				.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, longInputName, longInputUrl, "Low")
				.saveApplication(teamName)
				.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(teamName)
				.clickViewAppLink("iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",teamName);

		
		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
//		assertTrue("The length limit was incorrect for url.", 
//				applicationDetailPage.clickDetailsLink().getUrlText().length() == Application.URL_LENGTH);
		
		appName = applicationDetailPage.getNameText();
		
		// Test name duplication check
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
												.expandTeamRowByIndex(teamName)
												.addNewApplication(teamName, appName, "http://dummyurl", "Low")
												.saveApplicationInvalid(teamName);
		
		assertTrue("The duplicate message didn't appear correctly.", 
				teamIndexPage.getNameErrorMessage().contains("That name is already taken."));

		//cleanup
		loginPage = teamIndexPage.clickCloseAddAppModal(teamName)
										.clickOrganizationHeaderLink()
										.clickViewTeamLink(teamName)
										.clickDeleteButton()
										.logout();
	}

	@Test
	public void testEditBasicApplication() {
		String orgName = "testCreateApplicationOrg21";
		String appName1 = "testCreateApplicationApp21";
		String urlText1 = "http://testurl.com";
		String appName2 = "testCreateApplicationApp22";
		String urlText2 = "http://testurl.com352";
		// set up an organization
		teamIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(orgName)
				.addNewTeam()
				.expandTeamRowByIndex(orgName)
				.addNewApplication(orgName, appName1, urlText1, "Low")
				.saveApplication(orgName);
	
		
		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
													.expandTeamRowByIndex(orgName)
													.clickViewAppLink(appName1, orgName);

		assertTrue("The name was not preserved correctly.", 
					appName1.equals(applicationDetailPage.getNameText()));
//		assertTrue("The URL was not preserved correctly.", 
//					urlText1.equals(applicationDetailPage.clickDetailsLink().getUrlText()));
		
		applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
													.setNameInput(appName2)
													.setUrlInput(urlText2)
													.clickUpdateApplicationButton();
		
		assertTrue("The name was not preserved correctly.", 
				appName2.equals(applicationDetailPage.getNameText()));
		//TODO does not seem to be able to compare the urls on the application detail page, needs to be fixed
		//assertTrue("The URL was not preserved correctly.", 
		//		applicationDetailPage.clickDetailsLink().getUrlText().contains(urlText2));	
		
		// ensure that the application is present in the organization's app table.
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
													.expandTeamRowByIndex(orgName);
		
		assertTrue("The application does not appear in the organization page.", 
				teamIndexPage.isAppPresent(appName2));
		
		//cleanup
		loginPage = teamIndexPage.clickViewTeamLink(orgName)
										.clickDeleteButton()
										.logout();
	}

	//validation on edit is not implemented yet
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
		
		String emptyError = "This field cannot be blank";
		
		String emptyString = "";
		String whiteSpace = "     ";
		
		//set up an organization,
		//add an application for duplicate checking,
		//add an application for normal testing,
		// and Test a submission with no changes
		applicationDetailPage = loginPage.login("user", "password")
										.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(teamName)
										.addNewTeam()
										.expandTeamRowByIndex(teamName)
										.addNewApplication(teamName, appName2, validUrlText, "Low")
										.saveApplication(teamName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByIndex(teamName)
										.addNewApplication(teamName, appName, validUrlText, "Low")
										.saveApplication(teamName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByIndex(teamName)
										.clickViewAppLink(appName,teamName)
										.clickEditDeleteBtn()
										.clickUpdateApplicationButton();

		assertTrue("The name was not preserved correctly.", 
				appName.equals(applicationDetailPage.getNameText()));
//		assertTrue("The URL was not preserved correctly.", 
//				validUrlText.equals(applicationDetailPage.clickDetailsLink().getUrlText()));

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
//		assertTrue("The correct error did not appear for the url field.", 
//				applicationDetailPage.getUrlError().equals("Not a valid URL"));
		
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

        applicationDetailPage = applicationDetailPage.setNameInput(appName2)
                .setUrlInput("")
                .clickUpdateApplicationButtonInvalid();

		assertTrue("The duplicate message didn't appear correctly.", 
				applicationDetailPage.getNameError().equals("That name is already taken."));

		// Test browser field length limits
		applicationDetailPage = applicationDetailPage.setNameInput(longInputName)
												   .setUrlInput(longInputUrl)
												   .clickUpdateApplicationButton();

		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
//		assertTrue("The length limit was incorrect for url.", 
//				applicationDetailPage.clickDetailsLink().getUrlText().length() == Application.URL_LENGTH);
				
		//cleanup
		loginPage = applicationDetailPage.clickDeleteLink()
										.clickTextLinkInApplicationsTableBody(appName2)
										.clickDeleteLink()
										.clickDeleteButton()
										.logout();
	}

	@Test
	public void testAddWafAtApplicationCreationTimeAndDelete() {              //left off
		String wafName = "appCreateTimeWaf1";
		String type = "Snort";
		String orgName = "appCreateTimeWafOrg2";
		String appName = "appCreateTimeWafName2";
		String appUrl = "http://testurl.com";
		
		wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink()
														.clickAddWafLink()
														.createNewWaf(wafName, type)
														.clickCreateWaf();

		// Add Application with WAF
		applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(orgName)
										.addNewTeam()
										.expandTeamRowByIndex(orgName)
										.addNewApplication(orgName, appName, appUrl, "Low")
										.saveApplication(orgName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByIndex(orgName)
										.clickViewAppLink(appName,orgName)
										.clickEditDeleteBtn()
										.clickAddWaf()
										.addWaf(wafName);

		// Check that it also appears on the WAF page.
		wafDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
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
								.clickViewTeamLink(orgName)
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
		String wafName1 = "firstWaf" + getRandomString(8);
		String wafName2 = "wafToSwitch" + getRandomString(8);
		String type1 = "Snort" ;
		String type2 = "mod_security";
		String orgName = "switchWafOrg" + getRandomString(8);
		String appName = "switchWafApp" + getRandomString(8);
		String appUrl = "http://testurl.com";
		
		// create WAFs and set up the application with one
		// then switch to the other one and verify that the switch has been made.
		applicationDetailPage = loginPage.login("user", "password")
										 .clickWafsHeaderLink()
										 .clickAddWafLink()
										 .createNewWaf(wafName1, type1)
										 .clickCreateWaf()
                                         .clickWafsHeaderLink()
										 .clickAddWafLink()
										 .createNewWaf(wafName2, type2)
										 .clickCreateWaf()
										 .clickOrganizationHeaderLink()
										 .clickAddTeamButton()
										 .setTeamName(orgName)
										 .addNewTeam()
										 .expandTeamRowByIndex(orgName)
										 .addNewApplication(orgName, appName, appUrl, "Low")
										 .saveApplication(orgName)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByIndex(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickEditDeleteBtn()
										 .clickAddWaf()
										 .addWaf(wafName1)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByIndex(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickEditDeleteBtn()
										 .clickEditWaf()
										 .addWaf(wafName2)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByIndex(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickEditDeleteBtn();
								
		assertTrue("The edit didn't change the application's WAF.", 
				applicationDetailPage.getWafText().contains(wafName2));
		
		//cleanup
		loginPage = applicationDetailPage.clickCloseAppModal()
										.clickOrganizationHeaderLink()
										.clickViewTeamLink(orgName)
										.clickDeleteButton()
										.clickWafsHeaderLink()
										.clickDeleteWaf(wafName1)
										.clickDeleteWaf(wafName2)
										.logout();
	}

	@Test
	public void sameAppNameMultipleTeams(){
		String appName = getRandomString(10);
		String teamName1 = getRandomString(10);
		String teamName2 = getRandomString(10);
		applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName1)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName2)
				.addNewTeam()
				.expandTeamRowByIndex(teamName1)
				.addNewApplication(teamName1, appName, "", "Low")
				.saveApplication(teamName1)
				.expandTeamRowByIndex(teamName2)
				.addNewApplication(teamName2, appName, "", "Low")
				.saveApplication(teamName2)
				.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(teamName1)
				.clickViewAppLink(appName,teamName1);
		
		Boolean one  = applicationDetailPage.getNameText().contains(appName);
		
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
													.expandTeamRowByIndex(teamName2)
													.clickViewAppLink(appName,teamName2);
		
		Boolean two  = applicationDetailPage.getNameText().contains(appName);
		
		 applicationDetailPage.clickOrganizationHeaderLink()
			.clickViewTeamLink(teamName1)
			.clickDeleteButton()
            .clickOrganizationHeaderLink()
			.clickViewTeamLink(teamName2)
			.clickDeleteButton()
			.logout();
		 
		 assertTrue("Unable to add apps with the same name to different teams", one && two);
		
		
		
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
