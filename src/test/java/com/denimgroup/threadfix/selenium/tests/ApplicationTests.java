////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationEditPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;

public class ApplicationTests extends BaseTest {
	private WebDriver driver;
	private static LoginPage loginPage;
	private ApplicationDetailPage applicationDetailPage;
	private TeamIndexPage teamIndexPage;
	private ApplicationEditPage applicationEditPage;
	private WafIndexPage wafIndexPage;
	private WafRulesPage wafDetailPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test 
	public void testCreateBasicApplication() {
		String teamName = "testCreateApplicationOrgw" + getRandomString(3);
		String appName = "testCreateApplicationAppw" + getRandomString(3);
		String urlText = "http://testurl.com";
		
		teamIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName);		
		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
											.expandTeamRowByName(teamName)
											.clickViewAppLink(appName, teamName);

		
		assertTrue("The name was not preserved correctly.", applicationDetailPage.getNameText().contains(appName));
		
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();
		
		assertTrue("The organization was not preserved correctly.", 
				teamIndexPage.teamAddedToTable(teamName));
		
		//cleanup
		loginPage = teamIndexPage.expandTeamRowByName(teamName)
										.clickViewAppLink(appName, teamName)
										.clickActionButton()
										.clickDeleteLink()
										.clickDeleteButton()
										.logout();
		
	}
	
	@Test 
	public void testCreateBasicApplicationValidation() {
		String orgName = "testCreateApplicationOrg2a";
		String appName = null;
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
										.setTeamName(orgName)
										.addNewTeam()
										.expandTeamRowByName(orgName)
										.addNewApplication(orgName, emptyString, emptyString, "Low")
										.saveApplicationInvalid(orgName);
		
		assertTrue("The correct error did not appear for the name field.", 
				teamIndexPage.getNameErrorMessage().contains(emptyError));
		
		teamIndexPage = teamIndexPage.clickOrganizationHeaderLink()
									.expandTeamRowByName(orgName)
									.addNewApplication(orgName, whiteSpace, whiteSpace, "Low")
									.saveApplicationInvalid(orgName);
		
		
		assertTrue("The correct error did not appear for the name field.", 
				teamIndexPage.getNameErrorMessage().contains(emptyError));
		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains("Not a valid URL"));
		
		// Test URL format
		teamIndexPage = teamIndexPage.clickOrganizationHeaderLink()
									.expandTeamRowByName(orgName)
									.addNewApplication(orgName, "dummyApp", urlText, "Low")
									.saveApplicationInvalid(orgName);
		
		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains("Not a valid URL"));

		// Test browser field length limits
		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(orgName)
				.addNewApplication(orgName, longInputName, longInputUrl, "Low")
				.saveApplication(orgName)
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(orgName)
				.clickViewAppLink("iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",orgName);

		
		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
		assertTrue("The length limit was incorrect for url.", 
				applicationDetailPage.clickDetailsLink().getUrlText().length() == Application.URL_LENGTH);
		
		appName = applicationDetailPage.getNameText();
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();
		
		// Test name duplication check
		teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
												.expandTeamRowByName(orgName)
												.addNewApplication(orgName, appName, "http://dummyurl", "Low")
												.saveApplicationInvalid(orgName);
		
		assertTrue("The duplicate message didn't appear correctly.", 
				teamIndexPage.getNameErrorMessage().contains("That name is already taken."));

		//cleanup
		loginPage = teamIndexPage.clickOrganizationHeaderLink()
										.clickViewTeamLink(orgName)
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
				.expandTeamRowByName(orgName)
				.addNewApplication(orgName, appName1, urlText1, "Low")
				.saveApplication(orgName);
	
		
		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
													.expandTeamRowByName(orgName)
													.clickViewAppLink(appName1, orgName);

		assertTrue("The name was not preserved correctly.", 
					appName1.equals(applicationDetailPage.getNameText()));
		assertTrue("The URL was not preserved correctly.", 
					urlText1.equals(applicationDetailPage.clickDetailsLink().getUrlText()));
		
		applicationDetailPage = applicationDetailPage.clickEditLink()
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
													.expandTeamRowByName(orgName);
		
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
		String orgName = "testCreateApplicationOrg312";
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
										.setTeamName(orgName)
										.addNewTeam()
										.expandTeamRowByName(orgName)
										.addNewApplication(orgName, appName2, validUrlText, "Low")
										.saveApplication(orgName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByName(orgName)
										.addNewApplication(orgName, appName, validUrlText, "Low")
										.saveApplication(orgName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByName(orgName)
										.clickViewAppLink(appName,orgName)
										.clickEditLink()
										.clickUpdateApplicationButton();
		
		
		
		assertTrue("The name was not preserved correctly.", 
				appName.equals(applicationDetailPage.getNameText()));
		assertTrue("The URL was not preserved correctly.", 
				validUrlText.equals(applicationDetailPage.clickDetailsLink().getUrlText()));

		// Test blank input		
		applicationDetailPage = applicationDetailPage.clickEditLink()
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
				applicationEditPage.getUrlError().equals("Not a valid URL"));

		// Test name duplication check
		applicationDetailPage = applicationDetailPage.setNameInput(appName2)
												 .setUrlInput("http://dummyurl")
												 .clickUpdateApplicationButtonInvalid();

		assertTrue("The duplicate message didn't appear correctly.", 
				applicationEditPage.getNameError().equals("That name is already taken."));

		// Test browser field length limits
		applicationDetailPage = applicationDetailPage.setNameInput(longInputName)
												   .setUrlInput(longInputUrl)
												   .clickUpdateApplicationButton();

		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
		assertTrue("The length limit was incorrect for url.", 
				applicationDetailPage.clickDetailsLink().getUrlText().length() == Application.URL_LENGTH);
				
		//cleanup
		loginPage = applicationDetailPage.clickDeleteLink()
										.clickTextLinkInApplicationsTableBody(appName2)
										.clickDeleteLink()
										.clickDeleteButton()
										.logout();
	}
	
	@Test
	public void testAddWafAtApplicationCreationTimeAndDelete() {
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
										.expandTeamRowByName(orgName)
										.addNewApplication(orgName, appName, appUrl, "Low")
										.saveApplication(orgName)
										.clickOrganizationHeaderLink()
										.expandTeamRowByName(orgName)
										.clickViewAppLink(appName,orgName)
										.clickActionButton()
										.clickShowDetails()
										.clickAddWaf()
										.addWaf(wafName);
		
		assertTrue("The WAF was not added correctly.", 
				applicationDetailPage.getWafText().equals(wafName));	
		// Check that it also appears on the WAF page.
		wafDetailPage = applicationDetailPage.clickWafsHeaderLink()
											.clickRules(wafName);
		
		assertTrue("The WAF was not added correctly.", 
				wafDetailPage.isTextPresentInApplicationsTableBody(appName));
		
		// Attempt to delete the WAF and ensure that it is a failure because the Application is still there
		// If the page goes elsewhere, this call will fail.
		wafIndexPage = wafDetailPage.clickWafsHeaderLink()
								.clickDeleteWaf(wafName);
		
		// Delete app and org and make sure the Application doesn't appear in the WAFs table.
		wafDetailPage = wafIndexPage.clickOrganizationHeaderLink()
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
		String wafName1 = "firstWaf";
		String wafName2 = "wafToSwitch";
		String type1 = "Snort";
		String type2 = "mod_security";
		String orgName = "switchWafOrg";
		String appName = "switchWafApp";
		String appUrl = "http://testurl.com";
		
		// create WAFs and set up the application with one
		// then switch to the other one and verify that the switch has been made.
		applicationDetailPage = loginPage.login("user", "password")
										 .clickWafsHeaderLink()
										 .clickAddWafLink()
										 .createNewWaf(wafName1, type1)
										 .clickCreateWaf()
										 .clickAddWafLink()
										 .createNewWaf(wafName2, type2)
										 .clickCreateWaf()
										 .clickOrganizationHeaderLink()
										 .clickAddTeamButton()
										 .setTeamName(orgName)
										 .addNewTeam()
										 .expandTeamRowByName(orgName)
										 .addNewApplication(orgName, appName, appUrl, "Low")
										 .saveApplication(orgName)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByName(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickActionButton()
										 .clickShowDetails()
										 .clickAddWaf()
										 .addWaf(wafName1)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByName(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickActionButton()
										 .clickShowDetails()
										 .clickEditWaf()
										 .addWaf(wafName2)
										 .clickOrganizationHeaderLink()
										 .expandTeamRowByName(orgName)
										 .clickViewAppLink(appName,orgName)
										 .clickActionButton()
										 .clickShowDetails();
								
		assertTrue("The edit didn't change the application's WAF.", 
				applicationDetailPage.getWafText().contains(wafName2));
		
		//cleanup
		loginPage = applicationDetailPage.clickOrganizationHeaderLink()
										.clickViewTeamLink(orgName)
										.clickDeleteButton()
										.clickWafsHeaderLink()
										.clickDeleteWaf(wafName1)
										.clickDeleteWaf(wafName2)
										.logout();
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
