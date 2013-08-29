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
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class TeamTests extends BaseTest {
	
	public TeamTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private RemoteWebDriver driver;
	private static LoginPage loginPage;
	
	private TeamIndexPage teamIndexPage;
	private TeamDetailPage teamDetailPage;
	
	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	

	
	@Test
	public void testCreateTeam(){
		String newOrgName = "testCreateOrganization";
		
		teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", teamIndexPage.isTeamPresent(newOrgName));
		
		teamIndexPage = teamIndexPage.clickAddTeamButton()
								.setTeamName(newOrgName)
								.addNewTeam();
		assertTrue("The validation is not present",teamIndexPage.isCreateValidtionPresent(newOrgName));
		assertTrue("The organization was not present in the table.", teamIndexPage.isTeamPresent(newOrgName));

		teamIndexPage = teamIndexPage.clickViewTeamLink(newOrgName)
									.clickDeleteButton();
		assertFalse("The organization was still present after attempted deletion.", teamIndexPage.isTeamPresent(newOrgName));
	
		loginPage = teamIndexPage.logout();
	}
	
	@Test
	public void longTeamNameEditModalHeader(){
		String newOrgName = getRandomString(1024);
		teamDetailPage = loginPage.login("user", "password")
								.clickOrganizationHeaderLink()
								.clickAddTeamButton()
								.setTeamName(newOrgName)
								.addNewTeam()
								.clickViewTeamLink(newOrgName.substring(0,60))
								.clickEditOrganizationLink();
		int width = teamDetailPage.getEditModalHeaderWidth();
		teamDetailPage.clickCloseEditModal().clickDeleteButton();
		
		assertTrue("Header width was incorrect with long team name",width == 400);
		
		
	}
	
	@Test
	public void testCreateOrganizationBoundaries(){
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

		// Test empty input
		teamIndexPage = loginPage.login("user", "password")
									.clickOrganizationHeaderLink()
									.clickAddTeamButton()
									.setTeamName(emptyString)
									.addNewTeamInvalid();
		
		assertTrue("The correct error text was not present", emptyInputError.equals(teamIndexPage.getNameErrorMessage()));
		
		// Test whitespace input
		teamIndexPage = teamIndexPage.setTeamName(whiteSpaceString)
												 .addNewTeamInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(teamIndexPage.getNameErrorMessage()));
		
		// Test browser length limit
		teamIndexPage = teamIndexPage.setTeamName(longInput)
									.addNewTeam();
		String orgName ="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		assertTrue("The organization name was not cropped correctly.", teamIndexPage.isTeamPresent(orgName));
		
		// Test name duplication checking
		
		
		teamIndexPage = teamIndexPage.clickOrganizationHeaderLink()
													.clickAddTeamButton()
													.setTeamName(orgName)
													.addNewTeamInvalid();
		
		assertTrue(teamIndexPage.getNameErrorMessage().equals("That name is already taken."));
		
		// Delete and logout
		loginPage = teamIndexPage.clickCloseAddTeamModal()
									.clickViewTeamLink(orgName)
									.clickDeleteButton()
									.logout();
	}
	@Test
	public void testEditOrganization(){
		String newOrgName = "testEditOrganization";
		String editedOrgName = "testEditOrganization - edited";
		
		teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", teamIndexPage.isTeamPresent(newOrgName));
		
		// Save an organization
		teamIndexPage = teamIndexPage.clickAddTeamButton()
									.setTeamName(newOrgName)
									.addNewTeam();
		assertTrue("Organization Page did not save the name correctly.",  teamIndexPage.isTeamPresent(newOrgName));
		
		// Edit that organization
		teamDetailPage = teamIndexPage.clickOrganizationHeaderLink()
													.clickViewTeamLink(newOrgName)
													.clickEditOrganizationLink()
													.setNameInput(editedOrgName)
													.clickUpdateButtonValid();
		assertTrue("Editing did not change the name.", teamDetailPage.getOrgName().contains(editedOrgName));
		
		teamIndexPage = teamDetailPage.clickOrganizationHeaderLink();
		assertTrue("Organization Page did not save the name correctly.",  teamIndexPage.isTeamPresent(editedOrgName));
		teamIndexPage = teamIndexPage.clickViewTeamLink(editedOrgName)
									.clickDeleteButton();
		
		assertFalse("The organization was still present after attempted deletion.", teamIndexPage.isTeamPresent(editedOrgName));
	
		loginPage = teamIndexPage.logout();
	}
	//selenium issue
	@Ignore
	@Test
	public void testEditOrganizationBoundaries(){
		String orgName = "testEditOrganizationBoundaries";
		String orgNameDuplicateTest = "testEditOrganizationBoundaries2";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		teamDetailPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
																.clickAddTeamButton()
																.setTeamName(orgName)
																.addNewTeam()
																.clickAddTeamButton()
																.setTeamName(orgNameDuplicateTest)
																.addNewTeam()
																.clickViewTeamLink(orgName);
		
		// Test edit with no changes
		teamDetailPage = teamDetailPage.clickEditOrganizationLink().clickUpdateButtonValid();
		assertTrue("Organization Page did not save the name correctly.",teamDetailPage.getOrgName().contains(orgName));
		
		// Test empty input
		teamDetailPage = teamDetailPage.clickEditOrganizationLink()
													 .setNameInput(emptyString)
													 .clickUpdateButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(teamDetailPage.getErrorText()));
		
		// Test whitespace input
		teamDetailPage = teamDetailPage.setNameInput(whiteSpaceString)
												   .clickUpdateButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(teamDetailPage.getErrorText()));
		
		// Test browser length limit
		teamDetailPage = teamDetailPage.clickCloseEditModal()
													.clickEditOrganizationLink()
													.setNameInput(longInput)
													 .clickUpdateButtonValid();
		
		orgName = longInput.substring(0, Organization.NAME_LENGTH+1);
		
		assertTrue("The organization name was not cropped correctly.", teamDetailPage.getOrgName().equals(orgName));
		orgName = longInput.substring(0,Organization.NAME_LENGTH);
		
		// Test name duplication checking
		teamDetailPage = teamDetailPage.clickEditOrganizationLink()
													 .setNameInput(orgNameDuplicateTest)
													 .clickUpdateButtonInvalid();
		
		assertTrue(teamDetailPage.getErrorText().equals("That name is already taken."));
				
		// Delete and logout
		loginPage = teamDetailPage.clickOrganizationHeaderLink()
									.clickViewTeamLink(orgName)
									.clickDeleteButton()
									.clickOrganizationHeaderLink()
									.clickViewTeamLink(orgNameDuplicateTest)
									.clickDeleteButton()
									.logout();
	}
	
	@Test
	public void switchAppTeam(){
		String team1 = getRandomString(8);
		String team2 = getRandomString(8);
		String appName = getRandomString(8);
		TeamDetailPage adp = loginPage.login("user", "password").clickOrganizationHeaderLink()
								.clickAddTeamButton()
								.setTeamName(team1)
								.addNewTeam()
								.clickAddTeamButton()
								.setTeamName(team2)
								.addNewTeam()
								.expandTeamRowByName(team1)
								.addNewApplication(team1, appName, "", "Low")
								.saveApplication(team1)
								.clickOrganizationHeaderLink()
								.expandTeamRowByName(team1)
								.clickViewAppLink(appName, team1)
								.clickEditDeleteBtn()
								.setTeam(team2)
								.clickUpdateApplicationButton()
								.clickOrganizationHeaderLink()
								.clickViewTeamLink(team1);
		
		Boolean oneBool = adp.isAppPresent(appName);
		
		adp = adp.clickOrganizationHeaderLink()
				.clickViewTeamLink(team2);
		
		Boolean twoBool = adp.isAppPresent(appName);
		

		adp.clickOrganizationHeaderLink()
					.clickViewTeamLink(team1)
					.clickDeleteButton()
					.clickOrganizationHeaderLink()
					.clickViewTeamLink(team2)
					.clickDeleteButton()
					.logout();
		
		assertTrue("app was not switched properly", !oneBool && twoBool);
	}
}
