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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TeamTests extends BaseTest {

	private static LoginPage loginPage;
	
	private TeamIndexPage teamIndexPage;
	private TeamDetailPage teamDetailPage;
    private ApplicationDetailPage applicationDetailPage;

	@Test
	public void testCreateTeam(){
		String newOrgName = "testCreateOrganization";

		teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", teamIndexPage.isTeamPresent(newOrgName));

        teamIndexPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(newOrgName)
                .addNewTeam();

		assertTrue("The validation is not present", teamIndexPage.isCreateValidationPresent(newOrgName));
		assertTrue("The organization was not present in the table.", teamIndexPage.isTeamPresent(newOrgName));

		teamIndexPage = teamIndexPage.clickViewTeamLink(newOrgName)
									.clickDeleteButton();

		assertFalse("The organization was still present after attempted deletion.", teamIndexPage.isTeamPresent(newOrgName));
	
		loginPage = teamIndexPage.logout();
	}

    @Test
    public void testExpandAndCollapseIndividualTeam(){
        String teamName = getRandomString(8);

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .expandTeamRowByIndex(teamName);

        // TODO use DatabaseUtils.createTeam(newOrgName); instead of page objects.

        assertTrue("Team info was not expanded properly.", teamIndexPage.isTeamExpanded(teamName));

        teamIndexPage = teamIndexPage.expandTeamRowByIndex(teamName);

        assertFalse("Team info was not collapsed properly.", teamIndexPage.isTeamExpanded(teamName));

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    // TODO possible deletion due to tables having a height of zero, the aren't 'not displayed'
    @Ignore
    @Test
    public void testExpandAndCollapseAllTeams(){
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName1)
                .addNewTeam()
                .clickAddTeamButton()
                .setTeamName(teamName2)
                .addNewTeam()
                .expandAllTeams();

        assertTrue("All teams were not expanded properly.", teamIndexPage.areAllTeamsExpanded());

        teamIndexPage = teamIndexPage.collapseAllTeams();

         assertTrue("All teams were not collapsed properly.", teamIndexPage.areAllTeamsCollapsed());

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName1)
                .clickDeleteButton()
                .clickViewTeamLink(teamName2)
                .clickDeleteButton();

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

        TeamIndexCache.getCache().deleteTeamWithName(newOrgName);
        TeamIndexCache.getCache().addTeamWithName(editedOrgName);

		assertTrue("Editing did not change the name.", teamDetailPage.getOrgName().contains(editedOrgName));
		
		teamIndexPage = teamDetailPage.clickOrganizationHeaderLink();
		assertTrue("Organization Page did not save the name correctly.",  teamIndexPage.isTeamPresent(editedOrgName));
		teamIndexPage = teamIndexPage.clickViewTeamLink(editedOrgName)
									.clickDeleteButton();
		
		assertFalse("The organization was still present after attempted deletion.", teamIndexPage.isTeamPresent(editedOrgName));
	
		loginPage = teamIndexPage.logout();
	}

    @Test
    public void testViewMore() {
        String teamName = getRandomString(8);

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .clickViewTeamLink(teamName);

        assertTrue("View Team link did not work properly.", teamDetailPage.isTeamNameDisplayedCorrectly(teamName));

        teamIndexPage = teamDetailPage.clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    // TODO Wait for the graphs to have id's, then test
    @Ignore
    @Test
    public void testTeamGraphs() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication(teamName)
                .clickUploadScan(appName,teamName)
                .setFileInput("test")
                .clickUploadScanButton(appName);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByIndex(teamName);

        assertFalse("The graph of the expanded team was not shown properly.", teamIndexPage.isGraphDisplayed(teamName,appName));

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickDeleteButton();

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

		TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
								.clickAddTeamButton()
								.setTeamName(team1)
								.addNewTeam()
								.clickAddTeamButton()
								.setTeamName(team2)
								.addNewTeam();

        TeamDetailPage teamDetailPage = teamIndexPage
								.expandTeamRowByIndex(team1)
								.addNewApplication(team1, appName, "", "Low")
								.saveApplication(team1)
								.clickOrganizationHeaderLink()
								.expandTeamRowByIndex(team1)
								.clickViewAppLink(appName,team1)
								.clickEditDeleteBtn()
								.setTeam(team2)
								.clickUpdateApplicationButton()
								.clickOrganizationHeaderLink()
								.clickViewTeamLink(team1);
		
		Boolean oneBool = teamDetailPage.isAppPresent(appName);

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
				.clickViewTeamLink(team2);
		
		Boolean twoBool = teamDetailPage.isAppPresent(appName);

        teamDetailPage.clickOrganizationHeaderLink()
					.clickViewTeamLink(team1)
					.clickDeleteButton().clickOrganizationHeaderLink();

        teamIndexPage.clickViewTeamLink(team2)
				.clickDeleteButton()
				.logout();
		
		assertTrue("app was not switched properly", !oneBool && twoBool);
	}
}
