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
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class TeamIT extends BaseIT {

	@Test
	public void createTeamTest(){
		String teamName = getName();

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", teamIndexPage.isTeamPresent(teamName));

        teamIndexPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam(teamName);

		assertTrue("The validation is not present", teamIndexPage.isCreateValidationPresent(teamName));
		assertTrue("The organization was not present in the table.", teamIndexPage.isTeamPresent(teamName));
	}

    @Test
    public void createTeamValidation(){
        String emptyString = "";
        String whiteSpaceString = "           ";

        String emptyInputError = "Name is required.";

        // Test empty input
        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickAddTeamButton()
                .setTeamName(emptyString)
                .addNewTeamInvalid();

        assertTrue("The correct error text was not present",
                emptyInputError.equals(teamIndexPage.getErrorMessage("requiredError")));

        // Test whitespace input
        teamIndexPage = teamIndexPage.setTeamName(whiteSpaceString)
                .addNewTeamInvalid();
        assertTrue("The correct error text was not present",
                emptyInputError.equals(teamIndexPage.getErrorMessage("requiredError")));
    }

    @Test
    public void createTeamNameLengthValidation() {
        String newOrgName = getRandomString(70);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickAddTeamButton()
                .setTeamName(newOrgName);

        assertTrue("Header width was incorrect with long team name",
                teamIndexPage.getLengthError().contains("Maximum length is 60."));
    }

    @Test
    public void editTeamTest(){
        String newTeamName = getName();
        String editedTeamName = getName();
        DatabaseUtils.createTeam(newTeamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(newTeamName)
                .clickEditOrganizationLink()
                .setNameInput(editedTeamName)
                .clickUpdateButtonValid();

        assertTrue("Editing did not change the name.", teamDetailPage.getOrgName().contains(editedTeamName));

        teamIndexPage = teamDetailPage.clickOrganizationHeaderLink();
        assertTrue("Organization Page did not save the name correctly.",  teamIndexPage.isTeamPresent(editedTeamName));
    }

    @Test
    public void editTeamWithApplicationTest() {
        String originalTeamName = getName();
        String editedTeamName = getName();
        String appName = getName();

        DatabaseUtils.createTeam(originalTeamName);
        DatabaseUtils.createApplication(originalTeamName, appName);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(originalTeamName)
                .clickEditOrganizationLink()
                .setNameInput(editedTeamName)
                .clickModalSubmit();

        assertTrue("Success alert was not displayed.", teamDetailPage.isSuccessMessageDisplayed());
        assertTrue("Team name was not edited correctly.", teamDetailPage.isTeamNameDisplayedCorrectly(editedTeamName));
    }

    @Test
    public void editTeamValidation(){
        String orgName = getName();
        String orgNameDuplicateTest = getName();

        String emptyInputError = "Name is required.";

        String longInput = getRandomString(119);

        DatabaseUtils.createTeam(orgName);
        DatabaseUtils.createTeam(orgNameDuplicateTest);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
                .clickViewTeamLink(orgName);

        // Test edit with no changes
        teamDetailPage = teamDetailPage.clickEditOrganizationLink()
                .clickUpdateButtonValid();
        assertTrue("Organization Page did not save the name correctly.",teamDetailPage.getOrgName().contains(orgName));

        // Test empty input
        teamDetailPage = teamDetailPage.clickEditOrganizationLink()
                .setNameInput("")
                .clickUpdateButtonInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(teamDetailPage.getErrorMessage("requiredError")));

        // Test whitespace input
        teamDetailPage = teamDetailPage.setNameInput("           ")
                .clickUpdateButtonInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(teamDetailPage.getErrorMessage("requiredError")));

        orgName = longInput.substring(0, 60);

        teamDetailPage = teamDetailPage.setNameInput(orgName)
                .clickUpdateButtonValid();

        assertTrue("The organization name was not cropped correctly.", teamDetailPage.isTeamNameDisplayedCorrectly(orgName));
    }

    @Test
    public void viewMoreTest() {
        String teamName = createTeam();

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName);

        assertTrue("View Team link did not work properly.", teamDetailPage.isTeamNameDisplayedCorrectly(teamName));
    }

    @Test
    public void teamGraphsTest() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String file = ScanContents.getScanFilePath();

        DatabaseUtils.uploadScan(teamName, appName, file);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The graph of the expanded team was not shown properly.",
                teamIndexPage.isGraphDisplayed(teamName));
    }

    @Test
    public void expandAndCollapseSingleTeamTest() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName);

        assertTrue("Team was not expanded properly.", teamIndexPage.isAppDisplayed(teamName, appName));

        teamIndexPage.collapseTeamRowByName(teamName);

        assertFalse("Team was not collapsed properly.", teamIndexPage.isAppDisplayed(teamName, appName));
    }

    @Test
    public void expandAndCollapseAllTeamsTest(){
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName1 = createApplication(teamName1);
        String appName2 = createApplication(teamName2);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandAllTeams();
        assertTrue("Applications are not collapsed", teamIndexPage.isTeamsExpanded(teamName1,appName1));
        assertTrue("Applications are not collapsed", teamIndexPage.isTeamsExpanded(teamName2,appName2));

        //note the logic change in assert method call
        teamIndexPage = teamIndexPage.collapseAllTeams();
        assertFalse("Applications are not collapsed", teamIndexPage.isTeamsExpanded(teamName1, appName1));
        assertFalse("Applications are not collapsed", teamIndexPage.isTeamsExpanded(teamName2, appName2));
    }

    @Test
    public void deleteTeamTest() {
        String teamName = createTeam();

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName);

        TeamIndexPage teamIndexPage = teamDetailPage.clickDeleteButton();

        assertFalse("Team should have been deleted.", teamIndexPage.isTeamPresent(teamName));
    }
}
