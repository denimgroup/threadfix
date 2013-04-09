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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.selenium.pages.AddOrganizationPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationEditPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class OrganizationTests extends BaseTest {
	
	private WebDriver driver;
	private static LoginPage loginPage;
	
	private TeamIndexPage organizationIndexPage;
	private TeamDetailPage organizationDetailPage;
	private OrganizationEditPage editOrganizationPage;
	private AddOrganizationPage addOrganizationPage;
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	

	
	@Test
	public void testCreateOrganization(){
		String newOrgName = "testCreateOrganization";
		
		organizationIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", organizationIndexPage.isOrganizationNamePresent(newOrgName));
		
		organizationIndexPage = organizationIndexPage.clickAddTeamButton()
													.addNewTeam(newOrgName);
		
		assertTrue("The organization was not present in the table.", organizationIndexPage.isOrganizationNamePresent(newOrgName));

		organizationIndexPage = organizationIndexPage.expandTeamRowByName(newOrgName)
													.clickViewTeamLink()
													.clickDeleteButton();
		assertFalse("The organization was still present after attempted deletion.", organizationIndexPage.isOrganizationNamePresent(newOrgName));
	
		loginPage = organizationIndexPage.logout();
	}
	
	@Test
	public void testCreateOrganizationBoundaries(){
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

		// Test empty input
		organizationIndexPage = loginPage.login("user", "password")
									.clickOrganizationHeaderLink()
									.clickAddTeamButton()
									.setNameInput(emptyString)
									.clickSubmitButtonInvalid();
		
		assertTrue("The correct error text was not present", emptyInputError.equals(organizationIndexPage.getNameErrorMessage()));
		
		// Test whitespace input
		organizationIndexPage = organizationIndexPage.setNameInput(whiteSpaceString)
												 .clickSubmitButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(organizationIndexPage.getNameErrorMessage()));
		
		// Test browser length limit
		organizationIndexPage = organizationIndexPage.setNameInput(longInput)
													.clickSubmitButtonValid();
		
		assertTrue("The organization name was not cropped correctly.", organizationIndexPage.getTeamName(1).length() == Organization.NAME_LENGTH);
		
		// Test name duplication checking
		
		String orgName = organizationIndexPage.getTeamName(1);
		
		organizationIndexPage = organizationIndexPage.clickOrganizationHeaderLink()
													.clickAddTeamButton()
													.setNameInput(orgName)
													.clickSubmitButtonInvalid();
		
		assertTrue(organizationIndexPage.getNameErrorMessage().equals("That name is already taken."));
		
		// Delete and logout
		loginPage = organizationIndexPage.clickOrganizationHeaderLink()
									.expandTeamRowByName(orgName)
									.clickViewTeamLink()
									.clickDeleteButton()
									.logout();
	}
	
	@Test
	public void testEditOrganization(){
		String newOrgName = "testEditOrganization";
		String editedOrgName = "testEditOrganization - edited";
		
		organizationIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		assertFalse("The organization was already present.", organizationIndexPage.isOrganizationNamePresent(newOrgName));
		
		// Save an organization
		organizationIndexPage = organizationIndexPage.clickAddTeamButton()
													 .addNewTeam(newOrgName);
		assertTrue("Organization Page did not save the name correctly.",  organizationIndexPage.isOrganizationNamePresent(newOrgName));
		
		// Edit that organization
		organizationDetailPage = organizationIndexPage.clickOrganizationHeaderLink()
													.expandTeamRowByName(newOrgName)
													.clickViewTeamLink().clickEditOrganizationLink()
													.setNameInput(editedOrgName)
													.clickUpdateButtonValid();
		assertTrue("Editing did not change the name.", editedOrgName.equals(organizationDetailPage.getOrgName()));
		
		organizationIndexPage = organizationDetailPage.clickOrganizationHeaderLink()
													.expandTeamRowByName(newOrgName)
													.clickViewTeamLink()
													.clickDeleteButton();
		
		assertFalse("The organization was still present after attempted deletion.", organizationIndexPage.isOrganizationNamePresent(newOrgName));
	
		loginPage = organizationIndexPage.logout();
	}
	
	@Test
	public void testEditOrganizationBoundaries(){
		String orgName = "testEditOrganizationBoundaries";
		String orgNameDuplicateTest = "testEditOrganizationBoundaries2";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		organizationDetailPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
																.clickAddTeamButton()
																.addNewTeam(orgName)
																.clickAddTeamButton()
																.addNewTeam(orgNameDuplicateTest)
																.expandTeamRowByName(orgName)
																.clickViewTeamLink();
		
		// Test edit with no changes
		organizationDetailPage = organizationDetailPage.clickEditOrganizationLink().clickUpdateButtonValid();
		assertTrue("Organization Page did not save the name correctly.", orgName.equals(organizationDetailPage.getOrgName()));
		
		// Test empty input
		editOrganizationPage = organizationDetailPage.clickEditOrganizationLink()
													 .setNameInput(emptyString)
													 .clickUpdateButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(editOrganizationPage.getErrorText()));
		
		// Test whitespace input
		editOrganizationPage = editOrganizationPage.setNameInput(whiteSpaceString)
												   .clickUpdateButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(editOrganizationPage.getErrorText()));
		
		// Test browser length limit
		organizationDetailPage = editOrganizationPage.setNameInput(longInput)
													 .clickUpdateButtonValid();
		orgName = organizationDetailPage.getOrgName();
		
		assertTrue("The organization name was not cropped correctly.", organizationDetailPage.getOrgName().length() == Organization.NAME_LENGTH);
		
		// Test name duplication checking
		editOrganizationPage = organizationDetailPage.clickEditOrganizationLink()
													 .setNameInput(orgNameDuplicateTest)
													 .clickUpdateButtonInvalid();
		
		assertTrue(editOrganizationPage.getErrorText().equals("That name is already taken."));
				
		// Delete and logout
		loginPage = editOrganizationPage.clickOrganizationHeaderLink()
									.expandTeamRow(1)
									.clickViewTeamLink()
									.clickDeleteButton()
									.clickOrganizationHeaderLink()
									.expandTeamRow(1)
									.clickViewTeamLink()
									.clickDeleteButton()
									.logout();
	}
}
