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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DefectTrackerTests extends BaseTest {

	public DefectTrackerTests(String browser) {
		super(browser);
	}

	private RemoteWebDriver driver;
	private static LoginPage loginPage;

	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	private static final String TEST_JIRA_URL = DefectTrackerIndexPage.JIRA_URL;
	private static String JIRA_USERNAME = null;
	private static String JIRA_PASSWORD = null;
	private static String JIRA_URL = null;
	private static String JIRA_PROJECTNAME = null;
	private static String BUGZILLA_USERNAME = null;
	private static String BUGZILLA_PASSWORD = null;
	private static String BUGZILLA_URL = null;
	private static String BUGZILLA_PROJECTNAME = "For ThreadFix";
	private static String TFS_USERNAME = null;
	private static String TFS_PASSWORD = null;
	private static String TFS_URL = null;
	private static String TFS_PROJECTNAME = null;

	String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver) super.getDriver();
		loginPage = LoginPage.open(driver);
		assignVars();
	}

	private void assignVars() {
		String tmp = System.getProperty("JIRA_USERNAME");
		if (tmp != null) {
			JIRA_USERNAME = tmp;
		}
		tmp = System.getProperty("JIRA_PASSWORD");
		if (tmp != null) {
			JIRA_PASSWORD = tmp;
		}
		tmp = System.getProperty("JIRA_URL");
		if (tmp != null) {
			JIRA_URL = tmp;
		}
		tmp = System.getProperty("JIRAPROJECTNAME");
		if (tmp != null) {
			JIRA_PROJECTNAME = tmp;
		}
		tmp = System.getProperty("BUGZILLA_USERNAME");
		if (tmp != null) {
			BUGZILLA_USERNAME = tmp;
		}
		tmp = System.getProperty("BUGZILLA_PASSWORD");
		if (tmp != null) {
			BUGZILLA_PASSWORD = tmp;
		}
		tmp = System.getProperty("BUGZILLA_URL");
		if (tmp != null) {
			BUGZILLA_URL = tmp;
		}
		tmp = System.getProperty("BUGZILLAPROJECTNAME");
		if (tmp != null) {
			BUGZILLA_PROJECTNAME = tmp;
		}
		tmp = System.getProperty("TFS_USERNAME");
		if (tmp != null) {
			TFS_USERNAME = tmp;
		}
		tmp = System.getProperty("TFS_PASSWORD");
		if (tmp != null) {
			TFS_PASSWORD = tmp;
		}
		tmp = System.getProperty("TFS_URL");
		if (tmp != null) {
			TFS_URL = tmp;
		}
		tmp = System.getProperty("TFS_PROJNAME");
		if (tmp != null) {
			TFS_PROJECTNAME = tmp;
		}
	}

	// old numbering scheme is being used for edit and delete buttons waiting
	// for that change
	@Test
	public void testCreateDefectTracker() {
		String newDefectTrackerName = "testCreateDefectTracker"+ getRandomString(10);
		String type = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse(
				"The defectTracker was already present.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage.enterName(null, newDefectTrackerName)
				.enterType(null, type).enterURL(null, TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		assertTrue("The defectTracker was not present in the table.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(newDefectTrackerName);
		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.logout();
	}

	@Test
	public void testCreateDefectTrackerBoundaries() {
		String emptyString = "";
		String whiteSpaceString = "           ";
		String urlFormatString = "asdfwe";

		String emptyInputError = "This field cannot be blank";
		String urlError = "Not a valid URL";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		// Test empty and whitespace input
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, emptyString).enterURL(null, emptyString)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getUrlErrorsText()));

		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, whiteSpaceString)
				.enterURL(null, whiteSpaceString)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				urlError.equals(defectTrackerIndexPage.getUrlErrorsText()));

		// Test URL format checking
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, "normal name").enterURL(null, urlFormatString)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue("The URL format check error text was not present.",
				defectTrackerIndexPage.getUrlErrorsText().equals(urlError));

		// Test url validation
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, longInput)
				.enterURL(null, "http://" + longInput)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue(
				"The Defect Tracker URL was not validated correctly.",
				defectTrackerIndexPage.getUrlErrorsText().equals(
						"URL is invalid."));

		// Test browser length limit
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				longInput).enterURL(null, TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		// might need to change the row number that this is checking
		assertTrue(
				"The Defect Tracker name was not cropped correctly.",
				defectTrackerIndexPage.getDefectTrackerName(1).length() == DefectTracker.NAME_LENGTH);

		// Test name duplication checking
		String orgName = defectTrackerIndexPage.getDefectTrackerName(1);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDefectTrackersLink().clickAddDefectTrackerButton();
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, orgName).enterURL(null, TEST_BUGZILLA_URL)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals(
				"That name is already taken."));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickCloseCreateDT().clickDeleteButton(orgName);
	}

	// TODO improve this test - harder to fake with URL checking.
	@Test
	public void testEditDefectTracker() {
		String newDefectTrackerName = "testEditDefectTracker"+ getRandomString(10);
		String editedDefectTrackerName = "testEditDefectTracker-edit"+ getRandomString(10);

		String type1 = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse(
				"The defectTracker was already present.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, newDefectTrackerName).enterType(null, type1)
				.enterURL(null, TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		assertTrue("DefectTracker Page did not save the name correctly.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));
		assertTrue("DefectTracker Page did not save the type correctly.",
				defectTrackerIndexPage.doesTypeExistForName(
						newDefectTrackerName, type1));
		assertTrue("DefectTracker Page did not save the URL correctly.",
				defectTrackerIndexPage.doesURLExistForName(
						newDefectTrackerName, TEST_BUGZILLA_URL));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(
				newDefectTrackerName, editedDefectTrackerName);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue("Editing did not change the name.",
				defectTrackerIndexPage
						.doesNameExist(editedDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDefectTrackersLink().clickDeleteButton(editedDefectTrackerName);

		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.logout();
	}

	// TODO improve this test - harder to fake with URL checking.
	@Test
	public void testDeleteDefectTracker() {
		String newDefectTrackerName = "testEditDefectTracker"+ getRandomString(10);
		String type1 = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse("The defectTracker was already present.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, newDefectTrackerName).enterType(null, type1)
				.enterURL(null, TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(newDefectTrackerName)
													.clickDefectTrackersLink();

		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.logout();
	}

	// Not working yet
	@Test
	@Ignore
	public void testEditDefectTrackerBoundaries() {
		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker-edit";

		String type2 = "Bugzilla";

		String emptyString = "";
		String whiteSpaceString = "           ";

		String emptyInputError = "This field cannot be blank";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		// create Dummy WAF
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, defectTrackerNameDuplicateTest)
				.enterType(null, type2).enterURL(null, TEST_BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterName(null, newDefectTrackerName).enterType(null, type2)
				.enterURL(null, TEST_BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		// Test submission with no changes
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not save the name correctly.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));
		assertTrue("DefectTracker Page did not save the type correctly.",
				defectTrackerIndexPage.doesTypeExistForName(
						newDefectTrackerName, type2));
		assertTrue("DefectTracker Page did not save the url correctly.",
				defectTrackerIndexPage.doesURLExistForName(
						newDefectTrackerName, TEST_BUGZILLA_URL));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		// Test empty and whitespace input
		defectTrackerIndexPage.enterName(newDefectTrackerName, emptyString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButtonInvalid();

		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));

		defectTrackerIndexPage
				.enterName(newDefectTrackerName, whiteSpaceString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));

		// Test browser length limit
		defectTrackerIndexPage.enterName(newDefectTrackerName, longInput);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		newDefectTrackerName = defectTrackerIndexPage.getNameText(1);

		assertTrue(
				"The defectTracker name was not cropped correctly.",
				defectTrackerIndexPage.getNameText(1).length() == DefectTracker.NAME_LENGTH);

		// Test name duplication checking
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(defectTrackerNameDuplicateTest);
		defectTrackerIndexPage.setNameInput(defectTrackerNameDuplicateTest);
		defectTrackerIndexPage.clickUpdateDefectTrackerButtonInvalid();
		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals(
				"That name is already taken."));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(
				newDefectTrackerName).clickDeleteButton(
				defectTrackerNameDuplicateTest);

		loginPage = defectTrackerIndexPage.logout();
	}

	// Certificate Problems
	@Test
    @Ignore
	public void TFSCreate() {
		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String url = "https://tfs.denimgroup.com:8080";
		String type2 = "Microsoft TFS";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(null, type2);
		defectTrackerIndexPage = defectTrackerIndexPage.enterURL(null, url);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(
				newDefectTrackerName, newDefectTrackerName + " - edited");
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(
				newDefectTrackerName, type2);
		defectTrackerIndexPage = defectTrackerIndexPage.enterURL(
				newDefectTrackerName, url);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue(
				"DefectTracker Page did not create correctly.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(
				newDefectTrackerName).clickDefectTrackersLink();

		assertFalse(
				"DefectTracker Page did delete.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.clickDefectTrackersLink().logout();
	}

	@Test
	@Ignore
	public void TFSEdit() {
		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String url = "https://tfs.denimgroup.com:8080";
		String type2 = "Microsoft TFS";
		String replacementName = "replacementDefectTracker"
				+ getRandomString(10);

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type2);
		defectTrackerIndexPage.setUrlInput(url);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not create correctly.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(
				newDefectTrackerName).setNameInput(replacementName);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not edit correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDeleteButton(replacementName);

		loginPage = defectTrackerIndexPage.logout();
	}

	@Test
	public void jiraEdit() {
		String newDefectTrackerName = "testEditDefectTracker" + getRandomString(4);
		String type2 = "Jira";
		String replacementName = "replacementDefectTracker" + getRandomString(4);

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
																.clickDefectTrackersLink()
																.clickAddDefectTrackerButton()
																.enterName(null, newDefectTrackerName)
																.enterType(null, type2)
																.enterURL(null, TEST_JIRA_URL)
																.clickSaveNewDefectTracker()
																.clickEditLink(newDefectTrackerName)
																.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not create correctly.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
													.enterName(newDefectTrackerName,replacementName)
													.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not edit correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
													.clickDeleteButton(replacementName);
	}

	@Test
	public void jiraCreate() {
		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String type2 = "Jira";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
														.enterName(null,newDefectTrackerName)
														.enterType(null, type2)
														.enterURL(null,TEST_JIRA_URL)
														.clickSaveNewDefectTracker();

		assertTrue("DefectTracker Page did not create correctly.",
					defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(newDefectTrackerName)
														.clickDefectTrackersLink();

		assertFalse("DefectTracker Page did not delete.",
					defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.clickDefectTrackersLink().logout();
	}

	@Test
	public void bugzillaEdit() {
		String newDefectTrackerName = "testEditDefectTracker" + getRandomString(4);
		String type2 = "Bugzilla";
		String replacementName = "replacementDefectTracker" + getRandomString(4);

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
																	.clickDefectTrackersLink()
																	.clickAddDefectTrackerButton()
																	.enterName(null, newDefectTrackerName)
																	.enterType(null, type2)
																	.enterURL(null, "http://10.2.10.145/bugzilla/")
																	.clickSaveNewDefectTracker()
																	.clickEditLink(newDefectTrackerName)
																	.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not create correctly.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
														.enterName(newDefectTrackerName,replacementName)
														.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not edit correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
													.clickDeleteButton(replacementName);
	}

	@Test
	public void testAttachToAppBugzillaTracker() {
		assertFalse("BUGZILLA_PASSWORD is not assigned from system properties",
				BUGZILLA_PASSWORD == null);
		assertFalse("BUGZILLA_USERNAME is not assigned from system properties",
				BUGZILLA_USERNAME == null);
		assertFalse("BUGZILLA_URL is not assigned from system properties",
				BUGZILLA_URL == null);
		assertFalse(
				"BUGZILLA_PROJECTNAME is not assigned from system properties",
				BUGZILLA_PROJECTNAME == null);

		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String type = "Bugzilla";
		String teamName = "bugzillaAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);
		String urlText = "http://test.com";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(null, type);
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterURL(null, BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(newDefectTrackerName, BUGZILLA_USERNAME,
						BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn()
						.isDefectTrackerAttached());

		applicationDetailPage = applicationDetailPage.clickCloseAppModal();
		sleep(1500);
		loginPage = applicationDetailPage.clickOrganizationHeaderLink()
										.clickViewTeamLink(teamName)
										.clickDeleteButton()
										.clickDefectTrackersLink()
										.clickDeleteButton(newDefectTrackerName)
										.logout();
	}


	@Test
    @Ignore
	public void testAttachToAppTFSTracker() {
		assertFalse("TFS_PASSWORD is not assigned from system properties",
				TFS_PASSWORD == null);
		assertFalse("TFS_USERNAME is not assigned from system properties",
				TFS_USERNAME == null);
		assertFalse("BUGZILLA_URL is not assigned from system properties",
				TFS_URL == null);
		assertFalse("TFS_PROJECTNAME is not assigned from system properties",
				TFS_PROJECTNAME == null);

		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String type = "TFS";
		String teamName = "bugzillaAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);
		String urlText = "http://test.com";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(null, type);
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterURL(null, TFS_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(newDefectTrackerName, TFS_USERNAME,
						TFS_PASSWORD, TFS_PROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn()
						.isDefectTrackerAttached());

		sleep(1500);
		loginPage = applicationDetailPage.clickOrganizationHeaderLink()
										.clickOrganizationHeaderLink()
										.clickViewTeamLink(teamName)
										.clickDeleteButton()
										.clickDefectTrackersLink()
										.clickDeleteButton(newDefectTrackerName)
										.logout();
	}

	@Test
	public void testAttachToAppJiraTracker() {
		assertFalse("JIRA_PASSWORD is not assigned from system properties",
				JIRA_PASSWORD == null);
		assertFalse("JIRA_USERNAME is not assigned from system properties",
				JIRA_USERNAME == null);
		assertFalse("JIRA_URL is not assigned from system properties",
				JIRA_URL == null);
		assertFalse("JIRA_PROJECTNAME is not assigned from system properties",
				JIRA_PROJECTNAME == null);

		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String type = "Jira";
		String teamName = "jIRAAttachTestTeam" + getRandomString(3);
		String appName = "JIRAAttachTestApp" + getRandomString(3);
		String urlText = "http://test.com";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(null, type);
		defectTrackerIndexPage = defectTrackerIndexPage
				.enterURL(null, JIRA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(newDefectTrackerName, JIRA_USERNAME,
						JIRA_PASSWORD, JIRA_PROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn()
						.isDefectTrackerAttached());
		applicationDetailPage = applicationDetailPage.clickCloseAppModal();
		sleep(1500);
		loginPage = applicationDetailPage.clickOrganizationHeaderLink()
										.clickOrganizationHeaderLink()
										.clickViewTeamLink(teamName)
										.clickDeleteButton()
										.clickDefectTrackersLink()
										.clickDeleteButton(newDefectTrackerName)
										.logout();
	}

	@Test
	public void bugzillaCreate() {
		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String url = "http://10.2.10.145/bugzilla/";
		String type2 = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(null, type2);
		defectTrackerIndexPage = defectTrackerIndexPage.enterURL(null, url);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(
				newDefectTrackerName, newDefectTrackerName + " - edited");
		defectTrackerIndexPage = defectTrackerIndexPage.enterType(
				newDefectTrackerName, type2);
		defectTrackerIndexPage = defectTrackerIndexPage.enterURL(
				newDefectTrackerName, url);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();
		newDefectTrackerName += " - edited";
		assertTrue(
				"DefectTracker Page did not create correctly.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(
				newDefectTrackerName).clickDefectTrackersLink();

		assertFalse(
				"DefectTracker Page did not delete.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.clickDefectTrackersLink().logout();
	}

	@Test
	public void testSwitchDefectTrackers() {
		assertFalse("JIRA_PASSWORD is not assigned from system properties",JIRA_PASSWORD == null);
		assertFalse("JIRA_USERNAME is not assigned from system properties",JIRA_USERNAME == null);
		assertFalse("JIRA_URL is not assigned from system properties",JIRA_URL == null);
		assertFalse("JIRA_PROJECTNAME is not assigned from system properties",JIRA_PROJECTNAME == null);

		String newDefectTrackerNameOne = "testEditDefectTracker1" + getRandomString(3);
		String newDefectTrackerNameTwo = "testEditDefectTracker2" + getRandomString(3);
		String type = "Jira";
		String teamName = "jIRAAttachTestTeam" + getRandomString(3);
		String appName = "JIRAAttachTestApp" + getRandomString(3);
		String urlText = "http://test.com";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
																.clickDefectTrackersLink()
																.clickAddDefectTrackerButton()
																.enterName(null,newDefectTrackerNameOne)
																.enterType(null, type)
																.enterURL(null, JIRA_URL)
																.clickSaveNewDefectTracker()
																.clickAddDefectTrackerButton()
																.enterName(null,newDefectTrackerNameTwo)
																.enterType(null, type)
																.enterURL(null, JIRA_URL)
																.clickSaveNewDefectTracker();
		
		ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
																			.clickAddTeamButton()
																			.setTeamName(teamName)
																			.addNewTeam()
																			.expandTeamRowByIndex(teamName)
																			.addNewApplication(teamName, appName, urlText, "Low")
																			.saveApplication(teamName)
																			.clickViewAppLink(appName, teamName)
																			.addDefectTracker(newDefectTrackerNameOne, JIRA_USERNAME,JIRA_PASSWORD, JIRA_PROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
		
		applicationDetailPage = applicationDetailPage.clickCloseAppModal();

		sleep(2000);
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
													.clickOrganizationHeaderLink()
													.expandTeamRowByIndex(teamName)
													.clickViewAppLink(appName, teamName)
													.editDefectTracker(newDefectTrackerNameTwo, JIRA_USERNAME, JIRA_PASSWORD, JIRA_PROJECTNAME);

		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
		
		applicationDetailPage = applicationDetailPage.clickCloseAppModal();
		
		// Delete Both
		sleep(1500);
		loginPage = applicationDetailPage.clickOrganizationHeaderLink()
										.clickOrganizationHeaderLink()
										.clickViewTeamLink(teamName)
										.clickDeleteButton()
										.clickDefectTrackersLink()
										.clickDeleteButton(newDefectTrackerNameOne)
										.clickDeleteButton(newDefectTrackerNameTwo)
										.logout();
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	/*
	 * public DefectTrackerIndexPage attachDefectTrackerToApp(
	 * DefectTrackerIndexPage defectTrackerIndexPage, String appName, String
	 * teamName) { return defectTrackerIndexPage.clickOrganizationHeaderLink()
	 * .clickViewAppLink(appName, teamName).clickActionButton()
	 * addNewDefectTracker() }
	 */
}
