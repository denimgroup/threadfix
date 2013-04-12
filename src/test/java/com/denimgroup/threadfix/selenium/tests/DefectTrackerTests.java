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
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DefectTrackerTests extends BaseTest {

	private WebDriver driver;
	private static LoginPage loginPage;

	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	private static final String TEST_JIRA_URL = DefectTrackerIndexPage.DT_URL;

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
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	// old numbering scheme is being used for edit and delete buttons waiting
	// for that change
	@Test
	public void testCreateDefectTracker() {
		String newDefectTrackerName = "testCreateDefectTracker";
		String type = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse(
				"The defectTracker was already present.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();
		assertTrue("The defectTracker was not present in the table.",
				newDefectTrackerName.equals(defectTrackerIndexPage
						.getDefectTrackerName(1)));

		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(1);
		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

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
		defectTrackerIndexPage.setNameInput(emptyString);
		defectTrackerIndexPage.setUrlInput(emptyString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getUrlErrorsText()));

		defectTrackerIndexPage.setNameInput(whiteSpaceString);
		defectTrackerIndexPage.setUrlInput(whiteSpaceString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				urlError.equals(defectTrackerIndexPage.getUrlErrorsText()));

		// Test URL format checking
		defectTrackerIndexPage.setNameInput("normal name");
		defectTrackerIndexPage.setUrlInput(urlFormatString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The URL format check error text was not present.",
				defectTrackerIndexPage.getUrlErrorsText().equals(urlError));

		// Test url validation
		defectTrackerIndexPage.setNameInput(longInput);
		defectTrackerIndexPage.setUrlInput("http://" + longInput);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButtonInvalid();
		assertTrue(
				"The Defect Tracker URL was not validated correctly.",
				defectTrackerIndexPage.getUrlErrorsText().equals(
						"URL is invalid."));

		// Test browser length limit
		defectTrackerIndexPage.setNameInput(longInput);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
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
		defectTrackerIndexPage.setNameInput(orgName, 1);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL, 1);
		defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals(
				"That name is already taken."));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDefectTrackersLink().clickDeleteButton(1);

		loginPage = defectTrackerIndexPage.logout();
	}

	// TODO improve this test - harder to fake with URL checking.
	@Test
	public void testEditDefectTracker() {
		String newDefectTrackerName = "testEditDefectTracker";
		String editedDefectTrackerName = "testEditDefectTracker - edited";

		String type1 = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse(
				"The defectTracker was already present.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type1);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		assertTrue("DefectTracker Page did not save the name correctly.",
				newDefectTrackerName.equals(defectTrackerIndexPage
						.getDefectTrackerName(1)));
		assertTrue("DefectTracker Page did not save the type correctly.",
				type1.equals(defectTrackerIndexPage.getTypeText(1)));
		assertTrue("DefectTracker Page did not save the URL correctly.",
				TEST_BUGZILLA_URL.equals(defectTrackerIndexPage.getUrlText(1)));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		defectTrackerIndexPage.setNameInput(editedDefectTrackerName);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();
		assertTrue("Editing did not change the name.",
				editedDefectTrackerName.equals(defectTrackerIndexPage
						.getDefectTrackerName(1)));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickDefectTrackersLink().clickDeleteButton(1);
		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.logout();
	}

	// TODO improve this test - harder to fake with URL checking.
	@Test
	public void testDeleteDefectTracker() {
		String newDefectTrackerName = "testEditDefectTracker";
		String type1 = "Bugzilla";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();
		assertFalse(
				"The defectTracker was already present.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();

		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type1);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(1);
		assertFalse(
				"The defectTracker was still present after attempted deletion.",
				defectTrackerIndexPage
						.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		loginPage = defectTrackerIndexPage.logout();
	}

	// Not working yet
	@Ignore
	@Test
	public void testEditDefectTrackerBoundaries() {
		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker - edited";

		String type2 = "Bugzilla";

		String emptyString = "";
		String whiteSpaceString = "           ";

		String emptyInputError = "This field cannot be blank";

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		// create Dummy WAF
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();
		defectTrackerIndexPage.setNameInput(defectTrackerNameDuplicateTest);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type2);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton();
		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type2);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		// Test submission with no changes
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();
		assertTrue("DefectTracker Page did not save the name correctly.",
				newDefectTrackerName.equals(defectTrackerIndexPage
						.getNameInput()));
		assertTrue("DefectTracker Page did not save the type correctly.",
				type2.equals(defectTrackerIndexPage
						.getDefectTrackerTypeSelect()));
		assertTrue("DefectTracker Page did not save the url correctly.",
				TEST_BUGZILLA_URL.equals(defectTrackerIndexPage.getUrlInput()));

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickEditLink(newDefectTrackerName);

		// Test empty and whitespace input
		defectTrackerIndexPage.setNameInput(emptyString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButtonInvalid();
		log.debug("Output is '" + defectTrackerIndexPage.getNameErrorsText()
				+ "'");
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));

		defectTrackerIndexPage.setNameInput(whiteSpaceString);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage
						.getNameErrorsText()));

		// Test browser length limit
		defectTrackerIndexPage.setNameInput(longInput);
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
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(2)
				.clickDeleteButton(1);

		loginPage = defectTrackerIndexPage.logout();
	}

	// Certificate Problems
	@Test
	public void TFSCreate() {
		String newDefectTrackerName = "testEditDefectTracker"
				+ getRandomString(10);
		String url = "https://tfs.denimgroup.com:8080";
		String type2 = "Microsoft TFS";

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


		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteByName(newDefectTrackerName);

		loginPage = defectTrackerIndexPage.logout();
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

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage
				.login("user", "password")
				.clickDefectTrackersLink();

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

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
				.setNameInput(replacementName);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not edit correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteByName(replacementName);

		loginPage = defectTrackerIndexPage.logout();
	}
	/*
	@Test
	public void jiraEdit() {
		String newDefectTrackerName = "testEditDefectTracker" + getRandomString(10);
		String type2 = "Jira";
		String replacementName = "replacementDefectTracker" + getRandomString(10);

		DefectTrackerIndexPage defectTrackerIndexPage = loginPage
				.login("user", "password")
				.clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type2);
		defectTrackerIndexPage.setUrlInput(jiraURL);
		defectTrackerIndexPage = defectTrackerIndexPage
				.clickSaveNewDefectTracker();

		DefectTrackerEditPage editDefectTrackerPage = defectTrackerDetailPage
				.clickEditLink();

		defectTrackerDetailPage = editDefectTrackerPage
				.clickUpdateDefectTrackerButton(false);

		assertTrue("DefectTracker Page did not create correctly.",
				defectTrackerDetailPage.isDetailPage());

		editDefectTrackerPage = defectTrackerDetailPage.clickEditLink()
				.setNameInput(replacementName);
		defectTrackerDetailPage = editDefectTrackerPage
				.clickUpdateDefectTrackerButton(false);

		assertTrue("DefectTracker Page did not edit correctly.",
				defectTrackerDetailPage.checkName(replacementName));

		// Delete and logout
		defectTrackerIndexPage = defectTrackerDetailPage
				.clickConfigurationHeaderLink().clickDefectTrackersLink()
				.clickTextLinkInDefectTrackerTableBody(replacementName)
				.clickDeleteButton();

		loginPage = defectTrackerIndexPage.logout();
	}
	*/
}
