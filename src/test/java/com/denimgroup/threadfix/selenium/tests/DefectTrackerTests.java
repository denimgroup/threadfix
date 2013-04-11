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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DefectTrackerTests extends BaseTest {
	
	private WebDriver driver;
	private static LoginPage loginPage;
	
	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	
	String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	//old numbering scheme is being used for edit and delete buttons waiting for that change
	@Test
	public void testCreateDefectTracker(){
		String newDefectTrackerName = "testCreateDefectTracker";
		String type = "Bugzilla";
		
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
															.clickDefectTrackersLink();
		assertFalse("The defectTracker was already present.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton();
		
		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickSaveNewDefectTracker();
		assertTrue("The defectTracker was not present in the table.", newDefectTrackerName.equals(defectTrackerIndexPage.getDefectTrackerName(1)));
		


		defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(1);
		assertFalse("The defectTracker was still present after attempted deletion.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
	
		loginPage = defectTrackerIndexPage.logout();
	}
	
	@Test
	public void testCreateDefectTrackerBoundaries(){
		String emptyString = "";
		String whiteSpaceString = "           ";
		String urlFormatString = "asdfwe";
		
		String emptyInputError = "This field cannot be blank";
		String urlError = "Not a valid URL";
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickDefectTrackersLink();		
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton();
		
		// Test empty and whitespace input
		defectTrackerIndexPage.setNameInput(emptyString);
		defectTrackerIndexPage.setUrlInput(emptyString);
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));
		assertTrue("The correct error text was not present", emptyInputError.equals(defectTrackerIndexPage.getUrlErrorsText()));
		
		defectTrackerIndexPage.setNameInput(whiteSpaceString);
		defectTrackerIndexPage.setUrlInput(whiteSpaceString);
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));
		assertTrue("The correct error text was not present", urlError.equals(defectTrackerIndexPage.getUrlErrorsText()));
		
		// Test URL format checking
		defectTrackerIndexPage.setNameInput("normal name");
		defectTrackerIndexPage.setUrlInput(urlFormatString);
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The URL format check error text was not present.", defectTrackerIndexPage.getUrlErrorsText().equals(urlError));
		
		// Test url validation
		defectTrackerIndexPage.setNameInput(longInput);
		defectTrackerIndexPage.setUrlInput("http://" + longInput);
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The Defect Tracker URL was not validated correctly.", defectTrackerIndexPage.getUrlErrorsText().equals("URL is invalid."));
		
		// Test browser length limit
		defectTrackerIndexPage.setNameInput(longInput);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
		defectTrackerIndexPage = defectTrackerIndexPage.clickSaveNewDefectTracker();
		//might need to change the row number that this is checking
		assertTrue("The Defect Tracker name was not cropped correctly.",defectTrackerIndexPage.getDefectTrackerName(1).length() == DefectTracker.NAME_LENGTH);
		
		// Test name duplication checking
		String orgName = defectTrackerIndexPage.getDefectTrackerName(1);
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink().clickAddDefectTrackerButton();
		defectTrackerIndexPage.setNameInput(orgName,1);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL,1);
		defectTrackerIndexPage.clickAddDefectTrackerButtonInvalid();
		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals("That name is already taken."));
		
		// Delete and logout
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink().clickDeleteButton(1);
		
		loginPage = defectTrackerIndexPage.logout();
	}
	
	// TODO improve this test - harder to fake with URL checking.
	@Test
	public void testEditDefectTracker(){
		String newDefectTrackerName = "testEditDefectTracker";
		String editedDefectTrackerName = "testEditDefectTracker - edited";
		
		String type1 = "Bugzilla";
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickDefectTrackersLink();
		assertFalse("The defectTracker was already present.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton();
		
		defectTrackerIndexPage.setNameInput(newDefectTrackerName);
		defectTrackerIndexPage.setDefectTrackerTypeSelect(type1);
		defectTrackerIndexPage.setUrlInput(TEST_BUGZILLA_URL);
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickSaveNewDefectTracker();
		
		assertTrue("DefectTracker Page did not save the name correctly.", newDefectTrackerName.equals(defectTrackerIndexPage.getDefectTrackerName(1)));
		assertTrue("DefectTracker Page did not save the type correctly.", type1.equals(defectTrackerIndexPage.getTypeText(1)));
		assertTrue("DefectTracker Page did not save the URL correctly.", TEST_BUGZILLA_URL.equals(defectTrackerIndexPage.getUrlText(1)));
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName);
		
		defectTrackerIndexPage.setNameInput(editedDefectTrackerName);
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickUpdateDefectTrackerButton();
		assertTrue("Editing did not change the name.", editedDefectTrackerName.equals(defectTrackerIndexPage.getDefectTrackerName(1)));
		
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink().clickDeleteButton(1);
		assertFalse("The defectTracker was still present after attempted deletion.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
	
		loginPage = defectTrackerIndexPage.logout();
	}
	
	@Test
	public void testEditDefectTrackerBoundaries(){
		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker - edited";
		
		String type2 = "Bugzilla";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
				
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink().clickDefectTrackersLink();	

		// create Dummy WAF
		DefectTrackerIndexPage defectTrackerAddPage = defectTrackerIndexPage.clickAddDefectTrackerButton();
		defectTrackerAddPage.setNameInput(defectTrackerNameDuplicateTest);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type2);
		defectTrackerAddPage.setUrlInput(TEST_BUGZILLA_URL);
		DefectTrackerDetailPage defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		
		defectTrackerAddPage = defectTrackerDetailPage.clickBackToListLink()
													  .clickAddDefectTrackerLink();
		defectTrackerAddPage.setNameInput(newDefectTrackerName);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type2);
		defectTrackerAddPage.setUrlInput(TEST_BUGZILLA_URL);
		defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		
		DefectTrackerEditPage editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		
		// Test submission with no changes
		defectTrackerDetailPage = editDefectTrackerPage.clickUpdateDefectTrackerButton(false);
		assertTrue("DefectTracker Page did not save the name correctly.", newDefectTrackerName.equals(defectTrackerDetailPage.getNameText()));
		assertTrue("DefectTracker Page did not save the type correctly.", type2.equals(defectTrackerDetailPage.getTypeText()));
		assertTrue("DefectTracker Page did not save the url correctly.", TEST_BUGZILLA_URL.equals(defectTrackerDetailPage.getUrlText()));
		
		editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		
		// Test empty and whitespace input
		editDefectTrackerPage.setNameInput(emptyString);
		editDefectTrackerPage = editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid(false);
		log.debug("Output is '" + editDefectTrackerPage.getNameErrorsText() + "'");
		assertTrue("The correct error text was not present", emptyInputError.equals(editDefectTrackerPage.getNameErrorsText()));
		
		editDefectTrackerPage.setNameInput(whiteSpaceString);
		editDefectTrackerPage = editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid(false);
		assertTrue("The correct error text was not present", emptyInputError.equals(editDefectTrackerPage.getNameErrorsText()));
		
		// Test browser length limit
		editDefectTrackerPage.setNameInput(longInput);
		defectTrackerDetailPage = editDefectTrackerPage.clickUpdateDefectTrackerButton(false);
		
		newDefectTrackerName = defectTrackerDetailPage.getNameText();
		
		assertTrue("The defectTracker name was not cropped correctly.", defectTrackerDetailPage.getNameText().length() == DefectTracker.NAME_LENGTH);
		
		// Test name duplication checking
		editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		editDefectTrackerPage.setNameInput(defectTrackerNameDuplicateTest);
		editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid(false);
		assertTrue(editDefectTrackerPage.getNameErrorsText().equals("That name is already taken."));
					
		// Delete and logout
		defectTrackerIndexPage = editDefectTrackerPage.clickConfigurationHeaderLink()
									.clickDefectTrackersLink()
									.clickTextLinkInDefectTrackerTableBody(newDefectTrackerName)
									.clickDeleteButton()
									.clickTextLinkInDefectTrackerTableBody(defectTrackerNameDuplicateTest)
									.clickDeleteButton();
		
		loginPage = defectTrackerIndexPage.logout();
	}
}
