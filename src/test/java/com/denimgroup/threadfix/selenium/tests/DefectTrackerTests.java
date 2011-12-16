////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import com.denimgroup.threadfix.selenium.pages.DefectTrackerAddPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerEditPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DefectTrackerTests extends BaseTest {
	
	private WebDriver driver;
	private static LoginPage loginPage;
	
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
	
	@Test
	public void testCreateDefectTracker(){
		String newDefectTrackerName = "testCreateDefectTracker";
		String type = "Bugzilla";
		String defectTrackerDummyUrl = "http://test.com";
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
																						.clickDefectTrackersLink();
		assertFalse("The defectTracker was already present.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
		
		DefectTrackerAddPage defectTrackerAddPage = defectTrackerIndexPage.clickAddDefectTrackerLink();
		
		defectTrackerAddPage.setNameInput(newDefectTrackerName);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type);
		defectTrackerAddPage.setUrlInput(defectTrackerDummyUrl);
		
		DefectTrackerDetailPage defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		assertTrue("DefectTracker Page did not save the name correctly.", newDefectTrackerName.equals(defectTrackerDetailPage.getNameText()));
		
		defectTrackerIndexPage = defectTrackerDetailPage.clickConfigurationHeaderLink()
														.clickDefectTrackersLink();	
		assertTrue("The defectTracker was not present in the table.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));

		defectTrackerIndexPage = defectTrackerIndexPage.clickTextLinkInDefectTrackerTableBody(newDefectTrackerName).clickDeleteButton();
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
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink().clickDefectTrackersLink();		
		DefectTrackerAddPage addDefectTrackerPage = defectTrackerIndexPage.clickAddDefectTrackerLink();
		
		// Test empty and whitespace input
		addDefectTrackerPage.setNameInput(emptyString);
		addDefectTrackerPage.setUrlInput(emptyString);
		addDefectTrackerPage = addDefectTrackerPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(addDefectTrackerPage.getNameErrorsText()));
		assertTrue("The correct error text was not present", emptyInputError.equals(addDefectTrackerPage.getUrlErrorsText()));
		
		addDefectTrackerPage.setNameInput(whiteSpaceString);
		addDefectTrackerPage.setUrlInput(whiteSpaceString);
		addDefectTrackerPage = addDefectTrackerPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(addDefectTrackerPage.getNameErrorsText()));
		assertTrue("The correct error text was not present", urlError.equals(addDefectTrackerPage.getUrlErrorsText()));
		
		// Test URL format checking
		addDefectTrackerPage.setNameInput("normal name");
		addDefectTrackerPage.setUrlInput(urlFormatString);
		addDefectTrackerPage = addDefectTrackerPage.clickAddDefectTrackerButtonInvalid();
		assertTrue("The URL format check error text was not present.", addDefectTrackerPage.getUrlErrorsText().equals(urlError));
		
		// Test browser length limit
		addDefectTrackerPage.setNameInput(longInput);
		addDefectTrackerPage.setUrlInput("http://" + longInput);
		DefectTrackerDetailPage defectTrackerDetailPage = addDefectTrackerPage.clickAddDefectTrackerButton();
		assertTrue("The Defect Tracker name was not cropped correctly.", defectTrackerDetailPage.getNameText().length() == DefectTracker.NAME_LENGTH);
		assertTrue("The Defect Tracker URL was not cropped correctly.", defectTrackerDetailPage.getUrlText().length() == DefectTracker.URL_LENGTH);
		
		// Test name duplication checking
		String orgName = defectTrackerDetailPage.getNameText();
		
		addDefectTrackerPage = defectTrackerDetailPage.clickBackToListLink().clickAddDefectTrackerLink();
		addDefectTrackerPage.setNameInput(orgName);
		addDefectTrackerPage.setUrlInput("http://dummyurl.com");
		addDefectTrackerPage.clickAddDefectTrackerButtonInvalid();
		assertTrue(addDefectTrackerPage.getNameErrorsText().equals("That name is already taken."));
		
		// Delete and logout
		defectTrackerIndexPage = addDefectTrackerPage.clickConfigurationHeaderLink().clickDefectTrackersLink().clickTextLinkInDefectTrackerTableBody(orgName).clickDeleteButton();
		
		loginPage = defectTrackerIndexPage.logout();
	}
	
	@Test
	public void testEditDefectTracker(){
		String newDefectTrackerName = "testEditDefectTracker";
		String editedDefectTrackerName = "testEditDefectTracker - edited";
		
		String type1 = "Jira";
		String type2 = "Bugzilla";
		
		String url1 = "http://dummy-url.com";
		String url2 = "http://dummy-url-3.com";
		
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink().clickDefectTrackersLink();
		assertFalse("The defectTracker was already present.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
		
		DefectTrackerAddPage defectTrackerAddPage = defectTrackerIndexPage.clickAddDefectTrackerLink();
		
		defectTrackerAddPage.setNameInput(newDefectTrackerName);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type1);
		defectTrackerAddPage.setUrlInput(url1);
		
		DefectTrackerDetailPage defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		
		assertTrue("DefectTracker Page did not save the name correctly.", newDefectTrackerName.equals(defectTrackerDetailPage.getNameText()));
		assertTrue("DefectTracker Page did not save the type correctly.", type1.equals(defectTrackerDetailPage.getTypeText()));
		assertTrue("DefectTracker Page did not save the URL correctly.", url1.equals(defectTrackerDetailPage.getUrlText()));
		
		DefectTrackerEditPage defectTrackerEditPage = defectTrackerDetailPage.clickEditLink();
		
		defectTrackerEditPage.setNameInput(editedDefectTrackerName);
		defectTrackerEditPage.setDefectTrackerTypeSelect(type2);
		defectTrackerEditPage.setUrlInput(url2);
		
		defectTrackerDetailPage = defectTrackerEditPage.clickUpdateDefectTrackerButton();
		assertTrue("Editing did not change the name.", editedDefectTrackerName.equals(defectTrackerDetailPage.getNameText()));
		assertTrue("Editing did not change the type.", type2.equals(defectTrackerDetailPage.getTypeText()));
		assertTrue("Editing did not change the URL.", url2.equals(defectTrackerDetailPage.getUrlText()));
		
		defectTrackerIndexPage = defectTrackerDetailPage.clickConfigurationHeaderLink().clickDefectTrackersLink();
		
		defectTrackerIndexPage = defectTrackerIndexPage.clickTextLinkInDefectTrackerTableBody(editedDefectTrackerName).clickDeleteButton();
		assertFalse("The defectTracker was still present after attempted deletion.", defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
	
		loginPage = defectTrackerIndexPage.logout();
	}
	
	@Test
	public void testEditDefectTrackerBoundaries(){
		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker - edited";
		
		String type1 = "Jira";
		String type2 = "Bugzilla";
		
		String url1 = "http://dummy-url.com";
		String url2 = "http://dummy-url-3.com";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
				
		DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink().clickDefectTrackersLink();	
		
		// Create dummy WAFs
		DefectTrackerAddPage defectTrackerAddPage = defectTrackerIndexPage.clickAddDefectTrackerLink();
		defectTrackerAddPage.setNameInput(defectTrackerNameDuplicateTest);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type1);
		defectTrackerAddPage.setUrlInput(url1);
		DefectTrackerDetailPage defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		
		defectTrackerAddPage = defectTrackerDetailPage.clickBackToListLink().clickAddDefectTrackerLink();
		defectTrackerAddPage.setNameInput(newDefectTrackerName);
		defectTrackerAddPage.setDefectTrackerTypeSelect(type2);
		defectTrackerAddPage.setUrlInput(url2);
		defectTrackerDetailPage = defectTrackerAddPage.clickAddDefectTrackerButton();
		
		DefectTrackerEditPage editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		
		// Test submission with no changes
		defectTrackerDetailPage = editDefectTrackerPage.clickUpdateDefectTrackerButton();
		assertTrue("DefectTracker Page did not save the name correctly.", newDefectTrackerName.equals(defectTrackerDetailPage.getNameText()));
		assertTrue("DefectTracker Page did not save the type correctly.", type2.equals(defectTrackerDetailPage.getTypeText()));
		assertTrue("DefectTracker Page did not save the url correctly.", url2.equals(defectTrackerDetailPage.getUrlText()));
		
		editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		
		// Test empty and whitespace input
		editDefectTrackerPage.setNameInput(emptyString);
		editDefectTrackerPage = editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid();
		System.out.println("Output is '" + editDefectTrackerPage.getNameErrorsText() + "'");
		assertTrue("The correct error text was not present", emptyInputError.equals(editDefectTrackerPage.getNameErrorsText()));
		
		editDefectTrackerPage.setNameInput(whiteSpaceString);
		editDefectTrackerPage = editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(editDefectTrackerPage.getNameErrorsText()));
		
		// Test browser length limit
		editDefectTrackerPage.setNameInput(longInput);
		defectTrackerDetailPage = editDefectTrackerPage.clickUpdateDefectTrackerButton();
		
		newDefectTrackerName = defectTrackerDetailPage.getNameText();
		
		assertTrue("The defectTracker name was not cropped correctly.", defectTrackerDetailPage.getNameText().length() == DefectTracker.NAME_LENGTH);
		
		// Test name duplication checking
		editDefectTrackerPage = defectTrackerDetailPage.clickEditLink();
		editDefectTrackerPage.setNameInput(defectTrackerNameDuplicateTest);
		editDefectTrackerPage.clickUpdateDefectTrackerButtonInvalid();
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
