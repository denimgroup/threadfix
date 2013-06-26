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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class APIKeysTests extends BaseTest {
	private FirefoxDriver driver;

	private static LoginPage loginPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@Test
	public void navigationTest() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
				  							  .clickApiKeysLink();
		
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));
	}

	@Test
	public void createAPIKey() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
								   			  .clickApiKeysLink()
								   			  .clickNewLink()
								   			  .setNote("createAPIKey",null)
								   			  .setRestricted(null)
								   			  .clickSubmitButton(null)
								   			  .waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent("createAPIKey"));
		assertTrue("Api was not marked restricted.",indexPage.isRestricted("createAPIKey"));
		assertTrue("Validation Message not present.",indexPage.isCreateValidationPresent());
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));

		indexPage.clickDelete("createAPIKey");
		assertTrue("Validation Message not present.",indexPage.isDeleteValidationPresent());
	}

	@Test
	public void editKey() {
		
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
								   .clickApiKeysLink()
								   .clickNewLink()
								   .setNote("createAPIKey",null)
								   .clickSubmitButton(null)
								   .waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent("createAPIKey"));
		assertTrue("Validation Message not present.",indexPage.isCreateValidationPresent());
		indexPage =	indexPage.clickEdit("createAPIKey")
							.setNote("Sample ThreadFix REST key","createAPIKey")
							.clickSubmitButton("createAPIKey")
							.waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent("Sample ThreadFix REST key"));
		assertFalse("Api note is note present.",indexPage.isNotePresent("createAPIKey"));
		assertTrue("Validation Message not present.",indexPage.isEditValidationPresent());
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));

		indexPage.clickDelete("Sample ThreadFix REST key");
		assertTrue("Validation Message not present.",indexPage.isDeleteValidationPresent());
	}

	@Test
	public void markRestricted() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
					 						  .clickApiKeysLink()
											  .clickNewLink()
											  .setNote("markRestricted",null)
											  .clickSubmitButton(null)
											  .waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent("markRestricted"));
		assertTrue("Validation Message not present.",indexPage.isCreateValidationPresent());
		assertFalse("Api was marked restricted.",indexPage.isRestricted("markRestricted"));
		indexPage =	indexPage.clickEdit("markRestricted")
						.setNote("markRestricted","markRestricted")
						.setRestricted("markRestricted")
						.clickSubmitButton("markRestricted")
						.waitModalDisappear();
		assertTrue("Api was not marked restricted.",indexPage.isRestricted("markRestricted"));
		assertTrue("Api note is note present.",indexPage.isNotePresent("markRestricted"));
		assertTrue("Validation Message not present.",indexPage.isEditValidationPresent());
						
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));
		
		indexPage.clickDelete("markRestricted");
		assertTrue("Validation Message not present.",indexPage.isDeleteValidationPresent());
	}

	@Test
	public void deleteKey() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
								   .clickApiKeysLink()
								   .clickNewLink()			
								   .setNote("markRestricted",null)
								   .clickSubmitButton(null)
								   .waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent("markRestricted"));
		assertTrue("Validation Message not present.",indexPage.isCreateValidationPresent());
		String PageText = indexPage.clickDelete("markRestricted")
								   .getH2Tag();
		assertTrue("Validation Message not present.",indexPage.isDeleteValidationPresent());

		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
	}
	
	@Test
	public void nameLength(){
		String blankNote = "";
		String whiteSpace = "     ";
		String longNote = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		longNote = longNote + longNote + longNote;
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
				   .clickApiKeysLink()
				   .clickNewLink()			
				   .setNote(blankNote,null)
				   .clickSubmitButton(null)
				   .waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent(blankNote));
		assertTrue("Validation Message not present.",indexPage.isCreateValidationPresent());
		indexPage =	indexPage.clickEdit(blankNote)
				.setNote(whiteSpace,blankNote)
				.clickSubmitButton(blankNote)
				.waitModalDisappear();
		assertTrue("Api note is note present.",indexPage.isNotePresent(whiteSpace));
		assertTrue("Validation Message not present.",indexPage.isEditValidationPresent());
		indexPage =	indexPage.clickEdit(whiteSpace)
				.setNote(longNote,whiteSpace)
				.clickSubmitButton(whiteSpace)
				.waitModalDisappear();
		longNote = longNote.substring(0, 255);
		assertTrue("Api note is note present.",indexPage.isNotePresent(longNote));
		assertTrue("Api note is too long.",indexPage.isCorrectLength(longNote));
		assertTrue("Validation Message not present.",indexPage.isEditValidationPresent());
		indexPage = indexPage.clickDelete(longNote);
		assertTrue("Validation Message not present.",indexPage.isDeleteValidationPresent());
	}
}
