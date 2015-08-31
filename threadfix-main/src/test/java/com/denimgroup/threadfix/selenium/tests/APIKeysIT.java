////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApiKeysIT extends BaseIT {
	
    private ApiKeysIndexPage apiIndexPage;
	
	@Before
	public void init() {
		super.init();

        apiIndexPage = loginPage.defaultLogin()
                .clickApiKeysLink();
	}

	@Test
	public void testNavigateToPage() {
		assertTrue("API Keys page not found", apiIndexPage.getH2Tag().contains("API Keys"));
	}

	@Test
	public void testCreateApiKey() {
        final String NOTE = "createApiKey";

        apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
                .setNote(NOTE)
                .setRestricted()
                .clickSubmitButton();

		assertTrue("API key note was not present.", apiIndexPage.isApiKeyNotePresent(NOTE));
		assertTrue("API key was not marked restricted.", apiIndexPage.isApiKeyRestricted(NOTE));
		assertTrue("Creation success message was not present.", apiIndexPage.isCreationSuccessAlertPresent());
	}

	@Test
	public void testEditKey() {
        final String NOTE = getName();
        final String EDITED_NOTE = getName();

		apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
                .setNote(NOTE)
                .clickSubmitButton();

        apiIndexPage =	apiIndexPage.clickEditDeleteButton(NOTE)
                .setNote(EDITED_NOTE)
                .clickSubmitButton();

		assertTrue("API note was not edited properly.", apiIndexPage.isApiKeyNotePresent(EDITED_NOTE));
		assertFalse("Previous API note is still present.", apiIndexPage.isApiKeyNotePresent(NOTE));
		assertTrue("Edit API key success message is not present.", apiIndexPage.isEditSuccessAlertPresent());

        apiIndexPage.refreshPage();
        assertTrue("API note was not edited properly.", apiIndexPage.isApiKeyNotePresent(EDITED_NOTE));
        assertFalse("Previous API key note is still present.", apiIndexPage.isApiKeyNotePresent(NOTE));
	}

	@Test
	public void testMarkKeyRestricted() {
        String note = getName();
        //Create API Key
        apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
                .setNote(note)
                .clickSubmitButton();

        //Mark the API restricted
		apiIndexPage =	apiIndexPage.clickEditDeleteButton(note)
                .setRestricted()
                .clickSubmitButton();

		assertTrue("Api was not marked restricted.", apiIndexPage.isApiKeyRestricted(note));
	}

	@Test
	public void testDeleteKey() {
        String apiKeyNote = getRandomString(10);

        //Create API Key
		apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
                .setNote(apiKeyNote)
                .clickSubmitButton();

        apiIndexPage = apiIndexPage.deleteApiKey(apiKeyNote);

		assertTrue("Validation Message not present.",apiIndexPage.isDeleteSuccessAlertPresent());
        assertFalse("API Key was not deleted properly.", apiIndexPage.isApiKeyNotePresent(apiKeyNote));

        apiIndexPage.refreshPage();

        assertFalse("Deleted API key was still present after refresh.",
                apiIndexPage.isApiKeyNotePresent(apiKeyNote));
	}

	@Test
	public void testDisplayLongApiKeyNote(){
		String shortNote = getName();
		String longNoteA = getRandomString(2056);
        String longNoteB = getRandomString(254);
		int width, newWidth;

        //Create API Key with a short note
		apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
                .setNote(shortNote)
				.clickSubmitButton();

		width = apiIndexPage.getTableWidth();

        //Create API Key with a really long note
		apiIndexPage = apiIndexPage.clickCreateNewKeyLink()
				   .setNote(longNoteA)
				   .clickSubmitButtonInvalid();

        assertTrue("Character limit error message should have shown.",
                apiIndexPage.getNoteError().equals("Over 255 characters limit!"));

        apiIndexPage.setNote(longNoteB)
                .clickSubmitButton();

		newWidth = apiIndexPage.getTableWidth();

		assertTrue("Width of table is incorrect after creating an API Key with a long note", width == newWidth);

        //Edit API Key with short note to have long note
        apiIndexPage = apiIndexPage.clickEditDeleteButton(shortNote)
                .setNote(longNoteB)
                .clickSubmitButton();

        newWidth = apiIndexPage.getTableWidth();

        assertTrue("Width of table is incorrect after editing an API Key to have a long note", width == newWidth);
	}
}
