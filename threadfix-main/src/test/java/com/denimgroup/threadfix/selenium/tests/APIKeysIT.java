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
import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class APIKeysIT extends BaseIT {
	
    private ApiKeysIndexPage apiIndexPage;
	
	@Before
	public void init() {
		super.init();

        apiIndexPage = loginPage.defaultLogin()
                .clickApiKeysLink();
	}

	@Test
	public void navigationTest() {
		assertTrue("API Keys Page not found", apiIndexPage.getH2Tag().contains("API Keys"));
	}

	@Test
	public void createAPIKeyTest() {
        apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("createAPIKey")
                .setRestricted()
                .clickSubmitButton();

		assertTrue("Api note was not present.", apiIndexPage.isAPINotePresent("createAPIKey"));
		assertTrue("Api was not marked restricted as it should have been.",apiIndexPage.isAPIRestricted("createAPIKey"));
		assertTrue("Creation validation message not present.", apiIndexPage.isCreationSuccessAlertPresent());
	}

	@Test
	public void editKeyTest() {
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("editAPIKeyNote")
                .clickSubmitButton();

        apiIndexPage =	apiIndexPage.clickEdit("editAPIKeyNote")
                .setNote("editAPIKeyNote-Edited")
                .clickSubmitButton();

		assertTrue("API note was not edited properly.", apiIndexPage.isAPINotePresent("editAPIKeyNote-Edited"));
		assertFalse("Previous API note still present.", apiIndexPage.isAPINotePresent("editAPIKeyNote"));
		assertTrue("Edit validation message not present.", apiIndexPage.isEditSuccessAlertPresent());

        apiIndexPage.refreshPage();
        assertTrue("API note was not edited properly.", apiIndexPage.isAPINotePresent("editAPIKeyNote-Edited"));
        assertFalse("Previous API note still present.", apiIndexPage.isAPINotePresent("editAPIKeyNote"));
	}

	@Test
	public void markRestrictedTest() {
        String note = getName();
        //Create API Key
        apiIndexPage = apiIndexPage.clickNewLink()
                .setNote(note)
                .clickSubmitButton();

        //Mark the API restricted
		apiIndexPage =	apiIndexPage.clickEdit(note)
                .setRestricted()
                .clickSubmitButton();

		assertTrue("Api was not marked restricted.", apiIndexPage.isAPIRestricted(note));
	}

	@Test
	public void deleteKeyTest() {
        String apiKeyNote = getRandomString(10);

        //Create API Key
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote(apiKeyNote)
                .clickSubmitButton();

        apiIndexPage = apiIndexPage.clickDelete(apiKeyNote);

		assertTrue("Validation Message not present.",apiIndexPage.isDeleteSuccessAlertPresent());
        assertFalse("API Key was not deleted properly.", apiIndexPage.isAPINotePresent(apiKeyNote));

        apiIndexPage.refreshPage();

        assertFalse("Deleted API key was still present after refresh.",
                apiIndexPage.isAPINotePresent(apiKeyNote));
	}

	@Test
	public void longAPIKeyNoteDisplayTest(){
		String shortNote = getName();
		String longNoteA = getRandomString(2056);
        String longNoteB = getRandomString(254);
		int width, newWidth;

        //Create API Key with a short note
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote(shortNote)
				.clickSubmitButton();

		width = apiIndexPage.getTableWidth();

        //Create API Key with a really long note
		apiIndexPage = apiIndexPage.clickNewLink()
				   .setNote(longNoteA)
				   .clickInvalidSubmitButton();

        assertTrue("Character limit error message should have shown.",
                apiIndexPage.getNoteError().equals("Over 255 characters limit!"));

        apiIndexPage.setNote(longNoteB)
                .clickSubmitButton();

		newWidth = apiIndexPage.getTableWidth();

		assertTrue("Width of table is incorrect after creating an API Key with a long note", width == newWidth);

        //Edit API Key with short note to have long note
        apiIndexPage = apiIndexPage.clickEdit(shortNote)
                .setNote(longNoteB)
                .clickSubmitButton();

        newWidth = apiIndexPage.getTableWidth();

        assertTrue("Width of table is incorrect after editing an API Key to have a long note", width == newWidth);
	}
}
