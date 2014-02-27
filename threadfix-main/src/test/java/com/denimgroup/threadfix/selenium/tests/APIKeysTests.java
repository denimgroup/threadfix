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

import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class APIKeysTests extends BaseTest {
	
    private ApiKeysIndexPage apiIndexPage;
	
	@Before
	public void init() {
		super.init();

        apiIndexPage = loginPage.login("user", "password")
                .clickApiKeysLink();
	}

	@Test
	public void navigationTest() {
		assertTrue("API Keys Page not found", apiIndexPage.getH2Tag().contains("API Keys"));
	}

	@Test
	public void createAPIKeyTest() {
        //Create API Key
        apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("createAPIKey", null)
                .setRestricted(null)
                .clickSubmitButton(null)
                .waitModalDisappear();

		assertTrue("Api note was not present.", apiIndexPage.isAPINotePresent("createAPIKey"));
		assertTrue("Api was not marked restricted as it should have been.",apiIndexPage.isAPIRestricted("createAPIKey"));
		assertTrue("Creation validation message not present.", apiIndexPage.isCreationSuccessAlertPresent());
	}

	@Test
	public void editKeyTest() {
        //Create API Key
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("editAPIKeyNote", null)
                .clickSubmitButton(null)
                .waitModalDisappear();

        //Edit API Key
        apiIndexPage =	apiIndexPage.clickEdit("editAPIKeyNote")
                .setNote("Sample ThreadFix REST key", "editAPIKeyNote")
                .clickSubmitButton("editAPIKeyNote")
                .waitModalDisappear();

		assertTrue("API note was not edited properly.", apiIndexPage.isAPINotePresent("Sample ThreadFix REST key"));
		assertFalse("Previous API note still present.", apiIndexPage.isAPINotePresent("editAPIKeyNote"));
		assertTrue("Edit validation message not present.", apiIndexPage.isEditSuccessAlertPresent());
	}

	@Test
	public void markRestrictedTest() {
        //Create API Key
        apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("markRestricted", null)
                .clickSubmitButton(null)
                .waitModalDisappear();

        //Mark the API restricted
		apiIndexPage =	apiIndexPage.clickEdit("markRestricted")
                .setNote("markRestricted", "markRestricted")
                .setRestricted("markRestricted")
                .clickSubmitButton("markRestricted")
                .waitModalDisappear();

		assertTrue("Api was not marked restricted.", apiIndexPage.isAPIRestricted("markRestricted"));
	}

	@Test
	public void deleteKeyTest() {
        //Create API Key
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote("toDeleteAPIKey",null)
                .clickSubmitButton(null)
                .waitModalDisappear();

        apiIndexPage = apiIndexPage.clickDelete("toDeleteAPIKey");

		assertTrue("Validation Message not present.",apiIndexPage.isDeleteSuccessAlertPresent());
        assertFalse("API Key was not deleted properly.", apiIndexPage.isAPINotePresent("toDeleteAPIKey"));
	}

	@Test
	public void longApiKeyNoteDisplayTest(){
		String shortNote = getRandomString(8);
		String longNoteA = getRandomString(2056);
        String longNoteB = getRandomString(2056);
		int width, newWidth;

        //Create API Key with a short note
		apiIndexPage = apiIndexPage.clickNewLink()
                .setNote(shortNote, null)
				.clickSubmitButton(null)
				.waitModalDisappear();

		width = apiIndexPage.getTableWidth();

        //Create API Key with a really long note
		apiIndexPage = apiIndexPage.clickNewLink()
				   .setNote(longNoteA, null)
				   .clickSubmitButton(null)
				   .waitModalDisappear();

		newWidth = apiIndexPage.getTableWidth();

		assertTrue("Width of table is incorrect after creating an API Key with a long note", width == newWidth);

        //Edit API Key with short note to have long note
        apiIndexPage = apiIndexPage.clickEdit(shortNote)
                .setNote(shortNote, longNoteB)
                .clickSubmitButton(longNoteB)
                .waitModalDisappear();

        newWidth = apiIndexPage.getTableWidth();

        assertTrue("Width of table is incorrect after editing an API Key to have a long note", width == newWidth);
	}
}
