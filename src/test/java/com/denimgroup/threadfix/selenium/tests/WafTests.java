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

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.WafAddPage;
import com.denimgroup.threadfix.selenium.pages.WafDetailPage;
import com.denimgroup.threadfix.selenium.pages.WafEditPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;

public class WafTests extends BaseTest {
	
	private WebDriver driver;
	private static LoginPage loginPage;
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test
	public void testCreateWaf(){
		String newWafName = "testCreateWaf";
		String type = "mod_security";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		assertFalse("The waf was already present.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
		
		WafAddPage wafAddPage = wafIndexPage.clickAddWafLink();
		
		wafAddPage.setNameInput(newWafName);
		wafAddPage.setTypeSelect(type);
		
		WafDetailPage wafDetailPage = wafAddPage.clickAddWafButton();
		assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafDetailPage.getNameText()));
		
		wafIndexPage = wafDetailPage.clickWafsHeaderLink();	
		assertTrue("The waf was not present in the table.", wafIndexPage.isTextPresentInWafTableBody(newWafName));

		wafIndexPage = wafIndexPage.clickTextLinkInWafTableBody(newWafName).clickDeleteButton();
		assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	
		loginPage = wafIndexPage.logout();
	}
	
	@Test
	public void testCreateWafBoundaries(){
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();		
		WafAddPage addWafPage = wafIndexPage.clickAddWafLink();
		
		// Test empty and whitespace input
		addWafPage.setNameInput(emptyString);
		addWafPage = addWafPage.clickAddWafButtonInvalid();
		log.debug("Output is '" + addWafPage.getNameErrorsText() + "'");
		assertTrue("The correct error text was not present", emptyInputError.equals(addWafPage.getNameErrorsText()));
		
		addWafPage.setNameInput(whiteSpaceString);
		addWafPage = addWafPage.clickAddWafButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(addWafPage.getNameErrorsText()));
		
		// Test browser length limit
		addWafPage.setNameInput(longInput);
		WafDetailPage wafDetailPage = addWafPage.clickAddWafButton();
		
		assertTrue("The waf name was not cropped correctly.", wafDetailPage.getNameText().length() == Waf.NAME_LENGTH);
		
		// Test name duplication checking
		String orgName = wafDetailPage.getNameText();
		
		addWafPage = wafDetailPage.clickBackToListLink().clickAddWafLink();
		addWafPage.setNameInput(orgName);
		addWafPage.clickAddWafButtonInvalid();
		
		assertTrue(addWafPage.getNameErrorsText().equals("That name is already taken."));
		
		// Delete and logout
		wafIndexPage = addWafPage.clickWafsHeaderLink().clickTextLinkInWafTableBody(orgName).clickDeleteButton();
		
		loginPage = wafIndexPage.logout();
	}
	
	@Test
	public void testEditWaf(){
		String newOrgName = "testEditWaf";
		String editedOrgName = "testEditWaf - edited";
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		assertFalse("The waf was already present.", wafIndexPage.isTextPresentInWafTableBody(newOrgName));
		
		WafAddPage wafAddPage = wafIndexPage.clickAddWafLink();
		
		wafAddPage.setNameInput(newOrgName);
		wafAddPage.setTypeSelect(type1);
		
		WafDetailPage wafDetailPage = wafAddPage.clickAddWafButton();
		
		assertTrue("Waf Page did not save the name correctly.", newOrgName.equals(wafDetailPage.getNameText()));
		assertTrue("Waf Page did not save the type correctly.", type1.equals(wafDetailPage.getWafTypeText()));
		
		WafEditPage wafEditPage = wafDetailPage.clickEditLink();
		
		wafEditPage.setNameInput(editedOrgName);
		wafEditPage.setTypeSelect(type2);
		
		wafDetailPage = wafEditPage.clickUpdateWafButton();
		assertTrue("Editing did not change the name.", editedOrgName.equals(wafDetailPage.getNameText()));
		assertTrue("Editing did not change the type.", type2.equals(wafDetailPage.getWafTypeText()));
		
		wafIndexPage = wafDetailPage.clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickTextLinkInWafTableBody(editedOrgName).clickDeleteButton();
		assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newOrgName));
	
		loginPage = wafIndexPage.logout();
	}
	
	@Test
	public void testEditWafBoundaries(){
		String wafName = "testEditWafBoundaries";
		String wafNameDuplicateTest = "testEditWafBoundaries2";
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();	
		
		// Create dummy WAFs
		
		WafAddPage wafAddPage = wafIndexPage.clickAddWafLink();
		wafAddPage.setNameInput(wafNameDuplicateTest);
		wafAddPage.setTypeSelect(type1);
		WafDetailPage wafDetailPage = wafAddPage.clickAddWafButton();
		
		wafAddPage = wafDetailPage.clickBackToListLink().clickAddWafLink();
		wafAddPage.setNameInput(wafName);
		wafAddPage.setTypeSelect(type2);
		wafDetailPage = wafAddPage.clickAddWafButton();
	
		// Test submission with no changes
		wafDetailPage = wafDetailPage.clickEditLink().clickUpdateWafButton();
		assertTrue("Waf Page did not save the name correctly.", wafName.equals(wafDetailPage.getNameText()));
		WafEditPage editWafPage = wafDetailPage.clickEditLink();
		
		// Test empty and whitespace input
		editWafPage.setNameInput(emptyString);
		editWafPage = editWafPage.clickUpdateWafButtonInvalid();
		log.debug("Output is '" + editWafPage.getNameErrorsText() + "'");
		assertTrue("The correct error text was not present", emptyInputError.equals(editWafPage.getNameErrorsText()));
		
		editWafPage.setNameInput(whiteSpaceString);
		editWafPage = editWafPage.clickUpdateWafButtonInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(editWafPage.getNameErrorsText()));
		
		// Test browser length limit
		editWafPage.setNameInput(longInput);
		wafDetailPage = editWafPage.clickUpdateWafButton();
		
		wafName = wafDetailPage.getNameText();
		
		assertTrue("The waf name was not cropped correctly.", wafDetailPage.getNameText().length() == Waf.NAME_LENGTH);
		
		// Test name duplication checking
		editWafPage = wafDetailPage.clickEditLink();
		editWafPage.setNameInput(wafNameDuplicateTest);
		editWafPage.clickUpdateWafButtonInvalid();
		
		assertTrue(editWafPage.getNameErrorsText().equals("That name is already taken."));
					
		// Delete and logout
		wafIndexPage = editWafPage.clickWafsHeaderLink().clickTextLinkInWafTableBody(wafName).clickDeleteButton();
		wafIndexPage = wafIndexPage.clickTextLinkInWafTableBody(wafNameDuplicateTest).clickDeleteButton();
		
		loginPage = wafIndexPage.logout();
	}
}
