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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;

import org.junit.Test;
import org.openqa.selenium.By;

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;

import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;


public class WafTests extends BaseTest {
	
	@Test
	public void testCreateWaf(){
		String newWafName = "testCreateWaf" + getRandomString(3);
		String type = "mod_security";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickCreateWaf();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
	}

    @Test
    public void testDeleteWaf() {
        String wafName = "testDeleteWaf" + getRandomString(3);
        String wafType = "mod_security";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

        wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(wafName, wafType)
                .clickCreateWaf();

        wafIndexPage = wafIndexPage.clickDeleteWaf(wafName)
                .clickWafsHeaderLink();

        assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(wafName));
    }
	
	@Test
	public void testCreateWafSnort(){
		String newWafName = "testCreateSnortWaf" + getRandomString(3);
		String type = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickCreateWaf();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
	}
	
	@Test
	public void testCreateWafImperva(){
		String newWafName = "testCreateImpervaWaf" + getRandomString(3);
		String type = "Imperva SecureSphere";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickCreateWaf();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
	}

	@Test
	public void testCreateWafBigIp(){
		String newWafName = "testCreateBigIpWaf" + getRandomString(3);
		String type = "BIG-IP ASM";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickCreateWaf();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
	}

	@Test
	public void testCreateWafDenyAllrWeb(){
		String newWafName = "testCreateDenyAllrWebWaf" + getRandomString(5);
		String type = "DenyAll rWeb";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickCreateWaf();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
	}
	
	@Test
	public void testCreateWafFieldValidation() {
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink();

		// Test empty and whitespace input
		wafIndexPage = wafIndexPage.setNewNameInput(emptyString)
                .clickCreateWafInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		wafIndexPage = wafIndexPage.setNewNameInput(whiteSpaceString)
                .clickCreateWafInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		// Test browser length limit
		wafIndexPage = wafIndexPage.setNewNameInput(longInput)
                .clickCreateWaf();
		assertTrue("The waf name was not cropped correctly.", wafIndexPage.isNamePresent(longInput.substring(0, Waf.NAME_LENGTH)));
		
		// Test name duplication checking
		String wafName = wafIndexPage.getNameText(1);
		
		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .setNewNameInput(wafName)
                .clickCreateWafInvalid();
		
		assertTrue(wafIndexPage.getNameErrorsText().equals("That name is already taken."));
	}

	@Test
	public void testEditWaf(){
		String originalWaf = "testEditWaf" + getRandomString(3);
		String editedWaf = originalWaf + "-edited";
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(originalWaf, type1)
                .clickCreateWaf();

		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(originalWaf)
                .editWaf(originalWaf, editedWaf, type2)
                .clickUpdateWaf(originalWaf)
                .clickWafsHeaderLink();

		assertTrue("Editing did not change the name.", wafIndexPage.isNamePresent(editedWaf));
		assertTrue("Editing did not change the type.", wafIndexPage.isTextPresentInWafTableBody(type2));
	}

    @Test
    public void testEditWafFieldValidation(){
        String wafName = "testEditWafFieldValidation" + getRandomString(3);
        String wafNameDuplicateTest = "testEditWafFieldValidation-Duplicate" + getRandomString(3);

        String type1 = "mod_security";
        String type2 = "Snort";

        String emptyString = "";
        String whiteSpaceString = "           ";

        String emptyInputError = "This field cannot be blank";

        String longInput = "aaaaaaaaaaaaaaaaaaaaeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        //create dummy wafs
        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

        wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(wafName,type1)
                .clickCreateWaf();

        wafIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafNameDuplicateTest,type1)
                .clickCreateWaf();

        // Test submission with no changes
        wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(wafName)
                .clickUpdateWaf(wafName)
                .clickWafsHeaderLink();
        assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(wafName));

        // Test empty and whitespace input
        wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(wafName)
                .editWaf(wafName, emptyString, type2)
                .clickUpdateWafInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));

        wafIndexPage = wafIndexPage
                .editWaf(wafName, whiteSpaceString, type2)
                .clickUpdateWafInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));

        // Test browser length limit
        wafIndexPage = wafIndexPage
                .editWaf(wafName, longInput, type2)
                .clickUpdateWaf(wafName);

        wafName = wafIndexPage.getWafName(1);
        assertTrue("The waf name was not cropped correctly.", wafIndexPage.isNamePresent(longInput.substring(0, Waf.NAME_LENGTH)));

        // Test name duplication checking
        wafIndexPage = wafIndexPage.clickEditWaf(wafName)
                .editWaf(wafName, wafNameDuplicateTest, type2)
                .clickUpdateWafInvalid();

        assertTrue(wafIndexPage.getNameErrorsText().equals("That name is already taken."));
    }

    @Test
    public void longWafNameEditModalHeaderTest(){
        String wafName = getRandomString(1024);
        String type = "Imperva SecureSphere";
        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, type)
                .clickCreateWaf()
                .clickEditWaf(wafName.substring(0, 50));
        int width = wafIndexPage.getWafEditHeaderWidth(wafName.substring(0, 50));

        wafIndexPage.clickCloseWafModal(wafName.substring(0,50)).clickDeleteWaf(wafName.substring(0,50));

        assertTrue("Waf edit header was too wide",width == 400);
    }

	@Test
	public void attachModSecWafToaNewApp() throws MalformedURLException {
		String teamName = "attachModSecTeam" + getRandomString(3);
		String appName = "attachModSecApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.getScanFilePath());

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
            .clickOrganizationHeaderLink();

		String wafName = "testCreateModSecWaf" + getRandomString(3);
		String wafType = "mod_security";

        WafIndexPage wafIndexPage = teamIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, wafType)
                .clickCreateWaf();

		//Add waf to application
		ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                 .expandTeamRowByName(teamName)
                 .clickViewAppLink(appName, teamName)
                 .clickEditDeleteBtn()
                 .clickAddWaf()
                 .addWaf(wafName);

		//Generating  Deny waf Rules
		WafRulesPage wafRulesPage = applicationDetailPage.clickWafsHeaderLink()
                .clickRules(wafName)
                .setWafApplicationSelect(teamName, appName)
                .setWafDirectiveSelect("deny")
                .clickGenerateWafRulesButton();

		String PageText = driver.findElement(By.id("wafrule")).getText();
		assertTrue("Waf rule not generated", PageText.contains("SecRule"));

		// Generate pass Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("pass")
                .clickGenerateWafRulesButton();

		String PageText2 = driver.findElement(By.id("wafrule")).getText();
		assertTrue("Waf rule not generated", PageText2.contains("SecRule"));

		// Generate drop Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("drop")
                .clickGenerateWafRulesButton();

		String PageText5 = driver.findElement(By.id("wafrule")).getText();
		assertTrue("Waf rule not generated", PageText5.contains("SecRule"));

		// Generate allow Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("allow")
                .clickGenerateWafRulesButton();

		String PageText6 = driver.findElement(By.id("wafrule")).getText();
		assertTrue("Waf rule not generated", PageText6.contains("SecRule"));
	}
}
