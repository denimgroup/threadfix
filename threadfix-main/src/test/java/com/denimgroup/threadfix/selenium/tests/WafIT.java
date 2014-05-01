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

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import java.net.MalformedURLException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


@Category(CommunityTests.class)
public class WafIT extends BaseIT {
	
	@Test
	public void testCreateWaf(){
		String newWafName = "testCreateWaf" + getRandomString(3);
		String type = "mod_security";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
                .setWafName(newWafName)
                .setWafType(type)
                .clickModalSubmit();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
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
                .clickModalSubmit();

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
                .clickModalSubmit();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
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
                .clickModalSubmit();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
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
                .clickModalSubmit();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
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
                .clickModalSubmit();
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
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
		wafIndexPage = wafIndexPage.setWafName(emptyString)
                .clickModalSubmitInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		wafIndexPage = wafIndexPage.setWafName(whiteSpaceString)
                .clickModalSubmitInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		// Test browser length limit
		wafIndexPage = wafIndexPage.setWafName(longInput)
                .clickModalSubmit();
		assertTrue("The waf name was not cropped correctly.", wafIndexPage.isWafPresent(longInput.substring(0, Waf.NAME_LENGTH)));
		
		// Test name duplication checking
		String wafName = wafIndexPage.getNameText(1);
		
		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .setWafName(wafName)
                .clickModalSubmitInvalid();
		
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
                .clickModalSubmit();

		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(originalWaf)
                .editWaf(originalWaf, editedWaf, type2)
                .clickModalSubmit()
                .clickWafsHeaderLink();

		assertTrue("Editing did not change the name.", wafIndexPage.isWafPresent(editedWaf));
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
                .clickModalSubmit();

        wafIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafNameDuplicateTest,type1)
                .clickModalSubmit();

        // Test submission with no changes
        wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(wafName)
                .clickModalSubmit()
                .clickWafsHeaderLink();
        assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(wafName));

        // Test empty and whitespace input
        wafIndexPage = wafIndexPage.clickWafsHeaderLink()
                .clickEditWaf(wafName)
                .editWaf(wafName, emptyString, type2)
                .clickModalSubmitInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));

        wafIndexPage = wafIndexPage
                .editWaf(wafName, whiteSpaceString, type2)
                .clickModalSubmitInvalid();
        assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));

        // Test browser length limit
        wafIndexPage = wafIndexPage
                .editWaf(wafName, longInput, type2)
                .clickModalSubmit();

        assertTrue("The waf name was not cropped correctly.", wafIndexPage.isWafPresent(wafName));

        // Test name duplication checking
        wafIndexPage = wafIndexPage.clickEditWaf(wafName)
                .editWaf(wafName, wafNameDuplicateTest, type2)
                .clickModalSubmitInvalid();

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
                .clickModalSubmit(WafIndexPage.class)
                .clickEditWaf(wafName.substring(0, 50));
        int width = wafIndexPage.getWafEditHeaderWidth(wafName.substring(0, 50));

        wafIndexPage.clickCloseWafModal().clickDeleteWaf(wafName.substring(0,50));

        assertTrue("Waf edit header was too wide",width == 400);
    }

	@Test
	public void attachModSecWafToaNewApp() throws MalformedURLException {
		String teamName = "attachModSecTeam" + getRandomString(3);
		String appName = "attachModSecApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.getScanFilePath());

		String wafName = "testCreateModSecWaf" + getRandomString(3);
		String wafType = "mod_security";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, wafType)
                .clickModalSubmit();

		//Add waf to application
		ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                 .expandTeamRowByName(teamName)
                 .clickViewAppLink(appName, teamName)
                 .clickEditDeleteBtn()
                 .clickAddWaf()
                 .addWaf(wafName);

		//Generating  Deny waf Rules
		WafRulesPage wafRulesPage = applicationDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickRules(wafName)
                .setWafApplicationSelect(teamName, appName)
                .setWafDirectiveSelect("deny")
                .clickGenerateWafRulesButton();

        String pageText = wafRulesPage.tryGetText(By.id("wafrule"));
		assertTrue("Waf rule not generated", pageText.contains("SecRule"));

		// Generate pass Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("pass")
                .clickGenerateWafRulesButton();

		String pageText2 = wafRulesPage.tryGetText(By.id("wafrule"));
		assertTrue("Waf rule not generated", pageText2.contains("SecRule"));

		// Generate drop Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("drop")
                .clickGenerateWafRulesButton();

        String pageText5 = wafRulesPage.tryGetText(By.id("wafrule"));
		assertTrue("Waf rule not generated", pageText5.contains("SecRule"));

		// Generate allow Waf Rules
		wafRulesPage = wafRulesPage.setWafDirectiveSelect("allow")
                .clickGenerateWafRulesButton();

        String pageText6 = wafRulesPage.tryGetText(By.id("wafrule"));
		assertTrue("Waf rule not generated", pageText6.contains("SecRule"));
	}
}
