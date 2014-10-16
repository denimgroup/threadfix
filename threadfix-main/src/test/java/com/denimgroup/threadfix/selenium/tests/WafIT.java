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
import com.denimgroup.threadfix.selenium.pages.*;
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
		String newWafName = getName();
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
        String wafName = getName();
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
		String newWafName = getName();
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
		String newWafName = getName();
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
		String newWafName = getName();
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
		String newWafName = getName();
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
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();
		
		wafIndexPage = wafIndexPage.clickAddWafLink();

		// Test empty and whitespace input
		wafIndexPage = wafIndexPage.setWafName(emptyString)
                .clickModalSubmitInvalid();
        assertTrue("The correct error text was not present", wafIndexPage.isElementVisible("nameRequiredError"));
		
		wafIndexPage = wafIndexPage.setWafName(whiteSpaceString)
                .clickModalSubmitInvalid();
        assertTrue("The correct error text was not present", wafIndexPage.isElementVisible("nameRequiredError"));
		
		// Test browser length limit
		wafIndexPage = wafIndexPage.setWafName(getRandomString(65))
                .clickModalSubmitInvalid();
        sleep(500);
        assertTrue("The correct error text was not present", wafIndexPage.isElementVisible("characterLimitError"));
	}

	@Test
	public void testEditWaf(){
		String originalWaf = getName();
		String editedWaf = originalWaf + "-edited";
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

		wafIndexPage = wafIndexPage.clickAddWafLink()
                .createNewWaf(originalWaf, type1)
                .clickModalSubmit();

        wafIndexPage.refreshPage();

		wafIndexPage.clickEditWaf(originalWaf)
                .editWaf(originalWaf, editedWaf, type2)
                .clickModalSubmit()
                .clickWafsHeaderLink();

		assertTrue("Editing did not change the name.", wafIndexPage.isWafPresent(editedWaf));
		assertTrue("Editing did not change the type.", wafIndexPage.isTextPresentInWafTableBody(type2));
	}

    @Test
    public void testEditWafFieldValidation(){
        String wafName = getName();
        String wafNameDuplicateTest = getName();

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
        assertTrue("The correct error text was not present", wafIndexPage.isElementVisible("nameRequiredError"));

        wafIndexPage = wafIndexPage
                .editWaf(wafName, whiteSpaceString, type2)
                .clickModalSubmitInvalid();
        assertTrue("The correct error text was not present", wafIndexPage.isElementVisible("nameRequiredError"));

        // Test browser length limit
        wafIndexPage = wafIndexPage
                .editWaf(wafName, longInput, type2)
                .clickModalSubmitInvalid();

        assertTrue("Name length error was not displayed", wafIndexPage.isElementVisible("characterLimitError"));

        wafIndexPage.clickModalCancel();
        driver.navigate().refresh();

        // Test name duplication checking
        wafIndexPage = wafIndexPage.clickEditWaf(wafName)
                .editWaf(wafName, wafNameDuplicateTest, type2)
                .clickModalSubmitInvalid();

        assertTrue("Duplicate name error was not displayed", wafIndexPage.isElementVisible("otherNameError"));
    }

	@Test
	public void attachModSecWafToaNewApp() throws MalformedURLException {
		String teamName = createTeam();
		String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.getScanFilePath());

		String wafName = getName();
		String wafType = "mod_security";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, wafType)
                .clickModalSubmit();

		//Add waf to application
		TeamIndexPage teamIndexPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName)
                .clickDynamicSubmit();

        assertTrue("waf was not added.", driver.findElement(By.id("wafName")).getText().contains(wafName));

        applicationDetailPage.saveWafAdd();
        sleep(15000);

		//Generating  Deny waf Rules
		WafRulesPage wafRulesPage = applicationDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickRules(wafName)
                .setWafApplicationSelect(teamName, appName)
                .setWafDirectiveSelect("deny")
                .clickGenerateWafRulesButton();

		assertTrue("Waf rule not generated", driver.findElement(By.linkText("Download Waf Rules")).isDisplayed());

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

    @Test
    public void testWafNameOnModalHeader() {
        String originalWaf = getName();
        String emptyString = "";
        String type = "Snort";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(originalWaf, type)
                .clickModalSubmit();

        wafIndexPage.clickEditWaf(originalWaf);

        assertTrue("Waf Modal Header wasn't showed Correct name", wafIndexPage.isModalHeadrDisplayCorrect("Edit WAF ", originalWaf));

        wafIndexPage.editWaf(originalWaf, emptyString, type);

        assertTrue("Waf Modal Header wasn't showed Correct name", wafIndexPage.isModalHeadrDisplayCorrect("Edit WAF", emptyString));
    }

    @Test
    public void CreateWafWithTheSameNameOfPrevious() {
        String wafName = getName();
        String newWafName = getName();
        String type = "Snort";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

        wafIndexPage.clickAddWafLink()
                .createNewWaf(wafName, type)
                .clickModalSubmit();

        assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(wafName));
        assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafName));

        wafIndexPage.clickDeleteWaf(wafName);

        assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafName));

        wafIndexPage.clickAddWafLink()
                .createNewWaf(newWafName, type)
                .clickModalSubmit();

        assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(newWafName));
        assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));
    }

    @Test
    public void checkWafLogFileLink() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String wafName = getName();
        String logFile = ScanContents.SCAN_FILE_MAP.get("Snort Log");

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafsHeaderLink();

        WafRulesPage wafRulesPage = wafIndexPage.clickRules(wafName)
                .clickGenerateWafRulesButton();

        wafRulesPage.refreshPage();

        wafRulesPage.setLogFile(logFile);

        WafLogPage wafLogPage = wafRulesPage.clickUploadLogFile();

        wafLogPage.clickContinue();

        wafIndexPage.clickRules(wafName);

        WafSecurityEventDetailsPage wafSecurityEventDetailsPage = wafRulesPage.clickViewDetails()
                .clickLogLink()
                .clickVulnerabilityLink();


        assertTrue("Security Event Detail Give Error", wafSecurityEventDetailsPage.isLogsNumberPresent());
    }

    @Test
    public void checkDeletedWaf() {
        String wafName1 = getName();
        String wafName2 = getName();
        String wafType = "Snort";

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink();

        wafIndexPage.clickAddWafLink()
                .setWafName(wafName1)
                .setWafType(wafType)
                .clickModalSubmit();

        assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(wafName1));
        assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafName1));

        wafIndexPage = wafIndexPage.clickAddWafLink()
                .setWafName(wafName2)
                .setWafType(wafType)
                .clickModalSubmit();

        assertTrue("The waf was not present in the table.", wafIndexPage.isWafPresent(wafName2));
        assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafName2));

        wafIndexPage.clickDeleteWaf(wafName1)
                .refreshPage();

        assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(wafName1));
    }

    @Test
    public void DeleteAssignWafToApplication() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String wafName = getName();

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWAfButtom();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom();
        }

        assertTrue("Waf wasn't created", applicationDetailPage.checkWafName().contains(wafName));

        applicationDetailPage.clickModalSubmit();

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafsHeaderLink()
                .clickDeleteWaf(wafName);

        assertTrue("Waf Deleted successfully", wafIndexPage.isErrorPresent("Failed to delete a WAF with application mappings."));

        applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf()
                .addWaf("None")
                .clickUpdateApplicationButton();

        wafIndexPage = applicationDetailPage.clickWafsHeaderLink()
                .clickDeleteWaf(wafName);

        assertTrue("Waf wasn't deleted successfully", wafIndexPage.isSuccessPresent(wafName));
    }

    @Test
    public void testApplicationNameNav() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String wafName = getName();

        ApplicationDetailPage applicationDetailPage1 = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        WafIndexPage wafIndexPage = applicationDetailPage1.clickEditDeleteBtn()
                .clickSetWaf()
                .clickCreateNewWaf()
                .setWafName(wafName)
                .clickDynamicSubmit()
                .clickModalSubmit()
                .clickWafsHeaderLink();

        ApplicationDetailPage applicationDetailPage2 = wafIndexPage.clickRules(wafName).clickAppName(appName);

        String appNameTest = applicationDetailPage2.getNameText();

        assertTrue("Application link did not navigate correclty", appName.equals(appNameTest));
    }

    @Test
    public void testDownloadWafRules() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String wafName = getName();

        DatabaseUtils.uploadScan(teamName,appName,ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"));
        DatabaseUtils.createWaf(wafName,"Snort");

        WafRulesPage wafRulesPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName)
                .clickAttachWaf()
                .clickUpdateApplicationButton()
                .clickWafsHeaderLink()
                .clickRules(wafName)
                .clickGenerateWafRulesButton();

        assertTrue("Download Waf Rules not working", wafRulesPage.clickDownloadWafRulesEnabled());
    }

    @Test
    public void testCancelButton() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String wafName = getName();

        DatabaseUtils.uploadScan(teamName,appName,ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"));
        DatabaseUtils.createWaf(wafName,"Snort");

        WafRulesPage wafRulesPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName)
                .clickAttachWaf()
                .clickUpdateApplicationButton()
                .clickWafsHeaderLink()
                .clickRules(wafName)
                .clickGenerateWafRulesButton();

        WafIndexPage wafIndexPage = wafRulesPage.clickWafsHeaderLink()
                .clickRules(wafName)
                .clickCancelButton();

        assertTrue("Cancel link did not work", wafIndexPage.isWafPresent(wafName));
    }

    @Test
    public void testFiredWafNav() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String wafName = getName();

        DatabaseUtils.uploadScan(teamName,appName,ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"));
        DatabaseUtils.createWaf(wafName,"Snort");

        WafRulesPage wafRulesPage1 = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName)
                .clickAttachWaf()
                .clickUpdateApplicationButton()
                .clickWafsHeaderLink()
                .clickRules(wafName)
                .clickGenerateWafRulesButton();

        WafRulesPage wafRulesPage2 = wafRulesPage1.clickWafsHeaderLink()
                .clickRules(wafName)
                .clickViewDetails();

        assertTrue("Fired Waf Navigation failed", wafRulesPage2.checkFiredWafNav("100000"));
    }
}
