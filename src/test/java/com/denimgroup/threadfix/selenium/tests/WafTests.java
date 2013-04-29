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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.selenium.pages.ApplicationAddPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationEditPage;
import com.denimgroup.threadfix.selenium.pages.GeneratedReportPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.ReportsIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;


public class WafTests extends BaseTest {
	private FirefoxDriver driver;
	//private WebDriver driver;
	private static LoginPage loginPage;
	private WafIndexPage wafIndexPage;
	private ApplicationEditPage applicationEditPage;
	public ApplicationDetailPage applicationDetailPage;
	public UploadScanPage uploadScanPage;
	public TeamIndexPage teamIndexPage;
	public TeamDetailPage teamDetailPage;
	public ReportsIndexPage reportsIndexPage;
	public GeneratedReportPage generatedReportPage;
	public TeamIndexPage organizationIndexPage;
	public ApplicationAddPage applicationAddPage;
	
	Random generator = new Random();

	public String appWasAlreadyUploadedErrorText = "Scan file has already been uploaded.";

	private static Map<String, String> fileMap = ScanTests.SCAN_FILE_MAP;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
		}
	
	public static URL getScanFilePath(String category, String scannerName,
			String fileName) {
		String string = "SupportingFiles/" + category + "/" + scannerName + "/"
				+ fileName;

		return ClassLoader.getSystemResource(string);// .getFile();
	}
	
	@After
	public void shutDown() {
		driver.quit();
	}
	
	@Test
	public void testCreateWaf(){
		String newWafName = "testCreateWaf" + getRandomString(5);
		String type = "mod_security";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newWafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink().createNewWaf(newWafName, type).clickCreateWaf();
		
		//assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafIndexPage.getWafName(1)));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));

		loginPage = wafIndexPage.clickDeleteWaf(newWafName).clickWafsHeaderLink().logout();
		
		//assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	
	}
	
	@Test
	public void testCreateWafSnort(){
		String newWafName = "testCreateSnortWaf" + getRandomString(5);
		String type = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newWafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink().createNewWaf(newWafName, type).clickCreateWaf();
		
		//assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafIndexPage.getWafName(1)));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));

		loginPage = wafIndexPage.clickDeleteWaf(newWafName).clickWafsHeaderLink().logout();
		
		//assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	
		
	}
	
	//Create Imperva Waf
	
	@Test
	public void testCreateWafImperva(){
		String newWafName = "testCreateImpervaWaf" + getRandomString(5);
		String type = "Imperva SecureSphere";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newWafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
								.createNewWaf(newWafName, type)
								.clickCreateWaf();
		
		//assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafIndexPage.getWafName(1)));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));

		loginPage = wafIndexPage.clickDeleteWaf(newWafName).clickWafsHeaderLink().logout();
		
		//assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	

		
	}
	
	
	
	//Create BIG-IP ASM Waf
	
	@Test
	public void testCreateWafBigIp(){
		String newWafName = "testCreateBigIpWaf" + getRandomString(5);
		String type = "BIG-IP ASM";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newWafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink().createNewWaf(newWafName, type).clickCreateWaf();
		
		//assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafIndexPage.getWafName(1)));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));

		wafIndexPage = wafIndexPage.clickDeleteWaf(newWafName);
		
		//assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	
		loginPage = wafIndexPage.clickWafsHeaderLink().logout();
		
	}
	
	
	
	//Create DenyAllrWeb Waf
			
	@Test
	public void testCreateWafDenyAllrWeb(){
		String newWafName = "testCreateDenyAllrWebWaf" + getRandomString(5);
		String type = "DenyAll rWeb";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newWafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink().createNewWaf(newWafName, type).clickCreateWaf();
		
		//assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafIndexPage.getWafName(1)));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newWafName));

		wafIndexPage = wafIndexPage.clickDeleteWaf(newWafName);
		
		//assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isTextPresentInWafTableBody(newWafName));
	
		loginPage = wafIndexPage.logout();
	}
	
	/* In progress */
	/* waf modal does not yet contain validaition with the modal */
	@Test
	public void testCreateWafBoundaries(){
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();		
		
		wafIndexPage = wafIndexPage.clickAddWafLink();
		//does not currently prompt an error should be uncommented when that is fixed
		// Test empty and whitespace input
		wafIndexPage = wafIndexPage.setNewNameInput(emptyString);
		wafIndexPage = wafIndexPage.clickCreateWafInvalid();
		log.debug("Output is '" + wafIndexPage.getNameErrorsText() + "'");
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		wafIndexPage = wafIndexPage.setNewNameInput(whiteSpaceString);
		wafIndexPage = wafIndexPage.clickCreateWafInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		// Test browser length limit
		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
								.clickAddWafLink()
								.setNewNameInput(longInput);
		wafIndexPage = wafIndexPage.clickCreateWaf();
		
		assertTrue("The waf name was not cropped correctly.", wafIndexPage.getNameText(1).length() == Waf.NAME_LENGTH);
		
		// Test name duplication checking
		String wafName = wafIndexPage.getNameText(1);
		
		wafIndexPage = wafIndexPage.clickWafsHeaderLink().clickAddWafLink();
		wafIndexPage.setNewNameInput(wafName);
		
		wafIndexPage.clickCreateWafInvalid();
		
		assertTrue(wafIndexPage.getNameErrorsText().equals("That name is already taken."));
		
		// Delete and logout
		loginPage = wafIndexPage.clickWafsHeaderLink().clickDeleteWaf(wafName).logout();
		
		
	}

	
	//Create Snort Waf, attach it to an application and generate rules

	
	@Test
	public void testEditWaf(){
		String newOrgName = "testEditWaf";
		String editedOrgName = "testEditWaf - edited";
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(newOrgName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
								.createNewWaf(newOrgName,type1)
								.clickCreateWaf();
		
		
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newOrgName));
		assertTrue("Waf Page did not save the type correctly.", wafIndexPage.isTextPresentInWafTableBody(type1));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(newOrgName));
		
		wafIndexPage = wafIndexPage.clickWafsHeaderLink()
								.clickEditWaf(newOrgName)
								.editWaf(newOrgName, editedOrgName, type2)
								.clickUpdateWaf()
								.clickWafsHeaderLink();
		

		
		assertTrue("Editing did not change the name.", wafIndexPage.isNamePresent(editedOrgName));
		assertTrue("Editing did not change the type.", wafIndexPage.isTextPresentInWafTableBody(type2));
		//assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(editedOrgName));
		
		wafIndexPage = wafIndexPage.clickDeleteWaf(editedOrgName);
		assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isNamePresent(newOrgName));
	
		loginPage = wafIndexPage.logout();
	}
	
	
	/////////////////////////////////////////////////
	
	
	//Create mod-Security Waf and generate rules
	
	@Test
	public void attachModSecWafToaNewApp() throws MalformedURLException {
		String orgName = "testCreateOrg2";
		String appName = "testCreateApp2";
		String urlText = "http://testur2.com";

		//set up an organization
		organizationIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
									.clickAddTeamButton()
									.setTeamName(orgName)
									.addNewTeam()
									.expandTeamRowByName(orgName)
									.addNewApplication(orgName, appName, urlText, "Low")
									.saveApplication(orgName);

		//boolean first = true;

		/*for (String channelc : fileMap.keySet()) {
			organizationIndexPage = organizationIndexPage.expandTeamRowByName(orgName)
													.clickUploadScan(appName,orgName);
		}

		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = null;

				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}

				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}

			wafIndexPage = organizationIndexPage
					// clickAddChannelButton()
					.setFileInput(mapEntry.getValue(),appName)
					.clickUploadScanButton(appName)
					.clickWafsHeaderLink();

		}*/
		
		//Creating a new Waf
		
		String newWafName = "testCreateModSecWaf1";
		String type = "mod_security";

		wafIndexPage = organizationIndexPage.clickWafsHeaderLink()
				.clickAddWafLink()
				.createNewWaf(newWafName, type)
				.clickCreateWaf();

		assertTrue("Waf Page did not save the name correctly.", wafIndexPage.isNamePresent(newWafName));

		//Add waf to application
		applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
				 .expandTeamRowByName(orgName)
				 .clickViewAppLink(appName,orgName)
				 .clickActionButton()
				 .clickShowDetails()
				 .clickAddWaf()
				 .addWaf(newWafName);


		//Generating  Deny waf Rules
		applicationDetailPage.clickWafsHeaderLink()
							.clickRules(newWafName)
							.setWafDirectiveSelect("deny");
							
		WafRulesPage wafDetailPage = new WafRulesPage(driver);	
		wafDetailPage.setWafDirectiveSelect("deny");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafRulesPage(driver);
		String PageText = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText.contains("SecRule"));

		// Generate pass Waf Rules
		wafDetailPage = new WafRulesPage(driver);
		wafDetailPage.setWafDirectiveSelect("pass");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafRulesPage(driver);
		String PageText2 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText2.contains("SecRule"));

		// Generate drop Waf Rules
		wafDetailPage = new WafRulesPage(driver);
		wafDetailPage.setWafDirectiveSelect("drop");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafRulesPage(driver);
		String PageText5 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText5.contains("SecRule"));

		// Generate allow Waf Rules
		wafDetailPage = new WafRulesPage(driver);
		wafDetailPage.setWafDirectiveSelect("allow");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafRulesPage(driver);
		String PageText6 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText6.contains("SecRule"));
	}
	/*
	// Generate Snort Waf Rules
	@Test
	public void attachWafToaNewApp() throws MalformedURLException {
		String orgName = "testCreateOrg1";
		String appName = "testCreateApp1";
		String urlText = "http://testurl.com";

		//set up an organization
		organizationAddPage = loginPage.login("user", "password").clickAddTeamButton();

		organizationAddPage.setNameInput(orgName);

		boolean first = true;

		//add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid().clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);
		applicationDetailPage = applicationAddPage.clickAddApplicationButton();


		for (String channelc : fileMap.keySet()) {
			if (first) {
				first = false;
				uploadScanPage = applicationDetailPage.clickUploadScanLinkFirstTime()
						.setChannelTypeSelect(channelc)
						.clickAddChannelButton();

			} else {
				uploadScanPage = uploadScanPage.clickAddAnotherChannelLink()
						.setChannelTypeSelect(channelc)
						.clickAddChannelButton();
			}
		}

		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = null;
				
				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}

			uploadScanPage = uploadScanPage
					// clickAddChannelButton()
					.setFileInput(mapEntry.getValue())
					.setChannelSelect(mapEntry.getKey())
					.clickUploadScanButton()
					.clickUploadScanLink();

		}

		//Creating a new Waf

		String newWafName = "testCreateSnortWaf1";
		String type = "Snort";
		driver.findElementById("wafsHeader").click();
		wafIndexPage = new WafIndexPage(driver);
		wafIndexPage.clickAddWafLink();

		wafAddPage = new WafAddPage(driver);
		wafAddPage.setNameInput(newWafName);
		wafAddPage.setTypeSelect(type);
		WafDetailPage wafDetailPage = wafAddPage.clickAddWafButton();
		assertTrue("Waf Page did not save the name correctly.", newWafName.equals(wafDetailPage.getNameText()));

		//Add waf to application
		wafDetailPage.clickTeamHeaderLink();
		organizationIndexPage = new TeamIndexPage(driver);
		organizationIndexPage.clickOrganizationLink("testCreateOrg1");
		organizationDetailPage = new TeamDetailPage(driver);
		organizationDetailPage.clickTextLinkInApplicationsTableBody("testCreateApp1");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationEditPage = applicationDetailPage.clickEditLink();
		applicationEditPage.setWafSelect("testCreateSnortWaf1");
		applicationEditPage.clickUpdateApplicationButton();
		applicationDetailPage = new ApplicationDetailPage(driver);
		driver.findElementById("wafText").click();

		//Generating  Alert waf Rules
		wafDetailPage = new WafDetailPage(driver);	
		wafDetailPage.setWafDirectiveSelect("alert");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText.contains("alert"));

		// Generate log waf rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("log");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText1 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText1.contains("log"));

		// Generate pass Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("pass");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText2 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText2.contains("pass"));

		// Generate activate Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("activate");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText3 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText3.contains("activate"));

		// Generate Dynamic Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("dynamic");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText4 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText4.contains("dynamic"));

		// Generate drop Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("drop");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText5 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText5.contains("drop"));

		// Generate reject Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("reject");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText6 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText6.contains("reject"));

		// Generate sdrop Waf Rules
		wafDetailPage = new WafDetailPage(driver);
		wafDetailPage.setWafDirectiveSelect("sdrop");
		wafDetailPage.clickGenerateWafRulesButton();
		wafDetailPage = new WafDetailPage(driver);
		String PageText7 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText7.contains("sdrop"));
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
		wafIndexPage = editWafPage.clickWafsLink().clickTextLinkInWafTableBody(wafName).clickDeleteButton();
		wafIndexPage = wafIndexPage.clickTextLinkInWafTableBody(wafNameDuplicateTest).clickDeleteButton();
		
		loginPage = wafIndexPage.logout();
	}
	*/
}
