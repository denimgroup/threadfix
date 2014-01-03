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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.selenium.pages.ApplicationAddPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.GeneratedReportPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.ReportsIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;


public class WafTests extends BaseTest {
	public WafTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private RemoteWebDriver driver;
	private static LoginPage loginPage;
	private WafIndexPage wafIndexPage;
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

	private static Map<String, String> fileMap = ScanContents.SCAN_FILE_MAP;

	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
		}
	
	public static URL getScanFilePath(String category, String scannerName,
			String fileName) {
		String string = "/SupportingFiles/" + category + "/" + scannerName + "/"
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

		loginPage = wafIndexPage.clickWafsHeaderLink().clickDeleteWaf(newWafName).clickWafsHeaderLink().logout();
		
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

		// Test empty and whitespace input
		wafIndexPage = wafIndexPage.setNewNameInput(emptyString);
		wafIndexPage = wafIndexPage.clickCreateWafInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		wafIndexPage = wafIndexPage.setNewNameInput(whiteSpaceString);
		wafIndexPage = wafIndexPage.clickCreateWafInvalid();
		assertTrue("The correct error text was not present", emptyInputError.equals(wafIndexPage.getNameErrorsText()));
		
		// Test browser length limit
		wafIndexPage = wafIndexPage.setNewNameInput(longInput).clickCreateWaf();
		//wafIndexPage = wafIndexPage.clickCreateWaf();
		assertTrue("The waf name was not cropped correctly.", wafIndexPage.isNamePresent(longInput.substring(0, Waf.NAME_LENGTH)));
		
		// Test name duplication checking
		String wafName = wafIndexPage.getNameText(1);
		
		wafIndexPage = wafIndexPage.clickWafsHeaderLink().clickAddWafLink();
		wafIndexPage.setNewNameInput(wafName);
		
		wafIndexPage.clickCreateWafInvalid();
		
		assertTrue(wafIndexPage.getNameErrorsText().equals("That name is already taken."));
		
		// Delete and logout
		loginPage = wafIndexPage.clickCloseCreateWafModal().clickDeleteWaf(wafName).logout();
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
								.clickUpdateWaf(newOrgName)
								.clickWafsHeaderLink();
		

		
		assertTrue("Editing did not change the name.", wafIndexPage.isNamePresent(editedOrgName));
		assertTrue("Editing did not change the type.", wafIndexPage.isTextPresentInWafTableBody(type2));
		//assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(editedOrgName));
		
		wafIndexPage = wafIndexPage.clickDeleteWaf(editedOrgName);
		assertFalse("The waf was still present after attempted deletion.", wafIndexPage.isNamePresent(newOrgName));
	
		loginPage = wafIndexPage.logout();
	}

	//Create mod-Security Waf and generate rules
	@Test
	public void attachModSecWafToaNewApp() throws MalformedURLException {
		String orgName = "testCreateOrg2"+getRandomString(8);
		String appName = "testCreateApp2"+getRandomString(8);
		String urlText = "http://testur2.com";
		String rtApp = "Demo Site BE";
		String whKey = System.getProperty("WHITEHAT_KEY");

		//set up an organization
		organizationIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
			.clickAddTeamButton()
            .setTeamName(orgName)
            .addNewTeam()
            .clickOrganizationHeaderLink()
            .addNewApplication(orgName, appName, urlText, "Low")
            .saveApplication(orgName);

		applicationDetailPage = organizationIndexPage.clickRemoteProvidersLink()
			.clickConfigureWhiteHat()
			.setWhiteHatAPI(whKey)
			.saveWhiteHat()
			.clickEditMapping(rtApp)
			.setTeamMapping(rtApp, orgName)
			.setAppMapping(rtApp, appName)
			.clickSaveMapping(rtApp)
			.clickImportScan(rtApp);
		
		String newWafName = "testCreateModSecWaf1";
		String type = "mod_security";

		wafIndexPage = organizationIndexPage.clickWafsHeaderLink()
            .clickAddWafLink()
            .createNewWaf(newWafName, type)
            .clickCreateWaf();

		assertTrue("Waf Page did not save the name correctly.", wafIndexPage.isNamePresent(newWafName));

		//Add waf to application
		applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
             .expandTeamRowByIndex(orgName)
             .clickViewAppLink(appName, orgName)
             .clickEditDeleteBtn()
             .clickAddWaf()
             .addWaf(newWafName);


		//Generating  Deny waf Rules
		applicationDetailPage.clickWafsHeaderLink()
            .clickRules(newWafName)
            .setWafDirectiveSelect("deny");
							
		WafRulesPage WafRulesPage = new WafRulesPage(driver);	
		WafRulesPage.setWafDirectiveSelect("deny");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText.contains("SecRule"));

		// Generate pass Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("pass");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText2 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText2.contains("SecRule"));

		// Generate drop Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("drop");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText5 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText5.contains("SecRule"));

		// Generate allow Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("allow");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText6 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText6.contains("SecRule"));
		WafRulesPage.clickOrganizationHeaderLink()
				.clickViewTeamLink(orgName)
				.clickDeleteButton()
				.clickWafsHeaderLink()
				.clickDeleteWaf(newWafName);
		
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

	// Generate Snort Waf Rules
	@Test
	public void attachWafToaNewApp() throws MalformedURLException {
		String orgName = "testCreateOrg1"+getRandomString(8);
		String appName = "testCreateApp1"+getRandomString(8);
		String urlText = "http://testurl.com";
		String rtApp = "Demo Site BE";
		String whKey = System.getProperty("WHITEHAT_KEY");

		//set up an organization
		organizationIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(orgName)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(orgName)
				.addNewApplication(orgName, appName, urlText, "Low")
				.saveApplication(orgName);

		applicationDetailPage = organizationIndexPage.clickRemoteProvidersLink()
							.clickConfigureWhiteHat()
							.setWhiteHatAPI(whKey)
							.saveWhiteHat()
							.clickEditMapping(rtApp)
							.setTeamMapping(rtApp, orgName)
							.setAppMapping(rtApp, appName)
							.clickSaveMapping(rtApp)
							.clickImportScan(rtApp);
		
//		applicationDetailPage = organizationIndexPage.clickViewAppLink(appName, orgName);
//		
//		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
//			if (mapEntry.getValue() != null){
//				File appScanFile = null;
//				if (System.getProperty("scanFileBaseLocation") == null) {
//						appScanFile = new File(new URL(mapEntry.getValue()).getFile());
//				} else {
//					appScanFile = new File(mapEntry.getValue());
//				}
//				assertTrue("The test file did not exist.", appScanFile.exists());
//			} else {
//				continue;
//			}
//
//			applicationDetailPage = applicationDetailPage.clickUploadScanLink()
//						.setFileInput(mapEntry.getValue())
//						.submitScan();
//		}

		//Creating a new Waf

		String newWafName = "testCreateSnortWaf1";
		String type = "Snort";

		wafIndexPage = organizationIndexPage.clickWafsHeaderLink()
				.clickAddWafLink()
				.createNewWaf(newWafName, type)
				.clickCreateWaf();


		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(newWafName));

		//Add waf to application
		applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
				 .expandTeamRowByIndex(orgName)
				 .clickViewAppLink(appName,orgName)
				 .clickEditDeleteBtn()
				 .clickAddWaf()
				 .addWaf(newWafName);

		//Generating  Alert waf Rules
		applicationDetailPage.clickWafsHeaderLink()
		.clickRules(newWafName);
		
		WafRulesPage WafRulesPage = new WafRulesPage(driver);	
		WafRulesPage.setWafDirectiveSelect("alert");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText.contains("alert"));

		// Generate log waf rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("log");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText1 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText1.contains("log"));

		// Generate pass Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("pass");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText2 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText2.contains("pass"));

		// Generate activate Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("activate");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText3 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText3.contains("activate"));

		// Generate Dynamic Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("dynamic");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText4 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText4.contains("dynamic"));

		// Generate drop Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("drop");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText5 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText5.contains("drop"));

		// Generate reject Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("reject");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText6 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText6.contains("reject"));

		// Generate sdrop Waf Rules
		WafRulesPage = new WafRulesPage(driver);
		WafRulesPage.setWafDirectiveSelect("sdrop");
		WafRulesPage.clickGenerateWafRulesButton();
		WafRulesPage = new WafRulesPage(driver);
		String PageText7 = driver.findElementById("wafrule").getText();
		assertTrue("Waf rule not generated", PageText7.contains("sdrop"));
		
		WafRulesPage.clickOrganizationHeaderLink()
			.clickViewTeamLink(orgName)
			.clickDeleteButton()
			.clickWafsHeaderLink()
			.clickDeleteWaf(newWafName);
	}

	@Test
	public void testEditWafBoundaries(){
		String wafName = "testEditWafBoundaries"+getRandomString(6);
		String wafNameDuplicateTest = "testEditWafBoundaries2"+getRandomString(6);
		
		String type1 = "mod_security";
		String type2 = "Snort";
		
		String emptyString = "";
		String whiteSpaceString = "           ";
		
		String emptyInputError = "This field cannot be blank";
		
		String longInput = "aaaaaaaaaaaaaaaaaaaaeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
		//create dummy wafs
		WafIndexPage wafIndexPage = loginPage.login("user", "password").clickWafsHeaderLink();
		assertFalse("The waf was already present.", wafIndexPage.isNamePresent(wafName));
		
		wafIndexPage = wafIndexPage.clickAddWafLink()
								.createNewWaf(wafName,type1)
								.clickCreateWaf();
        wafIndexPage.clickWafsHeaderLink()
								.clickAddWafLink()
								.createNewWaf(wafNameDuplicateTest,type1)
								.clickCreateWaf();
		
		
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(wafName));
		assertTrue("Waf Page did not save the type correctly.", wafIndexPage.isTextPresentInWafTableBody(type1));
//		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafName));
		
		assertTrue("The waf was not present in the table.", wafIndexPage.isNamePresent(wafNameDuplicateTest));
		assertTrue("Waf Page did not save the type correctly.", wafIndexPage.isTextPresentInWafTableBody(type1));
		assertTrue("The success alert is not present. ", wafIndexPage.isSuccessPresent(wafNameDuplicateTest));
	
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
		//log.debug("Output is '" + editWafPage.getNameErrorsText() + "'");
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
//		System.out.println(wafName);
		assertTrue("The waf name was not cropped correctly.", wafIndexPage.isNamePresent(longInput.substring(0, Waf.NAME_LENGTH)));
		
		// Test name duplication checking
		wafIndexPage = wafIndexPage.clickEditWaf(wafName)
								.editWaf(wafName, wafNameDuplicateTest, type2)
								.clickUpdateWafInvalid();
		
		assertTrue(wafIndexPage.getNameErrorsText().equals("That name is already taken."));
					
		// Delete and logout
		wafIndexPage.clickWafsHeaderLink()
					.clickDeleteWaf(wafName)
					.clickDeleteWaf(wafNameDuplicateTest)
					.logout();
		
	}
	
}
