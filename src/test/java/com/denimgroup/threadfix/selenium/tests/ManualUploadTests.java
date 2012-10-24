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

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.selenium.pages.AddOrganizationPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationAddPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.ManualUploadPage;

public class ManualUploadTests extends BaseTest {
	private FirefoxDriver driver;
	private ManualUploadPage manualUploadPage;
	private ApplicationDetailPage applicationDetailPage;
	private AddOrganizationPage organizationAddPage;
	private LoginPage loginPage;
	private ApplicationAddPage applicationAddPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@After
	public void shutDown() {
		driver.quit();
	}

	@Test
	public void testNavigation() {
		String orgName = "testCreateApplicationOrgA";
		String appName = "testCreateApplicationAppA";
		String urlText = "http://testurl.com";

		// set up an organization
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.logout();
	}

	@Test
	public void testManualAddCritical() {
		String orgName = "testCreateApplicationOrgB1234";
		String appName = "testCreateApplicationAppB1234";
		String urlText = "http://testurl.com";

		// set up an organization
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
	
		manualUploadPage
				.fillAllClickSaveManual(
						true,
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						"/demo/EvalInjection2.php",
						"command",
						"Critical",
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
	}
	

	@Test
	public void testManualAddHigh() {
		String orgName = "testCreateApplicationOrgC";
		String appName = "testCreateApplicationAppC";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage
				.fillAllClickSaveManual(
						true,
						"File and Directory Information Exposure",
						"/demo/",
						" ",
						"High",
						"File and Directory Information Exposure");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}

	@Test
	public void testManualAddMedium() {
		String orgName = "testCreateApplicationOrgD";
		String appName = "testCreateApplicationAppD";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage
				.fillAllClickSaveManual(
						true,
						"Cross-Site Request Forgery (CSRF)",
						"/demo/EvalInjection.php/EvalInjection2.php",
						" ",
						"Medium",
						"Cross-Site Request Forgery (CSRF)");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}

	@Test
	public void testManualAddLow() {
		String orgName = "testCreateApplicationOrgE";
		String appName = "testCreateApplicationAppE";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage
				.fillAllClickSaveManual(
						true,
						"Information Exposure",
						"/demo/PredictableResource.php",
						" ",
						"Low",
						"Information Exposure");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}

	@Test
	public void testManualAddInfo() {
		String orgName = "testCreateApplicationOrgF";
		String appName = "testCreateApplicationAppF";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage
				.fillAllClickSaveManual(
						true,
						"Information Exposure Through Directory Listing",
						"/demo/DirectoryIndexing/",
						" ",
						"Info",
						"Information Exposure Through Directory Listing");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}
	
	
	
	@Test
	public void testStaticUploadCritical(){
		String orgName = "testCreateApplicationOrg1";
		String appName = "testCreateApplicationApp1";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.fillAllClickSaveStatic(true, "XML Injection (aka Blind XPath Injection)",
									"/demo/XPathInjection2.php", "123", "username", "Critical","XML Injection (aka Blind XPath Injection)");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
		
	}
	
	@Test
	public void testStaticUploadHigh(){
		String orgName = "testCreateApplicationOrg2";
		String appName = "testCreateApplicationApp2";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.fillAllClickSaveStatic(true, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
									"/demo/EvalInjection2.php", "123", "command", "High","Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
		
	}
	
	
	@Test
	public void testStaticUploadMedium(){
		String orgName = "testCreateApplicationOrg3";
		String appName = "testCreateApplicationApp3";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.fillAllClickSaveStatic(true, "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
									"/demo/XPathInjection2.php", "123", "password", "Medium","Improper Neutralization of Data within XPath Expressions ('XPath Injection')");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
		
	}
	
	
	@Test
	public void testStaticUploadLow(){
		String orgName = "testCreateApplicationOrg4";
		String appName = "testCreateApplicationApp4";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.fillAllClickSaveStatic(true, "Cross-Site Request Forgery (CSRF)",
									"/wavsep/active/SInjection-Detection-Evaluation-POST-200Valid/Case06-InjectionInView-Numeric-PermissionBypass-WithDifferent200Responses.jsp", "123", " ", "Low","Cross-Site Request Forgery (CSRF)");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
		
	}
	
	
	
	@Test
	public void testStaticUploadInfo(){
		String orgName = "testCreateApplicationOrg5";
		String appName = "testCreateApplicationApp5";
		String urlText = "http://testurl.com";
		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage = new ManualUploadPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.fillAllClickSaveStatic(true, "Improper Cross-boundary Removal of Sensitive Data",
									"/demo/PredictableResource.php", "123", " ", "Info","Improper Cross-boundary Removal of Sensitive Data");
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
		
	}
	
	@Test
	public void ManualValidationtest(){
		String orgName = "testCreateApplicationOrgVa16";
		String appName = "testCreateApplicationAppVa16";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.clickSubmit();		
		manualUploadPage = new ManualUploadPage(driver);
		String ErrorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", ErrorText.equals("Vulnerability is a required field."));
		
		String DescError = driver.findElementById("longDescription.errors").getText();
		assertTrue("Description Error not Found", DescError.equals("Description is a required field."));
		
		manualUploadPage.clickBack();
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}
	
	
	
	@Test
	public void StaticValidationtest(){
		String orgName = "testCreateApplicationOrgVa18";
		String appName = "testCreateApplicationAppVa18";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
	    applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		manualUploadPage.getStaticRadiobtn().click();
		manualUploadPage = new ManualUploadPage(driver);
		manualUploadPage.clickStaticSubmit();		
		manualUploadPage = new ManualUploadPage(driver);
		String ErrorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", ErrorText.equals("Vulnerability is a required field."));
	
		String DescError = driver.findElementById("longDescription.errors").getText();
		assertTrue("Description Error not Found", DescError.equals("Description is a required field."));
		
		manualUploadPage.clickBack();
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}

	@Test
	public void ManualInvalidVulnstest(){
		String orgName = "testCreateApplicationOrgVa17";
		String appName = "testCreateApplicationAppVa17";
		String urlText = "http://testurl.com";

		organizationAddPage = loginPage.login("user", "password")
				.clickAddOrganizationButton();

		organizationAddPage.setNameInput(orgName);

		// add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid()
				.clickAddApplicationLink();

		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);

		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		applicationDetailPage.clickAddFindingManuallyLink();
		manualUploadPage = new ManualUploadPage(driver);
		
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("ManualFindingsPage Not Found",
				PageText.contains("New Finding"));
		
		manualUploadPage.fillAllClickSaveStatic(true, "ABCDEFGHIJKL",
				"/demo/PredictableResource.php", "123", " ", "Info","Improper Cross-boundary Removal of Sensitive Data");	
		
		manualUploadPage = new ManualUploadPage(driver);
		String ErrorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", ErrorText.equals("Vulnerability is invalid."));
		
		manualUploadPage.clickBack();
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.logout();
		
	}
}
