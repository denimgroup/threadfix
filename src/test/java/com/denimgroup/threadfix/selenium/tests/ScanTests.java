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

import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.selenium.pages.AddChannelPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationDetailPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;

public class ScanTests extends BaseTest {
	
	private WebDriver driver;
	private static LoginPage loginPage;
	public ApplicationDetailPage applicationDetailPage;
	public UploadScanPage uploadScanPage;
	public AddChannelPage addChannelPage;
	public OrganizationIndexPage organizationIndexPage;
	public OrganizationDetailPage organizationDetailPage;
	
	public String appWasAlreadyUploadedErrorText = "Scan file has already been uploaded.";
	
	private static Map<String, URL> fileMap = new HashMap<String, URL>();
	static {
		fileMap.put("Microsoft CAT.NET", getScanFilePath("Static","CAT.NET","catnet_RiskE.xml") );
		fileMap.put("FindBugs", getScanFilePath("Static","FindBugs","findbugs-normal.xml") );
		fileMap.put("IBM Rational AppScan", getScanFilePath("Dynamic","AppScan","appscan-php-demo.xml") );
		fileMap.put("Mavituna Security Netsparker", getScanFilePath("Dynamic","NetSparker","netsparker-demo-site.xml") );
		fileMap.put("Skipfish", getScanFilePath("Dynamic","Skipfish","skipfish-demo-site.zip") );
		fileMap.put("w3af", getScanFilePath("Dynamic","w3af","w3af-demo-site.xml") );
		fileMap.put("OWASP Zed Attack Proxy", getScanFilePath("Dynamic","ZAP","zaproxy-normal.xml") );
		fileMap.put("Nessus", getScanFilePath("Dynamic","Nessus","nessus_report_TFTarget.xml") );
		fileMap.put("Arachni", getScanFilePath("Dynamic","Arachni","php-demo.xml") );
		fileMap.put("WebInspect", null);
		fileMap.put("Brakeman", null);
		fileMap.put("Fortify 360", null);
		fileMap.put("Acunetix WVS", null);
		fileMap.put("Burp Suite", getScanFilePath("Dynamic","Burp","burp-demo-site.xml") );
	}
		
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	public static URL getScanFilePath(String category, String scannerName, String fileName) {
		String string = "SupportingFiles/" + category  + "/" + scannerName + "/" + fileName;
		
		return ClassLoader.getSystemResource(string);//.getFile();
	}
	
	@Test
	public void testAddApplicationChannels() {
		String orgName = "normalOrgName";
		String appName = "normalAppName";
		String appUrl = "http://normalurl.com";
				
		applicationDetailPage = loginPage.login("user", "password")
										 .clickAddOrganizationButton()
										 .setNameInput(orgName)
										 .clickSubmitButtonValid()
										 .clickAddApplicationLink()
										 .setNameInput(appName)
										 .setUrlInput(appUrl)
										 .clickAddApplicationButton();
		
		boolean first = true;
		
		for (String channel : fileMap.keySet()) {
			if (first) {
				first = false;
				uploadScanPage = applicationDetailPage.clickUploadScanLinkFirstTime()
												 	  .setChannelTypeSelect(channel)
													  .clickAddChannelButton();
													  
			} else {
				uploadScanPage = uploadScanPage.clickAddAnotherChannelLink()
											   .setChannelTypeSelect(channel)
											   .clickAddChannelButton();
			}
		}
		
		// Make sure that all options made it through
		List<String> channelOptionsList = uploadScanPage.getChannelSelectContents();
		for (String string : channelOptionsList) {
			assertTrue("One of the Channel Types was not present.", fileMap.keySet().contains(string));
		}
		
		// Make sure that no options are left to add
		addChannelPage = uploadScanPage.clickAddAnotherChannelLink();
		List<String> optionsToAdd = addChannelPage.getChannelTypeSelectContents();
		assertTrue("There were more options available than there should have been.", optionsToAdd.size() == 0);
		
		//cleanup
		loginPage = addChannelPage.clickCancelButton()
								  .clickDeleteLink()
								  .clickDeleteButton()
								  .logout();
	}
	
	// Mostly smoke test
	@Test
	public void testUploadScans() {
		
		// log in
		organizationIndexPage = loginPage.login("user", "password");
		
		// create an org and an app and upload the scan, then delete everything
		for (Entry<String, URL> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = new File(mapEntry.getValue().getFile());
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}
			
			applicationDetailPage = organizationIndexPage.clickAddOrganizationButton()
														 .setNameInput(mapEntry.getKey() + "normaltest")
														 .clickSubmitButtonValid()
														 .clickAddApplicationLink()
														 .setNameInput(mapEntry.getKey() + "normaltest")
														 .setUrlInput("http://" + mapEntry.getKey())
														 .clickAddApplicationButton()
														 .clickUploadScanLinkFirstTime()
														 .setChannelTypeSelect(mapEntry.getKey())
														 .clickAddChannelButton()
														 .setFileInput(mapEntry.getValue())
														 .setChannelSelect(mapEntry.getKey())
														 .clickUploadScanButton();
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				log.debug("Thread interrupted. Continuing.");
			}
			
			organizationIndexPage = applicationDetailPage.clickDeleteLink()
														 .clickDeleteButton();
		}
	}
	
	@Test
	public void testUploadDuplicateScans() {
		// log in
		organizationIndexPage = loginPage.login("user", "password");
		
		// create an org and an app and upload the scan, then delete everything
		for (Entry<String, URL> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = new File(mapEntry.getValue().getFile());
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}
			
			uploadScanPage = organizationIndexPage.clickAddOrganizationButton()
												  .setNameInput(mapEntry.getKey() + "duplicate")
												  .clickSubmitButtonValid()
												  .clickAddApplicationLink()
												  .setNameInput(mapEntry.getKey() + "duplicate")
												  .setUrlInput("http://" + mapEntry.getKey())
												  .clickAddApplicationButton()
												  .clickUploadScanLinkFirstTime()
												  .setChannelTypeSelect(mapEntry.getKey())
												  .clickAddChannelButton()
												  .setFileInput(mapEntry.getValue())
												  .setChannelSelect(mapEntry.getKey())
												  .clickUploadScanButton()
												  .clickUploadScanLink()
												  .setFileInput(mapEntry.getValue())
												  .setChannelSelect(mapEntry.getKey())
												  .clickUploadScanButtonInvalid();

			assertTrue("The correct error text was not present.", 
					uploadScanPage.getScanError().equals(appWasAlreadyUploadedErrorText));
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				log.debug("Thread interrupted. Continuing.");
			}
			
			organizationIndexPage = uploadScanPage.clickCancelLink()
												  .clickDeleteLink()
												  .clickDeleteButton();
		}
	}
	
	public static final String XSS = "Failure to Preserve Web Page Structure ('Cross-site Scripting')";
	public static final String SQLI = "Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')";
	
	@Test
	public void microsoftCatNetScan() {
		String key = "Microsoft CAT.NET";
		
		String[][] expectedResults = {
				{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "email"},
				{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "txtSubject"},
				{ XSS, "Critical", "/zigguratutilityweb/message.aspx", ""},
				{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
				{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "txtMessage"},
				{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtCardNumber"},
				{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
				{ SQLI, "Critical", "/zigguratutilityweb/loginpage.aspx", "txtPassword"},
				{ SQLI, "Critical", "/zigguratutilityweb/loginpage.aspx", "txtUsername"},
				{ SQLI, "Critical", "/zigguratutilityweb/viewstatement.aspx", "StatementID"},
				{ SQLI, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
			};
		
		runScanTest(key, expectedResults);
	}
	
	public void runScanTest(String scannerName, String[][] expectedResults) {
		organizationIndexPage = loginPage.login("user", "password");
		
		applicationDetailPage = organizationIndexPage.clickAddOrganizationButton()
													 .setNameInput(scannerName + getRandomString(10))
													 .clickSubmitButtonValid()
													 .clickAddApplicationLink()
													 .setNameInput(scannerName + getRandomString(10))
													 .setUrlInput("http://" + scannerName)
													 .clickAddApplicationButton()
													 .clickUploadScanLinkFirstTime()
													 .setChannelTypeSelect(scannerName)
													 .clickAddChannelButton()
													 .setFileInput(fileMap.get(scannerName))
													 .setChannelSelect(scannerName)
													 .clickUploadScanButton();
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		applicationDetailPage = applicationDetailPage.clickRefreshLink();
		
		for (int i=1; i <= expectedResults.length; i++) {
			log.debug("i = " + i);
			
			assertTrue(applicationDetailPage.getElementText("vulnName" + i)
											.equals(expectedResults[i-1][0]));
			
			assertTrue(applicationDetailPage.getElementText("severity" + i)
					.equals(expectedResults[i-1][1]));
			
			assertTrue(applicationDetailPage.getElementText("path" + i)
					.equals(expectedResults[i-1][2]));
			
			assertTrue(applicationDetailPage.getElementText("parameter" + i)
					.equals(expectedResults[i-1][3]));
		}
	}
}
