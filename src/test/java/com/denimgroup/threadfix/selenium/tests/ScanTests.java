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

import com.denimgroup.threadfix.data.entities.GenericVulnerability;
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
	
	// Set to false for HSQL ordering
	// TODO force sorting so this isn't an issue
	// TODO or make this a parameter that is passed in
	boolean mySQL = true;
	
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
		fileMap.put("WebInspect",getScanFilePath("Dynamic","WebInspect","webinspect-demo-site.xml"));
		fileMap.put("Brakeman", getScanFilePath("Static","Brakeman","brakeman.json")); 
		fileMap.put("Fortify 360", getScanFilePath("Static","Fortify","ZigguratUtility.fpr"));
		fileMap.put("Acunetix WVS", getScanFilePath("Dynamic","Acunetix","testaspnet.xml"));
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
				System.out.println("Thread interrupted. Continuing.");
			}
			
			organizationIndexPage = applicationDetailPage.clickRefreshLink()
														 .clickViewScansLink()
														 .clickDeleteScanButton(0)
														 .clickBackToAppLink()
														 .clickDeleteLink()
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
				System.out.println("Thread interrupted. Continuing.");
			}
			
			organizationIndexPage = uploadScanPage.clickCancelLink()
												  .clickViewScansLink()
					 							  .clickDeleteScanButton(0)
					 							  .clickBackToAppLink()
												  .clickDeleteLink()
												  .clickDeleteButton();
		}
	}
	
	// TODO move to a less fragile method of checking names
	final static String XSS = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING;
	final static String SQLI = "Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')";
	final static String PATH_TRAVERSAL = "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')";
	final static String COMMAND_INJECTION = "Improper Sanitization of Special Elements used in a Command ('Command Injection')";
	final static String CODE_INJECTION = "Failure to Control Generation of Code ('Code Injection')";
	final static String OS_INJECTION = "Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')";
	final static String RESOURCE_INJECTION = "Improper Control of Resource Identifiers ('Resource Injection')";
	final static String INFORMATION_EXPOSURE = "Information Exposure";
	final static String INFO_EXPOSURE_ERROR_MESSAGE = "Information Exposure Through an Error Message";
	final static String GENERIC_INJECTION = "Failure to Sanitize Data into a Different Plane ('Injection')";
	final static String FORCED_BROWSING = "Direct Request ('Forced Browsing')";
	final static String REFLECTION_ATTACK = "Reflection Attack in an Authentication Protocol";
	final static String DIRECTORY_LISTING = "Information Leak Through Directory Listing";
	final static String IMPROPER_INPUT_VALIDATION = "Improper Input Validation";
	final static String SOURCE_CODE_INCLUDE = "Information Leak Through Include Source Code";
	final static String CONFIGURATION = "Configuration";
	final static String INFO_LEAK_TEST_CODE = "Information Leak Through Test Code";
	final static String INFO_LEAK_COMMENTS = "Information Leak Through Comments";
	final static String INFO_LEAK_SERVER_ERROR = "Information Leak Through Server Error Message";
	final static String IMPROPER_HANDLING_OF_MISSING_VALUES = "Improper Handling of Missing Values";
	final static String CSRF = "Cross-Site Request Forgery (CSRF)";
	final static String LDAP_INJECTION = "Failure to Sanitize Data into LDAP Queries ('LDAP Injection')"; 
	final static String EVAL_INJECTION = "Improper Sanitization of Directives in Dynamically Evaluated Code ('Eval Injection')";
	final static String FORMAT_STRING_INJECTION = "Uncontrolled Format String";
	final static String XPATH_INJECTION = "Failure to Sanitize Data within XPath Expressions ('XPath injection')";
	final static String EXTERNAL_FILEPATH_CONTROL = "External Control of File Name or Path";
	final static String SESSION_FIXATION = "Session Fixation";
	final static String INFO_LEAK_DIRECTORIES = "File and Directory Information Exposure";
	final static String XML_INJECTION = "XML Injection (aka Blind XPath Injection)";
	final static String ACCESS_CONTROL = "Access Control (Authorization) Issues";
	final static String OPEN_REDIRECT = "URL Redirection to Untrusted Site ('Open Redirect')";
	final static String EXTERNAL_CONTROL_OF_PARAM = "External Control of Assumed-Immutable Web Parameter";
	final static String ARGUMENT_INJECTION = "Argument Injection or Modification";
	final static String ASP_NET_DEBUG = "ASP.NET Misconfiguration: Creating Debug Binary";
	final static String ASP_NET_CUSTOM_ERROR = "ASP.NET Misconfiguration: Missing Custom Error Page";
	final static String IMPROPER_RESOURCE_SHUTDOWN = "Improper Resource Shutdown or Release";
	final static String TRUST_BOUNDARY_VIOLATION = "Trust Boundary Violation";
	final static String NON_SERIALIZABLE_OBJECT = "J2EE Bad Practices: Non-serializable Object Stored in Session";
	final static String NULL_POINTER = "Unchecked Return Value to NULL Pointer Dereference";
	final static String UNCHECKED_ERROR = "Unchecked Error Condition";
	final static String CLEARTEXT_SENSITIVE_INFO = "Cleartext Transmission of Sensitive Information";
	final static String IMPROPER_RESTRICTION_AUTH = "Improper Restriction of Excessive Authentication Attempts";
	final static String NON_SECURE_COOKIE = "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute";
	final static String INFO_LEAK_BROWSER_CACHE = "Information Leak Through Browser Caching";
	final static String FILES_ACCESSIBLE = "Files or Directories Accessible to External Parties";
	final static String FAILURE_TO_HANDLE_ENCODING = "Failure to Handle Alternate Encoding";
	final static String IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA = "Improper Cross-boundary Removal of Sensitive Data";
	final static String ASP_NET_VALIDATION_MISSING = "ASP.NET Misconfiguration: Not Using Input Validation Framework";
	
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
		
		if (mySQL) {
			expectedResults = new String[][] {
					{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "email"},
					{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "txtSubject"},
					{ XSS, "Critical", "/zigguratutilityweb/message.aspx", ""},
					{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
					{ XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "txtMessage"},
					{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtCardNumber"},
					{ XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
					{ SQLI, "Critical", "/zigguratutilityweb/loginpage.aspx", "txtUsername"},
					{ SQLI, "Critical", "/zigguratutilityweb/viewstatement.aspx", "StatementID"},
					{ SQLI, "Critical", "/zigguratutilityweb/loginpage.aspx", "txtPassword"},
					{ SQLI, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtAmount"},
				};
		}
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void findBugsScan() {
		
		String key = "FindBugs";
		String[][] expectedResults = {
				{ XSS, "Critical", "securibench/micro/pred/Pred6.java", "name"},
				{ XSS, "Critical", "securibench/micro/session/Session2.java", "name"},
				{ XSS, "Critical", "securibench/micro/basic/Basic18.java", "s"},
				{ XSS, "Critical", "securibench/micro/basic/Basic9.java", "s1"},
				{ XSS, "Critical", "securibench/micro/pred/Pred7.java", "name"},
				{ XSS, "Critical", "securibench/micro/aliasing/Aliasing4.java", "name"},
				{ XSS, "Critical", "securibench/micro/aliasing/Aliasing1.java", "name"},
				{ XSS, "Critical", "securibench/micro/pred/Pred8.java", "name"},
				{ XSS, "Critical", "securibench/micro/session/Session1.java", "name"},
				{ XSS, "Critical", "securibench/micro/basic/Basic1.java", "str"},
				{ XSS, "Critical", "securibench/micro/pred/Pred9.java", "name"},
				{ XSS, "Critical", "securibench/micro/pred/Pred5.java", "name"},
				{ XSS, "Critical", "securibench/micro/basic/Basic8.java", "str"},
				{ XSS, "Critical", "securibench/micro/basic/Basic2.java", "str"},
				{ XSS, "Critical", "securibench/micro/basic/Basic4.java", "str"},
				{ XSS, "Critical", "securibench/micro/pred/Pred4.java", "name"},
				{ XSS, "Critical", "securibench/micro/basic/Basic28.java", "name"},
				{ XSS, "High", "securibench/micro/pred/Pred2.java", "name"},
				{ XSS, "High", "securibench/micro/pred/Pred3.java", "name"},
				{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates5.java", ""},
				{ XSS, "High", "securibench/micro/basic/Basic30.java", ""},
				{ XSS, "High", "securibench/micro/basic/Basic29.java", ""},
				{ XSS, "High", "securibench/micro/basic/Basic27.java", ""},
				{ XSS, "High", "securibench/micro/basic/Basic34.java", "headerValue"},
				{ XSS, "High", "securibench/micro/basic/Basic10.java", "s5"},
				{ XSS, "High", "securibench/micro/basic/Basic32.java", "header"},
				{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates3.java", ""},
				{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates4.java", ""},
				{ XSS, "High", "securibench/micro/basic/Basic35.java", ""},
				{ SQLI, "High", "securibench/micro/basic/Basic19.java", ""},
				{ SQLI, "High", "securibench/micro/basic/Basic21.java", ""},
				{ SQLI, "High", "securibench/micro/basic/Basic20.java", ""},
		};
		
		if (mySQL) {
			expectedResults = new String[][] {
					{XSS, "Critical", "securibench/micro/aliasing/Aliasing4.java", "name"},
					{XSS, "Critical", "securibench/micro/session/Session2.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic1.java", "str"},
					{XSS, "Critical", "securibench/micro/pred/Pred8.java", "name"},
					{XSS, "Critical", "securibench/micro/session/Session1.java", "name"},
					{XSS, "Critical", "securibench/micro/aliasing/Aliasing1.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic9.java", "s1"},
					{XSS, "Critical", "securibench/micro/pred/Pred7.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic18.java", "s"},
					{XSS, "Critical", "securibench/micro/pred/Pred9.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic8.java", "str"},
					{XSS, "Critical", "securibench/micro/pred/Pred5.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic28.java", "name"},
					{XSS, "Critical", "securibench/micro/basic/Basic2.java", "str"},
					{XSS, "Critical", "securibench/micro/basic/Basic4.java", "str"},
					{XSS, "Critical", "securibench/micro/pred/Pred6.java", "name"},
					{XSS, "Critical", "securibench/micro/pred/Pred4.java", "name"},
					{XSS, "High", "securibench/micro/basic/Basic30.java",""},
					{XSS, "High", "securibench/micro/basic/Basic29.java",""},
					{XSS, "High", "securibench/micro/basic/Basic27.java",""},
					{XSS, "High", "securibench/micro/strong_updates/StrongUpdates5.java",""},
					{XSS, "High", "securibench/micro/pred/Pred3.java", "name"},
					{XSS, "High", "securibench/micro/basic/Basic10.java", "s5"},
					{XSS, "High", "securibench/micro/basic/Basic34.java", "headerValue"},
					{XSS, "High", "securibench/micro/basic/Basic35.java",""},
					{XSS, "High", "securibench/micro/basic/Basic32.java", "header"},
					{XSS, "High", "securibench/micro/strong_updates/StrongUpdates3.java",""},
					{XSS, "High", "securibench/micro/strong_updates/StrongUpdates4.java",""},
					{XSS, "High", "securibench/micro/pred/Pred2.java", "name"},
					{SQLI, "High", "securibench/micro/basic/Basic19.java",""},
					{SQLI, "High", "securibench/micro/basic/Basic21.java",""},
					{SQLI, "High", "securibench/micro/basic/Basic20.java",""},
			};
		}
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void ibmAppscanScan() {
		String key = "IBM Rational AppScan";
		String[][] expectedResults = {
				{ PATH_TRAVERSAL, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{ COMMAND_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{ XSS, "Critical", "/demo/XPathInjection2.php", "password"},
				{ XSS, "Critical", "/demo/EvalInjection2.php", "command"},
				{ XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
				{ XSS, "Critical", "/demo/XPathInjection2.php", "username"},
				{ XSS, "Critical", "/demo/XPathInjection2.php", ""},
				{ SQLI, "Critical", "/demo/XPathInjection2.php", "username"},
				{ SQLI, "Critical", "/demo/XPathInjection2.php", "password"},
				{ INFO_EXPOSURE_ERROR_MESSAGE, "Critical", "/demo/SQLI2.php", "username"},
				{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "username"},
				{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "password"},
				{ GENERIC_INJECTION, "Medium", "/demo/XSS-reflected2.php", "username"},
				{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "username"},
				{ REFLECTION_ATTACK, "Medium", "/demo/XSS-reflected2.php", "username"},
				{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "password"},
				{ DIRECTORY_LISTING, "Medium", "/demo/DIRECT~1/", ""},
				{ DIRECTORY_LISTING, "Medium", "/demo/DirectoryIndexing/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/aux/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com1/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/com3/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/cgi-bin/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/aux/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com2/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/com2/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/com1/", ""},
				{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com3/", ""},
				{ INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
				{ INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", ""},
				{ INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
				{ FORCED_BROWSING, "Low", "/demo/DIRECT~1/", ""},
				{ FORCED_BROWSING, "Low", "/demo/DirectoryIndexing/", ""},
				{ INFO_LEAK_TEST_CODE, "Low", "/demo/PredictableResource.php", ""},
				{ INFO_LEAK_TEST_CODE, "Low", "/", ""},
				{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected2.php", ""},
				{ INFO_LEAK_COMMENTS, "Low", "/demo/", ""},
				{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected.php", ""},
				{ INFO_LEAK_COMMENTS, "Low", "/demo/SQLI.php", ""},
				{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/SQLI2.php", "username"},
				{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "password"},
				{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "username"},
				{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/LDAPInjection2.php", "username"},
				{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/EvalInjection2.php", "command"},
				};
		
		if (mySQL) {
			expectedResults = new String[][] {
					{"Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Improper Sanitization of Special Elements used in a Command ('Command Injection')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XPathInjection2.php", "password"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XPathInjection2.php", ""},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XPathInjection2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XSS-reflected2.php", "username"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/XPathInjection2.php", "username"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/XPathInjection2.php", "password"},
					{"Information Exposure Through an Error Message", "Critical", "/demo/SQLI2.php", "username"},
					{"Failure to Sanitize Data into a Different Plane ('Injection')", "Medium", "/demo/XPathInjection2.php", "password"},
					{"Failure to Sanitize Data into a Different Plane ('Injection')", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Failure to Sanitize Data into a Different Plane ('Injection')", "Medium", "/demo/XPathInjection2.php", "username"},
					{"Reflection Attack in an Authentication Protocol", "Medium", "/demo/XPathInjection2.php", "username"},
					{"Reflection Attack in an Authentication Protocol", "Medium", "/demo/XPathInjection2.php", "password"},
					{"Reflection Attack in an Authentication Protocol", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Information Leak Through Directory Listing", "Medium", "/demo/DirectoryIndexing/", ""},
					{"Information Leak Through Directory Listing", "Medium", "/demo/DIRECT~1/", ""},
					{"Improper Input Validation", "Low", "/demo/aux/", ""},
					{"Improper Input Validation", "Low", "/com3/", ""},
					{"Improper Input Validation", "Low", "/cgi-bin/", ""},
					{"Improper Input Validation", "Low", "/demo/com2/", ""},
					{"Improper Input Validation", "Low", "/com2/", ""},
					{"Improper Input Validation", "Low", "/demo/com1/", ""},
					{"Improper Input Validation", "Low", "/demo/", ""},
					{"Improper Input Validation", "Low", "/com1/", ""},
					{"Improper Input Validation", "Low", "/aux/", ""},
					{"Improper Input Validation", "Low", "/demo/com3/", ""},
					{"Information Exposure", "Low", "/demo/PredictableResource.php", ""},
					{"Information Exposure", "Low", "/demo/PathTraversal.php", ""},
					{"Information Exposure", "Low", "/demo/XSS-cookie.php", ""},
					{"Direct Request ('Forced Browsing')", "Low", "/demo/DirectoryIndexing/", ""},
					{"Direct Request ('Forced Browsing')", "Low", "/demo/DIRECT~1/", ""},
					{"Information Leak Through Test Code", "Low", "/", ""},
					{"Information Leak Through Test Code", "Low", "/demo/PredictableResource.php", ""},
					{"Information Leak Through Comments", "Low", "/demo/SQLI.php", ""},
					{"Information Leak Through Comments", "Low", "/demo/XSS-reflected2.php", ""},
					{"Information Leak Through Comments", "Low", "/demo/", ""},
					{"Information Leak Through Comments", "Low", "/demo/XSS-reflected.php", ""},
					{"Information Leak Through Server Error Message", "Info", "/demo/LDAPInjection2.php", "username"},
					{"Information Leak Through Server Error Message", "Info", "/demo/XPathInjection2.php", "username"},
					{"Information Leak Through Server Error Message", "Info", "/demo/EvalInjection2.php", "command"},
					{"Information Leak Through Server Error Message", "Info", "/demo/XPathInjection2.php", "password"},
					{"Information Leak Through Server Error Message", "Info", "/demo/SQLI2.php", "username"},
			};
		}
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void netsparkerScan(){
		String key = "Mavituna Security Netsparker";
		String[][] expectedResults = {
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{CODE_INJECTION, "Critical", "/demo/EvalInjection2.php", "command"},
				{XSS, "High", "/demo/XPathInjection2.php", "password"},
				{XSS, "High", "/demo/EvalInjection2.php", "command"},
				{XSS, "High", "/demo/XSS-reflected2.php", "username"},
				{XSS, "High", "/demo/SQLI2.php", "username"},
				{XSS, "High", "/demo/XPathInjection2.php", "username"},
				{RESOURCE_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{SOURCE_CODE_INCLUDE, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
				{CONFIGURATION, "Low", "/demo/", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/", ""},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Low", "/demo/SQLI2.php", "username"},
				{FORCED_BROWSING, "Low", "/demo/PredictableResource.php.bak", ""},
				{FORCED_BROWSING, "Low", "/demo/LDAPInjection.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/EvalInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XPathInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/FormatString2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/SQLI2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XSS-cookie.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XSS-reflected2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/LDAPInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/PathTraversal.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/OSCommandInjection2.php", ""},
				{"Information Leak Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},
		};
		
		if (mySQL) {
			expectedResults = new String[] [] {
					{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Control Generation of Code ('Code Injection')", "Critical", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XPathInjection2.php", "password"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XSS-reflected2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/SQLI2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XPathInjection2.php", "username"},
					{"Improper Control of Resource Identifiers ('Resource Injection')", "High", "/demo/OSCommandInjection2.php", "fileName"},
					{"Information Leak Through Include Source Code", "Medium", "/demo/OSCommandInjection2.php", "fileName"},
					{"Configuration", "Low", "/demo/", ""},
					{"Information Exposure", "Low", "/demo/PredictableResource.php", ""},
					{"Information Exposure", "Low", "/demo/", ""},
					{"Information Exposure Through an Error Message", "Low", "/demo/SQLI2.php", "username"},
					{"Direct Request ('Forced Browsing')", "Low", "/demo/LDAPInjection.php", ""},
					{"Direct Request ('Forced Browsing')", "Low", "/demo/PredictableResource.php.bak", ""},
					{"Information Exposure", "Info", "/demo/LDAPInjection2.php", ""},
					{"Information Exposure", "Info", "/demo/EvalInjection2.php", ""},
					{"Information Exposure", "Info", "/demo/OSCommandInjection2.php", ""},
					{"Information Exposure", "Info", "/demo/XPathInjection2.php", ""},
					{"Information Exposure", "Info", "/demo/XSS-reflected2.php", ""},
					{"Information Exposure", "Info", "/demo/FormatString2.php", ""},
					{"Information Exposure", "Info", "/demo/SQLI2.php", ""},
					{"Information Exposure", "Info", "/demo/PathTraversal.php", ""},
					{"Information Exposure", "Info", "/demo/XSS-cookie.php", ""},
					{"Information Leak Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},	
			};
		}
		
		runScanTest(key, expectedResults);
	}
	
	
	@Test
	public void skipFishScan(){
		String key = "Skipfish";
		String[][] expectedResults = {
				{SQLI, "Critical", "/demo/EvalInjection2.php", "command"},
				{SQLI, "Critical", "/demo/LDAPInjection2.php", "username"},
				{SQLI, "Critical", "/demo/SQLI2.php", "username"},
				{PATH_TRAVERSAL, "High", "/demo/PathTraversal.php","action"},
				{XSS, "High", "/demo/XSS-cookie.php","cookie"},
				{XSS, "High", "/demo/XSS-reflected2.php","username"},
				{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/EvalInjection2.php",""},
				{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/PathTraversal.php","action"},
				{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/FormatString2.php","name"},
				{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-cookie.php",""},
				{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-reflected2.php","username"},
				{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/",""},
				{INFO_LEAK_SERVER_ERROR, "High", "/demo/SQLI2.php","username"},
				{CSRF, "Medium", "/demo/FormatString2.php",""},
				{CSRF, "Medium", "/demo/OSCommandInjection2.php",""},
				{CSRF, "Medium", "/demo/XSS-cookie.php",""},
				{CSRF, "Medium", "/demo/LDAPInjection2.php",""},
				{CSRF, "Medium", "/demo/EvalInjection2.php",""},
				{CSRF, "Medium", "/demo/XSS-reflected2.php",""},
				{CSRF, "Medium", "/demo/SQLI2.php",""},	
				
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/SQLI2.php", "username"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/EvalInjection2.php", "command"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/LDAPInjection2.php", "username"},
					{"Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "High", "/demo/PathTraversal.php", "action"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XSS-cookie.php", "cookie"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XSS-reflected2.php", "username"},
					{"Improper Handling of Missing Values", "High", "/demo/PathTraversal.php", "action"},
					{"Improper Handling of Missing Values", "High", "/demo/XSS-cookie.php", "cookie"},
					{"Improper Handling of Missing Values", "High", "/demo/XSS-reflected2.php", "username"},
					{"Improper Handling of Missing Values", "High", "/demo/FormatString2.php", "name"},
					{"Improper Handling of Missing Values", "High", "/demo/EvalInjection2.php", "command"},
					{"Information Leak Through Directory Listing", "High", "/demo/DirectoryIndexing/", ""},
					{"Information Leak Through Server Error Message", "High", "/demo/SQLI2.php", "username"},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/XSS-reflected2.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/SQLI2.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/XSS-cookie.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/FormatString2.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/OSCommandInjection2.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/LDAPInjection2.php", ""},
					{"Cross-Site Request Forgery (CSRF)", "Medium", "/demo/EvalInjection2.php", ""},
			};
		}
		runScanTest(key, expectedResults);
	}
	
	
	@Test
	public void w3afScan() {
		
		String key = "w3af";
		String[][] expectedResults = {
				{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "High", "/demo/XSS-cookie.php", "cookie"},
				{SQLI,"High", "/demo/SQLI2.php","username"},
				{LDAP_INJECTION,"High", "/demo/LDAPInjection2.php","username"},
				{EVAL_INJECTION,"High", "/demo/EvalInjection2.php","command"},
				{XSS,"Medium", "/demo/XSS-reflected2.php","username"},
				{XSS,"Medium", "/demo/EvalInjection2.php","command"},
				{FORMAT_STRING_INJECTION,"Medium", "/demo/FormatString2.php","name"},
				{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","username"},
				{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","password"},
				{FORCED_BROWSING,"Info", "/demo/PredictableResource.php.bak",""},
				{FORCED_BROWSING,"Info", "/demo.zip",""},
				
		};
		
		if (mySQL) {
			expectedResults = new String[] [] { 
					{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "High", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XSS-cookie.php", "cookie"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/demo/SQLI2.php", "username"},
					{"Failure to Sanitize Data into LDAP Queries ('LDAP Injection')", "High", "/demo/LDAPInjection2.php", "username"},
					{"Improper Sanitization of Directives in Dynamically Evaluated Code ('Eval Injection')", "High", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Uncontrolled Format String", "Medium", "/demo/FormatString2.php", "name"},
					{"Failure to Sanitize Data within XPath Expressions ('XPath injection')", "Medium", "/demo/XPathInjection2.php", "password"},
					{"Failure to Sanitize Data within XPath Expressions ('XPath injection')", "Medium", "/demo/XPathInjection2.php", "username"},
					{"Direct Request ('Forced Browsing')", "Info", "/demo.zip", ""},
					{"Direct Request ('Forced Browsing')", "Info", "/demo/PredictableResource.php.bak", ""},
			};
		}
		
		runScanTest(key, expectedResults);		
				
	}
	
	
	@Test
	public void zaproxyScan() {
		String key = "OWASP Zed Attack Proxy";
		String[][] expectedResults = {
				{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/", ""},
				{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
				{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
				{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
				{XSS, "Medium", "/demo/XPathInjection2.php", "username"},
				{SQLI, "Medium", "/demo/SQLI2.php", "username"},
	
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
					{"Information Leak Through Directory Listing", "High", "/demo/DirectoryIndexing/", ""},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XPathInjection2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XPathInjection2.php", "password"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Medium", "/demo/SQLI2.php", "username"},
			};
		}
		
		runScanTest(key, expectedResults);		
				
	}
	
	
	@Test
	public void nessusScan() {
		String key = "Nessus";
		String[][] expectedResults = {
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{SQLI, "Critical", "/demo/SQLI2.php", "username"},
				{EXTERNAL_FILEPATH_CONTROL, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
				{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
				{XSS, "Medium", "/demo/XSS-cookie.php", "cookie"},
				{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
				{SESSION_FIXATION, "Medium", "/demo/XSS-reflected2.php", "username"},
				{FORCED_BROWSING, "Medium", "/demo/PredictableResource.php.bak", ""},
				{DIRECTORY_LISTING, "Low", "/demo/DirectoryIndexing/", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
					{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/SQLI2.php", "username"},
					{"External Control of File Name or Path", "Medium", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XPathInjection2.php", "password"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Medium", "/demo/XSS-cookie.php", "cookie"},
					{"Session Fixation", "Medium", "/demo/XSS-reflected2.php", "username"},
					{"Direct Request ('Forced Browsing')", "Medium", "/demo/PredictableResource.php.bak", ""},
					{"Information Leak Through Directory Listing", "Low", "/demo/DirectoryIndexing/", ""},

			};
		}
		runScanTest(key, expectedResults);		
				
	}
	
	@Test
	public void arachniScan() {
		String key = "Arachni";
		String[][] expectedResults = {
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "Critical", "/demo/XPathInjection2.php", "username"},
				{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
				{XSS, "Critical", "/demo/XPathInjection2.php", "password"},
				{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
				{SQLI, "Critical", "/demo/SQLI2.php", "username"},
				{LDAP_INJECTION, "Critical", "/demo/LDAPInjection2.php", "username"},
				{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "password"},
				{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "username"},
				{INFO_LEAK_DIRECTORIES, "High", "/demo/", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
					{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XPathInjection2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XSS-reflected2.php", "username"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XPathInjection2.php", "password"},
					{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/demo/SQLI2.php", "username"},
					{"Failure to Sanitize Data into LDAP Queries ('LDAP Injection')", "Critical", "/demo/LDAPInjection2.php", "username"},
					{"XML Injection (aka Blind XPath Injection)", "Critical", "/demo/XPathInjection2.php", "password"},
					{"XML Injection (aka Blind XPath Injection)", "Critical", "/demo/XPathInjection2.php", "username"},
					{"File and Directory Information Exposure", "High", "/demo/", ""},

			};
		}
		runScanTest(key, expectedResults);		
	}
	
	
	@Test
	public void webInspectScan() {
		String key = "WebInspect";
		String[][] expectedResults = {
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
				{XSS, "Critical", "/demo/XSS-cookie.php", "cookie"},
				{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
				{INFORMATION_EXPOSURE, "Critical", "/demo/SQLI2.php", "username"},
				{INFORMATION_EXPOSURE, "Critical", "/demo/password.txt", ""},
				{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.bak", ""},
				{INFORMATION_EXPOSURE, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.BAK", ""},
				{LDAP_INJECTION, "Medium", "/demo/LDAPInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Medium", "/demo/LDAPInjection2.php", ""},
				{ACCESS_CONTROL, "Medium", "/demo/XPathInjection2.php", ""},
				{FORCED_BROWSING, "Medium", "/test.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", "action"},
				{INFORMATION_EXPOSURE, "Low", "/cgi-bin/test.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/FormatString2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/test.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", "cookie"},
				{INFORMATION_EXPOSURE, "Low", "/demo/XSS-reflected2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/SQLI2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/EvalInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/XPathInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/OSCommandInjection2.php", ""},
				{DIRECTORY_LISTING, "Low", "/cgi-bin/", ""},
				{DIRECTORY_LISTING, "Low", "/demo/", ""},
				{INFORMATION_EXPOSURE, "Info", "/", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
					{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XSS-cookie.php", "cookie"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/EvalInjection2.php", "command"},
					{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/demo/XSS-reflected2.php", "username"},
					{"Information Exposure", "Critical", "/demo/SQLI2.php", "username"},
					{"Information Exposure", "Critical", "/demo/password.txt", ""},
					{"Information Exposure", "High", "/demo/PredictableResource.php.BAK", ""},
					{"Information Exposure", "High", "/demo/OSCommandInjection2.php", "fileName"},
					{"Information Exposure", "High", "/demo/PredictableResource.php.bak", ""},
					{"Failure to Sanitize Data into LDAP Queries ('LDAP Injection')", "Medium", "/demo/LDAPInjection2.php", ""},
					{"Information Exposure", "Medium", "/demo/LDAPInjection2.php", ""},
					{"Access Control (Authorization) Issues", "Medium", "/demo/XPathInjection2.php", ""},
					{"Direct Request ('Forced Browsing')", "Medium", "/test.php", ""},
					{"Information Exposure", "Low", "/test.php", ""},
					{"Information Exposure", "Low", "/demo/FormatString2.php", ""},
					{"Information Exposure", "Low", "/cgi-bin/test.php", ""},
					{"Information Exposure", "Low", "/demo/XSS-cookie.php", "cookie"},
					{"Information Exposure", "Low", "/demo/PathTraversal.php", "action"},
					{"Information Exposure", "Low", "/demo/XPathInjection2.php", ""},
					{"Information Exposure", "Low", "/demo/EvalInjection2.php", ""},
					{"Information Exposure", "Low", "/demo/PathTraversal.php", ""},
					{"Information Exposure", "Low", "/demo/SQLI2.php", ""},
					{"Information Exposure", "Low", "/demo/OSCommandInjection2.php", ""},
					{"Information Exposure", "Low", "/demo/XSS-reflected2.php", ""},
					{"Information Leak Through Directory Listing", "Low", "/cgi-bin/", ""},
					{"Information Leak Through Directory Listing", "Low", "/demo/", ""},
					{"Information Exposure", "Info", "/", ""},
			};
		}
		runScanTest(key, expectedResults);		
				
	}
	
	@Test
	public void brakeManScan() {
		String key = "Brakeman";
		String[][] expectedResults = {
				{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
				{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
				{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
				{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/index.html", "User.new"},
				{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/results.html", "null"},
				{SQLI, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:query]"},
				{OPEN_REDIRECT, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params"},
				{CSRF, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/application_controller.rb", "null"},
				{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
				{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
				{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
				{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
				{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
				{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
				{FORCED_BROWSING, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/config/routes.rb", "null"},
				{EXTERNAL_CONTROL_OF_PARAM, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/post, user.rb", "null"},
				{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "User.find(params[:id])"},
				{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "Post.find(params[:id])"},
		};
		runScanTest(key, expectedResults);		
	}
	
	
	@Test
	public void fortify360Scan() {
		String key = "Fortify 360";
		String[][] expectedResults = {
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CcfUsed"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "PreviousBill"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CurrentNaturalGas"},
				{XSS, "Critical", "/zigguratutilityweb/makepayment.aspx", "txtCardNumber"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CurrentElectricity"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CityServices"},
				{XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "email"},
				{XSS, "Critical", "/zigguratutilityweb/message.aspx", "Msg"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Address"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Payments"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "BillingDate"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Name"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "StateLocalTaxes"},
				{XSS, "Critical", "/zigguratutilityweb/contactus.aspx", "txtSubject"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CustomerNumber"},
				{XSS, "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "KiloWattHourUsed"},
				{SQLI, "Critical", "/zigguratutilityweb/viewstatement.aspx", "StatementID"},
				{SQLI, "Critical", "/zigguratutilityweb/loginpage.aspx", "txtUsername"},
				{ASP_NET_DEBUG, "Medium", "/zigguratutilityweb/web.config", ""},
				{ASP_NET_CUSTOM_ERROR, "Medium", "/zigguratutilityweb/web.config", ""},
				{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/zigguratutilityweb/home.aspx", ""},
				{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/zigguratutilityweb/viewstatement.aspx", ""},
				{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/zigguratutilityweb/viewstatement.aspx", ""},
				{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/zigguratutilityweb/home.aspx", ""},
				{TRUST_BOUNDARY_VIOLATION, "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{ASP_NET_VALIDATION_MISSING, "Medium", "/zigguratutilityweb/message.aspx", ""},
				{NON_SERIALIZABLE_OBJECT, "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{NULL_POINTER, "Medium", "/zigguratutilityweb/makepayment.aspx.", ""},
				{NULL_POINTER, "Medium", "/zigguratutilityweb/home.aspx", ""},
				{NULL_POINTER, "Medium", "/zigguratutilityweb/makepayment.aspx", ""},
				{SQLI, "Info", "/zigguratutilityweb/app_code/dbutil.cs", ""},
				{UNCHECKED_ERROR, "Info", "/zigguratutilityweb/app_code/dbutil.cs", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "KiloWattHourUsed"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CcfUsed"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Address"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/message.aspx", "Msg"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/contactus.aspx", "email"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CityServices"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CurrentElectricity"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/makepayment.aspx", "txtCardNumber"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CurrentNaturalGas"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "PreviousBill"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Payments"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/contactus.aspx", "txtSubject"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "StateLocalTaxes"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "CustomerNumber"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "Name"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/zigguratutilityweb/app_code/dbutil.cs", "BillingDate"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/zigguratutilityweb/loginpage.aspx", "txtUsername"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/zigguratutilityweb/viewstatement.aspx", "StatementID"},
				{"ASP.NET Misconfiguration: Creating Debug Binary", "Medium", "/zigguratutilityweb/web.config", ""},
				{"ASP.NET Misconfiguration: Missing Custom Error Page", "Medium", "/zigguratutilityweb/web.config", ""},
				{"Improper Resource Shutdown or Release", "Medium", "/zigguratutilityweb/home.aspx", ""},
				{"Improper Resource Shutdown or Release", "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{"Improper Resource Shutdown or Release", "Medium", "/zigguratutilityweb/home.aspx", ""},
				{"Improper Resource Shutdown or Release", "Medium", "/zigguratutilityweb/viewstatement.aspx", ""},
				{"Improper Resource Shutdown or Release", "Medium", "/zigguratutilityweb/viewstatement.aspx", ""},
				{"Trust Boundary Violation", "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{"ASP.NET Misconfiguration: Not Using Input Validation Framework", "Medium", "/zigguratutilityweb/message.aspx", ""},
				{"J2EE Bad Practices: Non-serializable Object Stored in Session", "Medium", "/zigguratutilityweb/loginpage.aspx", ""},
				{"Unchecked Return Value to NULL Pointer Dereference", "Medium", "/zigguratutilityweb/makepayment.aspx", ""},
				{"Unchecked Return Value to NULL Pointer Dereference", "Medium", "/zigguratutilityweb/home.aspx", ""},
				{"Unchecked Return Value to NULL Pointer Dereference", "Medium", "/zigguratutilityweb/makepayment.aspx", ""},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Info", "/zigguratutilityweb/app_code/dbutil.cs", ""},
				{"Unchecked Error Condition", "Info", "/zigguratutilityweb/app_code/dbutil.cs", ""},
			};
		}
		runScanTest(key, expectedResults);
	}

	@Test
	public void acunetixScan() {
		String key = "Acunetix WVS";
		String[][] expectedResults = {
				{XSS, "Critical", "/readnews.aspx", "NewsAd"},
				{XSS, "Critical", "/comments.aspx", "tbComment"},
				{SQLI, "Critical", "/comments.aspx", "tbComment"},
				{SQLI, "Critical", "/login.aspx", "tbUsername"},
				{SQLI, "Critical", "/comments.aspx", "id"},
				{SQLI, "Critical", "/readnews.aspx", "id"},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "Web Server", ""},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "NewsAd"},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/default.aspx", "delete"},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "id"},
				{CLEARTEXT_SENSITIVE_INFO, "Medium", "/signup.aspx", ""},
				{CLEARTEXT_SENSITIVE_INFO, "Medium", "/login.aspx", ""},
				{INFORMATION_EXPOSURE, "Low", "Web Server", ""},
				{IMPROPER_RESTRICTION_AUTH, "Low", "/signup.aspx", ""},
				{IMPROPER_RESTRICTION_AUTH, "Low", "/login.aspx", ""},
				{NON_SECURE_COOKIE, "Low", "/", ""},
				{INFO_LEAK_BROWSER_CACHE, "Info", "/signup.aspx", ""},
				{INFO_LEAK_BROWSER_CACHE, "Info", "/login.aspx", ""},
				{FILES_ACCESSIBLE, "Info", "/login.aspx", ""},
				{FILES_ACCESSIBLE, "Info", "/web.config", ""},
				{FILES_ACCESSIBLE, "Info", "/login.aspx.resx", ""},
				{FILES_ACCESSIBLE, "Info", "/login.aspx.cs", ""},
				{FILES_ACCESSIBLE, "Info", "/_vti_cnf", ""},
				{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj.webinfo", ""},
				{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/readnews.aspx", "NewsAd"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "Critical", "/comments.aspx", "tbComment"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/comments.aspx", "id"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/comments.aspx", "tbComment"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/login.aspx", "tbUsername"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/readnews.aspx", "id"},
				{"Information Exposure Through an Error Message", "Medium", "Web Server", ""},
				{"Information Exposure Through an Error Message", "Medium", "/default.aspx", "delete"},
				{"Information Exposure Through an Error Message", "Medium", "/readnews.aspx", "NewsAd"},
				{"Information Exposure Through an Error Message", "Medium", "/readnews.aspx", "id"},
				{"Cleartext Transmission of Sensitive Information", "Medium", "/signup.aspx", ""},
				{"Cleartext Transmission of Sensitive Information", "Medium", "/login.aspx", ""},
				{"Information Exposure", "Low", "Web Server", ""},
				{"Improper Restriction of Excessive Authentication Attempts", "Low", "/login.aspx", ""},
				{"Improper Restriction of Excessive Authentication Attempts", "Low", "/signup.aspx", ""},
				{"Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "Low", "/", ""},
				{"Information Leak Through Browser Caching", "Info", "/signup.aspx", ""},
				{"Information Leak Through Browser Caching", "Info", "/login.aspx", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/login.aspx.cs", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/web.config", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/login.aspx.resx", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/_vti_cnf/acublog.csproj", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/_vti_cnf/acublog.csproj.webinfo", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/_vti_cnf", ""},
				{"Files or Directories Accessible to External Parties", "Info", "/login.aspx", ""},
			};
		}
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void burpScan() {
		String key = "Burp Suite";
		String[][] expectedResults = {
				{FAILURE_TO_HANDLE_ENCODING, "", "/demo/XSS.php", ""},
				{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "High", "/demo/XSS-reflected2.php", "username"},
				{XSS, "High", "/demo/EvalInjection2.php", "command"},
				{SQLI, "High", "/demo/SQLI2.php", "username"},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PathTraversal.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-cookie.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PredictableResource.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-stored.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected2.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection.php", ""},
				{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/", ""},
				{IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA, "Info", "/demo/PredictableResource.php", ""},
				{DIRECTORY_LISTING, "Info", "/demo/DirectoryIndexing/", ""},
		};
		
		if (mySQL) {
			expectedResults = new String [][] {
				{"Failure to Handle Alternate Encoding", "", "/demo/XSS.php", ""},
				{"Improper Sanitization of Special Elements used in an OS Command ('OS Command Injection')", "High", "/demo/OSCommandInjection2.php", "fileName"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/EvalInjection2.php", "command"},
				{"Failure to Preserve Web Page Structure ('Cross-site Scripting')", "High", "/demo/XSS-reflected2.php", "username"},
				{"Improper Sanitization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/demo/SQLI2.php", "username"},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/EvalInjection2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/FormatString.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XPathInjection.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/OSCommandInjection2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/DirectoryIndexing/admin.txt", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XSS-reflected.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/SQLI.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XPathInjection2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/LDAPInjection2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/SQLI2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/LDAPInjection.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XSS-stored.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XSS-reflected2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/EvalInjection.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/FormatString2.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/OSCommandInjection.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/PathTraversal.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/PredictableResource.php", ""},
				{"Failure to Handle Alternate Encoding", "Info", "/demo/XSS-cookie.php", ""},
				{"Information Exposure", "Info", "/", ""},
				{"Improper Cross-boundary Removal of Sensitive Data", "Info", "/demo/PredictableResource.php", ""},
				{"Information Leak Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},
			};
		}
		runScanTest(key, expectedResults);
	}
	
	
	public void runScanTest(String scannerName, String[][] expectedResults) {
		organizationIndexPage = loginPage.login("user", "password");
		
		String orgName = scannerName + getRandomString(10);
		
		applicationDetailPage = organizationIndexPage.clickAddOrganizationButton()
													 .setNameInput(orgName)
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
		
			assertTrue(applicationDetailPage.getElementText("vulnName" + i)
											.equals(expectedResults[i-1][0]));
			
			assertTrue(applicationDetailPage.getElementText("severity" + i)
					.equals(expectedResults[i-1][1]));
			
			assertTrue(applicationDetailPage.getElementText("path" + i)
					.equals(expectedResults[i-1][2]));
			
			assertTrue(applicationDetailPage.getElementText("parameter" + i)
					.equals(expectedResults[i-1][3]));
		}
		
		applicationDetailPage.clickViewScansLink()
							 .clickDeleteScanButton(0)
							 .clickBackToAppLink()
							 .clickDeleteLink()
							 .clickDeleteButton();
	}
}
