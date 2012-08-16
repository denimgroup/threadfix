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
		fileMap.put("IBM Rational AppScan Source Edition", null);
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
	final static String ACCESS_CONTROL = "Improper Access Control";
	final static String ARGUMENT_INJECTION = "Argument Injection or Modification";
	final static String ASP_NET_CUSTOM_ERROR = "ASP.NET Misconfiguration: Missing Custom Error Page";
	final static String ASP_NET_DEBUG = "ASP.NET Misconfiguration: Creating Debug Binary";
	final static String ASP_NET_VALIDATION_MISSING = "ASP.NET Misconfiguration: Not Using Input Validation Framework";
	final static String CLEARTEXT_SENSITIVE_INFO = "Cleartext Transmission of Sensitive Information";
	final static String CODE_INJECTION = "Improper Control of Generation of Code ('Code Injection')";
	final static String COMMAND_INJECTION = "Improper Neutralization of Special Elements used in a Command ('Command Injection')";
	final static String CONFIGURATION = "Configuration";
	final static String CSRF = "Cross-Site Request Forgery (CSRF)";
	final static String DIRECTORY_LISTING = "Information Exposure Through Directory Listing";
	final static String EVAL_INJECTION = GenericVulnerability.CWE_EVAL_INJECTION;
	final static String EXTERNAL_CONTROL_OF_PARAM = "External Control of Assumed-Immutable Web Parameter";
	final static String EXTERNAL_FILEPATH_CONTROL = "External Control of File Name or Path";
	final static String FAILURE_TO_HANDLE_ENCODING = "Improper Handling of Alternate Encoding";
	final static String FILES_ACCESSIBLE = "Files or Directories Accessible to External Parties";
	final static String FORCED_BROWSING = "Direct Request ('Forced Browsing')";
	final static String FORMAT_STRING_INJECTION = GenericVulnerability.CWE_FORMAT_STRING_INJECTION;
	final static String GENERIC_INJECTION = "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')";
	final static String IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA = "Improper Cross-boundary Removal of Sensitive Data";
	final static String IMPROPER_HANDLING_OF_MISSING_VALUES = "Improper Handling of Missing Values";
	final static String IMPROPER_INPUT_VALIDATION = "Improper Input Validation";
	final static String IMPROPER_RESOURCE_SHUTDOWN = "Improper Resource Shutdown or Release";
	final static String IMPROPER_RESTRICTION_AUTH = "Improper Restriction of Excessive Authentication Attempts";
	final static String INFORMATION_EXPOSURE = "Information Exposure";
	final static String INFO_EXPOSURE_ERROR_MESSAGE = "Information Exposure Through an Error Message";
	final static String INFO_LEAK_BROWSER_CACHE = "Information Exposure Through Browser Caching";
	final static String INFO_LEAK_COMMENTS = "Information Exposure Through Comments";
	final static String INFO_LEAK_DIRECTORIES = "File and Directory Information Exposure";
	final static String INFO_LEAK_SERVER_ERROR = "Information Exposure Through Server Error Message";
	final static String INFO_LEAK_TEST_CODE = "Information Exposure Through Test Code";
	final static String LDAP_INJECTION = GenericVulnerability.CWE_LDAP_INJECTION; 
	final static String NON_SECURE_COOKIE = "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute";
	final static String NON_SERIALIZABLE_OBJECT = "J2EE Bad Practices: Non-serializable Object Stored in Session";
	final static String NULL_POINTER = "Unchecked Return Value to NULL Pointer Dereference";
	final static String OPEN_REDIRECT = "URL Redirection to Untrusted Site ('Open Redirect')";
	final static String OS_INJECTION = GenericVulnerability.CWE_OS_COMMAND_INJECTION;
	final static String PATH_TRAVERSAL = GenericVulnerability.CWE_PATH_TRAVERSAL;
	final static String REFLECTION_ATTACK = "Reflection Attack in an Authentication Protocol";
	final static String RESOURCE_INJECTION = "Improper Control of Resource Identifiers ('Resource Injection')";
	final static String SESSION_FIXATION = "Session Fixation";
	final static String SOURCE_CODE_INCLUDE = "Information Exposure Through Include Source Code";
	final static String SQLI = GenericVulnerability.CWE_SQL_INJECTION;
	final static String TRUST_BOUNDARY_VIOLATION = "Trust Boundary Violation";
	final static String UNCHECKED_ERROR = "Unchecked Error Condition";
	final static String XML_INJECTION = "XML Injection (aka Blind XPath Injection)";
	final static String XPATH_INJECTION = GenericVulnerability.CWE_XPATH_INJECTION;
	final static String XSS = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING;
	
	@Test
	public void microsoftCatNetScan() {
		String key = "Microsoft CAT.NET";
		
		String[][] expectedResults = {
				{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtMessage"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
				{ XSS, "Critical", "/ZigguratUtilityWeb/Message.aspx", ""},
				{ SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtPassword"},
				{ SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
				{ SQLI, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
				{ SQLI, "Critical", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
			};
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void findBugsScan() {
		
		String key = "FindBugs";
		String[][] expectedResults = new String[][] {
			{ XSS, "Critical", "securibench/micro/aliasing/Aliasing1.java", "name"},
			{ XSS, "Critical", "securibench/micro/aliasing/Aliasing4.java", "name"},
			{ XSS, "Critical", "securibench/micro/basic/Basic1.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic18.java", "s"},
			{ XSS, "Critical", "securibench/micro/basic/Basic2.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic28.java", "name"},
			{ XSS, "Critical", "securibench/micro/basic/Basic4.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic8.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic9.java", "s1"},
			{ XSS, "Critical", "securibench/micro/pred/Pred4.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred5.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred6.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred7.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred8.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred9.java", "name"},
			{ XSS, "Critical", "securibench/micro/session/Session1.java", "name"},
			{ XSS, "Critical", "securibench/micro/session/Session2.java", "name"},
			{ XSS, "High", "securibench/micro/basic/Basic10.java", "s5"},
			{ XSS, "High", "securibench/micro/basic/Basic27.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic29.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic30.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic32.java", "header"},
			{ XSS, "High", "securibench/micro/basic/Basic34.java", "headerValue"},
			{ XSS, "High", "securibench/micro/basic/Basic35.java", ""},
			{ XSS, "High", "securibench/micro/pred/Pred2.java", "name"},
			{ XSS, "High", "securibench/micro/pred/Pred3.java", "name"},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates3.java", ""},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates4.java", ""},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates5.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic19.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic20.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic21.java", ""},
		};
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void ibmAppscanScan() {
		String key = "IBM Rational AppScan";
		String[][] expectedResults = new String[][] {
					{ PATH_TRAVERSAL, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{ XSS, "Critical", "/demo/EvalInjection2.php", "command"},
					{ XSS, "Critical", "/demo/XPathInjection2.php", "password"},
					{ XSS, "Critical", "/demo/XPathInjection2.php", "username"},
					{ XSS, "Critical", "/demo/XPathInjection2.php", ""},
					{ XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
					{ COMMAND_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
					{ SQLI, "Critical", "/demo/XPathInjection2.php", "username"},
					{ SQLI, "Critical", "/demo/XPathInjection2.php", "password"},
					{ INFO_EXPOSURE_ERROR_MESSAGE, "Critical", "/demo/SQLI2.php", "username"},
					{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "username"},
					{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "password"},
					{ GENERIC_INJECTION, "Medium", "/demo/XSS-reflected2.php", "username"},
					{ DIRECTORY_LISTING, "Medium", "/demo/DIRECT~1/", ""},
					{ DIRECTORY_LISTING, "Medium", "/demo/DirectoryIndexing/", ""},
					{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "username"},
					{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "password"},
					{ REFLECTION_ATTACK, "Medium", "/demo/XSS-reflected2.php", "username"},
					{ FORCED_BROWSING, "Low", "/demo/DIRECT~1/", ""},
					{ FORCED_BROWSING, "Low", "/demo/DirectoryIndexing/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/aux/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/cgi-bin/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/com1/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/com2/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/com3/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/aux/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com1/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com2/", ""},
					{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com3/", ""},
					{ INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
					{ INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
					{ INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", ""},
					{ INFO_LEAK_COMMENTS, "Low", "/demo/", ""},
					{ INFO_LEAK_COMMENTS, "Low", "/demo/SQLI.php", ""},
					{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected.php", ""},
					{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected2.php", ""},
					{ INFO_LEAK_TEST_CODE, "Low", "/", ""},
					{ INFO_LEAK_TEST_CODE, "Low", "/demo/PredictableResource.php", ""},
					{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/EvalInjection2.php", "command"},
					{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/LDAPInjection2.php", "username"},
					{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/SQLI2.php", "username"},
					{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "password"},
					{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "username"},
			};
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void netsparkerScan(){
		String key = "Mavituna Security Netsparker";
		String[][] expectedResults = new String[] [] {
				{CODE_INJECTION, "Critical", "/demo/EvalInjection2.php", "command"},
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{RESOURCE_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{XSS, "High", "/demo/EvalInjection2.php", "command"},
				{XSS, "High", "/demo/SQLI2.php", "username"},
				{XSS, "High", "/demo/XPathInjection2.php", "password"},
				{XSS, "High", "/demo/XPathInjection2.php", "username"},
				{XSS, "High", "/demo/XSS-reflected2.php", "username"},
				{SOURCE_CODE_INCLUDE, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
				{CONFIGURATION, "Low", "/demo/", ""},
				{FORCED_BROWSING, "Low", "/demo/LDAPInjection.php", ""},
				{FORCED_BROWSING, "Low", "/demo/PredictableResource.php.bak", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
				{INFO_EXPOSURE_ERROR_MESSAGE, "Low", "/demo/SQLI2.php", "username"},
				{INFORMATION_EXPOSURE, "Info", "/demo/EvalInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/FormatString2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/LDAPInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/OSCommandInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/PathTraversal.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/SQLI2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XPathInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XSS-cookie.php", ""},
				{INFORMATION_EXPOSURE, "Info", "/demo/XSS-reflected2.php", ""},
				{"Information Exposure Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},
		};
		
		runScanTest(key, expectedResults);
	}
	
	
	@Test
	public void skipFishScan(){
		String key = "Skipfish";
		String[][] expectedResults = new String [][] {
					{SQLI, "Critical", "/demo/EvalInjection2.php", "command"},
					{SQLI, "Critical", "/demo/LDAPInjection2.php", "username"},
					{SQLI, "Critical", "/demo/SQLI2.php", "username"},
					{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/EvalInjection2.php","command"},
					{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/FormatString2.php","name"},
					{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/PathTraversal.php","action"},
					{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-cookie.php","cookie"},
					{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-reflected2.php","username"},
					{PATH_TRAVERSAL, "High", "/demo/PathTraversal.php","action"},
					{XSS, "High", "/demo/XSS-cookie.php","cookie"},
					{XSS, "High", "/demo/XSS-reflected2.php","username"},
					{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/",""},
					{INFO_LEAK_SERVER_ERROR, "High", "/demo/SQLI2.php","username"},
					{CSRF, "Medium", "/demo/EvalInjection2.php",""},
					{CSRF, "Medium", "/demo/FormatString2.php",""},
					{CSRF, "Medium", "/demo/LDAPInjection2.php",""},
					{CSRF, "Medium", "/demo/OSCommandInjection2.php",""},
					{CSRF, "Medium", "/demo/SQLI2.php",""},	
					{CSRF, "Medium", "/demo/XSS-cookie.php",""},
					{CSRF, "Medium", "/demo/XSS-reflected2.php",""},
				
			};
		
		runScanTest(key, expectedResults);
	}
	
	
	@Test
	public void w3afScan() {
		
		String key = "w3af";
		String[][] expectedResults = new String[] [] { 
			{EVAL_INJECTION,"High", "/demo/EvalInjection2.php","command"},
			{XSS, "High", "/demo/XSS-cookie.php", "cookie"},
			{LDAP_INJECTION,"High", "/demo/LDAPInjection2.php","username"},
			{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI,"High", "/demo/SQLI2.php","username"},
			{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","username"},
			{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","password"},
			{XSS,"Medium", "/demo/EvalInjection2.php","command"},
			{XSS,"Medium", "/demo/XSS-reflected2.php","username"},
			{FORMAT_STRING_INJECTION,"Medium", "/demo/FormatString2.php","name"},
			{FORCED_BROWSING,"Info", "/demo.zip",""},
			{FORCED_BROWSING,"Info", "/demo/PredictableResource.php.bak",""},
			
		};
		
		runScanTest(key, expectedResults);		
	}
	
	@Test
	public void zaproxyScan() {
		String key = "OWASP Zed Attack Proxy";
		String[][] expectedResults = new String [][] {
			{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/", ""},
			{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "username"},
			{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
			{SQLI, "Medium", "/demo/SQLI2.php", "username"},
		};
		
		runScanTest(key, expectedResults);
	}

	@Test
	public void nessusScan() {
		String key = "Nessus";
		String[][] expectedResults = new String [][] {
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "Critical", "/demo/SQLI2.php", "username"},
			{FORCED_BROWSING, "Medium", "/demo/PredictableResource.php.bak", ""},
			{EXTERNAL_FILEPATH_CONTROL, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
			{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
			{XSS, "Medium", "/demo/XSS-cookie.php", "cookie"},
			{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
			{SESSION_FIXATION, "Medium", "/demo/XSS-reflected2.php", "username"},
			{DIRECTORY_LISTING, "Low", "/demo/DirectoryIndexing/", ""},
		};
		
		runScanTest(key, expectedResults);		
	}
	
	@Test
	public void arachniScan() {
		String key = "Arachni";
		String[][] expectedResults = new String [][] {
			{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
			{XSS, "Critical", "/demo/XPathInjection2.php", "username"},
			{XSS, "Critical", "/demo/XPathInjection2.php", "password"},
			{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
			{LDAP_INJECTION, "Critical", "/demo/LDAPInjection2.php", "username"},
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "Critical", "/demo/SQLI2.php", "username"},
			{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "password"},
			{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "username"},
			{INFO_LEAK_DIRECTORIES, "High", "/demo/", ""},
		};
		
		runScanTest(key, expectedResults);		
	}
	
	
	@Test
	public void webInspectScan() {
		String key = "WebInspect";
		String[][] expectedResults = new String [][] {
				{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
				{XSS, "Critical", "/demo/XSS-cookie.php", "cookie"},
				{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
				{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
				{INFORMATION_EXPOSURE, "Critical", "/demo/SQLI2.php", "username"},
				{INFORMATION_EXPOSURE, "Critical", "/demo/password.txt", ""},
				{INFORMATION_EXPOSURE, "High", "/demo/OSCommandInjection2.php", "fileName"},
				{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.BAK", ""},
				{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.bak", ""},
				{FORCED_BROWSING, "Medium", "/test.php", ""},
				{ACCESS_CONTROL, "Medium", "/demo/XPathInjection2.php", ""},
				{LDAP_INJECTION, "Medium", "/demo/LDAPInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Medium", "/demo/LDAPInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/cgi-bin/test.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/EvalInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/FormatString2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/OSCommandInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", "action"},
				{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/SQLI2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/XPathInjection2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", "cookie"},
				{INFORMATION_EXPOSURE, "Low", "/demo/XSS-reflected2.php", ""},
				{INFORMATION_EXPOSURE, "Low", "/test.php", ""},
				{DIRECTORY_LISTING, "Low", "/cgi-bin/", ""},
				{DIRECTORY_LISTING, "Low", "/demo/", ""},
				{INFORMATION_EXPOSURE, "Info", "/", ""},
		};
		runScanTest(key,expectedResults);
	}
	
	@Test
	public void brakeManScan() {
		String key = "Brakeman";
		String[][] expectedResults = new String [][] {
			{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/index.html", "User.new"},
			{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/results.html", "null"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			
			
			{SQLI, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:query]"},
			{OPEN_REDIRECT, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params"},
			{CSRF, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/application_controller.rb", "null"},
			
			
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
			
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
			
			
			{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
			
			{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
			
			{FORCED_BROWSING, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/config/routes.rb", "null"},
			{EXTERNAL_CONTROL_OF_PARAM, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/post, user.rb", "null"},
			
			{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "Post.find(params[:id])"},
			{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "User.find(params[:id])"},
		};
		
		runScanTest(key, expectedResults);		

	}
	
	@Test
	public void fortify360Scan() {
		String key = "Fortify 360";
		String[][] expectedResults = new String [][] {
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CcfUsed"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "PreviousBill"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentNaturalGas"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentElectricity"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CityServices"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Address"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Payments"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "BillingDate"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Name"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "StateLocalTaxes"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CustomerNumber"},
			{XSS, "Critical", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "KiloWattHourUsed"},
			{XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
			{XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
			{XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
			{XSS, "Critical", "/zigguratutilityweb/message.aspx", "Msg"},
			{SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
			{SQLI, "Critical", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
			{ASP_NET_DEBUG, "Medium", "/ZigguratUtilityWeb/web.config", ""},
			{ASP_NET_CUSTOM_ERROR, "Medium", "/ZigguratUtilityWeb/web.config", ""},
			{ASP_NET_VALIDATION_MISSING, "Medium", "/zigguratutilityweb/message.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
			{NON_SERIALIZABLE_OBJECT, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{TRUST_BOUNDARY_VIOLATION, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
			{SQLI, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""},
			{UNCHECKED_ERROR, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""}
		};
		
		runScanTest(key, expectedResults);
	}

	@Test
	public void acunetixScan() {
		String key = "Acunetix WVS";
		String[][] expectedResults = new String [][] {
			{XSS, "Critical", "/comments.aspx", "tbComment"},
			{XSS, "Critical", "/readnews.aspx", "NewsAd"},
			{SQLI, "Critical", "/comments.aspx", "tbComment"},
			{SQLI, "Critical", "/comments.aspx", "id"},
			{SQLI, "Critical", "/login.aspx", "tbUsername"},
			{SQLI, "Critical", "/readnews.aspx", "id"},
			{CLEARTEXT_SENSITIVE_INFO, "Medium", "/login.aspx", ""},
			{CLEARTEXT_SENSITIVE_INFO, "Medium", "/signup.aspx", ""},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/default.aspx", "delete"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "NewsAd"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "id"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "Web Server", ""},
			{IMPROPER_RESTRICTION_AUTH, "Low", "/login.aspx", ""},
			{IMPROPER_RESTRICTION_AUTH, "Low", "/signup.aspx", ""},
			{INFORMATION_EXPOSURE, "Low", "Web Server", ""},
			{NON_SECURE_COOKIE, "Low", "/", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj.webinfo", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx.cs", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx.resx", ""},
			{FILES_ACCESSIBLE, "Info", "/web.config", ""},
			{INFO_LEAK_BROWSER_CACHE, "Info", "/login.aspx", ""},
			{INFO_LEAK_BROWSER_CACHE, "Info", "/signup.aspx", ""},
		};
		
		runScanTest(key, expectedResults);
	}
	
	@Test
	public void burpScan() {
		String key = "Burp Suite";
		String[][] expectedResults = new String [][] {
			{XSS, "High", "/demo/EvalInjection2.php", "command"},
			{XSS, "High", "/demo/XSS-reflected2.php", "username"},
			{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "High", "/demo/SQLI2.php", "username"},
			{IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA, "Info", "/demo/PredictableResource.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/DirectoryIndexing/admin.txt", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PathTraversal.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PredictableResource.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-cookie.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-stored.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/",""},
			{DIRECTORY_LISTING,"Info","/demo/DirectoryIndexing/",""},
		};

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
			
			System.out.println(i);
		
			String elementText = applicationDetailPage.getElementText("vulnName" + i);
			assertTrue(elementText.equals(expectedResults[i-1][0]));
			
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
