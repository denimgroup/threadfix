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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import java.util.Set;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;

@RunWith(Parameterized.class)
public abstract class BaseTest {
	
	protected final Log log = LogFactory.getLog(this.getClass());
	
	private WebDriver driver;
	private static ChromeDriverService service;
	
	public BaseTest(String browser){
		if(browser.equals("chrome")){
			String location = BaseTest.class.getClassLoader().getResource("Drivers").getFile();
			String log = "";
			if(System.getProperty("os.name").startsWith("Windows")){
				location = location + "/chromedriver.exe";
				log = "NUL";
			}else{
				location = location + "/chromedriver";
				log = "/dev/null";
			}
		    service = new ChromeDriverService.Builder()
		    							.usingDriverExecutable(new File(location))
		    							.usingAnyFreePort()
		    							.withLogFile(new File(log))
		    							.build();
		    try {
				service.start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		    driver = new RemoteWebDriver(service.getUrl(),DesiredCapabilities.chrome());
		}
		
		if(browser.equals("firefox")){
			driver = new FirefoxDriver();
		}
		
		if(browser.equals("IE")){
			String location = BaseTest.class.getClassLoader().getResource("Drivers").getFile();
			location = location + "/IEDriverServer.exe";
			DesiredCapabilities capabilities = new DesiredCapabilities();
			capabilities.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);
			driver = new InternetExplorerDriver(capabilities); 
		}
	}
	
	@Parameterized.Parameters
	public static Collection<String[]> drivers() {
		Collection<String[]> params = new ArrayList<>();
		String  ff = System.getProperty("FIREFOX");
		String  chrome = System.getProperty("CHROME");
		String  ie = System.getProperty("IE");
		if(!(ff==null) && ff.equals("true")){
			String[] f = {"firefox"};
			params.add(f);
		}
		
		if(!(chrome==null) && chrome.equals("true")){
			String[] f = {"chrome"};
			params.add(f);
		}
		
		if(!(ie==null) && ie.equals("true")){
			String[] f = {"IE"};
			params.add(f);
		}
		return params;
	}
	
	@Before
	public void init() {
	}

	@After
	public void shutDown() {
		if(driver instanceof InternetExplorerDriver || driver instanceof FirefoxDriver){
			driver.quit();
		}else{
			service.stop();
		}
	}
	
	public WebDriver getDriver(){
		log.debug("Getting Driver");
		return driver;
	}
	
	/**
	 * This method is a wrapper for RandomStringUtils.random with a preset character set.
	 * @return random string
	 */
	protected String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}
	
	protected <T> Set<Set<T>> powerSet(T[] items) {
		int count = 1 << items.length;
		
		Set<Set<T>> setOfSets = new HashSet<>();
		
		for (int i = 0; i < count; i++) {
			
			Set<T> set = new HashSet<>();
			int j = 0;
			for (T item : items) {
				if ((i >> j++) % 2 == 1)
					set.add(item);
			}
			
			setOfSets.add(set);
		}
		
		return setOfSets;
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
}
