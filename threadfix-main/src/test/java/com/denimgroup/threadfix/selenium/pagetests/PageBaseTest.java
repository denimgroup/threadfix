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
package com.denimgroup.threadfix.selenium.pagetests;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;

import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;

@RunWith(Parameterized.class)
public class PageBaseTest {
	
	private final String USER = "user";
	private final String PASSWORD = "password";
	protected final Log log = LogFactory.getLog(this.getClass());
	private WebDriver driver;
	
//	@Parameters
	@Parameters(name="Browser: {0}")
	public static Collection<String[]> drivers() {
		Collection<String[]> params = new ArrayList<String[]>();
		String  ff = System.getProperty("FIREFOX");
		String  chrome = System.getProperty("CHROME");
		String  ie = System.getProperty("IE");
		if(!(ff==null) && ff.equals("true")){
			String[] f = {"firefox"};
			params.add(f);
		}
		if(!(chrome==null) && chrome.equals("true")){
			String[] c = {"chrome"};
			params.add(c);
		}
		
		if(!(ie==null) && ie.equals("true")){
			String[] e = {"IE"};
			params.add(e);
		}
		return params;
	}
	
	public PageBaseTest(String browser){
		if(browser.equals("chrome")){
			String location = PageBaseTest.class.getClassLoader().getResource("Drivers").getPath();
			if(System.getProperty("os.name").startsWith("Windows")){
				location = location + "/chromedriver.exe";
			}else{
				location = location + "/chromedriver";
			}
			System.setProperty("webdriver.chrome.driver",location);
			driver = new ChromeDriver();

		}
		
		if(browser.equals("firefox")){
			driver = new FirefoxDriver();
		}
		
		if(browser.equals("IE")){
			String location = PageBaseTest.class.getClassLoader().getResource("Drivers").getFile();
			location = location + "/IEDriverServer.exe";
			DesiredCapabilities capabilities = new DesiredCapabilities();
			capabilities.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);
			driver = new InternetExplorerDriver(capabilities); 
		}
	}
	
	
	@Before
	public void init() {
	}

	@After
	public void shutDown() {
			driver.quit();
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
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public DashboardPage login(){
		LoginPage loginPage = new LoginPage(driver);
		return loginPage.login(USER, PASSWORD);
	}
}
