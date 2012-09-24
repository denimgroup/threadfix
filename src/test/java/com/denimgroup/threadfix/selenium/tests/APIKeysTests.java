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

import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import com.denimgroup.threadfix.selenium.pages.ConfigurationIndexPage;
import com.denimgroup.threadfix.selenium.pages.CreateApiKeyPage;
import com.denimgroup.threadfix.selenium.pages.EditApiKeyPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class APIKeysTests extends BaseTest {
	private FirefoxDriver driver;

	private ApiKeysIndexPage apiIndexPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		driver.manage().timeouts().implicitlyWait(45, TimeUnit.SECONDS);
		loginAdmin();
	}

	@After
	public void shutDown() {
		driver.quit();
	}

	@Test
	public void navigationTest() {
		driver.findElementById("configurationHeader").click();
		ConfigurationIndexPage configPage = new ConfigurationIndexPage(driver);
		configPage.clickApiKeysLink();
		apiIndexPage = new ApiKeysIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("API Keys Page not found", PageText.contains("API Keys"));

	}

	@Test
	public void createAPIKey() {
		driver.findElementById("configurationHeader").click();
		ConfigurationIndexPage configPage = new ConfigurationIndexPage(driver);
		configPage.clickApiKeysLink();
		apiIndexPage = new ApiKeysIndexPage(driver);
		apiIndexPage.clickNewLink();
		CreateApiKeyPage createApiPage = new CreateApiKeyPage(driver);
		createApiPage.clickCreate();
		apiIndexPage = new ApiKeysIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
		sleep(1000);

	}

	@Test
	public void editKey() {
		driver.findElementById("configurationHeader").click();
		ConfigurationIndexPage configPage = new ConfigurationIndexPage(driver);
		configPage.clickApiKeysLink();
		apiIndexPage = new ApiKeysIndexPage(driver);
		apiIndexPage.clickNewLink();
		CreateApiKeyPage createApiPage = new CreateApiKeyPage(driver);
		createApiPage.clickCreate();
		apiIndexPage.clickEdit(0);
		EditApiKeyPage editApiPage = new EditApiKeyPage(driver);
		editApiPage.fillAllClickSave("Sample ThreadFix REST key", false);
		apiIndexPage = new ApiKeysIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
		sleep(1000);
	}

	@Test
	public void markRestricted() {
		driver.findElementById("configurationHeader").click();
		ConfigurationIndexPage configPage = new ConfigurationIndexPage(driver);
		configPage.clickApiKeysLink();
		apiIndexPage = new ApiKeysIndexPage(driver);
		apiIndexPage.clickNewLink();
		CreateApiKeyPage createApiPage = new CreateApiKeyPage(driver);
		createApiPage.clickCreate();
		apiIndexPage = new ApiKeysIndexPage(driver);
		EditApiKeyPage editApiPage = apiIndexPage.clickEdit(0);
		editApiPage.fillAllClickSave("Sample ThreadFix REST key 2", true);
		apiIndexPage = new ApiKeysIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
		sleep(1000);
	}

	@Test
	public void deleteKey() {
		driver.findElementById("configurationHeader").click();
		ConfigurationIndexPage configPage = new ConfigurationIndexPage(driver);
		configPage.clickApiKeysLink();
		apiIndexPage = new ApiKeysIndexPage(driver);
		apiIndexPage.clickDelete(0);
		apiIndexPage = new ApiKeysIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
		sleep(1000);

	}

	public void loginAdmin() {
		LoginPage page = new LoginPage(driver);
		page.login("user", "password");

	}

	private void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public FirefoxDriver getDriver() {
		return driver;
	}

}
