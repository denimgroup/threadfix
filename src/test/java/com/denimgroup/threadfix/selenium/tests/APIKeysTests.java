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

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class APIKeysTests extends BaseTest {
	private FirefoxDriver driver;

	private static LoginPage loginPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@Test
	public void navigationTest() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
				  							  .clickConfigurationHeaderLink()
				  							  .clickApiKeysLink();
		
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));
	}

	@Test
	public void createAPIKey() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
											  .clickConfigurationHeaderLink()
								   			  .clickApiKeysLink()
								   			  .clickNewLink()
								   			  .clickCreate();
		
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));

		indexPage.clickDelete(0);
	}

	@Test
	public void editKey() {
		
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
								   .clickConfigurationHeaderLink()
								   .clickApiKeysLink()
								   .clickNewLink()
								   .clickCreate()
								   .clickEdit(0)
								   .fillAllClickSave("Sample ThreadFix REST key", false);
		
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));

		indexPage.clickDelete(0);
		// TODO assert that the proper text is there
	}

	@Test
	public void markRestricted() {
		ApiKeysIndexPage indexPage = loginPage.login("user", "password")
											  .clickConfigurationHeaderLink()
					 						  .clickApiKeysLink()
											  .clickNewLink()
											  .clickCreate()
											  .clickEdit(0)
											  .fillAllClickSave("Sample ThreadFix REST key", false);
						
		assertTrue("API Keys Page not found", indexPage.getH2Tag().contains("API Keys"));
		
		indexPage.clickDelete(0);
	}

	@Test
	public void deleteKey() {
		String PageText = loginPage.login("user", "password")
								   .clickConfigurationHeaderLink()
								   .clickApiKeysLink()
								   .clickNewLink()
								   .clickCreate()
								   .clickDelete(0)
								   .getH2Tag();

		assertTrue("API Keys Page not found", PageText.contains("API Keys"));
	}

}
