////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.selenium.pages.LoginPage;
import org.apache.commons.lang.RandomStringUtils;
import org.junit.After;
import org.junit.Before;
import org.openqa.selenium.By;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;

public abstract class BaseTest {
	
	protected WebDriver driver;
    protected LoginPage loginPage;

	public BaseTest() {
		DesiredCapabilities capability = new DesiredCapabilities();
        capability.setBrowserName(DesiredCapabilities.firefox().getBrowserName());
        FirefoxProfile profile = new FirefoxProfile();
        capability.setCapability(FirefoxDriver.PROFILE, profile);
        capability.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);

        profile.setAcceptUntrustedCertificates(true);

        driver = new FirefoxDriver(capability);
	}

	@Before
	public void init() {
        TeamIndexCache.getCache().clear();
        loginPage = LoginPage.open(driver);
    }

	@After
	public void shutDown() {
        driver.quit();
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * This method is a wrapper for RandomStringUtils.random with a preset character set.
	 * @return random string
	 */
	protected String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}

}
