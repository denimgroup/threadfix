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
package com.denimgroup.threadfix.selenium.pages;

import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;

public abstract class BasePage {
	
	protected final Log log = LogFactory.getLog(this.getClass());
	
	public final static int NUM_SECONDS_TO_WAIT = 10;
	
	protected FirefoxDriver driver;
	
	public BasePage(WebDriver webdriver){
		driver = (FirefoxDriver) webdriver;
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
		
		log.debug("Loading " + this.getClass().toString());
	}
	
	public LoginPage logout() {
		driver.findElementById("logoutLink").click();
		return new LoginPage(driver);
	}
	
	public OrganizationIndexPage clickOrganizationHeaderLink() {
		driver.findElementById("orgHeader").click();
		return new OrganizationIndexPage(driver);
	}
	
	public WafIndexPage clickWafsHeaderLink() {
		driver.findElementById("wafsHeader").click();
		return new WafIndexPage(driver);
	}
	
	/*
	public ReportsPage clickReportsHeaderLink() {
		driver.findElementById("reportsHeader").click();
		return new ReportsPage(driver);
	}
	*/
	
	public ConfigurationIndexPage clickConfigurationHeaderLink() {
		driver.findElementById("configurationHeader").click();
		return new ConfigurationIndexPage(driver);
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
}