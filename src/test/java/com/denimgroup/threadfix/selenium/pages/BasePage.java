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
package com.denimgroup.threadfix.selenium.pages;

import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openqa.selenium.Alert;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.interactions.Actions;

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
		sleep(1000);
		return new OrganizationIndexPage(driver);
	}
	
	public WafIndexPage clickWafsHeaderLink() {
		driver.findElementById("wafsHeader").click();
		return new WafIndexPage(driver);
	}

	public ReportsIndexPage clickReportsHeaderLink() {
		driver.findElementById("reportsHeader").click();
		return new ReportsIndexPage(driver);
	}
	
	public void hoverOverAdministration(){
		
		Actions builder = new Actions(driver); 
		Actions hoverOverRegistrar = builder.moveToElement(driver.findElementById("configurationHeader"));
		hoverOverRegistrar.perform();
	}
	
	public ApiKeysIndexPage clickApiKeysLink(){
		hoverOverAdministration();
		driver.findElementById("apiKeysLink").click();
		return new ApiKeysIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickDefectTrackersLink(){
		hoverOverAdministration();
		driver.findElementById("defectTrackersLink").click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickRemoteProvidersLink(){
		hoverOverAdministration();
		driver.findElementById("remoteProvidersLink").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public UserChangePasswordPage clickChangePasswordLink(){
		hoverOverAdministration();
		driver.findElementById("changePasswordLink").click();
		return new UserChangePasswordPage(driver);
	}
	
	public UserIndexPage clickManageUsersLink(){
		hoverOverAdministration();
		driver.findElementById("manageUsersLink").click();
		return new UserIndexPage(driver);
	}
	
	public RolesIndexPage clickManageRolesLink(){
		hoverOverAdministration();
		driver.findElementById("manageRolesLink").click();
		return new RolesIndexPage(driver);
	}
	
	public ErrorLogPage clickViewLogsLink(){
		hoverOverAdministration();
		driver.findElementById("viewLogsLink").click();
		return new ErrorLogPage(driver);
	}
	
	public ConfigureDefaultsPage clickConfigureDefaultsLink(){
		hoverOverAdministration();
		driver.findElementById("viewLogsLink").click();
		return new ConfigureDefaultsPage(driver);
		
	}
	
	
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public void waitForElementPresence(String element, int number) {
		int count = 0;
		// wait til jsonResult2 is present
		while (!isElementPresent(element)) {
			sleep(1000);
			if (count++ > number) {
				return;
			}
		}
	}
	
	public boolean isElementPresent(String elementId) {
		try {
			return driver.findElementById(elementId) != null;
		} catch (NoSuchElementException e) {
			return false;
		}
	}
	
	public String getH2Tag() {
		return driver.findElementByTagName("h2").getText();
	}
	
	protected void handleAlert() {
		Alert alert = driver.switchTo().alert();
		alert.accept();
	}
}
