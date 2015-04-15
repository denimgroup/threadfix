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
package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class ConfigurationIndexPage extends BasePage {
	
	private WebElement defectTrackersLink;
	private WebElement jobStatusesLink;
	private WebElement manageUsersLink;
	private WebElement remoteProvidersLink;
	private WebElement rolesLink;
	private WebElement apiKeysLink;
	private WebElement changeMyPasswordLink;
	
	public ConfigurationIndexPage(WebDriver webdriver) {
		super(webdriver);

		defectTrackersLink = driver.findElementById("defectTrackersLink");
		jobStatusesLink = driver.findElementById("jobStatusesLink");
		manageUsersLink = driver.findElementById("manageUsersLink");
		remoteProvidersLink = driver.findElementById("remoteProvidersLink");
		apiKeysLink = driver.findElementById("apiKeysLink");
		rolesLink = driver.findElementById("manageRolesLink");
		changeMyPasswordLink = driver.findElementById("changePasswordLink");
	}

	public DefectTrackerIndexPage clickDefectTrackersLink() {
		defectTrackersLink.click();
		return new DefectTrackerIndexPage(driver);
	}

	public TeamIndexPage clickJobStatusesLink() {
		jobStatusesLink.click();
		return new TeamIndexPage(driver);
	}

	public UserIndexPage clickManageUsersLink() {
		manageUsersLink.click();
		return new UserIndexPage(driver);
	}

	public ApiKeysIndexPage clickApiKeysLink() {
		apiKeysLink.click();
		return new ApiKeysIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickRemoteProvidersLink() {
		remoteProvidersLink.click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public UserChangePasswordPage clickChangeMyPasswordLink() {
		changeMyPasswordLink.click();
		return new UserChangePasswordPage(driver);
	}

	public RolesIndexPage clickRolesLink() {
		rolesLink.click();
		return new RolesIndexPage(driver);
	}
}
