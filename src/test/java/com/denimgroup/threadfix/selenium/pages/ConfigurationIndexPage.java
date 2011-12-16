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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class ConfigurationIndexPage extends BasePage {
	
	private WebElement channelsLink;
	private WebElement defectTrackersLink;
	private WebElement jobStatusesLink;
	private WebElement manageUsersLink;
	private WebElement whiteHatSentinelLink;
	private WebElement apiKeysLink;
	
	public ConfigurationIndexPage(WebDriver webdriver) {
		super(webdriver);

		channelsLink = driver.findElementById("channelsLink");
		defectTrackersLink = driver.findElementById("defectTrackersLink");
		jobStatusesLink = driver.findElementById("jobStatusesLink");
		manageUsersLink = driver.findElementById("manageUsersLink");
		whiteHatSentinelLink = driver.findElementById("whiteHatSentinelLink");
		apiKeysLink = driver.findElementById("apiKeysLink");
		
	}
	
	public OrganizationIndexPage clickChannelsLink() {
		channelsLink.click();
		return new OrganizationIndexPage(driver);
	}

	public DefectTrackerIndexPage clickDefectTrackersLink() {
		defectTrackersLink.click();
		return new DefectTrackerIndexPage(driver);
	}

	public OrganizationIndexPage clickJobStatusesLink() {
		jobStatusesLink.click();
		return new OrganizationIndexPage(driver);
	}

	public UserIndexPage clickManageUsersLink() {
		manageUsersLink.click();
		return new UserIndexPage(driver);
	}

	public OrganizationIndexPage clickWhiteHatSentinelLink() {
		whiteHatSentinelLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickApiKeysLink() {
		apiKeysLink.click();
		return new OrganizationIndexPage(driver);
	}
}
