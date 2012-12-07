////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class OrganizationIndexPage extends BasePage {

	private WebElement organizationTable;
	
	private WebElement lastOrganizationFoundInTableLink;
		
	public OrganizationIndexPage(WebDriver webdriver) {
		super(webdriver);
		organizationTable = driver.findElementById("orgTableBody");
	}
	
	public AddOrganizationPage clickAddOrganizationButton() {
		driver.findElementById("addOrganization").click();
		return new AddOrganizationPage(driver);
	}
	
	public boolean isOrganizationNamePresent(String organizationName) {
	
		for (WebElement element : organizationTable.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(organizationName)) {
				lastOrganizationFoundInTableLink = element;
				return true;
			}
		}
		
		return false;
	}
	
	public OrganizationDetailPage clickOrganizationLink(String organizationName) {
		if (isOrganizationNamePresent(organizationName)) {
			lastOrganizationFoundInTableLink.click();
			return new OrganizationDetailPage(driver);
		} else {
			return null;
		}
	}
	
	public UserChangePasswordPage clickChangePasswordLinkIfPresent() {
		if (driver.findElementById("changePasswordLink") != null) {
			driver.findElementById("changePasswordLink").click();
			return new UserChangePasswordPage(driver);
		} else {
			return null;
		}
	}
}
