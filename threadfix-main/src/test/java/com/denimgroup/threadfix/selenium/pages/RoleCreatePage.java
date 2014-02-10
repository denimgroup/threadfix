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

public class RoleCreatePage extends BasePage {
	
	private WebElement createRoleButton;
	private WebElement backToRolesLink;
	private WebElement displayNameInput;

	public RoleCreatePage(WebDriver webdriver) {
		super(webdriver);
		displayNameInput = driver.findElementById("displayName");
		createRoleButton = driver.findElementById("createRoleButton");
		backToRolesLink = driver.findElementById("backToRolesButton");
	}
	
	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}

	public String getDisplayNameError() {
		return driver.findElementById("displayName.errors").getText();
	}

	public RoleCreatePage setDisplayNameInput(String displayName) {
		displayNameInput.sendKeys(displayName);
		return new RoleCreatePage(driver);
	}
	
	public RolesIndexPage clickCreateRoleButton() {
		createRoleButton.click();
		return new RolesIndexPage(driver);
	}
	
	public RoleCreatePage clickCreateRoleButtonInvalid() {
		createRoleButton.click();
		return new RoleCreatePage(driver);
	}
	
	public RolesIndexPage clickBackToIndexLink() {
		backToRolesLink.click();
		return new RolesIndexPage(driver);	
	}
	
	public boolean getCanViewJobStatusesValue() {
		return driver.findElementById("canViewJobStatusesTrue").isSelected();
	}
	
	public boolean getPermissionValue(String permissionName) {
		return driver.findElementById(permissionName + "True").isSelected();
	}
	
	public RoleCreatePage setPermissionValue(String permissionName, boolean value) {
		
		String target = value ? "True" : "False";
		driver.findElementById(permissionName + target).click();
		
		return this;
	}
}
