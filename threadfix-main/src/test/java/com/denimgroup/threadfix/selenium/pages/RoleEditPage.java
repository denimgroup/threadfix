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

public class RoleEditPage extends BasePage {
	
	private WebElement updateRoleButton;
	private WebElement backToRolesButton;
	private WebElement nameInput;

	public RoleEditPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("displayName");
		updateRoleButton = driver.findElementById("updateRoleButton");
		backToRolesButton = driver.findElementById("backToRolesButton");
	}

	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}

	public RoleEditPage setNameInput(String name) {
		nameInput.clear();
		nameInput.sendKeys(name);
		return this;
	}
	
	public RolesIndexPage clickUpdateRoleButton() {
		updateRoleButton.click();
		return new RolesIndexPage(driver);
	}
	
	public RoleEditPage clickUpdateRoleButtonInvalid() {
		updateRoleButton.click();
		return new RoleEditPage(driver);
	}
	
	public RolesIndexPage clickBackToIndexLink() {
		backToRolesButton.click();
		return new RolesIndexPage(driver);	
	}
	
	public String getPermissionError(String permissionName) {
		return driver.findElementById(permissionName + "Error").getText();
	}
	
	public boolean getPermissionValue(String permissionName) {
		return driver.findElementById(permissionName + "True").isSelected();
	}
	
	public RoleEditPage setPermissionValue(String permissionName, boolean value) {
		String target = value ? "True" : "False";
		driver.findElementById(permissionName + target).click();
		
		return this;
	}
}
