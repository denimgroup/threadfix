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

public class UserChangePasswordPage extends BasePage {
	private WebElement currentPassword;
	private WebElement newPassword;
	private WebElement confirmPassword;
	private WebElement updatePasswordButton;
	private WebElement backToConfigurationLink;

	public UserChangePasswordPage(WebDriver webDriver) {
		super(webDriver);
		currentPassword = driver.findElementById("currentPasswordInput");
		newPassword = driver.findElementById("passwordInput");
		confirmPassword = driver.findElementById("passwordConfirmInput");
		updatePasswordButton = driver.findElementById("updateUserButton");
	}

	public static UserChangePasswordPage open(WebDriver webdriver) {
		return new UserChangePasswordPage(webdriver);
	}

	public UserChangePasswordPage setCurrentPassword(String currentPasswordString) {
		currentPassword.clear();
		currentPassword.sendKeys(currentPasswordString);
		return this;
	}

	public UserChangePasswordPage setNewPassword(String newPasswordString) {
		newPassword.clear();
		newPassword.sendKeys(newPasswordString);
		return this;
	}

	public UserChangePasswordPage setConfirmPassword(String confirmPasswordString) {
		confirmPassword.clear();
		confirmPassword.sendKeys(confirmPasswordString);
		return this;
	}

	public UserChangePasswordPage clickUpdate() {
		updatePasswordButton.click();
		return new UserChangePasswordPage(driver);
	}
	
	public UserChangePasswordPage clickUpdateInvalid() {
		updatePasswordButton.click();
		return new UserChangePasswordPage(driver);
	}

	public ConfigurationIndexPage clickBackToListLink() {
		backToConfigurationLink.click();
		return new ConfigurationIndexPage(driver);
	}
	
	public String getErrorText(String path) {
        String toReturn = driver.findElementById(path).getText();
		return toReturn;
	}

    public String getPasswordRequiredError() {
        return driver.findElementById("passwordRequiredError").getText();
    }
	
	public boolean isSaveSuccessful(){
		return driver.findElementByClassName("alert-success").getText().trim().contains("The password change was successful");
	}
	
}