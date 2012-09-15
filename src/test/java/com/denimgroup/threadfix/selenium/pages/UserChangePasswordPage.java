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

public class UserChangePasswordPage extends BasePage {
	private WebElement currentPassword;
	private WebElement newPassword;
	private WebElement confirmPassword;
	private WebElement updatePasswordBtn;
	private WebElement backtoConfigurationLink;

	public UserChangePasswordPage(WebDriver webDriver) {
		super(webDriver);
		currentPassword = driver.findElementById("currentPasswordInput");
		newPassword = driver.findElementById("passwordInput");
		confirmPassword = driver.findElementById("passwordConfirmInput");
		updatePasswordBtn = driver.findElementById("updateUserButton");
		backtoConfigurationLink = driver.findElementById("cancelLink");
	}

	public static UserChangePasswordPage open(WebDriver webdriver) {
		return new UserChangePasswordPage(webdriver);
	}

	// public UserChangePasswordPage change(String currentPwd, String newPwd,
	// String confirmPwd) {
	// setcurrentPwd(currentPwd);
	// setnewPwd(newPwd);
	// setconfirmPwd(confirmPwd);
	// clickUpdate();
	// sleep(1000);
	// }

	public void setcurrentPwd(String currentPwd) {
		currentPassword.clear();
		currentPassword.sendKeys(currentPwd);
	}

	public void setnewPwd(String newPwd) {
		newPassword.clear();
		newPassword.sendKeys(newPwd);
	}

	public void setconfirmPwd(String confirmPwd) {
		confirmPassword.clear();
		confirmPassword.sendKeys(confirmPwd);
	}

	public void clickUpdate() {
		updatePasswordBtn.click();
		sleep(1000);
	}

	public void clickBackToListLink() {
		backtoConfigurationLink.click();
		sleep(1000);
	}

	public void fillAllClickSave(String CurrentPwd, String NewPwd,
			String ConfirmPwd) {
		fillRequired(CurrentPwd, NewPwd, ConfirmPwd);
		setcurrentPwd(CurrentPwd);
		setnewPwd(NewPwd);
		setconfirmPwd(ConfirmPwd);
		updatePasswordBtn.click();
		sleep(1000);
	}

	public void fillRequired(String CurrentPwd, String NewPwd, String ConfirmPwd) {
		setcurrentPwd(CurrentPwd);
		setnewPwd(NewPwd);
		setconfirmPwd(ConfirmPwd);
	}

}