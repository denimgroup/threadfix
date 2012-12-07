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

import org.openqa.selenium.Alert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RemoteProviderCredentialsPage extends BasePage {
	private WebElement userNameInput;
	private WebElement passwordInput;
	private WebElement apiKeyInput;
	private WebElement saveButton;
	private WebElement backToIndexLink;

	public RemoteProviderCredentialsPage(WebDriver webDriver) {
		super(webDriver);

		saveButton = driver.findElementById("submitButton");
		backToIndexLink = driver.findElementByLinkText("Back to Index");
	}

	public RemoteProviderCredentialsPage setUserName(String username) {
		userNameInput = driver.findElementById("usernameInput");
		userNameInput.clear();
		userNameInput.sendKeys(username);
		return this;
	}

	public RemoteProviderCredentialsPage setPassword(String password) {
		passwordInput = driver.findElementById("passwordInput");
		passwordInput.clear();
		passwordInput.sendKeys(password);
		return this;
	}

	public RemoteProviderCredentialsPage setAPI(String apiKey) {
		apiKeyInput = driver.findElementById("apiKeyInput");
		apiKeyInput.clear();
		apiKeyInput.sendKeys(apiKey);
		return this;
	}
	
	public RemoteProvidersIndexPage clickBackButton() {
		backToIndexLink.click();
		return new RemoteProvidersIndexPage(driver);
	}

	public RemoteProvidersIndexPage clickSave(boolean showsWarning) {
		saveButton.click();

		if (showsWarning) {
			Alert alert = driver.switchTo().alert();
			alert.accept();
		}

		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage fillAllClickSaveUsernamePassword(String userName, String password, boolean showsWarning) {
		fillRequired(userName, password);
		return clickSave(showsWarning);
	}

	public RemoteProviderCredentialsPage fillRequired(String uName, String Pwd) {
		setUserName(uName);
		setPassword(Pwd);
		return this;
	}
}
