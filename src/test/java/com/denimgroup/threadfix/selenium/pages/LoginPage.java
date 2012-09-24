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

public class LoginPage extends BasePage {

	static String url = "http://localhost/threadfix/";
	private WebElement usernameField;
	private WebElement passwordField;
	private WebElement loginButton;

	public LoginPage(WebDriver webdriver) {
		super(webdriver);
		
		String maybeUrl = System.getProperty("url");
		if (maybeUrl != null) {
			url = maybeUrl;
		}
		
		webdriver.get(url);
		webdriver.get(url);
		usernameField = driver.findElementById("username");
		passwordField = driver.findElementById("password");
		loginButton = driver.findElementById("login");
	}
	
	public static LoginPage open(WebDriver webdriver) {
		return new LoginPage(webdriver);
	}
	
	public OrganizationIndexPage login(String user, String password) {
		setUsername(user);
		setPassword(password);
		clickLogin();
		return new OrganizationIndexPage(driver);
	}
	
	private void setUsername(String user) {
		usernameField.sendKeys(user);
	}
	
	private void setPassword(String password) {
		passwordField.sendKeys(password);
	}
	
	private OrganizationIndexPage clickLogin() {
		loginButton.click();
		return new OrganizationIndexPage(driver);
	}
}
