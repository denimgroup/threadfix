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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.ie.InternetExplorerDriver;

public class LoginPage extends BasePage {

	static String url = "http://localhost:8080/threadfix/";
	private WebElement rememberCheckbox;

	public LoginPage(WebDriver webdriver) {
		super(webdriver);
		
		String maybeUrl = System.getProperty("url");
		if (maybeUrl != null) {
			url = maybeUrl;
		}
		
		webdriver.get(url);
		if(webdriver instanceof InternetExplorerDriver){
			driver.get("javascript:document.getElementById('overridelink').click();");
		}
		//rememberCheckbox = driver.findElementById("checkbox");
	}
	
	public static LoginPage open(WebDriver webdriver) {
		return new LoginPage(webdriver);
	}
	
	public DashboardPage login(String user, String password) {
		return setUsername(user).setPassword(password).clickLogin();
	}
	
	public LoginPage loginInvalid(String user, String password) {
		setUsername(user).setPassword(password);
		driver.findElementById("login").click();
		return new LoginPage(driver);
	}
	
	public boolean isloginError(){
		return driver.findElementById("loginError").getText().trim().equals("Error: Username or Password incorrect");
	}

	public LoginPage checkRememberCheckbox() {
		rememberCheckbox.click();
		return this;
	}
	
	public boolean isLoggedOut(){
		return driver.getCurrentUrl().contains("login");
	}
	
	private LoginPage setUsername(String user) {
		driver.findElementById("username").sendKeys(user);
		return this;
	}
	
	private LoginPage setPassword(String password) {
		driver.findElementById("password").sendKeys(password);
		return this;
	}
	
	private DashboardPage clickLogin() {
		driver.findElementById("login").click();
		waitForElement(driver.findElementById("main-content"));
		return new DashboardPage(driver);
	}
}
