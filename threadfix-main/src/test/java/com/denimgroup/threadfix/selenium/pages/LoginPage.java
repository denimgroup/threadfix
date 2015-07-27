////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.selenium.utils.LoginFailedException;
import org.openqa.selenium.*;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.net.URL;

public class LoginPage extends BasePage {

	public static String url = System.getProperty("LOGIN_URL");

	public LoginPage(WebDriver webdriver) {
		super(webdriver);

		String maybeUrl = System.getProperty("url");
		if (maybeUrl != null) {
			url = maybeUrl;
		}

		webdriver.get(url);

        if (!webdriver.getPageSource().contains("id=\"username\"")) {
            System.out.println("Something went wrong.");
            System.out.println("Retrieving " + url);
            System.out.println("Got " + webdriver.getPageSource());

            System.out.println("Going to attempt to add the cert.");
        }

		if(webdriver instanceof InternetExplorerDriver){
			driver.get("javascript:document.getElementById('overridelink').click();");
		}
	}
	
	/*----------------perform functions----------------*/
	public static LoginPage open(WebDriver webdriver) {
		return new LoginPage(webdriver);
	}

    public DashboardPage defaultLogin() {
        return login("user", "password");
    }
	
    public DashboardPage login(String user, String password) {
        setUsername(user).setPassword(password);

        driver.findElementById("login").click();

//        if (!isElementPresent("tab-dashboard")) {
//            driver.findElementById("password").sendKeys(Keys.ENTER);
//        }

        try {
            WebDriverWait waitForHeader = new WebDriverWait(driver, 45);
            waitForHeader.until(ExpectedConditions.presenceOfElementLocated(By.id("orgHeader")));
        } catch (TimeoutException e) {
            takeScreenShot();
            throw new LoginFailedException("Login Failed", e);
        }

        return new DashboardPage(driver);
    }
	
	public LoginPage loginInvalid(String user, String password) {
		setUsername(user).setPassword(password);
		driver.findElementById("login").click();

        if (!isElementPresent("loginError")) {
            driver.findElementById("login").click();
        }

		sleep(3000);
		return new LoginPage(driver);
	}
	
	/*----------------get Functions----------------*/
	public boolean isLoginErrorPresent(){
		return driver.findElementById("loginError").getText().trim().equals("Error: Username or Password incorrect");
	}
	
	public boolean isLoggedOut(){
		return driver.getCurrentUrl().contains("login");
	}
	
	public boolean isUserNameFieldPresent(){
		return driver.findElementById("username").isDisplayed();
	}
	
	public String getUserNameInput(){
		return driver.findElementById("username").getAttribute("value");
	}
	
	public boolean isPasswordFieldPresent(){
		return driver.findElementById("password").isDisplayed();
	}
	
	public String getLoginInput(){
		return driver.findElementById("password").getAttribute("value");
	}
	
	public boolean isLoginButtonPresent(){
		return driver.findElementById("login").isDisplayed();
	}
	
	public boolean isLoginButtonClickable(){
        return isClickable("login");
	}

	/*----------------set functions----------------*/
	public LoginPage setUsername(String user) {
        WebElement usernameField = driver.findElementById("username");
        usernameField.sendKeys(user);

        if (usernameField.getAttribute("value").equals("")) {
            System.out.println("Username field was empty, re-entering username.");
            usernameField.sendKeys(user);
        }

        return this;
	}
	
	public LoginPage setPassword(String password) {
		WebElement passwordField = driver.findElementById("password");
        passwordField.sendKeys(password);

        if (passwordField.getAttribute("value").equals("")) {
            System.out.println("Password field was empty, re-entering password.");
            passwordField.sendKeys(password);
        }

        return this;
	}
	
}
