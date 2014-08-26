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

import com.denimgroup.threadfix.selenium.utils.LoginFailedException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.time.DateFormatUtils;
import org.openqa.selenium.*;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.File;
import java.io.IOException;
import java.util.Date;

public class LoginPage extends BasePage {

	public static String url = "http://localhost:8080/threadfix/";
    //public static String url = "https://localhost:8443/threadfix/";
    //public static String url = "http://jenkins-slave5:8080/threadfix/";

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
	
	/*public DashboardPage login(String user, String password) {
		return setUsername(user).setPassword(password).clickLogin();
	}*/

    public DashboardPage login(String user, String password) {
        setUsername(user).setPassword(password);

        driver.findElementById("login").click();

        if (isElementPresent("login")) {

            if (driver.findElementById("username").getAttribute("value").equals("")) {
                System.out.println("Username field was empty, re-entering username.");
                driver.findElementById("username").sendKeys(user);
            }

            driver.findElementById("password").sendKeys(Keys.ENTER);
        }

        try {
            WebDriverWait waitForHeader = new WebDriverWait(driver, 60);
            waitForHeader.until(ExpectedConditions.presenceOfElementLocated(By.id("orgHeader")));
        } catch (TimeoutException e) {
            File screenShot = driver.getScreenshotAs(OutputType.FILE);
            String fileName = DateFormatUtils.format(new Date(), "HH-MM-SS");

            try {
                FileUtils.copyFile(screenShot, new File(System.getProperty("SCREENSHOT_BASE") + fileName + ".jpg"));
                System.out.println("Saving screen shot with filename: " + System.getProperty("SCREENSHOT_BASE") + fileName + ".jpg");
            } catch (IOException f) {
                System.err.println("Unable to save file.\n" + f.getMessage());
            }

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
		driver.findElementById("username").sendKeys(user);
        return this;
	}
	
	public LoginPage setPassword(String password) {
		driver.findElementById("password").sendKeys(password);
        return this;
	}
	
	/*----------------click Functions----------------*/
	private DashboardPage clickLogin() {
        WebElement passwordField = driver.findElementById("password");
        driver.findElementById("login").click();

        if (isElementPresent("login")) {
            passwordField.sendKeys(Keys.ENTER);

            if (isElementPresent("loginError")) {
                throw new LoginFailedException("Login Failed, username and password were not accepted.");
            }
        }

        try {
            WebDriverWait waitForHeader = new WebDriverWait(driver, 60);
            waitForHeader.until(ExpectedConditions.presenceOfElementLocated(By.id("orgHeader")));
        } catch (TimeoutException e) {
            File screenShot = driver.getScreenshotAs(OutputType.FILE);
            String fileName = DateFormatUtils.format(new Date(), "HH-MM-SS");

            try {
                FileUtils.copyFile(screenShot, new File(System.getProperty("SCREENSHOT_BASE") + fileName + ".jpg"));
                System.out.println("Saving screen shot with filename: " + System.getProperty("SCREENSHOT_BASE") + fileName + ".jpg");
            } catch (IOException f) {
                System.err.println("Unable to save file.\n" + f.getMessage());
            }

            throw new LoginFailedException("Login Failed", e);
        }

		return new DashboardPage(driver);
	}

}
