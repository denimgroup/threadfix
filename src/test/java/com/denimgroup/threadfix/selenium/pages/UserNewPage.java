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

public class UserNewPage extends BasePage {

	private WebElement nameInput;
	private WebElement passwordInput;
	private WebElement passwordConfirmInput;
	private WebElement addUserButton;
	private WebElement cancelLink;
	
	public UserNewPage(WebDriver webdriver) {
		super(webdriver);
		
		nameInput = driver.findElementById("nameInput");
		passwordInput = driver.findElementById("passwordInput");
		passwordConfirmInput = driver.findElementById("passwordConfirmInput");
		addUserButton = driver.findElementById("addUserButton");
		cancelLink = driver.findElementById("cancelLink");
	}
	
	public String getNameInput(){
		return nameInput.getAttribute("value");
	}

	public UserNewPage setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
		return this;
	}
	
	public String getPasswordInput(){
		return passwordInput.getAttribute("value");
	}

	public UserNewPage setPasswordInput(String text){
		passwordInput.clear();
		passwordInput.sendKeys(text);
		return this;
	}

	public String getPasswordConfirmInput(){
		return passwordConfirmInput.getAttribute("value");
	}

	public UserNewPage setPasswordConfirmInput(String text){
		passwordConfirmInput.clear();
		passwordConfirmInput.sendKeys(text);
		return this;
	}
	
	public UserIndexPage clickAddUserButton() {
		addUserButton.click();
		return new UserIndexPage(driver);
	}

	public UserNewPage clickAddUserButtonInvalid() {
		addUserButton.click();
		return new UserNewPage(driver);
	}
	
	public UserIndexPage clickCancelLink() {
		cancelLink.click();
		return new UserIndexPage(driver);
	}
	
	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getRoleError() {
		return driver.findElementById("role.id.errors").getText();
	}
	
	public String getPasswordError() {
		return driver.findElementById("password.errors").getText();
	}
}
