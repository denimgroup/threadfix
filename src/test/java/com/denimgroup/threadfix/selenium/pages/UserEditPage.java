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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class UserEditPage extends BasePage {
	
	private WebElement nameInput;
	private WebElement passwordInput;
	private WebElement passwordConfirmInput;
	private Select roleSelect;
	private WebElement updateUserButton;
	private WebElement cancelLink;

	public UserEditPage(WebDriver webdriver) {
		super(webdriver);

		nameInput = driver.findElementById("nameInput");
		passwordInput = driver.findElementById("passwordInput");
		passwordConfirmInput = driver.findElementById("passwordConfirmInput");
		roleSelect = new Select(driver.findElementById("roleSelect"));
		updateUserButton = driver.findElementById("updateUserButton");
		cancelLink = driver.findElementById("cancelLink");
	}
	
	public String getNameInput(){
		return nameInput.getAttribute("value");
	}

	public void setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
	}
	
	public String getPasswordInput(){
		return passwordInput.getAttribute("value");
	}

	public void setPasswordInput(String text){
		passwordInput.clear();
		passwordInput.sendKeys(text);
	}

	public String getPasswordConfirmInput(){
		return passwordConfirmInput.getAttribute("value");
	}

	public void setPasswordConfirmInput(String text){
		passwordConfirmInput.clear();
		passwordConfirmInput.sendKeys(text);
	}

	public String getRoleSelect(){
		return roleSelect.getFirstSelectedOption().getText();
	}

	public void setRoleSelect(String text){
		roleSelect.selectByVisibleText(text);
	}

	public UserIndexPage clickUpdateUserButton() {
		updateUserButton.click();
		return new UserIndexPage(driver);
	}
	
	public UserEditPage clickUpdateUserButtonInvalid() {
		updateUserButton.click();
		return new UserEditPage(driver);
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
