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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class UserIndexPage extends BasePage {


    public UserIndexPage(WebDriver webdriver) {
        super(webdriver);
    }

    public UserIndexPage clickDeleteButton(String roleName) {
		clickEditLink(roleName);
		sleep(500);
		driver.findElementById("delete" + (roleName)).click();
		handleAlert();
		return new UserIndexPage(driver);
	}

    public UserIndexPage clickDelete(String user){
        driver.findElementById("delete" + user).click();
        handleAlert();
        return new UserIndexPage(driver);
    }
	
	public UserPermissionsPage clickEditPermissions(String name){
		driver.findElementById("editPermissions" + (name)).click();
		sleep(500);
		return new UserPermissionsPage(driver);
	}

	public UserIndexPage clickAddUserLink() {
		driver.findElementById("newUserModalLink").click();
		waitForElement(driver.findElementById("nameAndPasswordForm"));
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickCloseAddUserModal(){
		driver.findElementById("newUserModal").findElement(By.className("modal-footer")).findElements(By.className("btn")).get(0).click();
		sleep(1000);
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterName(String name,String oldName){
		if(oldName == null){
			driver.findElementById("nameInput").clear();
			driver.findElementById("nameInput").sendKeys(name);
		}else{
			driver.findElementById("nameInput"+(oldName)).clear();
			driver.findElementById("nameInput"+(oldName)).sendKeys(name);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterPassword(String password,String oldName){
		if(oldName == null){
			driver.findElementById("passwordInput").clear();
			driver.findElementById("passwordInput").sendKeys(password);
		}else{
			driver.findElementById("passwordInput"+(oldName)).clear();
			driver.findElementById("passwordInput"+(oldName)).sendKeys(password);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterConfirmPassword(String password,String oldName){
		if(oldName == null){
			driver.findElementById("passwordConfirmInput").clear();
			driver.findElementById("passwordConfirmInput").sendKeys(password);
		}else{
			driver.findElementById("passwordConfirmInput"+(oldName)).clear();
			driver.findElementById("passwordConfirmInput"+(oldName)).sendKeys(password);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickLDAP(String oldName){
		if(oldName == null){
			driver.findElementById("newUserModal").findElement(By.id("isLdapUserCheckbox")).click();
		}else{
			driver.findElementById("isLdapUserCheckbox"+(oldName)).click();
		}
		return new UserIndexPage(driver);
	}
	
	public boolean isLDAPSelected(String oldName){
		return driver.findElementById("isLdapUserCheckbox"+(oldName)).isSelected();
	}
	
	public UserIndexPage clickGlobalAccess(String oldName){
		if(oldName == null){
			driver.findElementById("hasGlobalGroupAccessCheckbox").click();
		}else{
			driver.findElementById("hasGlobalGroupAccessCheckbox" + (oldName)).click();
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage chooseRoleForGlobalAccess(String role,String oldName){
		if(oldName == null){
			new Select(driver.findElementById("roleSelect")).selectByVisibleText(role);
		}else{
			new Select(driver.findElementById("roleSelect"+(oldName))).selectByVisibleText(role);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickAddNewUserBtn(){
		driver.findElementById("addUserButton").click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickAddNewUserBtnInvalid(){
		sleep(500);
		driver.findElementById("addUserButton").click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	
	public UserIndexPage clickUpdateUserBtn(String name){
		driver.findElementById("addUserButton" + name).click();
		sleep(1000);
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickUpdateUserBtnInvalid(String name){
		sleep(500);
		driver.findElementById("addUserButton").click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	public String getGlobalAccessRole(String name){
		return new Select(driver.findElementById("roleSelect"+(name))).getAllSelectedOptions().get(0).getText().trim();
	}
	
	public boolean isUserNamePresent(String userName) {
        return driver.findElementsById("editUserModal" + userName + "Link").size() != 0;
	}
	
	public UserIndexPage clickEditLink(String roleName) {
		driver.findElementById("editUserModal"+roleName+"Link").click();
		sleep(1000);
		return new UserIndexPage(driver);
	}
	
	public boolean isSuccessDisplayed(String name){
		return driver.findElementByClassName("alert-success").getText().contains(name);
	}
	
	public String getNameError(){
		return driver.findElementById("name.errors").getText().trim();
	}
	
	public String getPasswordError(){
		return driver.findElementById("passwordInputErrorSpan").getText().trim();
	}

    public String getPasswordMatchError(){
        return driver.findElementById("passwordInputError").getText().trim();
    }
	
	public UserIndexPage clickCancel(String name){
		driver.findElementByClassName("modal-footer").click();
		sleep(1000);
		return new UserIndexPage(driver);	
	}
	
	public boolean isGlobalAccessErrorPresent(){
		return driver.findElementById("hasGlobalGroupAccessErrors").getText().contains("This would leave users unable to access the user management portion of ThreadFix.");
	}
	
	public boolean isRoleSelected(String oldName,String role){
		sleep(1000);
		if(oldName == null){
			return new Select(driver.findElementById("roleSelect")).getFirstSelectedOption().getText().contains(role);
		}else{
			return new Select(driver.findElementById("roleSelect"+(oldName))).getFirstSelectedOption().getText().contains(role);
		}

	}
	
	public boolean isGlobalAccessSelected(String oldName){
		return driver.findElementById("hasGlobalGroupAccessCheckbox" + (oldName)).isSelected();
	}
}
