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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class UserIndexPage extends BasePage {
	
	private WebElement addUserLink;
	
//	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> names = new ArrayList<>();
	private List<WebElement> editLinks = new ArrayList<>();

	public int getNumRows() {
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public UserIndexPage(WebDriver webdriver) {
		super(webdriver);

		addUserLink = driver.findElementById("newUserModalLink");
		
		for (int i = 1; i <= getNumRows(); i++) {
//			deleteButtons.add(driver.findElementById("delete" + i));
			names.add(driver.findElementById("name" + i));
			editLinks.add(driver.findElementById("editUserModal" + i +"Link"));
			//edit permissions buttons
		}
	}
	
	private int getIndex(String roleName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}
	
	public UserIndexPage clickDeleteButton(String roleName) {
		clickEditLink(roleName);
		sleep(500);
		driver.findElementById("delete"+(getIndex(roleName)+1)).click();
		handleAlert();
		return new UserIndexPage(driver);
	}
	
	public LoginPage clickDeleteButtonSameUser(String roleName) {
		clickEditLink(roleName);
		sleep(500);
		driver.findElementById("delete"+(getIndex(roleName)+1)).click();
		handleAlert();
		return new LoginPage(driver);
	}
	
	public UserPermissionsPage clickEditPermissions(String name){
		driver.findElementById("editPermissions"+(getIndex(name)+1)).click();
		return new UserPermissionsPage(driver);
	}

	public UserIndexPage clickAddUserLink() {
		addUserLink.click();
		waitForElement(driver.findElementById("nameAndPasswordForm"));
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterName(String name,String oldName){
		if(oldName == null){
			driver.findElementById("nameInput").clear();
			driver.findElementById("nameInput").sendKeys(name);
		}else{
			driver.findElementById("nameInput"+(getIndex(oldName)+1)).clear();
			driver.findElementById("nameInput"+(getIndex(oldName)+1)).sendKeys(name);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterPassword(String password,String oldName){
		if(oldName == null){
			driver.findElementById("passwordInput").clear();
			driver.findElementById("passwordInput").sendKeys(password);
		}else{
			driver.findElementById("passwordInput"+(getIndex(oldName)+1)).clear();
			driver.findElementById("passwordInput"+(getIndex(oldName)+1)).sendKeys(password);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage enterConfirmPassword(String password,String oldName){
		if(oldName == null){
			driver.findElementById("passwordConfirmInput").clear();
			driver.findElementById("passwordConfirmInput").sendKeys(password);
		}else{
			driver.findElementById("passwordConfirmInput"+(getIndex(oldName)+1)).clear();
			driver.findElementById("passwordConfirmInput"+(getIndex(oldName)+1)).sendKeys(password);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickLDAP(String oldName){
		if(oldName == null){
			driver.findElementById("newUserModal").findElement(By.id("isLdapUserCheckbox")).click();
		}else{
			driver.findElementById("isLdapUserCheckbox"+(getIndex(oldName)+1)).click();
		}
		return new UserIndexPage(driver);
	}
	
	public boolean isLDAPSelected(String oldName){
		return driver.findElementById("isLdapUserCheckbox"+(getIndex(oldName)+1)).isSelected();
	}
	
	public UserIndexPage clickGlobalAccess(String oldName){
		if(oldName == null){
			driver.findElementById("hasGlobalGroupAccessCheckbox" + (getIndex(oldName)+1)).click();
		}else{
			driver.findElementById("hasGlobalGroupAccessCheckbox" + (getIndex(oldName)+1)).click();
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage chooseRoleForGlobalAccess(String role,String oldName){
		if(oldName == null){
			new Select(driver.findElementById("roleSelect")).selectByVisibleText(role);
		}else{
			new Select(driver.findElementById("roleSelect"+(getIndex(oldName)+1))).selectByVisibleText(role);
		}
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickAddNewUserBtn(){
		driver.findElementsById("addUserButton").get(getNumRows()).click();
		sleep(1000);
//		waitForInvisibleElement(driver.findElementById("newUserModal"));
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickAddNewUserBtnInvalid(){
		sleep(500);
		driver.findElementsById("addUserButton").get(getNumRows()).click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	
	public UserIndexPage clickUpdateUserBtn(String name){
		driver.findElementsById("addUserButton").get(getIndex(name)).click();
//		waitForInvisibleElement(driver.findElementById("editUserModal"+(getIndex(name)+1)));
		sleep(1000);
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickUpdateUserBtnInvalid(String name){
		sleep(500);
		driver.findElementsById("addUserButton").get(getIndex(name)).click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	public String getGlobalAccessRole(String name){
		return new Select(driver.findElementById("roleSelect"+(getIndex(name)+1))).getAllSelectedOptions().get(0).getText().trim(); 
	}
	
	public boolean isUserNamePresent(String userName) {
		return getIndex(userName) != -1;
	}
	
	public UserIndexPage clickEditLink(String roleName) {
		editLinks.get(getIndex(roleName)).click();
		return new UserIndexPage(driver);
	}
	
	public boolean isSuccessDisplayed(String name){
		return driver.findElementByClassName("alert-success").getText().contains(name);
	}
	
	public String getNameError(){
		return driver.findElementById("name.errors").getText().trim();
	}
	
	public String getPasswordError(){
		return driver.findElementById("password.errors").getText().trim();
	}
	
	public UserIndexPage clickCancel(String name){
		driver.findElementsByClassName("modal-footer").get(getIndex(name)).findElement(By.className("btn")).click();
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
			return new Select(driver.findElementById("roleSelect"+(getIndex(oldName)+1))).getFirstSelectedOption().getText().contains(role);
		}

	}
	
	public boolean isGlobalAccessSelected(String oldName){
		return driver.findElementById("hasGlobalGroupAccessCheckbox" + (getIndex(oldName)+1)).isSelected();
	}
}
