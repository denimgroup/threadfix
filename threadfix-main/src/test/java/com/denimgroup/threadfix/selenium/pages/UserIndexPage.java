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

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import java.util.List;

public class UserIndexPage extends BasePage {

    public UserIndexPage(WebDriver webdriver) {
        super(webdriver);
    }

    /*------------------------------------ Action Methods ------------------------------------*/

    public UserIndexPage clickDeleteButton(String roleName) {
		clickUserLink(roleName);
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

    public UserIndexPage deleteTeamRole(String teamName, String roleName) {
        driver.findElementById("deleteAppMap" + teamName + "all" + roleName).click();
        handleAlert();
        return new UserIndexPage(driver);
    }

    //TODO: Delete this method after updating user tests.
	public UserPermissionsPage clickEditPermissions(String name){
		driver.findElementById("editPermissions" + name).click();
		//waitForElement(driver.findElementById("addPermissionButton"));
        sleep(1000);
        return new UserPermissionsPage(driver);
	}

	public UserIndexPage clickAddUserLink() {
		driver.findElementById("newUserModalLink").click();
		waitForElement(driver.findElementById("submit"));
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickCloseAddUserModal(){
		driver.findElementById("newUserModal").findElement(By.className("modal-footer")).findElements(By.className("btn")).get(0).click();
		sleep(1000);
		return new UserIndexPage(driver);
	}

    public UserIndexPage setName(String username) {
        WebElement nameField = driver.findElementById("name");
        nameField.clear();
        nameField.sendKeys(username);
        return this;
    }

    public UserIndexPage setDisplayName(String displayName) {
        driver.findElementByCssSelector("input#displayName").clear();
        driver.findElementByCssSelector("input#displayName").sendKeys(displayName);
        return this;
    }

    public UserIndexPage setPassword(String password) {
        driver.findElementById("password").clear();
        driver.findElementById("password").sendKeys(password);
        return this;
    }

    public UserIndexPage setConfirmPassword(String password) {
        driver.findElementById("confirm").clear();
        driver.findElementById("confirm").sendKeys(password);
        return this;
    }

    public UserIndexPage toggleLDAP() {
        driver.findElementById("isLdapUserCheckbox").click();
        return this;
    }

    public UserIndexPage toggleGlobalAccess() {
        driver.findElementById("hasGlobalGroupAccessCheckbox").click();
        return this;
    }

    public UserIndexPage chooseRoleForGlobalAccess(String role) {
        driver.findElementById("roleSelect").sendKeys(role);
        return this;
    }
	
	public UserIndexPage clickAddNewUserBtn() {
        waitForElement(driver.findElementById("submit"));
		driver.findElementById("submit").click();
		sleep(5000);
		return new UserIndexPage(driver);
	}

    public LoginPage clickLogOut() {
        clickUserTab();
        driver.findElementById("logoutLink").click();
        return new LoginPage(driver);
    }
	
	public UserIndexPage clickAddNewUserBtnInvalid(){
		sleep(500);
		driver.findElementById("submit").click();
		sleep(500);
		return new UserIndexPage(driver);
	}
	
	
	public UserIndexPage clickUpdateUserBtn(){
		driver.findElementById("submit").click();
		sleep(1000);
		return new UserIndexPage(driver);
	}

    public UserIndexPage expandTeamName() {
        driver.findElementById("orgSelect").click();
        return new UserIndexPage(driver);
    }

    public boolean compareOrderOfSelector(String firstTeam, String secondTeam) {
        int firstTeamValue;
        int secondTeamValue;

        this.setTeam(firstTeam);
        firstTeamValue = Integer.parseInt(new Select(driver.findElementById("orgSelect")).getFirstSelectedOption().getAttribute("value"));

        this.setTeam(secondTeam);
        secondTeamValue = Integer.parseInt(new Select(driver.findElementById("orgSelect")).getFirstSelectedOption().getAttribute("value"));

        return secondTeamValue > firstTeamValue;
    }
	
	public UserIndexPage clickUpdateUserBtnInvalid(String name){
		waitForElement(driver.findElementById("submit"));
		driver.findElementById("submit").click();
		return new UserIndexPage(driver);
	}

    public UserIndexPage clickSaveChanges() {
        driver.findElementById("submit").click();
        return new UserIndexPage(driver);
    }
	
	public String getGlobalAccessRole(){
		return driver.findElementById("roleSelect").getText();
	}

    public UserIndexPage clickUserLink(String userName) {
        driver.findElementByXPath("//li[@id=\'lastYearReport\']/a[text()=\'" + userName + "\']").click();
        waitForElement(driver.findElementById("submit"));
        return new UserIndexPage(driver);
    }

    public UserIndexPage clickSaveMap() {
        driver.findElementByXPath("//button[text()='Save Map']").click();
        return new UserIndexPage(driver);
    }

    public UserIndexPage clickSaveEdits() {
        driver.findElementByXPath("//button[text()='Save Edits']").click();
        return new UserIndexPage(driver);
    }

    public UserIndexPage clickCloseButton() {
        driver.findElementByXPath("//a[text()='Close']").click();
        return new UserIndexPage(driver);
    }
	
	public String getNameError(){
        String returnval;
		returnval = driver.findElementById("name.errors").getText().trim();
        return returnval;
	}
    public String getRequiredNameError(){
        String returnval;
        returnval = driver.findElementById("name.errors.required").getText().trim();
        return returnval;
    }
	
	public String getPasswordLengthError(){
		return driver.findElementById("password.error.length").getText().trim();
	}

    public String getPasswordMatchError(){
        return driver.findElementById("password.error.match").getText().trim();
    }

    public String getPasswordRequiredError() {
        return driver.findElementById("password.error.required").getText().trim();
    }

    public String getConfirmPasswordRequiredError() {
        return driver.findElementById("confirmPassword.error").getText().trim();
    }
	
	public UserIndexPage clickCancel(String name){
		driver.findElementByClassName("modal-footer").click();
		sleep(1000);
		return new UserIndexPage(driver);	
	}

    public UserIndexPage createUser(String user, String disp, String pass) {
        clickAddUserLink();
        setName(user);
        setDisplayName(disp);
        setPassword(pass);
        setConfirmPassword(pass);
        clickAddNewUserBtn();
        return new UserIndexPage(driver);
    }

    public UserIndexPage editUser(String user, String newName, String disp, String pass) {
        clickUserLink(user);
        setName(newName);
        setDisplayName(disp);
        setPassword(pass);
        setConfirmPassword(pass);
        clickUpdateUserBtn();
        return new UserIndexPage(driver);
    }

    public UserIndexPage clickAddTeamRole() {
        driver.findElementById("addPermissionButton").click();
        return new UserIndexPage(driver);
    }

    public UserIndexPage clickAddApplicationRole() {
        driver.findElementById("addApplicationRoleButton").click();
        return new UserIndexPage(driver);
    }

    public UserIndexPage setTeam(String team) {
        try {
            new Select(driver.findElementById("orgSelect")).selectByVisibleText(team);
        } catch (NoSuchElementException e) {
            driver.findElementByLinkText("Close").click();
            this.refreshPage();
            sleep(2000);
            this.clickAddTeamRole();
            this.setTeamNoCatch(team);
        }
        return this;
    }

    public UserIndexPage setTeamNoCatch(String teamName) {
        new Select(driver.findElementById("orgSelect")).selectByVisibleText(teamName);
        return this;
    }

    public UserIndexPage setTeamRole(String role) {
        new Select(driver.findElementById("roleSelectTeam")).selectByVisibleText(role);
        return this;
    }

    public UserIndexPage setApplicationRole(String app, String role) {
        new Select(driver.findElementById("roleSelectApp" + app)).selectByVisibleText(role);
        return this;
    }

    public UserIndexPage editSpecificPermissions(String teamName, String appName, String role) {
        driver.findElementById("editAppMap" + teamName + appName + role).click();
        return new UserIndexPage(driver);
    }

    /*----------------------------------- Boolean Methods -----------------------------------*/

    public boolean isPasswordFieldPresent() {
        return driver.findElementsById("password").size() != 0;
    }

    public boolean isLDAPSelected() {
        return driver.findElementById("isLdapUserCheckbox").isSelected();
    }

    public boolean isUserNamePresent(String userName) {
        return driver.findElementsById("editUserModal" + userName).size() != 0;
    }

    public boolean isSuccessDisplayed(String name){
        return driver.findElementByClassName("alert-success").getText().contains(name);
    }

	public boolean isGlobalAccessErrorPresent(){
		return driver.findElementById("hasGlobalGroupAccessErrors").getText().contains("This would leave users unable to access the user management portion of ThreadFix.");
	}
	
	public boolean isRoleSelected(String oldName,String role){
		waitForElement(driver.findElementById("roleSelect"));
		if(oldName == null){
			return new Select(driver.findElementById("roleSelect")).getFirstSelectedOption().getText().contains(role);
		}else{
			return new Select(driver.findElementById("roleSelect")).getFirstSelectedOption().getText().contains(role);
		}

	}
    public boolean isGlobalAccessSelected() {
        sleep(3000);
        return driver.findElementById("hasGlobalGroupAccessCheckbox").isSelected();
    }

    public boolean isSaveChangesButtonClickable(String name) {
        return isClickable("submit");
    }

    public boolean isTeamRoleConfigurationPresent() {
        return driver.findElementById("addPermissionButton").isDisplayed();
    }

    public boolean isApplicationRoleConfigurationPresent() {
        return driver.findElementById("addApplicationRoleButton").isDisplayed();
    }

    public boolean isTeamRolePresent(String teamName, String roleName) {
        try {
            driver.findElementById("teamName" + teamName + "all" + roleName);
            driver.findElementById(("roleName" + teamName + "all" + roleName));
        } catch (NoSuchElementException e) {
            return false;
        }
        return true;
    }

    public boolean isApplicationRolePresent(String teamName, String appName, String roleName) {
        try {
            driver.findElementById("teamName" + teamName + appName + roleName);
            driver.findElementById(("roleName" + teamName + appName + roleName));
            driver.findElementById("applicationName" + teamName + appName + roleName);
        } catch (NoSuchElementException e) {
            return false;
        }
        return true;
    }

    public boolean isErrorPresent(String errorMessage) {
        WebElement element = null;
        List<WebElement> elementList = driver.findElementsByClassName("errors");
        for (WebElement e : elementList) {
            if (e.isDisplayed()) {
                element = e;
                break;
            }
        }
        if (element == null) {
            System.out.println("No error message found.");
            return false;
        }
        return element.getText().contains(errorMessage);
    }
}
