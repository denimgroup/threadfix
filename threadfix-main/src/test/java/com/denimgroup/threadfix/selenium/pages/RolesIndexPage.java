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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;
import java.util.List;

public class RolesIndexPage extends BasePage {

	public RolesIndexPage(WebDriver webdriver) {
		super(webdriver);
	}
		
	public RolesIndexPage clickDeleteButton(String roleName) {
		clickEditLink(roleName);
		sleep(1000);
		driver.findElementById("deleteLink").click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickCreateRole(){
		driver.findElementById("createRoleModalLink").click();
		waitForElement(driver.findElementById("submit"));
		return new RolesIndexPage(driver);
	}

    public RolesIndexPage setRoleName(String roleName) {
        driver.findElementById("roleNameInput").clear();
        driver.findElementById("roleNameInput").sendKeys(roleName);
        return this;
    }

    public RolesIndexPage clickSaveRole() {
        driver.findElementById("submit").click();
        return new RolesIndexPage(driver);
    }

    public RolesIndexPage clickSaveRole(String role) {
        driver.findElementById("submit").click();
        return new RolesIndexPage(driver);
    }

	public RolesIndexPage clickSaveRoleInvalid(){
        driver.findElementById("submit").click();
		sleep(1000);
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickEditLink(String roleName) {
		driver.findElementById("editModalLink" + roleName).click();
		waitForElement(driver.findElementById("submit"));
		return new RolesIndexPage(driver);
	}

	public String getEditRoleError() {
		return driver.findElementById("errorSpan").getText();
	}

    public String getDupNameError() {
        return driver.findElementById("roleNameInputNameError").getText();
    }

    public String getNameError(){
		return driver.findElementById("roleNameInputRequiredError").getText();
	}

    public boolean getPermissionValue(String permissionName) {
        return driver.findElement(By.id(permissionName + "True")).isSelected();
    }

    public RolesIndexPage setPermissionValue(String permissionValue, boolean value) {
        if (value) {
            driver.findElementById(permissionValue + "True").click();
        } else {
            driver.findElementById(permissionValue + "False").click();
        }

        return this;
    }

    public RolesIndexPage toggleAllPermissions(boolean status) {
        if (status) {
            driver.findElementByLinkText("Select All").click();
        } else {
            driver.findElementByLinkText("Select None").click();
        }
        sleep(1000);
        return this;
    }

    public RolesIndexPage toggleSpecificPermission(boolean status, String elementID) {
        if(status) {
            driver.findElementById( elementID + "True").click();
        }else {
            driver.findElementById(elementID + "False").click();
        }
        sleep(1000);
        return this;
    }
	
	public RolesIndexPage clickCloseModal(){
        waitForElement(driver.findElementByClassName("modal-footer").findElement(By.className("btn")));
		driver.findElementByClassName("modal-footer").findElement(By.className("btn")).click();
		return new RolesIndexPage(driver);
	}
	
	public boolean isCreateValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Successfully created role " + role);
	}
	
	public boolean isEditValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Successfully edited role " + role);
	}
	
	public boolean isDeleteValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Role deletion was successful for Role " + role);
	}
	
	public boolean isNamePresent(String roleName){
		return driver.findElementsById("role" + roleName).size() != 0;
	}
}
