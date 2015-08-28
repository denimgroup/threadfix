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


import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class UserPermissionsPage extends BasePage {

    public UserPermissionsPage(WebDriver webdriver) {
        super(webdriver);
    }

    //===========================================================================================================
    // Action Methods
    //===========================================================================================================

    public UserPermissionsPage clickAddPermissionsLink() {
        sleep(1000);
        driver.findElementById("addPermissionButton").click();
        waitForElement(By.id("orgSelect"));
        return new UserPermissionsPage(driver);
    }

    public UserPermissionsPage setTeam(String team) {
        try {
            driver.findElementById("orgSelect").sendKeys(team);
        } catch (NoSuchElementException e) {
            driver.findElementByLinkText("Close").click();
            this.refreshPage();
            sleep(2000);
            this.clickAddPermissionsLink();
            this.setTeamNoCatch(team);
        }
        return this;
    }

    public UserPermissionsPage setTeamNoCatch(String teamName) {
        driver.findElementById("orgSelect").sendKeys(teamName);
        return this;
    }

    //Note, the default is that all apps is selected
    public UserPermissionsPage toggleAllApps() {
        driver.findElementById("allAppsCheckbox").click();
        return this;
    }

    public UserPermissionsPage setTeamRole(String role) {
        driver.findElementById("roleSelectTeam").sendKeys(role);
        return this;
    }

    public UserPermissionsPage setApplicationRole(String appName, String role) {
        driver.findElementById("roleSelectApp" + appName).sendKeys(role);
        return this;
    }

    public UserPermissionsPage clickDeleteButton(String teamName, String appName, String role) {
        driver.findElementById("deleteAppMap" + teamName + appName + role).click();
        handleAlert();
        return new UserPermissionsPage(driver);
    }

    public UserPermissionsPage expandTeamName() {
        driver.findElementById("orgSelect").click();
        return this;
    }

    public UserPermissionsPage editSpecificPermissions(String teamName, String appName, String role) {
        driver.findElementById("editAppMap" + teamName + appName + role).click();
        return new UserPermissionsPage(driver);
    }

    public String errorAlert() {
        return driver.findElementByClassName("alert-error").getText();
    }

    //===========================================================================================================
    // Boolean Methods
    //===========================================================================================================

    public boolean isUserNamePresent(String userName) {
        return driver.findElementByTagName("h2").getText().contains(userName);
    }

    public boolean isPermissionsModalPresent() {
        return driver.findElementById("myModalLabel").isDisplayed();
    }

    public boolean isPermissionPresent(String teamName, String appName, String role) {
        try {
            if (!driver.findElementById("teamName" + teamName + appName + role).getText().contains(teamName)) {
                return false;
            }

            if (appName.equals("all")) {
                if (!driver.findElementById("applicationName" + teamName + appName + role).getText().contains("All")) {
                    return false;
                }
            } else {
                if (!driver.findElementById("applicationName" + teamName + appName + role).getText().contains(appName)) {
                    return false;
                }
            }

            if (!driver.findElementById("roleName" + teamName + appName + role).getText().contains(role)) {
                return false;
            }
        } catch (NoSuchElementException e) {
            System.err.println(e.getMessage());
            return false;
        }

        return true;
    }

    public boolean isErrorPresent(String errorMessage) {
        return driver.findElementByClassName("errors").getText().contains(errorMessage);
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

    public boolean isAddPermissionClickable() {
        return driver.findElementsByCssSelector("#btn.disabled").isEmpty();
    }

}
