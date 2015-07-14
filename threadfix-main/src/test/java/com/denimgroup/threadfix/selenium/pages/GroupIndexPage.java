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

import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

public class GroupIndexPage extends BasePage {

    public GroupIndexPage(WebDriver webdriver) {
        super(webdriver);
    }

    /*------------------------------------ Utility Methods ------------------------------------*/

    public GroupIndexPage clickCreateGroup() {
        driver.findElementById("newGroupModalLink").click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage clickDeleteButton(String groupName) {
        clickEditLink(groupName);
        driver.findElementByCssSelector("a#deleteRoleLink:not(.ng-hide)").click();
        handleAlert();
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage setGroupName(String groupName) {
        driver.findElementById("groupNameInput").clear();
        driver.findElementById("groupNameInput").sendKeys(groupName);
        return this;
    }

    public GroupIndexPage editGroupName(String groupName) {
        driver.findElementById("name").clear();
        driver.findElementById("name").sendKeys(groupName);
        return this;
    }

    public GroupIndexPage setGroupGlobalRole(String globalRole) {
        //Enter key is sent to update other fields on page
        driver.findElementById("roleSelect").sendKeys(globalRole + Keys.ENTER);
        return this;
    }

    public GroupIndexPage clickSaveGroup() {
        driver.findElementByCssSelector("button#submit:not(.disabled)").click();
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage clickEditLink(String groupName) {
        refreshPage();
        driver.findElementByXPath("//li[@id=\'groupList\']/a[text()=\'" + groupName + "\']").click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage setUserField(String userName) {
        driver.findElementById("userTypeahead").sendKeys(userName);
        driver.findElementByXPath("//div[@id=\'users\']//a[strong[text()=\'" + userName + "\'] and not(text())]").click();
        return this;
    }

    public GroupIndexPage clickAddUser() {
        driver.findElementByXPath("//a[text()=\'Add User\']").click();
        return this;
    }

    public GroupIndexPage clickRemoveUser(String userName) {
        driver.findElementByXPath("//td[text()=\'" + userName + "\']/following-sibling::td/a").click();
        handleAlert();
        return this;
    }

    public GroupIndexPage clickAddTeamRole() {
        driver.findElementByCssSelector("div#config[ng-show=\'currentGroup\'] a#addPermissionButton").click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage setTeamName(String teamName) {
        //Sends keys for team name and Enter key to update other fields on page
        driver.findElementById("orgSelect").sendKeys(teamName + Keys.ENTER);
        return this;
    }

    public GroupIndexPage setTeamRole(String role) {
        driver.findElementById("roleSelectTeam").sendKeys(role);
        return this;
    }

    public GroupIndexPage clickEditTeamRole(String teamName, String roleName) {
        driver.findElementById("editAppMap" + teamName + "all" + roleName).click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage clickDeleteTeamRole(String teamName, String roleName) {
        driver.findElementById("deleteAppMap" + teamName + "all" + roleName).click();
        handleAlert();
        return this;
    }

    public GroupIndexPage clickAddApplicationRole() {
        driver.findElementByCssSelector("div#config[ng-show=\'currentGroup\'] a#addApplicationRoleButton").click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage setApplicationRole(String appName, String role) {
        driver.findElementById("roleSelectApp" + appName).sendKeys(role);
        return this;
    }

    public GroupIndexPage clickEditApplicationRole(String teamName, String appName, String roleName) {
        driver.findElementById("editAppMap" + teamName + appName + roleName).click();
        waitForElement(driver.findElementById("submit"));
        return new GroupIndexPage(driver);
    }

    public GroupIndexPage clickDeleteApplicationRole(String teamName, String appName, String roleName) {
        driver.findElementById("deleteAppMap" + teamName + appName + roleName).click();
        handleAlert();
        return this;
    }

    /*------------------------------------ Boolean Methods ------------------------------------*/

    public boolean isGroupPresent(String groupName) {
        try{
            driver.findElementByXPath("//li[@id=\'groupList\']/a[text()=\'" + groupName + "\']");
        } catch(NoSuchElementException e){
            return false;
        }
        return true;
    }

    public boolean isUserPresent(String userName) {
        try{
            driver.findElementByXPath("//div[@id=\'users\']//td[text()=\'" + userName + "\']");
        } catch(NoSuchElementException e){
            return false;
        }
        return true;
    }

    public boolean isValidationPresent() {
        try {
            driver.findElementByCssSelector("div.alert-success:not(.ng-hide)");
        } catch (NoSuchElementException e){
            return false;
        }
        return true;
    }

    public boolean isTeamRolePresent(String teamName, String roleName) {
        try {
            driver.findElementById("teamName" + teamName +"all" + roleName);
        } catch(NoSuchElementException e){
            return false;
        }
        return true;
    }

    public boolean isApplicationRolePresent(String teamName, String appName, String roleName) {
        try{
            driver.findElementById("teamName" + teamName + appName + roleName);
        } catch(NoSuchElementException e){
            return false;
        }
        return true;
    }

    public boolean isSaveChangesClickable() {
        try{
            driver.findElementByCssSelector("button#submit:not(.disabled)");
        } catch(NoSuchElementException e){
            return false;
        }
        return true;
    }

    /*------------------------------------ Getter Methods ------------------------------------*/

    public String getValidationMessage() {
        return driver.findElementByCssSelector("div.alert-success:not(.ng-hide)").getText();
    }

    public String getGroupGlobalRole() {
        return driver.findElementByCssSelector("select#roleSelect option[selected]").getText();
    }

    public String getNameError(){
        return driver.findElementById("groupNameInputRequiredError").getText();
    }

    public String getEditNameError(){
        return driver.findElementById("name.errors.required").getText();
    }

    public String getDuplicateNameError() {
        return driver.findElementById("errorSpan").getText();
    }

    public String getErrorAlertMessage() { return driver.findElementByCssSelector("div.alert-danger:not(.ng-hide)").getText(); }
}
