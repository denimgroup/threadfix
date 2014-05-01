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

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;

public class TeamDetailPage extends BasePage {

    public TeamDetailPage(WebDriver webdriver) {
        super(webdriver);
        driver.findElementById("applicationsTableBody");
    }

    public String getOrgName() {
        return driver.findElementById("name").getText();
    }

    public TeamDetailPage clickActionButton(){
        driver.findElementById("actionButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public FilterPage clickEditTeamFilters() {
        driver.findElementById("editfiltersButton1").click();
        waitForElement(driver.findElementById("createNewKeyModalButton"));
        return new FilterPage(driver);
    }

    public TeamDetailPage clickEditOrganizationLink() {
        clickActionButton();
        driver.findElementById("teamModalButton").click();
        waitForElement(driver.findElementById("deleteTeamButton"));
        return new TeamDetailPage(driver);
    }

    public boolean isAppPresent(String appName){
        return driver.findElementById("applicationsTableBody").getText().contains(appName);
    }

    public int getEditModalHeaderWidth(){
        return driver.findElementById("editFormDiv").findElement(By.className("ellipsis")).getSize().width;
    }

    public TeamDetailPage clickCloseEditModal(){
        driver.findElementById("closeTeamModalButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage setNameInput(String editedOrgName) {
        driver.findElementById("teamNameInput").clear();
        driver.findElementById("teamNameInput").sendKeys(editedOrgName);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickUpdateButtonValid() {
        clickModalSubmit();
        sleep(1000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickUpdateButtonInvalid() {
        return clickModalSubmit();
    }

    public TeamIndexPage clickDeleteButton() {
        clickEditOrganizationLink();
        sleep(500);
        driver.findElementById("deleteTeamButton").click();
        Alert alert = driver.switchTo().alert();
        alert.accept();
        sleep(1000);
        return new TeamIndexPage(driver);
    }

    public String getErrorText() {
        return driver.findElementById("name.errors").getText().trim();
    }

    public int getNumTeamRows() {
        if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
            return driver.findElementsByClassName("pointer").size();
        }
        return 0;
    }

    public boolean applicationVulnerabilitiesFiltered(String appName, String level, String expected) {
        return driver.findElementById("app" + level + "Vulns" + appName).getText().equals(expected);
    }

    public boolean isActionBtnPresent(){
        return driver.findElementById("actionButton").isDisplayed();
    }

    public boolean isActionBtnClickable(){
        return isClickable("actionButton");
    }

    public boolean isEditDeleteLinkPresent(){
        return driver.findElementById("teamModalButton").isDisplayed();
    }

    public boolean isEditDeleteLinkClickable(){
        return isClickable("teamModalButton");
    }

    public boolean isEditDeleteModalPresent(){
        return driver.findElementById("deleteTeamButton").isDisplayed();
    }

    public boolean isDeleteTeamButtonPresent(){
        return driver.findElementById("deleteLink").isDisplayed();
    }

    public boolean EDDeleteClickable(){
        return isClickable("deleteLink");
    }

    public boolean EDClosePresent(){
        return driver.findElementById("closeModalButton").isDisplayed();
    }

    public boolean EDCloseClickable(){
        return isClickable("closeModalButton");
    }

    public boolean EDSavePresent(){
        return driver.findElementById("submit").isDisplayed();
    }

    public boolean EDSaveClickable(){
        return isClickable("submit");
    }

    public boolean EDNamePresent(){
        return driver.findElementById("teamNameInput").isDisplayed();
    }

    public boolean isTeamNameDisplayedCorrectly(String teamName) {
        String pageName = driver.findElementById("name").getText();
        pageName = pageName.replaceAll("(.*) Action$", "$1");
        return teamName.equals(pageName);
    }

    public boolean isPUEditPermLinkPresent(){
        //TODO switch to use user name to check right link
        return driver.findElementById("editPermissions1").isDisplayed();
    }

    public boolean isPUEditPermLinkClickable(){
        //TODO switch to use user name to check right link
        return isClickable("editPermissions1");
    }

    public boolean isPUClosePresent(){
        return driver.findElementById("usersModal").findElement(By.className("btn")).isDisplayed();
    }

    //correct to work with classes and stuff expectedConditions
    @SuppressWarnings("static-access")
    public boolean isPUCloseClickable(){
        return ExpectedConditions.elementToBeClickable(By.id("usersModal").className("btn")) != null;
    }

    public boolean isleftViewMoreLinkPresent(){
        return driver.findElementById("leftViewMore").isDisplayed();
    }

    public boolean isleftViewMoreLinkClickable(){
        return isClickable("leftViewMore");
    }

    public boolean is6MonthChartPresnt(){
        return driver.findElementById("leftTileReport").isDisplayed();
    }

    public boolean isrightViewMoreLinkClickable(){
        return isClickable("rightViewMore");
    }

    public boolean isTop10ChartPresent(){
        return driver.findElementById("rightTileReport").isDisplayed();
    }

    public boolean isAddAppBtnPresent(){
        return driver.findElementById("addApplicationModalButton").isDisplayed();
    }

    public boolean isAddAppBtnClickable(){
        return isClickable("addApplicationModalButton");
    }

    public boolean isAppLinkPresent(String appName){
        return driver.findElementByLinkText(appName).isDisplayed();
    }

    public boolean isAppLinkClickable(String appName){
        return ExpectedConditions.elementToBeClickable(By.linkText(appName)) != null;
    }

    public TeamDetailPage clickUserPermLink() {
        clickActionButton();
        sleep(3000);
        driver.findElementById("userListModelButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public int getNumPermUsers(){
        return driver.findElementById("userTableBody").findElements(By.className("bodyRow")).size();
    }

    public boolean isUserPresentPerm(String user){
        for(int i = 1; i <= getNumPermUsers();i++){
            if (driver.findElementById("name"+i).getText().contains(user)){
                return true;
            }
        }
        return false;
    }

}
