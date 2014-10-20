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
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;

public class TeamDetailPage extends BasePage {

    public TeamDetailPage(WebDriver webdriver) {
        super(webdriver);
        driver.findElementById("applicationsTableBody");
    }

    /*------------------------------ Action Methods ------------------------------*/

    public String getOrgName() {
        return driver.findElementById("name").getText();
    }

    public String successAlert(){
        waitForElement(driver.findElementByClassName("alert-success"));
        return driver.findElementByClassName("alert-success").getText().trim();
    }

    public TeamDetailPage clickActionButton(){
        driver.findElementById("actionButton").click();
        waitForElement(driver.findElementById("teamModalButton"));
        return new TeamDetailPage(driver);
    }

    public  TeamDetailPage clickActionButtonWithoutEditButton() {
        driver.findElementById("actionButton").click();
        waitForElement(driver.findElementById("editfiltersButton1"));
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickEditDeleteButton() {
        driver.findElementById("teamModalButton").click();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickEditOrganizationLink() {
        clickActionButton();
        driver.findElementById("teamModalButton").click();
        waitForElement(driver.findElementById("deleteTeamButton"));
        return new TeamDetailPage(driver);
    }

    public FilterPage clickEditTeamFilters() {
        driver.findElementById("editfiltersButton1").click();
        waitForElement(driver.findElementById("createNewKeyModalButton"));
        return new FilterPage(driver);
    }

    public TeamDetailPage clickUserPermLink() {
        clickActionButton();
        sleep(3000);
        driver.findElementById("userListModelButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickAddApplicationButton() {
        driver.findElementById("addApplicationModalButton").click();
        waitForElement(driver.findElementById("applicationNameInput"));
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage setApplicationInfo(String appName, String url, String criticality) {
        setApplicationName(appName);
        setApplicationUrl(url);
        setApplicationCriticality(criticality);
        return this;
    }

    public TeamDetailPage setApplicationName(String appName) {
        driver.findElementById("applicationNameInput").clear();
        driver.findElementById("applicationNameInput").sendKeys(appName);
        return this;
    }

    public TeamDetailPage setApplicationUrl(String url) {
        driver.findElementById("applicationUrlInput").clear();
        driver.findElementById("applicationUrlInput").sendKeys(url);
        return this;
    }

    public TeamDetailPage setApplicationCriticality(String criticality) {
        new Select(driver.findElementById("criticalityIdSelect")).selectByVisibleText(criticality);
        return this;
    }

    public ApplicationDetailPage clickAppLink(String appName) {
        driver.findElementByLinkText(appName).click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickVulnerabilitiesTab() {
        driver.findElementByLinkText("0 Vulnerabilities").click();
        waitForElement(driver.findElementByClassName("filter-controls"));
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickVulnerabilitiesTab(String number) {
        driver.findElementByLinkText(number + " Vulnerabilities").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
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
        return clickModalSubmit();
        //sleep(1000);
        //return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickUpdateButtonInvalid() {
        driver.findElementById("submit").click();
        sleep(1000);
        return new TeamDetailPage(driver);
    }

    public TeamIndexPage clickDeleteButton() {
        clickEditOrganizationLink();
        sleep(500);
        driver.findElementById("deleteTeamButton").click();
        Alert alert = driver.switchTo().alert();
        alert.accept();
        sleep(2000);
        return new TeamIndexPage(driver);
    }

    public TeamDetailPage toggleAllFilters() {
        driver.findElementById("toggleAllButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickClearFilters() {
        driver.findElementById("clearFiltersButton").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickLoadFilters() {
        driver.findElementByLinkText("Load Filters").click();
        waitForElement(driver.findElementById("filterSelect"));
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage expandSavedFilters() {
        sleep(2000);
        driver.findElementById("showSaveFilter").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage addSavedFilter(String newFilter) {
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(newFilter);
        driver.findElementById("saveFilterButton").click();
        waitForElement(driver.findElementById("saveFilterSuccessMessage"));
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage addInvalidNameSavedFilter(String newFilter) {
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(newFilter);
        return this;
    }

    public TeamDetailPage loadSavedFilter(String savedFilter) {
        new Select(driver.findElementById("filterSelect")).selectByVisibleText(savedFilter);
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage expandTeamApplication() {
        sleep(2000);
        driver.findElementById("expandApplicationFilters").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage addApplicationFilter(String application) {
        driver.findElementById("showApplicationInput1").click();
        driver.findElementById("applicationNameTypeahead1").sendKeys(application);
        driver.findElementById("applicationNameTypeahead1").sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage expandFieldControls() {
        sleep(2000);
        driver.findElementById("showFieldControls").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage addVulnerabilityTypeFilter(String vulnerabilityType, String defultVulnerability) {
        driver.findElementById("showTypeInput").click();
        driver.findElementById("vulnerabilityTypeTypeahead").sendKeys(vulnerabilityType);
        driver.findElementByLinkText(defultVulnerability).click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage setPathFilter(String path) {
        driver.findElementById("pathInput").sendKeys(path);
        driver.findElementById("pathInput").sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage setParameterFilter(String parameter) {
        driver.findElementById("parameterFilterInput").sendKeys(parameter);
        driver.findElementById("parameterFilterInput").sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleSeverityFilter(String level) {
        driver.findElementById("show" + level).click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleStatusFilter(String status) {
        driver.findElementById("show" + status).click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage expandScannerAndMerged() {
        sleep(2000);
        driver.findElementById("expandScannerFilters").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleTwoPlus() {
        driver.findElementByLinkText("2+").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleThreePlus() {
        driver.findElementByLinkText("3+").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleFourPlus() {
        driver.findElementByLinkText("4+").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleFivePlus() {
        driver.findElementByLinkText("5+").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage addScannerFilter(String scanner) {
        driver.findElementById("showScannerInput").click();
        driver.findElementById("scannerTypeahead").sendKeys(scanner);
        driver.findElementById("scannerTypeahead").sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage expandAging() {
        sleep(2000);
        driver.findElementById("showDateControls").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleLessThan() {
        driver.findElementByLinkText("Less Than").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleMoreThan() {
        driver.findElementByLinkText("More Than").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggleOneWeek() {
        driver.findElementByLinkText("1 Week").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggle30Days() {
        driver.findElementByLinkText("30 days").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggle60Days() {
        driver.findElementByLinkText("60 days").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage toggle90Days() {
        driver.findElementByLinkText("90 days").click();
        waitForResultsToLoad();
        return new TeamDetailPage(driver);
    }

    public void waitForResultsToLoad() {
        while (driver.findElementById("vulnTreeLoadingSpinner").isDisplayed()) {
            sleep(1000);
        }
    }

    /*------------------------------ Get Methods ------------------------------*/

    //TODO When ids are added change this!
    public String getErrorText() {
        return driver.findElementById("name.errors").getText().trim();
    }

    public String getErrorMessage(String key) {
        return driver.findElementById(key).getText().trim();
    }

    public int getNumTeamRows() {
        if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
            return driver.findElementsByClassName("pointer").size();
        }
        return 0;
    }

    public int getNumPermUsers(){
        return driver.findElementById("userTableBody").findElements(By.className("bodyRow")).size();
    }

    public int getFilterDivHeight() {
        return driver.findElement(By.className("filter-controls")).getSize().getHeight();
    }

    public int getEditModalHeaderWidth(){
        return driver.findElementById("editFormDiv").findElement(By.className("ellipsis")).getSize().width;
    }

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isAppPresent(String appName){
        return driver.findElementsByLinkText(appName).size() != 0;
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
        return driver.findElementById("deleteTeamButton").isDisplayed();
    }

    public boolean EDDeleteClickable(){
        return isClickable("deleteTeamButton");
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
        return driver.findElementByClassName("modal-footer").findElement(By.className("btn")).isDisplayed();
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
        try {
            return driver.findElementById("addApplicationModalButton").isDisplayed();
        } catch (org.openqa.selenium.NoSuchElementException e) {
            System.err.println(e.getMessage());
            return false;
        }
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

    public boolean isSuccessMessageDisplayed() {
        return driver.findElementByClassName("alert-success").isDisplayed();
    }

    public boolean isUserPresentPerm(String user){
        for(int i = 1; i <= getNumPermUsers();i++){
            if (driver.findElementById("name"+i).getText().contains(user)){
                return true;
            }
        }
        return false;
    }

    public boolean applicationVulnerabilitiesFiltered(String appName, String level, String expected) {
        return driver.findElementById("app" + level + "Vulns0").getText().equals(expected);
    }

    public boolean isSeverityLevelShown(String level) {
        return driver.findElementsById("expand" + level).size() != 0;
    }

    //TODO get rid of extra code when debugging is done.
    public boolean isVulnerabilityCountCorrect(String level, String expected) {
        if (expected.equals(driver.findElementById("totalBadge" + level).getText())) {
            return true;
        } else {
            this.takeScreenShot();
            return false;
        }
    }

    public boolean areAllVulnerabilitiesHidden() {
        return driver.findElementById("noResultsFound").getText().trim().equals("No results found.");
    }

    public boolean isSaveFilterDisabled() {
        String attributeValue = driver.findElementById("saveFilterButton").getAttribute("disabled");
        if (attributeValue != null) {
            return attributeValue.contains("true");
        }
        return false;
    }

    public boolean isSavedFilterSuccessMessageDisplayed() {
        return driver.findElementById("saveFilterSuccessMessage").isDisplayed();
    }

    public boolean isDuplicateNameErrorMessageDisplayed() {
        return driver.findElementById("saveFilterErrorMessage").isDisplayed();
    }

    public boolean isSavedFilterPresent(String savedFilter) {
        try {
            new Select(driver.findElementById("filterSelect")).selectByVisibleText(savedFilter);
            return true;
        } catch (org.openqa.selenium.NoSuchElementException e) {
            return false;
        }
    }

    public boolean isNumberOfOpenVulnerabilityCorrect(String expectedNumber, int row) {
        return driver.findElementById("appTotalVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isNumberOfCriticalCorrect(String expectedNumber, int row) {
        return driver.findElementById("appCriticalVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isNumberOfHighCorrect(String expectedNumber, int row) {
        return driver.findElementById("appHighVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isNumberOfMediumCorrect(String expectedNumber, int row) {
        return driver.findElementById("appMediumVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isNumberOfLowCorrect(String expectedNumber, int row) {
        return driver.findElementById("appLowVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isNumberOfInfoCorrect(String expectedNumber, int row) {
        return driver.findElementById("appInfoVulns" + row).getText().trim().equals(expectedNumber);
    }

    public boolean isTeamNamePresent(String teamName) {
        return driver.findElementById("name").isDisplayed();
    }
}