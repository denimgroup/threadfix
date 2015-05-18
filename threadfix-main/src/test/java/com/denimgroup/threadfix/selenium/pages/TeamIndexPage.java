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
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class TeamIndexPage extends BasePage {

    public TeamIndexPage(WebDriver webdriver) {
        super(webdriver);
    }

    /*------------------------------------ Action Methods ----------------------------------------*/

    public int getNumTeamRows() {
        if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
            return driver.findElementsByClassName("pointer").size();
        }
        return 0;
    }

    public TeamIndexPage clickAddTeamButton() {
        driver.findElementById("addTeamModalButton").click();
        waitForElement(driver.findElementById("myModalLabel"));
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage setTeamName(String name) {
        driver.findElementById("nameInput").clear();
        driver.findElementById("nameInput").sendKeys(name);
        return this;
    }

    public TeamIndexPage addNewTeam(String teamName) {
        driver.findElementById("submit").click();
        waitForElement(driver.findElementById("teamName" + teamName));
        sleep(1000);
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage addNewTeamInvalid() {
        driver.findElementById("submit").click();
        sleep(1000);
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage expandTeamRowByName(String teamName) {
        driver.findElementById("teamCaret" + teamName).click();
        sleep(1500);
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage collapseTeamRowByName(String teamName) {
        driver.findElementById("teamCaret" + teamName).click();
        sleep(1500);
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage expandAllTeams() {
        driver.findElementById("expandAllButton").click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage collapseAllTeams() {
        driver.findElementById("collapseAllButton").click();
        return new TeamIndexPage(driver);
    }

    public TeamDetailPage clickViewTeamLink(String teamName) {
        driver.findElementById("organizationLink" + teamName).click();
        sleep(4000);
        return new TeamDetailPage(driver);
    }

    public ApplicationDetailPage clickViewAppLink(String appName, String teamName) {
        sleep(500);
        driver.findElementById("applicationLink" + teamName + "-" + appName).click();
        waitForElement(driver.findElementById("actionButton1"));
        return new ApplicationDetailPage(driver);
    }

    public TeamIndexPage clickAddNewApplication(String teamName) {
        driver.findElementById("addApplicationModalButton" + teamName).click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage setApplicationName(String appName) {
        sleep(1000);
        driver.findElementById("applicationNameInput").clear();
        driver.findElementById("applicationNameInput").sendKeys(appName);
        return this;
    }

    public TeamIndexPage setApplicationUrl(String url) {
        sleep(1000);
        driver.findElementById("applicationUrlInput").clear();
        driver.findElementById("applicationUrlInput").sendKeys(url);
        return this;
    }

    public TeamIndexPage setApplicationCriticality(String criticality) {
        sleep(1000);
        new Select(driver.findElementById("criticalityIdSelect")).selectByVisibleText(criticality);
        return this;
    }

    public TeamIndexPage saveApplication() {
        driver.findElementById("submit").click();
        sleep(5000);
        return new TeamIndexPage(driver);
    }

    public ApplicationDetailPage clickApplicationName(String appName) {
        sleep(1000);
        driver.findElementByLinkText(appName).click();
        return new ApplicationDetailPage(driver);
    }

    public TeamIndexPage saveApplicationInvalid() {
        driver.findElementById("submit").click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage clickCloseAddAppModal() {
        driver.findElementByLinkText("Close").click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage addNewApplication(String teamName, String appName, String url, String criticality) {
        clickAddNewApplication(teamName);
        setApplicationName(appName);
        setApplicationUrl(url);
        setApplicationCriticality(criticality);
        return this;
    }


    public TeamIndexPage addRemoteSourceCodeInformation(String url, String revision, String userName, String password) {
        expandSourceCodeFields();
        setRepositoryURL(url);
        setRepositoryRevision(revision);
        setRepositoryUserName(userName);
        setRepositoryPassword(password);
        return this;
    }

    public TeamIndexPage setSourceCodeFolder(String path) {
        expandSourceCodeFields();
        setRepositoryPath(path);
        return this;
    }

    public TeamIndexPage setRemoteSourceCodeURL(String url) {
        expandSourceCodeFields();
        repositoryURL(url);
        return this;
    }

    public TeamIndexPage setRepositoryPath(String path) {
        driver.findElementById("repositoryFolderInput").sendKeys(path);
        return this;
    }

    public TeamIndexPage repositoryURL(String url) {
        driver.findElementById("repositoryUrlInput").sendKeys(url);
        return this;
    }

    public TeamIndexPage setUniqueId(String uniqueId) {
        driver.findElementById("uniqueIdInput").sendKeys(uniqueId);
        return this;
    }

    public TeamIndexPage expandSourceCodeFields() {
        driver.findElementByLinkText("Source Code Information").click();
        waitForElement(driver.findElementById("repositoryUrlInput"));
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage setRepositoryURL(String url) {
        driver.findElementById("repositoryUrlInput").sendKeys(url);
        return this;
    }

    public TeamIndexPage setRepositoryRevision(String revision) {
        driver.findElementById("repositoryBranch").sendKeys(revision);
        return this;
    }

    public TeamIndexPage setRepositoryUserName(String userName) {
        driver.findElementById("repositoryUsername").sendKeys(userName);
        return this;
    }

    public TeamIndexPage setRepositoryPassword(String password) {
        driver.findElementById("repositoryPassword").sendKeys(password);
        return this;
    }

    public TeamIndexPage uploadScanButton(String teamName, String appName) {
        driver.findElementById("uploadScanModalLink" + teamName + "-" + appName).click();
        return this;
    }

    public TeamIndexPage uploadNewScan(String file, String teamName, String appName) {
        driver.findElementById("scanFileInput").sendKeys(file);
        waitForElement(driver.findElementById("applicationLink" + teamName + "-" + appName));
        return new TeamIndexPage(driver);
    }

    public AnalyticsPage clickDetails() {
        driver.findElementById("submit").click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }


    /*------------------------------------ Get Methods ----------------------------------------*/

    public String getLengthError() {
        return driver.findElementById("lengthError").getText();
    }

    public String getErrorMessage(String key) {
        return driver.findElementById(key).getText();
    }

    public String getNameRequiredMessage() {
        return driver.findElementById("applicationNameInputRequiredError").getText();
    }

    public String getNameLengthMessage() {
        return driver.findElementById("applicationNameInputLengthError").getText();
    }

    public String getNameTakenErrorMessage() {
        return driver.findElementById("applicationNameInputNameError").getText();
    }

    public String getUrlErrorMessage() {
        return driver.findElementById("applicationUrlInputInvalidUrlError").getText();
    }

    public String successAlert() {
        waitForElement(driver.findElementByClassName("alert-success"));
        return driver.findElementByClassName("alert-success").getText().trim();
    }

    public String errorAlert() {
        return driver.findElementByClassName("alert-error").getText().trim();
    }

    /*----------------------------------- Boolean Methods -----------------------------------*/

    public boolean isAppPresent(String teamName, String appName) {
        return driver.findElementsById("applicationLink" + teamName + "-" + appName).size() != 0;
    }

    public boolean isAppDisplayed(String teamName, String appName) {
        return driver.findElementById("applicationLink" + teamName + "-" + appName).isDisplayed();
    }

    public boolean isTeamPresent(String teamName) {
        return driver.findElementsById("teamName" + teamName).size() != 0;
    }

    public boolean isCreateValidationPresent(String teamName) {
        return driver.findElementByClassName("alert-success").getText()
                .contains("Successfully added team " + teamName);
    }

    public boolean isAddTeamBtnPresent() {
        return driver.findElementById("addTeamModalButton").isDisplayed();
    }

    public boolean isAddTeamBtnClickable() {
        return isClickable("addTeamModalButton");
    }

    public boolean isAddApplicationButtonClickable() {
        return driver.findElementsByCssSelector("#submit.disabled").isEmpty();
    }

    public String getUrlRepositoryError() {
        return driver.findElementById("sourceUrlValidError").getText().trim();
    }

    public boolean isTeamsExpanded(String teamName, String appName) {
        return driver.findElementById("applicationLink" + teamName + "-" + appName).isDisplayed();
    }


    public boolean isExpandAllBtnPresent() {
        WebDriverWait wait = new WebDriverWait(driver, 60);
        wait.until(ExpectedConditions.elementToBeClickable(By.id("expandAllButton")));
        return driver.findElementById("expandAllButton").isDisplayed();
    }

    public boolean isExpandAllBtnClickable() {
        return isClickable("expandAllButton");
    }

    public boolean isCollapseAllBtnPresent() {
        return driver.findElementById("collapseAllButton").isDisplayed();
    }

    public boolean isCollapseAllBtnClickable() {
        return isClickable("collapseAllButton");
    }

    public boolean isGraphWedgeDisplayed(String teamName, String level) {
        return driver.findElementById(teamName + level + "Arc").isDisplayed();
    }

    public boolean teamVulnerabilitiesFiltered(String teamName, String level, String expected) {
        return driver.findElementById("num" + level + "Vulns" + teamName).getText().equals(expected);
    }

    public boolean applicationVulnerabilitiesFiltered(String teamName, String appName, String level, String expected) {
        return getApplicationSpecificVulnerabilityCount(teamName, appName, level).equals(expected);
    }

    public String getApplicationSpecificVulnerabilityCount(String teamName, String appName, String level) {
        return driver.findElement(By.id("num" + level + "Vulns" + teamName + "-" + appName)).getText().trim();
    }

    public boolean isUploadButtonPresent(String teamName, String appName) {
        return driver.findElementsById("uploadScanModalLink" + teamName + "-" + appName).size() != 0;
    }

    public boolean isUploadScanButtonDisplay() {
        return driver.findElementByLinkText("Upload Scan").isDisplayed();
    }

    public boolean isScanUploadedAlready(String teamName, String appName) {
        return driver.findElementByXPath("//span[text()='Scan file has already been uploaded.']").isDisplayed();
    }

    public boolean isTeamTotalNumberCorrect(String teamName, String expectednumber) {
        return driver.findElementById("numTotalVulns" + teamName).getText().trim().equals(expectednumber);
    }

    public boolean isApplicationTotalNumberCorrect(String teamName, String appName, String expectecNumber) {
        return driver.findElementById("numTotalVulns" + teamName + "-" + appName).getText().trim().equals(expectecNumber);
    }

    /*------------------------------------ Void Methods ----------------------------------------*/

    public void waitForPieWedge(String teamName, String level) {
        waitForElement(driver.findElementById(teamName + level + "Arc"));
    }
}

