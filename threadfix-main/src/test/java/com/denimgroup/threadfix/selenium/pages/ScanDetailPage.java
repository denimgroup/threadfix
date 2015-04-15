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

public class ScanDetailPage extends BasePage {

    public ScanDetailPage(WebDriver webdriver) {
        super(webdriver);
    }

    public String getScanHeader() {
        return getH2Tag().trim();
    }

    //TODO add method to click specific finding link

    public String getSeverity(int row) {
        return driver.findElementById("mappedSeverity" + row).getText();
    }

    public String getVulnType(int row) {
        return driver.findElementById("mappedSeverity" + row).getText();
    }

    public String getPath(int row) {
        return driver.findElementById("mappedSeverity" + row).getText();
    }

    public String getParameter(int row) {
        return driver.findElementById("mappedSeverity" + row).getText();
    }

    public String getNumMergedResults(int row) {
        return driver.findElementById("mappedSeverity" + row).getText();
    }

    public FindingDetailPage clickViewFinding() {
        driver.findElementById("mappedVulnType").click();
        sleep(3000);
        return new FindingDetailPage(driver);
    }

    public ScanDetailPage toggleStatistics() {
        driver.findElementById("statisticButton").click();
        sleep(500);
        return new ScanDetailPage(driver);
    }

    public ApplicationDetailPage clickApplicationNav() {
        driver.findElementByPartialLinkText("Application:").click();
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickTeamNav() {
        driver.findElementByPartialLinkText("Team:").click();
        return new TeamDetailPage(driver);
    }

    public boolean isViewFindingPresent() {
        return driver.findElementById("mappedVulnType").isDisplayed();
    }

    public boolean isImportedResultsCorrect(String expectedCount) {
        return driver.findElementById("importedResults").getText().trim().equals(expectedCount);
    }

    public boolean areStatisticsDisplayed() {
        return driver.findElementById("statisticsDiv").isDisplayed();
    }

    public boolean isHideStatisticsButtonDisplay(String expected) {
        return driver.findElementById("statisticButton").getText().trim().equals(expected);
    }

    public boolean isDuplicatedResultsCorrect(String expectedCount) {
        return driver.findElementById("duplicateResults").getText().trim().equals(expectedCount);
    }

    public boolean isTotalFindingCorrect(String expectedCount) {
        return driver.findElementById("totalFindings").getText().trim().equals(expectedCount);
    }

    public boolean isFindingsWithoutVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("findingsWithoutVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isFindingsWithVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("findingsWithVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isDuplicateFindingCorrect(String expectedCount) {
        return driver.findElementById("duplicateFindings").getText().trim().equals(expectedCount);
    }

    public boolean isHiddenVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("hiddenVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isTotalVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("totalVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isNewVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("newVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isOldVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("oldVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isResurfacedVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("resurfacedVulnerabilities").getText().trim().equals(expectedCount);
    }

    public boolean isClosedVulnerabilitiesCorrect(String expectedCount) {
        return driver.findElementById("closedVulnerabilities").getText().trim().equals(expectedCount);
    }
}

