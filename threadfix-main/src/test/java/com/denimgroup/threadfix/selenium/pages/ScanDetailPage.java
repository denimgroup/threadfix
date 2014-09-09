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
        waitForElement(driver.findElementById("importedResults"));
        return new ScanDetailPage(driver);
    }

    public boolean areStatisticsDisplayed() {
        return driver.findElementById("statisticsDiv").isDisplayed();
    }

    public boolean isViewFindingPresent() {
        return driver.findElementById("mappedVulnType").isDisplayed();
    }

    public boolean isImportedResultsCorrect() {
        String temp = driver.findElementById("importedResults").getText().trim();
        return temp.equals("45");
    }

    public boolean isDuplicatedResultsCorrect() {
        String temp = driver.findElementById("duplicateResults").getText().trim();
        return temp.equals("0");
    }
    public boolean isTotalFindingCorrect() {
        String temp = driver.findElementById("totalFindings").getText().trim();
        return temp.equals("45");
    }

    public boolean isFindingsWithoutVulnerabilitiesCorrect() {
        String temp = driver.findElementById("findingsWithoutVulnerabilities").getText().trim();
        return temp.equals("0");
    }

    public boolean isFindingsWithVulnerabilitiesCorrect() {
        String temp = driver.findElementById("findingsWithVulnerabilities").getText().trim();
        return temp.equals("45");
    }

    public boolean isDuplicateFindingCorrect() {
        String temp = driver.findElementById("duplicateFindings").getText().trim();
        return temp.equals("0");
    }

    public boolean isHiddenVulnerabilitiesCorrect() {
        String temp = driver.findElementById("hiddenVulnerabilities").getText().trim();
        return temp.equals("0");
    }

    public boolean isTotalVulnerabilitiesCorrect() {
        String temp = driver.findElementById("totalVulnerabilities").getText().trim();
        return temp.equals("45");
    }

    public boolean isNewVulnerabilitiesCorrect() {
        String temp = driver.findElementById("newVulnerabilities").getText().trim();
        return temp.equals("45");
    }

    public boolean isOldVulnerabilitiesCorrect() {
        String temp = driver.findElementById("oldVulnerabilities").getText().trim();
        return temp.equals("0");
    }

    public boolean isResurfacedVulnerabilitiesCorrect() {
        String temp = driver.findElementById("resurfacedVulnerabilities").getText().trim();
        return temp.equals("0");
    }

    public boolean isClosedVulnerabilitiesCorrect() {
        String temp = driver.findElementById("closedVulnerabilities").getText().trim();
        return temp.equals("0");
    }

}

