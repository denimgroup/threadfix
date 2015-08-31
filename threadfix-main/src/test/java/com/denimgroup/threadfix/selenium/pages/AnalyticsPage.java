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

import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.Select;

import java.util.ArrayList;

public class AnalyticsPage extends BasePage {

	public AnalyticsPage(WebDriver webdriver) {
		super(webdriver);
	}

    //===========================================================================================================
    // Action Methods
    //===========================================================================================================

    public AnalyticsPage clickTrendingTab(Boolean usingD3) {
        driver.findElementByLinkText("Trending").click();
        waitForElement(By.id("trendingFilterDiv"));
//        if(usingD3){
//            sleep(2500);
//        }
//        sleep(2500);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickSnapshotTab(Boolean usingD3) {
        //Runtime Fix
        sleep(5000);

        driver.findElementByLinkText("Snapshot").click();
        waitForElement(By.id("snapshotFilterDiv"));
        if(usingD3){
            sleep(2500);
        }
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickComplianceTab(Boolean usingD3) {
        driver.findElementByLinkText("Compliance").click();
        if(usingD3){
            sleep(2500);
        }
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickRemediationTab(Boolean usingD3) {
        driver.findElementByLinkText("Remediation").click();
        waitForElement(By.id("complianceFilterDiv"));
        if(usingD3){
            sleep(2500);
        }
        sleep(2500);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickVulnerabilitySearchTab() {
        //Runtime Fix
        sleep(5000);

        driver.findElementByLinkText("Vulnerability Search").click();
        waitForElement(By.id("vulnSearchDiv"));
        sleep(2500);
        return  new AnalyticsPage(driver);
    }

    public AnalyticsPage toggleAllFilter(String divId, Boolean expanding) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("toggleAllButton")).click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clearFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("clearFiltersButton")).click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandTeamApplicationFilter(String divId) {
        //Runtime Fix
        sleep(5000);

        WebElement filterDiv = driver.findElementById(divId);
        try {
            filterDiv.findElement(By.id("expandTeamAndApplicationFilters")).click();
        } catch (ElementNotVisibleException e) {
            sleep(5000);
            filterDiv.findElement(By.id("expandTeamAndApplicationFilters")).click();
        }
        waitForElement(By.cssSelector("#" + divId + " #showApplicationInput"));
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandTeamApplicationFilterReport(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("expandTeamAndApplicationFiltersReport")).click();
        waitForElement(By.cssSelector("#" + divId + " #showTeamInputReport"));
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addTeamFilter(String teamName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement teamNameSpace = filterDiv.findElement(By.id("teamNameTypeahead"));
        filterDiv.findElement(By.id("showTeamInput")).click();
        teamNameSpace.clear();
        teamNameSpace.sendKeys(teamName);
        sleep(1000);
        teamNameSpace.sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addTagFilter(String tagName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement tagNameSpace = filterDiv.findElement(By.id("tagNameTypeahead"));
        filterDiv.findElement(By.id("showTagInput")).click();
        tagNameSpace.clear();
        tagNameSpace.sendKeys(tagName);
        sleep(1000);
        tagNameSpace.sendKeys(Keys.ENTER);
        return new AnalyticsPage(driver);
    }

    public ApplicationDetailPage clickAppName() {
        driver.findElementById("appName0").findElement(By.tagName("a")).click();
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickTeamName() {
        driver.findElementById("teamName0").findElement(By.tagName("a")).click();
        return new TeamDetailPage(driver);
    }

    public VulnerabilityDetailPage clickViewMore(String number) {
        driver.findElementById("vulnLink" + number).click();
        return new VulnerabilityDetailPage(driver);
    }

    public AnalyticsPage expandTagFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("expandTagFilters")).click();
        waitForElement(By.cssSelector("#" + divId + " #showTagInput"));
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addTeamFilterReport(String teamName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement teamNameSpace = filterDiv.findElement(By.id("teamNameTypeaheadReport"));
        filterDiv.findElement(By.id("showTeamInputReport")).click();
        teamNameSpace.clear();
        teamNameSpace.sendKeys(teamName);
        teamNameSpace.sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        sleep(1500);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage saveCurrentFilter(String name, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showSaveFilter")).click();
        filterDiv.findElement(By.id("filterNameInput")).sendKeys(name);
        filterDiv.findElement(By.id("saveFilterButton")).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandAgingFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showDateControls")).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandFieldControls(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showFieldControls")).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage selectFieldControls(String level, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("show" + level)).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage toggleAgingFilter(String age, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.linkText(age)).click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandVulnComments(String number) {
        driver.findElementById("vulnName" + number).click();
        driver.findElementById("vulnName" + number).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage selectDropDownReport(String report) {
        new Select(driver.findElementById("reportSnapshotSelect")).selectByVisibleText(report);
        sleep(4000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage selectComplianceType(String type) {
        new Select(driver.findElements(By.id("complianceTypeSelect")).get(1)).selectByVisibleText(type);
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage loadFilter(String name, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.linkText("Load Filters")).click();
        filterDiv.findElement(By.id("filterSelect")).sendKeys(name);
        filterDiv.findElement(By.id("filterSelect")).sendKeys(Keys.ENTER);
        filterDiv.findElement(By.linkText("Filters")).click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addApplicationFilter(String appName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement applicationNameSpace = filterDiv.findElement(By.id("applicationNameTypeahead"));
        filterDiv.findElement(By.id("showApplicationInput")).click();
        applicationNameSpace.clear();
        applicationNameSpace.sendKeys(appName);
        applicationNameSpace.sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage sleepOnArrival(int length) {
        sleep(length);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandOwaspTopTenFilter(String divId) {

        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showOwasp")).click();
        waitForElement(By.cssSelector("#" + divId + " #owasp2013"));
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage selectOwaspYear(String year, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.cssSelector("li#owasp" + year + " a")).click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickAverageTimeToCloseSortButton(int times) {
        int count = 0;
        while (count++ < times) {
            driver.findElementByCssSelector("th#averageTimeToClose").click();
            sleep(5000);
        }
        return new AnalyticsPage(driver);
    }

    //===========================================================================================================
    // Set Methods
    //===========================================================================================================

    //===========================================================================================================
    // Get Methods
    //===========================================================================================================

    public int getFilterDivHeight(String divId) {
        return driver.findElement(By.id(divId)).getSize().getHeight();
    }

    public String mostVulnAppTip(String level, String team, String application) {
        hoverRealOverSVGElement(team + application + level + "Bar");
        return driver.findElementById("horizontalBarTip").getText();
    }

    public String mostVulnAppModalHeader(String level, String team, String application) {
        clickSVGElement(team + application + level + "Bar");
        String header = driver.findElementById("header2").getText().trim();
        driver.findElementById("header2");
        return header;
    }

    public String getCommentText(String commentNumber ) {
        return driver.findElementById("commentText" + commentNumber).getText();
    }

    public String getPortfolioSummaryItem(int itemNumber) {
        return driver.findElementByCssSelector("div#portfolioDiv tbody tr:nth-of-type(" + itemNumber +
                ") td.inputValue").getText();
    }

    public String getScanComparisonSummaryItem(int itemNumber) {
        return driver.findElementByCssSelector("div#scanComparisonDiv tbody tr:nth-of-type(" + itemNumber +
                ") td.inputValue").getText();
    }

    public String getScanComparisonFoundCount(String rowNumber) {
        return driver.findElementById("foundCount" + rowNumber).getText();
    }

    public String getScanComparisonFoundPercent(String rowNumber) {
        return driver.findElementById("foundPercent" + rowNumber).getText();
    }

    public String getScanComparisonFalsePostiveCount(String rowNumber) {
        return driver.findElementById("fpCount" + rowNumber).getText();
    }

    public String getScanComparisonFalsePositivePercent(String rowNumber) {
        return driver.findElementById("fpPercent" + rowNumber).getText();
    }

    public String getScanComparisonHAMEndpointCount(String rowNumber) {
        return driver.findElementById("foundHAMEndpoint" + rowNumber).getText();
    }

    public String getScanComparisonHAMEndpointPercent(String rowNumber) {
        return driver.findElementById("foundHAMEndpointPercent" + rowNumber).getText();
    }

    public String getProgressByVulnerabilityType(String rowNumber) {
        return driver.findElementById("descriptionVuln" + rowNumber).getText();
    }

    //===========================================================================================================
    // Helper Methods
    //===========================================================================================================

    public void waitForResultsToLoad() {
        while (driver.findElementById("vulnTreeLoadingSpinner").isDisplayed()) {
            sleep(2500);
        }
    }

    public AnalyticsPage waitForReportTab(String report) {
        waitForElementPresence(report + "Tab", 15);
        return new AnalyticsPage(driver);
    }

    //===========================================================================================================
    // Boolean Methods
    //===========================================================================================================

    public boolean isVulnerabilityCountCorrect(String level, String expected) {
        return expected.equals(tryGetText(By.id("totalBadge" + level)).trim());
    }

    public boolean isOwaspCountCorrect(String number, String expected) {
        return expected.equals(driver.findElementByCssSelector("span[id*=\'totalBadgeA" +
                number + " \']").getText().trim());
    }

    public boolean isTeamDisplayedinTeamDropDownReport(String teamName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showTeamInputReport")).click();
        filterDiv.findElement(By.id("teamNameTypeaheadReport")).sendKeys(teamName);
        return !driver.findElementsByLinkText(teamName).isEmpty();
    }

    public boolean isAppDisplayedinAppDropDownReport(String teamName, String appName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showApplicationInputReport")).click();
        filterDiv.findElement(By.id("applicationNameTypeaheadReport")).sendKeys(teamName);
        return !driver.findElementsByLinkText(teamName + " / " + appName).isEmpty();
    }

    public boolean isTeamDisplayedinTeamDropDown(String teamName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showTeamInput")).click();
        filterDiv.findElement(By.id("teamNameTypeahead")).sendKeys(teamName);
        return !driver.findElementsByLinkText(teamName).isEmpty();
    }

    public boolean isAppDisplayedinAppDropDown(String teamName, String appName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("showApplicationInput")).click();
        filterDiv.findElement(By.id("applicationNameTypeahead")).sendKeys(teamName);
        return !driver.findElementsByLinkText(teamName + " / " + appName).isEmpty();
    }

    public boolean isSeverityLevelShown(String level) {
        return driver.findElementsById("totalBadge" + level).size() != 0;
    }

    public boolean areAllVulnerabilitiesHidden() {
        return driver.findElementById("noResultsFound").getText().trim().equals("No results found.");
    }

    public boolean isReportCorrect() {
        WebElement filterDiv = driver.findElementById("trendingFilterDiv");
        return filterDiv.findElement(By.id("toggleAllButton")).isEnabled();
    }

    public boolean checkCorrectFilterLevel(String level) {
        ArrayList<String> levels = new ArrayList<String>();
        levels.add("Info"); levels.add("Low"); levels.add("Medium"); levels.add("High"); levels.add("Critical");
        levels.remove(level);

        WebElement filterDiv = driver.findElementById("vulnSearchDiv");
        return (filterDiv.findElement(By.id("show" + level)).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(0))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(1))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(2))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(3))).isSelected());
    }

    public boolean isProgressByVulnerabilityCountCorrect(int number) {
        return driver.findElements(By.cssSelector("#progressVulnsTable>tbody>tr")).size() == number;
    }
}
