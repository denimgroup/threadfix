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
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;

public class AnalyticsPage extends BasePage {

	public AnalyticsPage(WebDriver webdriver) {
		super(webdriver);
	}

    /* _____________________ Action Methods _____________________ */

    public AnalyticsPage clickTrendingTab() {
        driver.findElementByLinkText("Trending").click();
        sleep(2500);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickSnapshotTab() {
        driver.findElementByLinkText("Snapshot").click();
        sleep(2500);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickVulnerabilitySearchTab() {
        driver.findElementByLinkText("Vulnerability Search").click();
        sleep(2500);
        return  new AnalyticsPage(driver);
    }

    public AnalyticsPage toggleAllFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("toggleAllButton")).click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage toggleAllFilterReport(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("toggleAllButtonReport")).click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clearFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("clearFiltersButton")).click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clearFilterReport(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("clearFiltersButtonReport")).click();
        sleep(1000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandTeamApplicationFilter(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("expandTeamAndApplicationFilters")).click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandTeamApplicationFilterReport(String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        filterDiv.findElement(By.id("expandTeamAndApplicationFiltersReport")).click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addTeamFilter(String teamName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement teamNameSpace = filterDiv.findElement(By.id("teamNameTypeahead"));
        filterDiv.findElement(By.id("showTeamInput")).click();
        teamNameSpace.clear();
        teamNameSpace.sendKeys(teamName);
        teamNameSpace.sendKeys(Keys.ENTER);
        waitForResultsToLoad();
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

    public AnalyticsPage addApplicationFilterReport(String appName, String divId) {
        WebElement filterDiv = driver.findElementById(divId);
        WebElement applicationNameSpace = filterDiv.findElement(By.id("applicationNameTypeaheadReport"));
        filterDiv.findElement(By.id("showApplicationInputReport")).click();
        applicationNameSpace.clear();
        applicationNameSpace.sendKeys(appName);
        applicationNameSpace.sendKeys(Keys.ENTER);
        waitForResultsToLoad();
        return new AnalyticsPage(driver);
    }

    /* _____________________ Set Methods _____________________ */

    /* _____________________ Get Methods _____________________ */

    public int getFilterDivHeight(String divId) {
        return driver.findElement(By.id(divId)).getSize().getHeight();
    }

    /* _____________________ Helper Methods _____________________ */

    public void waitForResultsToLoad() {
        while (driver.findElementById("vulnTreeLoadingSpinner").isDisplayed()) {
            sleep(1000);
        }
    }

    /* _____________________ Boolean Methods _____________________ */

    public boolean isVulnerabilityCountCorrect(String level, String expected) {
        return expected.equals(driver.findElementById("totalBadge" + level).getText().trim());
    }

    public boolean isSeverityLevelShown(String level) {
        return driver.findElementsById("totalBadge" + level).size() != 0;
    }

    public boolean areAllVulnerabilitiesHidden() {
        return driver.findElementById("noResultsFound").getText().trim().equals("No results found.");
    }

    public boolean isReportCorrect() {
        WebElement filterDiv = driver.findElementById("trendingFilterDiv");
        return filterDiv.findElement(By.id("toggleAllButtonReport")).isEnabled();
    }

    public boolean checkCorrectFilterLevel(String level) {
        ArrayList<String> levels = new ArrayList<String>();
        levels.add("Info"); levels.add("Low"); levels.add("Medium"); levels.add("High"); levels.add("Critical");
        levels.remove(level);

        WebElement filterDiv = driver.findElementById("vulnSearchFilterDiv");
        return (filterDiv.findElement(By.id("show" + level)).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(0))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(1))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(2))).isSelected() &&
                !filterDiv.findElement(By.id("show" + levels.get(3))).isSelected());
    }
}
