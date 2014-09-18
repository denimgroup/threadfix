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
import org.openqa.selenium.support.ui.Select;

public class AnalyticsPage extends BasePage {

	public AnalyticsPage(WebDriver webdriver) {
		super(webdriver);
	}

    /* _____________________ Action Methods _____________________ */
    public AnalyticsPage clickTrendingTab() {
        driver.findElementByLinkText("Trending").click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickSnapshotTab() {
        driver.findElementByLinkText("Snapshot").click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickComparisonTab() {
        driver.findElementByLinkText("Comparison").click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickVulnerabilitySearchTab() {
        driver.findElementByLinkText("Vulnerability Search").click();
        return  new AnalyticsPage(driver);
    }

    public AnalyticsPage toggleAllFilter() {
        driver.findElementById("toggleAllButton").click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clearFilter() {
        driver.findElementById("clearFiltersButton").click();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage expandTeamApplicationFilter() {
        driver.findElementById("expandTeamAndApplicationFilters").click();
        sleep(2000);
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addTeamFilter(String teamName) {
        driver.findElementById("showTeamInput").click();
        driver.findElementById("teamNameTypeahead").clear();
        driver.findElementById("teamNameTypeahead").sendKeys(teamName);
        driver.findElementById("teamNameTypeahead").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage addApplicationFilter(String appName) {
        driver.findElementById("showApplicationInput").click();
        driver.findElementById("applicationNameTypeahead").clear();
        driver.findElementById("applicationNameTypeahead").sendKeys(appName);
        driver.findElementById("applicationNameTypeahead").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
        return new AnalyticsPage(driver);
    }

    public AnalyticsPage clickCloseVulnerabilityButton() {
        driver.findElementById("closeVulnerabilityLink").click();
        return new AnalyticsPage(driver);
    }

    /* _____________________ Set Methods _____________________ */

    /* _____________________ Get Methods _____________________ */
    public int getFilterDivHeight() {
        return driver.findElement(By.className("filter-controls")).getSize().getHeight();
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

    public boolean areAllVulnerabilitiesHidden() {
        return driver.findElementById("noResultsFound").getText().trim().equals("No results found.");
    }

    public boolean isReportCorrect(String report) {
        Select reportSelection = new Select(driver.findElementById("reportSelect"));
        return reportSelection.getFirstSelectedOption().getText().equals(report);
    }


}
