////////////////////////////////////////////////////////////////////////
//
//     Copyright (c)  9- 3 Denim Group, Ltd.
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
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class FilterPage extends BasePage {

    public FilterPage(WebDriver webDriver) {
        super(webDriver);
    }

    /*---------------------------- Vulnerability Filter ----------------------------*/
    public FilterPage clickCreateNewFilter() {
        WebDriverWait wait = new WebDriverWait(driver, 60);
        wait.until(ExpectedConditions.visibilityOf(driver.findElementById("createNewKeyModalButton")));
        driver.findElementById("createNewKeyModalButton").click();
        return new FilterPage(driver);
    }

    public FilterPage setVulnerabilityType(String vulnerabilityType) {
        waitForElement(driver.findElementById("sourceGenericVulnerability.name"));
        driver.findElementById("sourceGenericVulnerability.name").sendKeys(vulnerabilityType);
        return new FilterPage(driver);
    }

    public FilterPage setSeverity(String severity) {
        new Select(driver.findElementById("targetGenericSeverity.id")).selectByVisibleText(severity);
        return new FilterPage(driver);
    }

    public FilterPage clickAddFilter() {
        driver.findElementById("submit").click();
        return new FilterPage(driver);
    }

    public FilterPage addVulnerabilityFilter(String vulnerabilityType, String severity) {
        setVulnerabilityType(vulnerabilityType)
                .setSeverity(severity)
                .clickAddFilter();
        sleep(1500);
        return new FilterPage(driver);
    }

    public FilterPage deleteFilter() {
        driver.findElementById("edit0").findElement(By.className("btn")).click();
        driver.findElementById("deleteButton").click();

        Alert alert = driver.switchTo().alert();
        alert.accept();

        waitForElement(driver.findElementByClassName("alert-success"));
        return new FilterPage(driver);
    }

    /*---------------------------- Severity Filter ----------------------------*/
    public FilterPage enableSeverityFilters() {
        if (driver.findElementById("enabledBox").getAttribute("checked") == null) {
            driver.findElementById("enabledBox").click();
        }
        sleep(1000);
        return new FilterPage(driver);
    }

    public FilterPage disableSeverityFilters() {
        if (driver.findElementById("enabledBox").getAttribute("checked") != null) {
            driver.findElementById("enabledBox").click();
        }
        return new FilterPage(driver);
    }

    public FilterPage closeSuccessNotification() {
        driver.findElementByClassName("close").click();
        return new FilterPage(driver);
    }

    public FilterPage saveFilterChanges() {
        driver.findElementById("submitSeverityFilterForm").click();
        waitForElement(driver.findElementById("severitySuccessMessage"));
        return new FilterPage(driver);
    }

    public FilterPage showCritical() {
        driver.findElementById("showCritical1").click();
        return new FilterPage(driver);
    }

    public FilterPage hideCritical() {
        driver.findElementById("showCritical2").click();
        return new FilterPage(driver);
    }

    public FilterPage showHigh() {
        driver.findElementById("showHigh1").click();
        return new FilterPage(driver);
    }

    public FilterPage hideHigh() {
        driver.findElementById("showHigh2").click();
        return new FilterPage(driver);
    }

    public FilterPage showMedium() {
        driver.findElementById("showMedium1").click();
        return new FilterPage(driver);
    }

    public FilterPage hideMedium() {
        driver.findElementById("showMedium2").click();
        return new FilterPage(driver);
    }

    public FilterPage showLow() {
        driver.findElementById("showLow1").click();
        return new FilterPage(driver);
    }

    public FilterPage hideLow() {
        driver.findElementById("showLow2").click();
        return new FilterPage(driver);
    }

    public FilterPage showInfo() {
        driver.findElementById("showInfo1").click();
        return new FilterPage(driver);
    }

    public FilterPage hideInfo() {
        driver.findElementById("showInfo2").click();
        return new FilterPage(driver);
    }

    /*---------------------------- Page Methods ----------------------------*/
    public FilterPage waitForChanges() {
        sleep(300000);
        return this;
    }

    /*---------------------------- Boolean Methods ----------------------------*/

    public boolean isCreateNewFilterPresent() {
        return driver.findElementById("createNewKeyModalButton").isDisplayed();
    }

    public boolean isSuccessMessagePresent() {
        return driver.findElementsById("vulnFiltersSuccessMessage").size() != 0;
    }

    public boolean isVulnerabilityTypeFound() {
        return driver.findElementsById("genericVulnerabilityNameError").size() == 0;
    }

    public boolean isAccessDenied() {
        return driver.findElementById("main-content").getText().contains("Access Denied");
    }
}
