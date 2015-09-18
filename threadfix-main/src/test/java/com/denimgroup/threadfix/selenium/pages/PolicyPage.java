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

public class PolicyPage extends BasePage {

    public PolicyPage(WebDriver webDriver) { super(webDriver); }

    //===========================================================================================================
    // Procedure Methods
    //===========================================================================================================

    public PolicyPage createPolicy(String policyName, String filterName) {
        clickCreatePolicy()
                .setPolicyName(policyName)
                .setFilterForPolicy(filterName)
                .savePolicy();
        return this;
    }

    public PolicyPage createGenericFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickFieldControl("Critical")
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createNumberMergedFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickMergedFindingsThreePlus()
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createScannerFilter(String name, String scanner) {
        clickFiltersTab()
                .expandFilters()
                .setScannerFilter(scanner)
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createVulnerabilityFilter(String name, String vulnerability) {
        clickFiltersTab()
                .expandFilters()
                .setVulnerabilityFilter(vulnerability)
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createPathFilter(String name, String path) {
        clickFiltersTab()
                .expandFilters()
                .setPathFilter(path)
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createParameterFilter(String name, String parameter) {
        clickFiltersTab()
                .expandFilters()
                .setParameterFilter(parameter)
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createOpenFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickFieldControl("Open")
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createFalsePositiveFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickFieldControl("FalsePositive")
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createHiddenFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickFieldControl("Hidden")
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createAgingFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .clickMoreThan()
                .click90Days()
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    public PolicyPage createDateRangeFilter(String name) {
        clickFiltersTab()
                .expandFilters()
                .setDateRange("11-1-14", "1-1-15")
                .setFilterName(name)
                .clickPolicyTab();
        return new PolicyPage(driver);
    }

    //===========================================================================================================
    // Action Methods
    //===========================================================================================================

    public PolicyPage clickPolicyTab() {
        driver.findElementByLinkText("Policy").click();
        //This sleep is necessary; the page elements are all present upon page load but will
        //update shortly afterward, reverting any actions you make
        sleep(500);
        waitForElement(By.id("createNewModalButton"));
        return new PolicyPage(driver);
    }

    public PolicyPage clickFiltersTab() {
        driver.findElementByLinkText("Filters").click();
        //This sleep is necessary; the page elements are all present upon page load but will
        //update shortly afterward, reverting any actions you make
        sleep(500);
        waitForElement(By.id("saveFilterButton"));
        return new PolicyPage(driver);
    }

    public PolicyPage expandFilters() {
        if(driver.findElementById("toggleAllButton").getText().contains("Collapse")) {
            driver.findElementById("toggleAllButton").click();
            waitForInvisibleElement("showInfo");
        }
        driver.findElementById("toggleAllButton").click();
        waitForElement(By.id("showInfo"));
        return this;
    }

    public PolicyPage clickFieldControl(String label) {
        driver.findElementById("show" + label).click();
        return this;
    }

    public PolicyPage clickCreatePolicy() {
        waitForElement(By.id("policyTable"));
        driver.findElementById("createNewModalButton").click();
        waitForElement(By.id("policyCreateNameInput"));
        return new PolicyPage(driver);
    }

    public PolicyPage savePolicy() {
        driver.findElementById("submit").click();
        waitForInvisibleElement("myModalLabel");
        return new PolicyPage(driver);
    }

    public PolicyPage clickEditDeleteButton(String name) {
        driver.findElementById("editACModalButton" + name).click();
        waitForElement(By.id("deleteButton"));
        return new PolicyPage(driver);
    }

    public PolicyPage deletePolicy() {
        driver.findElementById("deleteButton").click();
        handleAlert();
        waitForInvisibleElement("myModalLabel");
        return new PolicyPage(driver);
    }

    public PolicyPage expandPolicy(String name) {
        waitForElement(By.id("policyCaret" + name));
        driver.findElementById("policyCaret" + name).click();
        waitForElement(By.cssSelector("#policyInfoDiv" + name + "[class*='expanded']"));
        return new PolicyPage(driver);
    }

    public PolicyPage addAppToPolicy(String policyName, String appName) {
        driver.findElementById("applicationNameTypeahead" + policyName).clear();
        driver.findElementById("applicationNameTypeahead" + policyName).sendKeys(appName);
        driver.findElementById("applicationNameTypeahead" + policyName).sendKeys(Keys.ENTER);
        driver.findElementById("submitButton" + policyName).click();
        return new PolicyPage(driver);
    }

    public PolicyPage removeAppFromPolicy(String policyName, String appName) {
        driver.findElementByCssSelector("#policy" + policyName + "AppRow" + appName + " #deleteButton" + appName).click();
        return new PolicyPage(driver);
    }

    public PolicyPage clickAddEmailsButton(String policyName) {
        tryClick(By.id("addEmailModalButton" + policyName));
        return new PolicyPage(driver);
    }

    public PolicyPage addEmailAddress(String address) {
        driver.findElementById("emailInput").clear();
        driver.findElementById("emailInput").sendKeys(address);
        driver.findElementById("addEmailButton").click();
        return this;
    }

    public PolicyPage addEmailList(String list) {
        new Select(driver.findElementById("emailListSelect")).selectByVisibleText(list);
        driver.findElementById("addEmailListButton").click();
        return this;
    }

    public PolicyPage clickAddEmailsButtonForApp(String appName, String policyName) {
        driver.findElementByCssSelector("#policy" + policyName + "AppRow" + appName + " #addEmailModalButton" + appName).click();
        return new PolicyPage(driver);
    }

    public PolicyPage clickMergedFindingsThreePlus() {
        driver.findElementByCssSelector("#set3MergedFindings>a").click();
        return this;
    }

    public PolicyPage clickSaveFilterButton() {
        driver.findElementById("saveFilterButton").click();
        return this;
    }

    public PolicyPage clickLessThan() {
        driver.findElementByCssSelector("#lessThan>a").click();
        return this;
    }

    public PolicyPage clickMoreThan() {
        driver.findElementByCssSelector("#moreThan>a").click();
        return this;
    }

    public PolicyPage click90Days() {
        driver.findElementByCssSelector("#ninetyDays>a").click();
        return this;
    }

    //===========================================================================================================
    // Set Methods
    //===========================================================================================================

    public PolicyPage setPolicyName(String name) {
        driver.findElementById("policyCreateNameInput").clear();
        driver.findElementById("policyCreateNameInput").sendKeys(name);
        return this;
    }

    public PolicyPage setFilterForPolicy(String name) {
        //TODO: Replace CSS lookup with ID when unique ID is added
        new Select(driver.findElementByCssSelector(".modal-form-table #filterSelect")).selectByVisibleText(name);
        return this;
    }

    public PolicyPage setFilterName(String name) {
        //TODO: Replace LinkText with ID when ID is added to success alert
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(name);
        driver.findElementById("saveFilterButton").click();
        waitForElement(By.linkText("Update Saved Filter"));
        return this;
    }

    public PolicyPage selectFilterToEdit(String name) {
        new Select(driver.findElementByCssSelector("div.saved-filters-tab>#filterSelect")).selectByVisibleText(name);
        return this;
    }

    public PolicyPage setScannerFilter(String scanner) {
        driver.findElementById("showScannerInput").click();
        driver.findElementById("scannerTypeahead").sendKeys(scanner);
        driver.findElementById("scannerTypeahead").sendKeys(Keys.ENTER);
        return this;
    }

    public PolicyPage setVulnerabilityFilter(String vulnerability) {
        driver.findElementById("showTypeInput").click();
        driver.findElementById("vulnerabilityTypeTypeahead").sendKeys(vulnerability);
        driver.findElementById("vulnerabilityTypeTypeahead").sendKeys(Keys.ENTER);
        return this;
    }

    public PolicyPage setPathFilter(String path) {
        driver.findElementById("pathInput").sendKeys(path);
        driver.findElementById("pathInput").sendKeys(Keys.ENTER);
        return this;
    }

    public PolicyPage setParameterFilter(String paramter) {
        driver.findElementById("parameterFilterInput").sendKeys(paramter);
        driver.findElementById("parameterFilterInput").sendKeys(Keys.ENTER);
        return this;
    }

    public PolicyPage setDateRange(String startDate, String endDate) {
        driver.findElementById("startDateInput").sendKeys(startDate);
        driver.findElementById("endDateInput").sendKeys(endDate);
        return this;
    }

    //===========================================================================================================
    // Get Methods
    //===========================================================================================================

    public String getEmailError() { return driver.findElementById("emailErrors").getText(); }

    public String getEmailListError() { return driver.findElementById("emailListErrors").getText(); }

    //===========================================================================================================
    // Boolean Methods
    //===========================================================================================================

    public boolean isPolicyPresent(String name) {
        return isElementPresent("policyName" + name);
    }

    public boolean isPolicyNameCorrect(String name) {
        return driver.findElementById("policyName" + name).getText().contains(name);
    }

    public boolean isPolicyFilterCorrect(String policyName, String filterName) {
        return driver.findElementById("policyFilter" + policyName).getText().contains(filterName);
    }

    public boolean isPolicyPassing(String name) {
        return driver.findElementById("policyPass" + name).getText().contains("PASS");
    }

    public boolean isAppPresent(String policyName, String appName) {
        try {
            waitForElement(By.cssSelector("#policy" + policyName + "AppRow" + appName));
            return true;
        } catch (TimeoutException e) {
            return false;
        }
    }

    public boolean isEmailPresent(String email) {
        if (driver.findElementById("emailExpanded").getAttribute("class").contains("expanded")) {
            driver.findElementById("caretEmail").click();
        }
        driver.findElementById("caretEmail").click();
        return isElementPresent(getIdForEmail(email));
    }

    public boolean isEmailListPresent(String list) {
        if (driver.findElementById("emailListExpanded").getAttribute("class").contains("expanded")) {
            driver.findElementById("acceptcriteriaCaretEmailList").click();
        }
        driver.findElementById("acceptcriteriaCaretEmailList").click();
        return isElementPresent("emailList" + list);
    }

    public boolean isSubmitDisabled() {
        return driver.findElementById("submit").getAttribute("class").contains("disabled");
    }

    public boolean isNameRequiredErrorDisplayed() {
            return !driver.findElementById("nameRequiredError").getAttribute("class").contains("ng-hide");
    }

    public boolean isLengthErrorDisplayed() {
        return !driver.findElementById("characterLimitError").getAttribute("class").contains("ng-hide");
    }

    public boolean canSaveDuplicatePolicy() {
        try {
            driver.findElementById("submit").click();
            waitForElement(By.cssSelector("#otherNameError:not(.ng-hide)"));
            return false;
        } catch (TimeoutException e) {
            return true;
        }
    }

    public boolean isAppPassing(String appName) {
        return tryGetText(By.cssSelector("#policyStatus" + appName + ":not(.ng-hide)")).contains("PASS");
    }

    //===========================================================================================================
    // Helper Methods
    //===========================================================================================================

    public String getIdForEmail(String email) {
        return "email" + email.replace("@", "").replace(".", "");
    }
}
