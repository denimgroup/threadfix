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
    // Action Methods
    //===========================================================================================================

    public PolicyPage clickPolicyTab() {
        driver.findElementByLinkText("Policy").click();
        waitForElement(By.id("createNewModalButton"));
        return new PolicyPage(driver);
    }

    public PolicyPage clickFiltersTab() {
        driver.findElementByLinkText("Filters").click();
        waitForElement(By.id("saveFilterButton"));
        return new PolicyPage(driver);
    }

    public PolicyPage expandFieldControls() {
        driver.findElementById("showFieldControls").click();
        waitForElement(By.id("showInfo"));
        return this;
    }

    public PolicyPage clickFieldControl(String label) {
        driver.findElementById("show" + label).click();
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

    public PolicyPage createGenericFilter(String name) {
        //TODO: When DGTF-1868 is resolved replace refreshPage with clickPolicyTab
        clickFiltersTab()
                .expandFieldControls()
                .clickFieldControl("Critical")
                .setFilterName(name)
                .refreshPage();
        return new PolicyPage(driver);
    }

    public PolicyPage clickCreatePolicy() {
        waitForElement(By.id("policyTable"));
        driver.findElementById("createNewModalButton").click();
        waitForElement(By.id("policyCreateNameInput"));
        return new PolicyPage(driver);
    }

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

    public PolicyPage savePolicy() {
        driver.findElementById("submit").click();
        waitForInvisibleElement("myModalLabel");
        return new PolicyPage(driver);
    }

    public PolicyPage createPolicy(String policyName, String filterName) {
        clickCreatePolicy()
                .setPolicyName(policyName)
                .setFilterForPolicy(filterName)
                .savePolicy();
        return this;
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
        driver.findElementById("addEmailModalButton" + policyName).click();
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
        driver.findElementByCssSelector("#ac" + policyName + "AppRow" + appName + " #addEmailModalButton" + appName).click();
        return new PolicyPage(driver);
    }

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

    //===========================================================================================================
    // Get Methods
    //===========================================================================================================

    public String getIdForEmail(String email) {
        return "email" + email.replace("@", "").replace(".", "");
    }
}
