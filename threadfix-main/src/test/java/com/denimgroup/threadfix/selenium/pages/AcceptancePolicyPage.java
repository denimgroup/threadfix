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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class AcceptancePolicyPage extends BasePage {

    public AcceptancePolicyPage(WebDriver webDriver) { super(webDriver); }

    /*------------------------------------ Utility Methods ------------------------------------*/

    public AcceptancePolicyPage clickAcceptancePolicyTab() {
        driver.findElementByLinkText("Acceptance Criteria").click();
        waitForElement(driver.findElementById("createNewModalButton"));
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage clickFiltersTab() {
        driver.findElementByLinkText("Filters").click();
        waitForElement(driver.findElementById("saveFilterButton"));
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage expandFieldControls() {
        driver.findElementById("showFieldControls").click();
        waitForElement(driver.findElementById("showInfo"));
        return this;
    }

    public AcceptancePolicyPage clickFieldControl(String label) {
        driver.findElementById("show" + label).click();
        return this;
    }

    public AcceptancePolicyPage setFilterName(String name) {
        //TODO: Replace LinkText with ID when ID is added to success alert
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(name);
        driver.findElementById("saveFilterButton").click();
        waitForElement(driver.findElementByLinkText("Update Saved Filter"));
        return this;
    }

    public AcceptancePolicyPage createGenericFilter(String name) {
        //TODO: When DGTF-1868 is resolved replace refreshPage with clickAcceptancePolicyTab
        clickFiltersTab()
                .expandFieldControls()
                .clickFieldControl("Critical")
                .setFilterName(name)
                .refreshPage();
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage clickCreateAcceptancePolicy() {
        driver.findElementById("createNewModalButton").click();
        waitForElement(driver.findElementById("acCreateNameInput"));
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage setAcceptancePolicyName(String name) {
        driver.findElementById("acCreateNameInput").clear();
        driver.findElementById("acCreateNameInput").sendKeys(name);
        return this;
    }

    public AcceptancePolicyPage setFilterForPolicy(String name) {
        //TODO: Replace CSS lookup with ID when unique ID is added
        driver.findElementByCssSelector(".modal-form-table #filterSelect").sendKeys(name);
        new Select(driver.findElementByCssSelector(".modal-form-table #filterSelect")).selectByVisibleText(name);
        return this;
    }

    public AcceptancePolicyPage saveAcceptancePolicy() {
        driver.findElementById("submit").click();
        waitForInvisibleElement("myModalLabel");
        //TODO: Remove screenshot after testing
        takeScreenShot();
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage createAcceptancePolicy(String policyName, String filterName) {
        clickCreateAcceptancePolicy()
                .setAcceptancePolicyName(policyName)
                .setFilterForPolicy(filterName)
                .saveAcceptancePolicy();
        return this;
    }

    public AcceptancePolicyPage clickEditDeleteButton(String name) {
        driver.findElementById("editACModalButton" + name).click();
        waitForElement(driver.findElementById("deleteButton"));
        return new AcceptancePolicyPage(driver);
    }

    public AcceptancePolicyPage deletePolicy() {
        driver.findElementById("deleteButton").click();
        handleAlert();
        waitForInvisibleElement("myModalLabel");
        return new AcceptancePolicyPage(driver);
    }

    /*------------------------------------ Boolean Methods ------------------------------------*/

    public boolean isPolicyPresent(String name) {
        return isElementPresent("acceptcriteriaName" + name);
    }

    public boolean isPolicyNameCorrect(String name) {
        return driver.findElementById("acceptcriteriaName" + name).getText().contains(name);
    }

    public boolean isPolicyFilterCorrect(String name) {
        return driver.findElementById("acceptcriteriaFilter" + name).getText().contains(name);
    }

    public boolean isPolicyPassing(String name) {
        return driver.findElementById("acceptcriteriaPass" + name).getText().contains("PASS");
    }

}
