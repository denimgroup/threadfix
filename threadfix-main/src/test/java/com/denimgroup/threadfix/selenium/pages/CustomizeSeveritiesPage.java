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

import org.openqa.selenium.ElementNotVisibleException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

public class CustomizeSeveritiesPage extends BasePage {

    public CustomizeSeveritiesPage(WebDriver webDriver) {
        super(webDriver);
    }

    public CustomizeSeveritiesPage clickShowHideTab() {
        driver.findElementByLinkText("Show and Hide").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage waitForChanges() {
        sleep(300000);
        return this;
    }

    /*---------------------------- Severity Filter ----------------------------*/

    public CustomizeSeveritiesPage enableSeverityFilters() {
        if (driver.findElementById("enabledBox").getAttribute("checked") == null) {
            driver.findElementById("enabledBox").click();
        }
        sleep(1000);
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage disableSeverityFilters() {
        if (driver.findElementById("enabledBox").getAttribute("checked") != null) {
            driver.findElementById("enabledBox").click();
        }
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage closeSuccessNotification() {
        try {
            driver.findElementByClassName("close").click();
        } catch (ElementNotVisibleException e) {
            List<WebElement> elements = driver.findElementsByClassName("close");
            for (WebElement element : elements) {
                if (element.isDisplayed()) {
                    element.click();
                    break;
                }
            }
        }
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage saveFilterChanges() {
        driver.findElementById("submitSeverityFilterForm").click();
        waitForElement(driver.findElementById("severitySuccessMessage"));
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage showCritical() {
        driver.findElementById("showCritical1").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage hideCritical() {
        driver.findElementById("showCritical2").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage showHigh() {
        driver.findElementById("showHigh1").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage hideHigh() {
        driver.findElementById("showHigh2").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage showMedium() {
        driver.findElementById("showMedium1").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage hideMedium() {
        driver.findElementById("showMedium2").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage showLow() {
        driver.findElementById("showLow1").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage hideLow() {
        driver.findElementById("showLow2").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage showInfo() {
        driver.findElementById("showInfo1").click();
        return new CustomizeSeveritiesPage(driver);
    }

    public CustomizeSeveritiesPage hideInfo() {
        driver.findElementById("showInfo2").click();
        return new CustomizeSeveritiesPage(driver);
    }
    
}
