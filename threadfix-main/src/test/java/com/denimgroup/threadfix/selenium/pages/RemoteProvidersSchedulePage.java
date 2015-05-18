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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class RemoteProvidersSchedulePage extends BasePage{

    public RemoteProvidersSchedulePage(WebDriver webDriver) {
        super(webDriver);
    }

    /*------------------------------ Action Methods ------------------------------*/

    public RemoteProvidersSchedulePage clickScheduleNewImportButton() {
        driver.findElementById("addImportQueueLink").click();
        waitForElement(driver.findElementById("submit"));
        return new RemoteProvidersSchedulePage(driver);
    }

    public RemoteProvidersIndexPage clickRemoteProvidersTab() {
        driver.findElementById("remoteProvidersTab").click();
        return new RemoteProvidersIndexPage(driver);
    }

    /*------------------------------ Set Methods ------------------------------*/

    public RemoteProvidersSchedulePage setFrequency(String frequency) {
        new Select(driver.findElementById("frequency")).selectByVisibleText(frequency);
        return this;
    }

    public RemoteProvidersSchedulePage setHour(int hour) {
        new Select(driver.findElementById("hour")).selectByVisibleText(Integer.toString(hour));
        return this;
    }

    public RemoteProvidersSchedulePage setMinute(int minute) {
        new Select(driver.findElementById("minute")).selectByVisibleText(Integer.toString(minute));
        return this;
    }

    public RemoteProvidersSchedulePage setPeriodOfDay(String periodOfDay) {
        new Select(driver.findElementById("selectedPeriod")).selectByVisibleText(periodOfDay);
        return this;
    }

    public RemoteProvidersSchedulePage setDay(String day) {
        new Select(driver.findElementById("selectedDay")).selectByVisibleText(day);
        return this;
    }

    public RemoteProvidersSchedulePage clickAddScheduledUpdated() {
        driver.findElementById("submit").click();
        return new RemoteProvidersSchedulePage(driver);
    }

    public DefectTrackerSchedulePage clickDeleteDefectTrackerButton(String expectedId) {
        driver.findElementById("scheduledImportDeleteButton" + expectedId).click();
        handleAlert();
        return new DefectTrackerSchedulePage(driver);
    }

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isNewImportButtonDisplayed() {
        return driver.findElementById("addImportQueueLink").isDisplayed();
    }

    public boolean isNewSchedulePresent(String expectedTime) {
        return driver.findElementById("scheduledImportDay" + expectedTime).isDisplayed();
    }

    public boolean isErrorPresent(String errorMessage) {
        return driver.findElementByClassName("errors").getText().trim().contains(errorMessage);
    }

    public boolean isDeleteButtonPresent(String elementId) {
        return driver.findElementsById("scheduledImportDeleteButton" + elementId).size() !=0;
    }
}
