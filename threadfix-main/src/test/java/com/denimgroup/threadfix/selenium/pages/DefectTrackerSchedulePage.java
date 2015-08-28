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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;


/**
 * Created by mghanizadeh on 9/18/2014.
 */
public class DefectTrackerSchedulePage extends BasePage{
    public DefectTrackerSchedulePage(WebDriver webDriver) {
        super(webDriver);
    }

    //===========================================================================================================
    // Action Methods
    //===========================================================================================================

    public DefectTrackerSchedulePage clickScheduleNewUpdateTab() {
        driver.findElementById("addUpdateQueueLink").click();
        waitForElement(By.id("submit"));
        return new DefectTrackerSchedulePage(driver);
    }

    public DefectTrackerSchedulePage clickDeleteDefectTrackerButton(String expectedId) {
        driver.findElementById("scheduledUpdateDeleteButton" + expectedId).click();
        handleAlert();
        return new DefectTrackerSchedulePage(driver);
    }

    //TODO Refactor when issue #618 is resolved
    public DefectTrackerSchedulePage clickAddScheduledUpdated() {
        driver.findElementById("submit").click();
        sleep(2000);
        return this;
    }

    //===========================================================================================================
    // Set Methods
    //===========================================================================================================

    public DefectTrackerSchedulePage setFrequency(String frequency) {
        new Select(driver.findElementById("frequency")).selectByVisibleText(frequency);
        return this;
    }

    public DefectTrackerSchedulePage setHour(int hour) {
        new Select(driver.findElementById("hour")).selectByVisibleText(Integer.toString(hour));
        return this;
    }

    public DefectTrackerSchedulePage setMinute(int minute) {
        new Select(driver.findElementById("minute")).selectByVisibleText(Integer.toString(minute));
        return this;
    }

    public DefectTrackerSchedulePage setPeriodOfDay(String periodOfDay) {
        new Select(driver.findElementById("selectedPeriod")).selectByVisibleText(periodOfDay);
        return this;
    }

    public DefectTrackerSchedulePage setDay(String dateSelecting) {
        new Select(driver.findElementById("selectedDay")).selectByVisibleText(dateSelecting);
        return this;
    }

    //===========================================================================================================
    // Boolean Methods
    //===========================================================================================================

    public boolean isNewSchedulePresent(String expectedTime) {
        return driver.findElementById("scheduledUpdateDay" + expectedTime).isDisplayed();
    }

    public boolean isErrorPresent(String errorMessage) {
        return driver.findElementById("dateError").getText().trim().contains(errorMessage);
    }

    public boolean isDeleteButtonPresent(String elementId) {
        return driver.findElementsById("scheduledUpdateDeleteButton" + elementId).size() !=0;
    }

    //===========================================================================================================
    // Helper Methods
    //===========================================================================================================

    public DefectTrackerSchedulePage waitForErrorMessage() {
        waitForElement(By.cssSelector("#dateError:not(.ng-hide)"));
        return new DefectTrackerSchedulePage(driver);
    }

}
