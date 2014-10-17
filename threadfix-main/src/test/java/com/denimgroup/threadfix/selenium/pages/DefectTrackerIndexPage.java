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
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

import javax.annotation.Nonnull;

public class DefectTrackerIndexPage extends BasePage {

	public DefectTrackerIndexPage(@Nonnull WebDriver webdriver) {
		super(webdriver);
	}

    /*----------------------------------- Action Methods -----------------------------------*/

	public DefectTrackerIndexPage clickEditLink(String defectTrackerName) {
		waitForElement(driver.findElementById("editDefectTrackerButton" + defectTrackerName));
        driver.findElementById("editDefectTrackerButton" + defectTrackerName).click();
        waitForElement(driver.findElementById("myModalLabel"));
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage setName(String newName){
        driver.findElementById("nameInput").clear();
        driver.findElementById("nameInput").sendKeys(newName);
		return this;
	}
	
	public DefectTrackerIndexPage setType(String newType){
		new Select(driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText(newType);
		return this;
	}
	
	public DefectTrackerIndexPage setURL(String newURL){
			driver.findElementById("urlInput").clear();
			driver.findElementById("urlInput").sendKeys(newURL);
		return this;
	}
	
	public DefectTrackerIndexPage clickDeleteButton(){
		driver.findElementById("deleteButton").click();
		handleAlert();
        sleep(1000);
		return new DefectTrackerIndexPage(driver);
	}

	public DefectTrackerIndexPage clickAddDefectTrackerButton() {
		driver.findElementById("addNewDTButton").click();
		waitForElement(driver.findElementById("submit"));
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickAddDefectTrackerButtonInvalid() {
		driver.findElementById("submit").click();
		return new DefectTrackerIndexPage(driver);
	}

    public DefectTrackerIndexPage clickSaveDefectTracker() {
        driver.findElementById("submit").click();

        WebDriverWait wait = new WebDriverWait(driver, 60);
        wait.until(ExpectedConditions.visibilityOf(driver.findElementByClassName("alert-success")));

        return new DefectTrackerIndexPage(driver);
    }

    public DefectTrackerIndexPage clickSaveDefectTrackerErrorExpected() {
        driver.findElementById("submit").click();
        waitForElement(driver.findElementById("nameServerError"));
        return new DefectTrackerIndexPage(driver);
    }

    public DefectTrackerSchedulePage clickScheduleUpdateTab() {
            String linkText = driver.findElementById("scheduledUpdateTab").getAttribute("heading");
            driver.findElementByLinkText(linkText).click();
            waitForElement(driver.findElementById("addUpdateQueueLink"));
            return new DefectTrackerSchedulePage(driver);
    }

	public String getNameRequiredErrorsText() {
		return driver.findElementById("nameRequiredError").getText();
	}

    public String getNameDuplicateErrorsText() {
        return driver.findElementById("nameServerError").getText();
    }

	public String getUrlErrorsText() {
		sleep(2000);
		return driver.findElementById("url.errors").getText();
	}

    public String getSuccessMessage(){
        return driver.findElementByClassName("alert-success").getText();
    }

    /*----------------------------------- Boolean Methods -----------------------------------*/

	public boolean isTextPresentInDefectTrackerTableBody(String newDefectTrackerName) {
        waitForElement(driver.findElementById("addNewDTButton"));
		return driver.findElementById("defectTrackerTableBody").getText().contains(newDefectTrackerName);
	}

    public boolean isNamePresent(String name) {
        return driver.findElementById("defectTrackerName" + name).getText().contains(name);
    }

    public boolean isUrlCorrect(String url, String name) {
        return driver.findElementById("defectTrackerUrl" + name).getText().contains(url);
    }

    public boolean isTypeCorrect(String type, String name) {
        return driver.findElementById("defectTrackerType" + name).getText().contains(type);
    }

    public boolean isCreateNewTrackerButtonPresent() {
        return driver.findElementById("addNewDTButton").isDisplayed();


    }
}