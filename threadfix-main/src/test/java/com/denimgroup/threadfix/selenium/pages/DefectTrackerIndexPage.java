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

import org.jetbrains.annotations.NotNull;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class DefectTrackerIndexPage extends BasePage {

	public static String DT_URL = "http://10.2.10.145/bugzilla";
	public static String JIRA_URL = "https://threadfix.atlassian.net/";

	public DefectTrackerIndexPage(@NotNull WebDriver webdriver) {
		super(webdriver);
	}

	public DefectTrackerIndexPage clickEditLink(String roleName) {
		waitForElement(driver.findElementById("editDefectTrackerButton" + roleName));
        driver.findElementById("editDefectTrackerButton" + roleName).click();
        waitForElement(driver.findElementById("myModalLabel"));
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage enterName(String newName){
        driver.findElementById("nameInput").clear();
        driver.findElementById("nameInput").sendKeys(newName);
		return this;
	}
	
	public DefectTrackerIndexPage enterType(String newType){
		new Select(driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText(newType);
		return this;
	}
	
	public DefectTrackerIndexPage enterURL(String newURL){
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

	public boolean isTextPresentInDefectTrackerTableBody(String newDefectTrackerName) {
		return driver.findElementById("defectTrackerTableBody").getText().contains(newDefectTrackerName);
	}

	public DefectTrackerIndexPage clickSaveDefectTracker() {
		driver.findElementById("submit").click();
		WebDriverWait wait = new WebDriverWait(driver, 60);
        wait.until(ExpectedConditions.visibilityOf(driver.findElementByClassName("alert-success")));
		sleep(5000);
        return new DefectTrackerIndexPage(driver);
	}

}