////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class DefectTrackerEditPage extends BasePage { 

	private WebElement nameInput;
	private WebElement urlInput;
	private Select defectTrackerTypeSelect;
	private WebElement updateDefectTrackerButton;
	private WebElement cancelLink;

	public DefectTrackerEditPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("nameInput");
		urlInput = driver.findElementById("urlInput");
		defectTrackerTypeSelect = new Select(driver.findElementById("defectTrackerTypeSelect"));
		updateDefectTrackerButton = driver.findElementById("updateDefectTrackerButton");
		cancelLink = driver.findElementById("cancelLink");
	}

	public String getNameInput(){
		return nameInput.getText();
	}

	public DefectTrackerEditPage setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
		return this;
	}

	public String getUrlInput(){
		return urlInput.getText();
	}

	public DefectTrackerEditPage setUrlInput(String text){
		urlInput.clear();
		urlInput.sendKeys(text);
		return this;
	}

	public String getDefectTrackerTypeSelect(){
		return defectTrackerTypeSelect.getFirstSelectedOption().getText();
	}

	public DefectTrackerEditPage setDefectTrackerTypeSelect(String code){
		defectTrackerTypeSelect.selectByVisibleText(code);
		return this;
	}

	public DefectTrackerDetailPage clickUpdateDefectTrackerButton(boolean dealWithAlert) {
		updateDefectTrackerButton.click();
		
		if (dealWithAlert) {
			Alert alert = driver.switchTo().alert();
			alert.accept();
		}
		
		return new DefectTrackerDetailPage(driver);
	}
	
	public DefectTrackerIndexPage clickCancelLink() {
		cancelLink.click();
		return new DefectTrackerIndexPage(driver);
	}

	public DefectTrackerEditPage clickUpdateDefectTrackerButtonInvalid(boolean isAlertPresent) {
		updateDefectTrackerButton.click();
		
		if (isAlertPresent) {
			Alert alert = driver.switchTo().alert();
			alert.accept();
		}
		
		return new DefectTrackerEditPage(driver);
	}
	
	public String getNameErrorsText() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getUrlErrorsText() {
		return driver.findElementById("url.errors").getText();
	}

}