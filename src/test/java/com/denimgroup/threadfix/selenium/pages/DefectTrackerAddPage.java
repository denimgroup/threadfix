////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class DefectTrackerAddPage extends BasePage { 

	private WebElement nameInput;
	private WebElement urlInput;
	private Select defectTrackerTypeSelect;
	private WebElement addDefectTrackerButton;
	private List<WebElement> editButtons = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> names = new ArrayList<WebElement>();

	public DefectTrackerAddPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("nameInput");
		urlInput = driver.findElementById("urlInput");
		defectTrackerTypeSelect = new Select(driver.findElementById("defectTrackerTypeSelect"));
		addDefectTrackerButton = driver.findElementById("addNewDTButton");
		
		for (int i = 1; i <= getNumRows(); i++) {
			editButtons.add(driver.findElementById("editDefectTracker" + i + "Button"));
			deleteButtons.add(driver.findElementById("deleteButton" + i));
			names.add(driver.findElementById("name" + i));
		}
	}

	public int getNumRows() {
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	private int getIndex(String roleName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}

	public DefectTrackerAddPage clickEditLink(String roleName) {
		editButtons.get(getIndex(roleName)).click();
		return this;
	}
	
	public String getNameInput(){
		return nameInput.getText();
	}

	public DefectTrackerAddPage setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
		return this;
	}

	public String getUrlInput(){
		return urlInput.getText();
	}

	public DefectTrackerAddPage setUrlInput(String text){
		urlInput.clear();
		urlInput.sendKeys(text);
		return this;
	}

	public String getDefectTrackerTypeSelect(){
		return defectTrackerTypeSelect.getFirstSelectedOption().getText();
	}

	public DefectTrackerAddPage setDefectTrackerTypeSelect(String code){
		defectTrackerTypeSelect.selectByVisibleText(code);
		return this;
	}

	public DefectTrackerAddPage clickAddDefectTrackerButton() {
		addDefectTrackerButton.click();
		return this;
	}
	
	public DefectTrackerAddPage clickAddDefectTrackerButtonInvalid() {
		addDefectTrackerButton.click();
		return new DefectTrackerAddPage(driver);
	}
	
	public String getNameErrorsText() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getUrlErrorsText() {
		return driver.findElementById("url.errors").getText();
	}
}