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

public class DefectTrackerIndexPage extends BasePage { 

	private WebElement nameInput;
	private WebElement urlInput;
	private Select defectTrackerTypeSelect;
	private WebElement addDefectTrackerButton;
	private List<WebElement> editButtons = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> names = new ArrayList<WebElement>();

	public static String DT_URL = "http://10.2.10.145/bugzilla";
	public static String JIRA_URL = "https://threadfix.atlassian.net/";

	public DefectTrackerIndexPage(WebDriver webdriver) {
		super(webdriver);
		//nameInput = driver.findElementById("nameInput");
		//urlInput = driver.findElementById("urlInput");
		//defectTrackerTypeSelect = new Select(driver.findElementById("defectTrackerTypeSelect"));
		addDefectTrackerButton = driver.findElementById("addNewDTButton");
		
		for (int i = 1; i <= getNumRows(); i++) {
			editButtons.add(driver.findElementById("editDefectTracker" + i + "Button"));
			deleteButtons.add(driver.findElementById("deleteButton" + i));
			names.add(driver.findElementById("defectTrackerName" + i));
		}
	}

	
	public int getNumRows() {
		int size = driver.findElementsByClassName("bodyRow").size();
		if(isTextPresentInDefectTrackerTableBody("No Defect Trackers found")){
			return 0;
		}
		return size;
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

	public DefectTrackerIndexPage clickEditLink(String roleName) {
		editButtons.get(getIndex(roleName)).click();
		return this;
	}
	
	public DefectTrackerIndexPage clickDeleteByName(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		return this;
	}
	
	public DefectTrackerIndexPage clickCloseButton() {
		driver.findElementById("closeNewDTModalButton").click();
		return this;
	}
	
	
	public String getDefectTrackerName(int row){
		return driver.findElementById("defectTrackerName"+row).getText();
	}
	
	public String getNameInput(){
		return nameInput.getText();
	}

	public DefectTrackerIndexPage setNameInput(String text){
		driver.findElementById("nameInput").clear();
		driver.findElementById("nameInput").sendKeys(text);
		return this;
	}
	
	public DefectTrackerIndexPage setNameInput(String text,int row){
		driver.findElementsById("nameInput").get(row).clear();
		driver.findElementsById("nameInput").get(row).sendKeys(text);
		return this;
	}

	public String getUrlInput(){
		return urlInput.getText();
	}

	public DefectTrackerIndexPage setUrlInput(String text){
		driver.findElementById("urlInput").clear();
		driver.findElementById("urlInput").sendKeys(text);
		return this;
	}
	
	public DefectTrackerIndexPage setUrlInput(String text,int row){
		driver.findElementsById("urlInput").get(row).clear();
		driver.findElementsById("urlInput").get(row).sendKeys(text);
		return this;
	}

	public String getDefectTrackerTypeSelect(){
		return defectTrackerTypeSelect.getFirstSelectedOption().getText();
	}

	public DefectTrackerIndexPage setDefectTrackerTypeSelect(String code){
		new Select(driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText(code);
		return this;
	}
	
	public DefectTrackerIndexPage setDefectTrackerTypeSelect(String code, int row){
		new Select(driver.findElementsById("defectTrackerTypeSelect").get(row)).selectByVisibleText(code);
		return this;
	}

	public DefectTrackerIndexPage clickAddDefectTrackerButton() {
		addDefectTrackerButton.click();
		waitForElement(driver.findElementById("createDefectTracker"));
		return this;
	}
	
	public DefectTrackerIndexPage clickAddDefectTrackerButtonInvalid() {
		driver.findElementById("submitDTCreateModal").click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public String getNameErrorsText() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getUrlErrorsText() {
		return driver.findElementById("url.errors").getText();
	}

	public boolean isTextPresentInDefectTrackerTableBody(String newDefectTrackerName) {
		return driver.findElementById("defectTrackerTableBody").getText().contains(newDefectTrackerName);
	}

	public DefectTrackerIndexPage clickDeleteButton(int row) {
		driver.findElementById("deleteButton"+row).click();
		handleAlert();
		return new DefectTrackerIndexPage(driver);
	}

	public DefectTrackerIndexPage clickSaveNewDefectTracker() {
		driver.findElementById("submitDTCreateModal").click();
		waitForInvisibleElement(driver.findElementById("createDefectTracker"));
		return new DefectTrackerIndexPage(driver);
	}

	public String getNameText(int i) {
		return driver.findElementById("defectTrackerName"+i).getText();
	}
	
	public String getTypeText(int i) {
		return driver.findElementById("defectTrackerType"+i).getText();
	}

	public String getUrlText(int i) {
		return driver.findElementById("defectTrackerUrl"+i).getText();
	}
	
	public DefectTrackerIndexPage clickUpdateDefectTrackerButton(){
		driver.findElementByLinkText("Update Defect Tracker").click();
		waitForInvisibleElement(driver.findElementByClassName("modal"));
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickUpdateDefectTrackerButtonInvalid(){
		driver.findElementByLinkText("Update Defect Tracker").click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public boolean doesNameExist(String name){
		for(int i = 1; i < getNumRows(); i ++){
			if(name.equals(getNameText(i))){
				return true;
			}
		}
		return false;
	}
}