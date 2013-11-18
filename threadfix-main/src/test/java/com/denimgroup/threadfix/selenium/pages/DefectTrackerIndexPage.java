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

import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class DefectTrackerIndexPage extends BasePage { 

	private WebElement nameInput;
	private WebElement urlInput;
	private Select defectTrackerTypeSelect;
	private WebElement addDefectTrackerButton;
	private List<WebElement> editButtons = new ArrayList<>();
//	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> names = new ArrayList<>();

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
//			deleteButtons.add(driver.findElementById("deleteButton" + i));
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
		sleep(1000);
		editButtons.get(getIndex(roleName)).click();
		sleep(1000);
		return new DefectTrackerIndexPage(driver);
	}
	/*
	public DefectTrackerIndexPage clickDeleteButton(String roleName) {
		//deleteButtons.get((getIndex(roleName)+1)).click();
		System.out.println("Deleting " + (getIndex(roleName)+1));
		driver.findElementById("deleteButton" + (getIndex(roleName)+1)).click();
		return new DefectTrackerIndexPage(driver);
	}
	*/
	
	public DefectTrackerIndexPage enterName(String oldName,String newName){
		if(oldName==null){
			driver.findElementsById("nameInput").get(names.size()).clear();
			driver.findElementsById("nameInput").get(names.size()).sendKeys(newName);
		}else{
			driver.findElementsById("nameInput").get(getIndex(oldName)).clear();
			driver.findElementsById("nameInput").get(getIndex(oldName)).sendKeys(newName);
		}
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage enterType(String oldName, String newType){
		if(oldName==null){
			new Select(driver.findElementsById("defectTrackerTypeSelect").get(names.size())).selectByVisibleText(newType);
		}else{
			new Select(driver.findElementsById("defectTrackerTypeSelect").get(getIndex(oldName))).selectByVisibleText(newType);
		}
		return new DefectTrackerIndexPage(driver);
	}
	
	
	public DefectTrackerIndexPage enterURL(String oldName, String newURL){
		if(oldName==null){
			driver.findElementsById("urlInput").get(names.size()).clear();
			driver.findElementsById("urlInput").get(names.size()).sendKeys(newURL);
		}else{
			driver.findElementsById("urlInput").get(getIndex(oldName)).clear();
			driver.findElementsById("urlInput").get(getIndex(oldName)).sendKeys(newURL);
		}
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickDeleteButton(String name){
////		for(int i = 0; i < getNumRows(); i ++){
//////			System.out.println(names.get(i).getText() + " and name = " + name);
////			if(name.equals(names.get(i).getText())){
////				//driver.findElementById("deleteButton" + (i + 1)).click();
//////				System.out.println("Got in here");
//////				driver.fin
//////				deleteButtons.get(i).click();
//				handleAlert();
//			}
//		}
		
		clickEditLink(name);
		sleep(500);
		driver.findElementById("deleteButton"+(getIndex(name)+1)).click();
		handleAlert();
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickCloseButton() {
		driver.findElementById("closeNewDTModalButton").click();
		return new DefectTrackerIndexPage(driver);
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
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage setNameInput(String text,int row){
		driver.findElementsById("nameInput").get(row).clear();
		driver.findElementsById("nameInput").get(row).sendKeys(text);
		return new DefectTrackerIndexPage(driver);
	}

	public String getUrlInput(){
		return urlInput.getText();
	}

	public DefectTrackerIndexPage setUrlInput(String text){
		driver.findElementById("urlInput").clear();
		driver.findElementById("urlInput").sendKeys(text);
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage setUrlInput(String text,int row){
		driver.findElementsById("urlInput").get(row).clear();
		driver.findElementsById("urlInput").get(row).sendKeys(text);
		return new DefectTrackerIndexPage(driver);
	}

	public String getDefectTrackerTypeSelect(){
		return defectTrackerTypeSelect.getFirstSelectedOption().getText();
	}

	public DefectTrackerIndexPage setDefectTrackerTypeSelect(String code){
		new Select(driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText(code);
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage setDefectTrackerTypeSelect(String code, int row){
		new Select(driver.findElementsById("defectTrackerTypeSelect").get(row)).selectByVisibleText(code);
		return new DefectTrackerIndexPage(driver);
	}

	public DefectTrackerIndexPage clickAddDefectTrackerButton() {
		addDefectTrackerButton.click();
		waitForElement(driver.findElementById("createDefectTracker"));
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickAddDefectTrackerButtonInvalid() {
		driver.findElementById("submitDTCreateModal").click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public String getNameErrorsText() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getUrlErrorsText() {
		sleep(2000);
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
		sleep(1000);
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
//		waitForInvisibleElement(driver.findElementByClassName("in"));
		sleep(3000);
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickUpdateDefectTrackerButtonInvalid(){
		driver.findElementByLinkText("Update Defect Tracker").click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public boolean doesNameExist(String name){
		for(int i = 1; i <= getNumRows(); i ++){
			try{
				if(name.equals(getNameText(i))){
					return true;
				}
			}catch(NoSuchElementException e){
				return false;
			}
		}
		return false;
	}
	
	public boolean doesTypeExistForName(String name, String type){
		for(int i = 1; i <= getNumRows(); i ++){
			if(name.equals(getNameText(i))){
				if(driver.findElementById("defectTrackerType" + i).getText().equals(type)){
					return true;
				}
			}
		}
		return false;
	}
	
	public boolean doesURLExistForName(String name, String url){
		for(int i = 1; i <= getNumRows(); i ++){
			if(name.equals(getNameText(i))){
				if(driver.findElementById("defectTrackerUrl" + i).getText().equals(url)){
					return true;
				}
			}
		}
		return false;
	}
}