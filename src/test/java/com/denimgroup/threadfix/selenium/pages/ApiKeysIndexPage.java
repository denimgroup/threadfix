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

public class ApiKeysIndexPage extends BasePage {

	private List<WebElement> notes = new ArrayList<WebElement>();
	//private List<WebElement> restrictedBoxes = new ArrayList<WebElement>();
	private WebElement createNewKeyLink;

	public ApiKeysIndexPage(WebDriver webdriver) {
		super(webdriver);
		createNewKeyLink = driver.findElementByLinkText("Create New Key");
		for (int i = 1; i <= getNumRows(); i++) {
			notes.add(driver.findElementById("note" + i));
		}
	}

	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().equals("No keys found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public int getIndex(String roleName) {
		int i = -1;
		for (WebElement note : notes) {
			i++;
			String text = note.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}

	public String getKeyText(String note) {
		return driver.findElementById("key"+getIndex(note)).getText();
	}

	public ApiKeysIndexPage clickEdit(String note) {
		driver.findElementById("editKey"+(getIndex(note)+1)).click();
		waitForElement(driver.findElementsByClassName("modal").get(getIndex(note)));
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickNewLink() {
		createNewKeyLink.click();
		waitForElement(driver.findElementById("newKeyModalDiv"));
		return new ApiKeysIndexPage(driver);
	}
	

	public ApiKeysIndexPage clickDelete(String note) {
		driver.findElementsById("deleteButton").get(getIndex(note)).click();
		handleAlert();

		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickSubmitButton(String oldNote){
		if(oldNote == null){
			driver.findElementsById("submitKeyModal").get(getNumRows()).click();
		}else{
			driver.findElementsById("submitKeyModal").get(getIndex(oldNote)).click();
		}
		return new ApiKeysIndexPage(driver);
	}
	
	public ApiKeysIndexPage setNote(String newNote,String oldNote){
		if(oldNote==null){
			driver.findElementsById("note").get(getNumRows()).clear();
			driver.findElementsById("note").get(getNumRows()).sendKeys(newNote);	
		}else{
			driver.findElementsById("note").get(getIndex(oldNote)).clear();
			driver.findElementsById("note").get(getIndex(oldNote)).sendKeys(newNote);	
		}
		return new ApiKeysIndexPage(driver);
	}
	
	public ApiKeysIndexPage setRestricted(String oldNote){
		if(oldNote==null){
			driver.findElementById("isRestrictedKey"+(getNumRows()+1)).click();
		}else{
			driver.findElementById("isRestrictedKey"+(getIndex(oldNote)+1)).click();
		}
		return new ApiKeysIndexPage(driver);
	}
	
	public ApiKeysIndexPage waitModalDisappear(){
		waitForInvisibleElement(driver.findElementById("newKeyModalDiv"));
		return new ApiKeysIndexPage(driver);
	}
	
	public boolean isCreateValidationPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("API key was successfully created.");
	}
	
	public boolean isEditValidationPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("API key was successfully edited.");
	}
	
	public boolean isDeleteValidationPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("API key was successfully deleted.");
	}
	
	public boolean isNotePresent(String note){
		return getIndex(note) != -1;
	}
	
	public boolean isRestricted(String note){
		return driver.findElementById("restricted"+(getIndex(note)+1)).getText().trim().equals("true".trim());
	}
	
	public boolean isCorrectLength(String note){
		return notes.get(getIndex(note)).getText().trim().length()<=255;
	}
	

	
}
