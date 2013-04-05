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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class ApiKeysIndexPage extends BasePage {

	private List<WebElement> keys = new ArrayList<WebElement>();
	private List<WebElement> notes = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();
	private List<WebElement> deleteButton = new ArrayList<WebElement>();
	private List<WebElement> restrictedBoxes = new ArrayList<WebElement>();
	private WebDriverWait wait = new WebDriverWait(driver,10);
	private WebElement createNewKeyLink;

	public ApiKeysIndexPage(WebDriver webdriver) {
		super(webdriver);
		createNewKeyLink = driver.findElementByLinkText("Create New Key");
		for (int i = 1; i <= getNumRows(); i++) {
			keys.add(driver.findElementById("key" + i));
			notes.add(driver.findElementById("note" + i));
			restrictedBoxes.add(driver.findElementById("restricted" + i));
		}
		if(getNumRows()!=0){
			editLinks = driver.findElementsByLinkText("Edit");
			deleteButton = driver.findElementsByLinkText("Delete");
		}
	}

	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().equals("No keys found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}

	public String getKeyText(int num) {
		return keys.get(num).getText();
	}

	public ApiKeysIndexPage clickEdit(int row) {
		editLinks.get(row).click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.className("modal-body")));
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickNewLink() {
		createNewKeyLink.click();
		waitForElement(driver.findElementById("newKeyModalDiv"));
		return new ApiKeysIndexPage(driver);
	}
	
	public ApiKeysIndexPage enterNewApiKeyInfo(String note, boolean restricted){
		driver.findElementById("note").sendKeys(note);
		if(restricted){
			driver.findElementById("isRestrictedKey1").click();
		}
		driver.findElementById("submitKeyModal").click();
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickDelete(int row) {
		//waitForElement(deleteButton.get(row));
	//	deleteButton.get(row).click();
		driver.findElementById("deleteButton").click();
		handleAlert();

		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickSubmitButton(){
		sleep(4000);
		driver.findElementById("submitKeyModal").click();
		return this;
	}
	
	public ApiKeysIndexPage setNote(String message){
		sleep(4000);
		driver.findElementById("note").sendKeys(message);
		return this;
	}
}
