////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.Alert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class ApiKeysIndexPage extends BasePage {

	private List<WebElement> keys = new ArrayList<WebElement>();
	private List<WebElement> notes = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();
	private List<WebElement> deleteButton = new ArrayList<WebElement>();
	private List<WebElement> restrictedBoxes = new ArrayList<WebElement>();
	private WebElement createNewKeyLink;

	public ApiKeysIndexPage(WebDriver webdriver) {
		super(webdriver);
		createNewKeyLink = driver.findElementByLinkText("Create New Key");
		for (int i = 1; i <= getNumRows(); i++) {
			keys.add(driver.findElementById("key" + i));
			notes.add(driver.findElementById("note" + i));
			editLinks.add(driver.findElementById("edit" + i));
			deleteButton.add(driver.findElementById("delete" + i));
			restrictedBoxes.add(driver.findElementById("restricted" + i));
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

	public EditApiKeyPage clickEdit(int Row) {
		editLinks.get(Row).click();
		sleep(1000);
		return new EditApiKeyPage(driver);
	}

	// public void ClickDelete(int Row){
	// DeleteBtn.get(Row).click();
	// Sleep(1000);
	// }

	public CreateApiKeyPage clickNewLink() {
		createNewKeyLink.click();
		return new CreateApiKeyPage(driver);
	}

	public ApiKeysIndexPage clickDelete(int Row) {
		deleteButton.get(Row).click();

		Alert alert = driver.switchTo().alert();
		alert.accept();

		return new ApiKeysIndexPage(driver);
	}

}
