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

import org.openqa.selenium.Alert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class DefectTrackerDetailPage extends BasePage { 

	private WebElement nameText;
	private WebElement urlText;
	private WebElement typeText;
	private WebElement editLink;
	private WebElement backToListLink;
	private WebElement deleteButton;

	public DefectTrackerDetailPage(WebDriver webdriver) {
		super(webdriver);
		nameText = driver.findElementById("nameText");
		urlText = driver.findElementById("urlText");
		typeText = driver.findElementById("typeText");
		editLink = driver.findElementById("editLink");
		backToListLink = driver.findElementById("backToListLink");
		deleteButton = driver.findElementById("deleteButton");

	}

	public String getNameText(){
		return nameText.getText();
	}

	public String getUrlText(){
		return urlText.getText();
	}

	public String getTypeText(){
		return typeText.getText();
	}

	public DefectTrackerEditPage clickEditLink() {
		editLink.click();
		return new DefectTrackerEditPage(driver);
	}
	
	public DefectTrackerIndexPage clickBackToListLink() {
		backToListLink.click();
		return new DefectTrackerIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickDeleteButton() {
		deleteButton.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new DefectTrackerIndexPage(driver);
	}

}