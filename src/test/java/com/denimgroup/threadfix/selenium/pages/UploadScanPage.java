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

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverBackedSelenium;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import com.thoughtworks.selenium.Selenium;

public class UploadScanPage extends BasePage { 

	private Select channelSelect;
	private WebElement fileInput;
	private WebElement addAnotherChannelLink;
	private WebElement cancelLink;
	private WebElement uploadScanButton;

	public UploadScanPage(WebDriver webdriver) {
		super(webdriver);
		channelSelect = new Select(driver.findElementById("channelSelect"));
		fileInput = driver.findElementById("fileInput");
		addAnotherChannelLink = driver.findElementById("addAnotherChannelLink");
		cancelLink = driver.findElementById("cancelLink");
		uploadScanButton = driver.findElementById("uploadScanButton");
	}

	public String getChannelSelect(){
		return channelSelect.getFirstSelectedOption().getText();
	}

	public UploadScanPage setChannelSelect(String code){
		channelSelect.selectByVisibleText(code);
		return this;
	}
	
	public List<String> getChannelSelectContents(){
		List<WebElement> loc = channelSelect.getOptions();
		List<String> businesses = new ArrayList<String>();
		for(WebElement el : loc){
			businesses.add(el.getText());
		}
		return businesses;
	}

	public String getFileInput(){
		return fileInput.getText();
	}

	public UploadScanPage setFileInput(URL text){
		//fileInput.clear();
		//fileInput.sendKeys(text);
		
		Selenium selenium = new WebDriverBackedSelenium(driver, driver.getCurrentUrl());
		
		selenium.type("xpath=//input[contains(@id,\"fileInput\")]", text.toString());
		//selenium.attachFile("xpath=//input[contains(@id,\"fileInput\")]", text.toString());

		return this;
	}

	public AddChannelPage clickAddAnotherChannelLink() {
		addAnotherChannelLink.click();
		return new AddChannelPage(driver);
	}
	
	public ApplicationDetailPage clickCancelLink() {
		cancelLink.click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickUploadScanButton() {
		uploadScanButton.click();
		return new ApplicationDetailPage(driver);
	}
	
	public UploadScanPage clickUploadScanButtonInvalid() {
		uploadScanButton.click();
		return new UploadScanPage(driver);
	}
	
	public String getScanError() {
		return driver.findElementByClassName("errors").getText();
	}

}